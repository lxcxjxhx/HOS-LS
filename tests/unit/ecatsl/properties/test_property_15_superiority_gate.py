"""Feature: evidence-constrained-taint-spec-learning, Property 15 tests.

Property 15: Superiority claims are evidence-gated.
Generate comparison evidence and limitations and assert claims only with
linked verified support and stated limitations.

Validates: Requirements 10.5-10.7.
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from src.ecatsl.dataset_release import build_release  # noqa: E402
from src.ecatsl.evaluation import (  # noqa: E402
    DEFAULT_BASELINE,
    build_evaluation_report,
    build_optimization_experiment,
    validate_experiment,
)
from src.ecatsl.models import (  # noqa: E402
    EvaluationTelemetry,
    FindingStatus,
    OperationalComplexity,
    Provenance,
)
from src.ecatsl.reporting import (  # noqa: E402
    TELEMETRY_DIFF_METRICS,
    build_optimization_report,
)

OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))

_LABELS = st.sampled_from(("vulnerable", "fixed", "clean"))
_STATUSES = st.sampled_from((FindingStatus.CONFIRMED, FindingStatus.UNCONFIRMED, None))
_PROJECTS = st.sampled_from(("proj-a", "proj-b"))
_NON_NEGATIVE = st.floats(
    min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False
)


def provenance() -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=OFFSET_TIME,
        source_identifier="bench/datasets/VulnGym",
        source_revision="v0.1.4",
        content_identity="dataset:v1",
    )


def telemetry(latency=0.0, tokens=0, money=0.0) -> EvaluationTelemetry:
    return EvaluationTelemetry(
        latency_seconds=latency,
        llm_tokens=tokens,
        llm_monetary_cost=money,
        complexity=OperationalComplexity(
            configured_adapters=0,
            pipeline_stages=0,
            external_service_dependencies=0,
            manual_execution_steps=0,
        ),
    )


@st.composite
def _case(draw):
    size = draw(st.integers(min_value=1, max_value=6))
    labels = [draw(_LABELS) for _ in range(size)]
    statuses = [draw(_STATUSES) for _ in range(size)]
    projects = [draw(_PROJECTS) for _ in range(size)]
    return labels, statuses, projects


def _evaluation(case, latency, tokens, money):
    labels, statuses, projects = case
    rows = []
    for index in range(len(labels)):
        rid = f"r{index}"
        rows.append(
            dict(
                id=rid,
                content=rid.encode(),
                content_hash=sha256(rid.encode()).hexdigest(),
                classification=labels[index],
                project_id=projects[index],
                project_time_group=f"{projects[index]}:t1",
            )
        )
    manifest, quality = build_release(
        rows,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        data_type="vulngym_entry",
    )
    classifications = {
        f"r{i}": status for i, status in enumerate(statuses) if status is not None
    }
    return build_evaluation_report(
        manifest,
        quality,
        classifications,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        telemetry=telemetry(latency, tokens, money),
    )


@settings(max_examples=100, deadline=None)
@given(
    case=_case(),
    baseline_latency=_NON_NEGATIVE,
    changed_latency=_NON_NEGATIVE,
    link=st.sampled_from(("none", "linked", "unlinked_id", "explicitly_missing")),
    completed=st.booleans(),
    stated_limitations=st.booleans(),
)
def test_property_15_superiority_gate(
    case, baseline_latency, changed_latency, link, completed, stated_limitations
):
    """Feature: evidence-constrained-taint-spec-learning, Property 15: a superiority claim appears exactly when the metric improved, its linked experiment completed with verified support, and limitations are stated; otherwise the measured difference is reported without superiority language (Req 10.5-10.7)."""
    baseline = _evaluation(case, baseline_latency, 0, 0.0)
    changed = _evaluation(case, changed_latency, 0, 0.0)
    ok, violations = validate_experiment(baseline, changed)
    assert ok and violations == ()

    difference = changed_latency - baseline_latency
    direction = (
        "improvement" if difference < 0
        else "regression" if difference > 0
        else "no_change"
    )

    experiment = None
    links = {}
    missing_links = ()
    if link != "none":
        experiment = build_optimization_experiment(
            baseline,
            changed,
            version="1",
            created_at=OFFSET_TIME,
            provenance=provenance(),
            baseline_configuration_id="base:default:v1",
            changed_configuration_id="opt:changed:v1",
        )
    if link == "linked":
        links = {"latency_seconds": experiment.artifact_id}
    elif link == "unlinked_id":
        # A link to an artifact identity that no completed experiment backs:
        # verified support is absent, so the claim gate stays closed.
        links = {"latency_seconds": "sha256:not-a-completed-experiment"}
    elif link == "explicitly_missing":
        # Contract: a metric in ``missing_links`` declares its experiment
        # linkage absent, so no link is supplied for it.
        missing_links = ("latency_seconds",)
    limitations = (
        {"latency_seconds": "measured on generated benchmark samples only"}
        if stated_limitations
        else {}
    )

    report = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=DEFAULT_BASELINE,
        experiment=experiment,
        experiment_completed=completed,
        experiment_links=links,
        limitations=limitations,
        missing_links=missing_links,
    )

    expected_claim = (
        direction == "improvement"
        and link == "linked"
        and completed
        and stated_limitations
    )
    latency_claim = next(c for c in report.claims if c.metric == "latency_seconds")
    assert latency_claim.claim == expected_claim
    assert latency_claim.measured_difference == difference
    assert latency_claim.direction == direction
    assert set(c.metric for c in report.claims) == set(TELEMETRY_DIFF_METRICS)

    differences = {
        item.name.removeprefix("diff:"): float(item.value)
        for item in report.measured_differences
    }
    assert differences["latency_seconds"] == difference

    if latency_claim.claim:
        # Emitted claim carries the complete supporting evidence chain.
        assert latency_claim.missing_evidence == ()
        assert latency_claim.experiment_completed
        assert latency_claim.experiment_artifact_id == experiment.artifact_id
        assert latency_claim.limitations == (
            "measured on generated benchmark samples only",
        )
    else:
        # No superiority language without the full evidence chain.
        assert not latency_claim.experiment_completed or not latency_claim.claim
        if direction == "improvement" and not latency_claim.claim:
            assert latency_claim.missing_evidence, (
                "an unclaimed improvement must state explicit missing evidence"
            )
        if not stated_limitations:
            assert "missing_limitations" in latency_claim.missing_evidence
        if link == "unlinked_id":
            assert "experiment_not_completed" in latency_claim.missing_evidence
        elif link in ("none", "explicitly_missing"):
            assert "missing_experiment_link" in latency_claim.missing_evidence
        elif link == "linked" and not completed:
            assert "experiment_not_completed" in latency_claim.missing_evidence
        # No claim anywhere despite possibly positive measured differences.
        assert not any(c.claim for c in report.claims if c.metric == "latency_seconds")

    # Missing-link bookkeeping covers exactly the metrics without support.
    expected_missing = tuple(
        metric
        for metric in TELEMETRY_DIFF_METRICS
        if links.get(metric) is None and metric not in missing_links
    )
    assert report.missing_experiment_link == expected_missing


@settings(max_examples=100, deadline=None)
@given(
    case=_case(),
    baseline_tokens=st.integers(min_value=0, max_value=5000),
    changed_tokens=st.integers(min_value=0, max_value=5000),
    link=st.sampled_from(("linked", "none")),
    completed=st.booleans(),
    stated_limitations=st.booleans(),
)
def test_property_15_token_cost_gate(
    case, baseline_tokens, changed_tokens, link, completed, stated_limitations
):
    """Feature: evidence-constrained-taint-spec-learning, Property 15: LLM token/money savings claims follow the same evidence gate, with the measured zero difference retained when telemetry is identical (Req 10.5, 10.7)."""
    baseline = _evaluation(case, 0.0, baseline_tokens, float(baseline_tokens))
    changed = _evaluation(case, 0.0, changed_tokens, float(changed_tokens))

    experiment = None
    links = {}
    if link == "linked":
        experiment = build_optimization_experiment(
            baseline,
            changed,
            version="1",
            created_at=OFFSET_TIME,
            provenance=provenance(),
            baseline_configuration_id="base:default:v1",
            changed_configuration_id="opt:changed:v1",
        )
        links = {"llm_tokens": experiment.artifact_id}
    limitations = (
        {"llm_tokens": "generated fixture traffic only"} if stated_limitations else {}
    )
    report = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=DEFAULT_BASELINE,
        experiment=experiment,
        experiment_completed=completed,
        experiment_links=links,
        limitations=limitations,
    )

    tokens_claim = next(c for c in report.claims if c.metric == "llm_tokens")
    expected_claim = (
        changed_tokens < baseline_tokens and link == "linked" and completed
        and stated_limitations
    )
    assert tokens_claim.claim == expected_claim
    assert tokens_claim.measured_difference == changed_tokens - baseline_tokens
    if tokens_claim.claim:
        assert tokens_claim.missing_evidence == ()
    else:
        assert not any(
            c.claim for c in report.claims if c.metric == "llm_tokens"
        )
        # A zero difference stays measured and retained, never claimed.
        if changed_tokens == baseline_tokens:
            assert tokens_claim.direction == "no_change"
            assert tokens_claim.measured_difference == 0.0
