"""Feature: evidence-constrained-taint-spec-learning, Property 11 tests.

Property 11: Evaluation and optimization reports are complete and claim-safe.
Generate telemetry, classifications, strata, and paired configurations and
assert zero-inclusive metrics, paired-experiment validity, and
evidence-gated improvement claims.

Validates: Requirements 8.1-8.6
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from src.ecatsl.dataset_release import build_release  # noqa: E402
from src.ecatsl.evaluation import (  # noqa: E402
    DEFAULT_BASELINE,
    build_evaluation_report,
    build_optimization_experiment,
    confusion_matrix,
    validate_experiment,
    verified_metrics,
)
from src.ecatsl.models import (  # noqa: E402
    Attribute,
    BenchmarkManifest,
    EvaluationTelemetry,
    FindingStatus,
    OperationalComplexity,
    Provenance,
)
from src.ecatsl.reporting import (  # noqa: E402
    TELEMETRY_DIFF_METRICS,
    build_cost_report,
    build_optimization_report,
)

OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))

_LABELS = st.sampled_from(("vulnerable", "fixed", "clean"))
_STATUSES = st.sampled_from((FindingStatus.CONFIRMED, FindingStatus.UNCONFIRMED, None))
_PROJECTS = st.sampled_from(("proj-a", "proj-b", "proj-c"))
_CWES = st.sampled_from(("CWE-89", "CWE-78", "CWE-918", ""))
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


@st.composite
def _evaluation_case(draw):
    """Sample classes, verified statuses, and per-sample project/CWE strata."""
    size = draw(st.integers(min_value=1, max_value=8))
    labels = [draw(_LABELS) for _ in range(size)]
    statuses = [draw(_STATUSES) for _ in range(size)]
    projects = [draw(_PROJECTS) for _ in range(size)]
    cwes = [draw(_CWES) for _ in range(size)]
    return labels, statuses, projects, cwes


def _rows_for(labels, projects):
    rows = []
    for index, (classification, project) in enumerate(zip(labels, projects)):
        rid = f"r{index}"
        rows.append(
            dict(
                id=rid,
                content=rid.encode(),
                content_hash=sha256(rid.encode()).hexdigest(),
                classification=classification,
                project_id=project,
                project_time_group=f"{project}:t1",
            )
        )
    return rows


def _attributes_for(labels, projects, cwes):
    attributes = []
    for index, (classification, project, cwe) in enumerate(
        zip(labels, projects, cwes)
    ):
        attributes.append(Attribute(name=f"project_id:r{index}", value=project))
        attributes.append(Attribute(name=f"classification:r{index}", value=classification))
        if cwe:
            attributes.append(Attribute(name=f"cwe:r{index}", value=cwe))
    return attributes


def manifest_with_attributes(rows, attributes):
    manifest, quality = build_release(
        rows,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        data_type="vulngym_entry",
    )
    if attributes:
        manifest = BenchmarkManifest(
            version=manifest.version,
            created_at=manifest.created_at,
            provenance=manifest.provenance,
            samples=manifest.samples,
            catalog_record_ids=manifest.catalog_record_ids,
            split_assignments=manifest.split_assignments,
            sample_attributes=tuple(attributes),
        )
    return manifest, quality


def telemetry(**kw):
    defaults = dict(
        latency_seconds=0.0,
        llm_tokens=0,
        llm_monetary_cost=0.0,
        complexity=OperationalComplexity(
            configured_adapters=0,
            pipeline_stages=0,
            external_service_dependencies=0,
            manual_execution_steps=0,
        ),
    )
    defaults.update(kw)
    return EvaluationTelemetry(**defaults)


def build_report(manifest, quality, classifications, **kw):
    kw.setdefault("version", "1")
    kw.setdefault("created_at", OFFSET_TIME)
    kw.setdefault("provenance", provenance())
    kw.setdefault("telemetry", telemetry())
    return build_evaluation_report(manifest, quality, classifications, **kw)


def metric_value(report, name):
    return next(float(a.value) for a in report.verified_metrics if a.name == name)


def _stratum_matches(parts, index, labels, projects, cwes):
    """Does sample ``index`` belong to the stratum parsed from ``parts``?"""
    if "cwe" in parts and parts["cwe"] != cwes[index]:
        return False
    if "project" in parts and parts["project"] != projects[index]:
        return False
    if "sample_class" in parts and parts["sample_class"] != labels[index]:
        return False
    return True


@settings(max_examples=100, deadline=None)
@given(case=_evaluation_case())
def test_property_11_zero_inclusive_metrics_and_strata(case):
    """Feature: evidence-constrained-taint-spec-learning, Property 11: global and per-stratum metrics are complete and zero-inclusive and equal the reference confusion-matrix calculation (Req 10.1-10.4, 10.2)."""
    labels, statuses, projects, cwes = case
    rows = _rows_for(labels, projects)
    manifest, quality = manifest_with_attributes(
        rows, _attributes_for(labels, projects, cwes)
    )
    classifications = {
        row["id"]: status for row, status in zip(rows, statuses) if status is not None
    }
    report = build_report(manifest, quality, classifications)

    reference_labels = [row["classification"] == "vulnerable" for row in rows]
    reference = confusion_matrix(reference_labels, statuses)
    metrics = verified_metrics(reference)
    assert metric_value(report, "precision") == metrics["precision"]
    assert metric_value(report, "recall") == metrics["recall"]
    assert metric_value(report, "f1") == metrics["f1"]
    assert metric_value(report, "tp") == float(reference.tp)
    assert metric_value(report, "fp") == float(reference.fp)
    assert metric_value(report, "fn") == float(reference.fn)
    assert metric_value(report, "tn") == float(reference.tn)
    assert metric_value(report, "sample_count") == float(len(rows))

    keys = [s.key for s in report.strata]
    assert len(keys) == len(set(keys))
    for stratum in report.strata:
        parts = dict(part.split("=", 1) for part in stratum.definition)
        matching = [
            index
            for index in range(len(rows))
            if _stratum_matches(parts, index, labels, projects, cwes)
        ]
        assert matching, "every reported stratum must contain at least one sample"
        assert stratum.sample_count == len(matching)
        assert stratum.sample_ids == tuple(f"r{index}" for index in matching)
        stratum_matrix = confusion_matrix(
            [reference_labels[index] for index in matching],
            [statuses[index] for index in matching],
        )
        assert (stratum.matrix.tp, stratum.matrix.fp, stratum.matrix.fn,
                stratum.matrix.tn) == (
            stratum_matrix.tp, stratum_matrix.fp, stratum_matrix.fn, stratum_matrix.tn
        )
        stratum_metrics = verified_metrics(stratum_matrix)
        assert stratum.precision == stratum_metrics["precision"]
        assert stratum.recall == stratum_metrics["recall"]
        assert stratum.f1 == stratum_metrics["f1"]

    cost = build_cost_report(
        report, version="1", created_at=OFFSET_TIME, provenance=provenance()
    )
    assert cost.evaluation_report_id == report.artifact_id
    assert len(cost.strata) == len(report.strata)
    for stratum_cost in cost.strata:
        # Degenerate strata telemetry stays zero-inclusive, never omitted (Req 10.4).
        assert stratum_cost.analysis_latency_seconds == 0.0
        assert stratum_cost.audit_cost == 0.0
        assert stratum_cost.llm_tokens == 0
        assert stratum_cost.llm_cost == 0.0
        assert stratum_cost.tooling_failures == 0
        assert stratum_cost.llm_failures == 0
        assert stratum_cost.rejected_candidates == 0


@settings(max_examples=100, deadline=None)
@given(
    case=_evaluation_case(),
    tooling=st.integers(min_value=0, max_value=5),
    llm=st.integers(min_value=0, max_value=5),
    rejected=st.integers(min_value=0, max_value=5),
)
def test_property_11_zero_inclusive_per_stratum_counters(case, tooling, llm, rejected):
    """Feature: evidence-constrained-taint-spec-learning, Property 11: per-stratum counters equal the zero-inclusive sum over their samples, and the cost report retains every stratum (Req 8.1, 10.4)."""
    labels, statuses, projects, cwes = case
    rows = _rows_for(labels, projects)
    manifest, quality = manifest_with_attributes(
        rows, _attributes_for(labels, projects, cwes)
    )
    classifications = {
        row["id"]: status for row, status in zip(rows, statuses) if status is not None
    }
    counts = {}
    for row in rows:
        counts[f"tooling_failures:{row['id']}"] = tooling
        counts[f"llm_failures:{row['id']}"] = llm
        counts[f"rejected_candidates:{row['id']}"] = rejected
    report = build_report(manifest, quality, classifications, counts=counts)

    cost = build_cost_report(
        report, version="1", created_at=OFFSET_TIME, provenance=provenance()
    )
    assert len(cost.strata) == len(report.strata)
    for stratum_cost in cost.strata:
        parts = dict(part.split("=", 1) for part in stratum_cost.definition)
        matching = [
            index
            for index in range(len(rows))
            if _stratum_matches(parts, index, labels, projects, cwes)
        ]
        assert stratum_cost.sample_count == len(matching)
        assert stratum_cost.tooling_failures == tooling * len(matching)
        assert stratum_cost.llm_failures == llm * len(matching)
        assert stratum_cost.rejected_candidates == rejected * len(matching)


@settings(max_examples=100, deadline=None)
@given(
    case=_evaluation_case(),
    baseline_latency=_NON_NEGATIVE,
    changed_latency=_NON_NEGATIVE,
    tamper=st.sampled_from(
        ("none", "manifest", "quality", "hashes", "strata", "environment")
    ),
)
def test_property_11_paired_experiment_validity(
    case, baseline_latency, changed_latency, tamper
):
    """Feature: evidence-constrained-taint-spec-learning, Property 11: paired experiments are accepted for identical evaluation identity and every telemetry payload (including zero differences) and rejected for each tampered identity dimension (Req 8.2-8.3)."""
    labels, statuses, projects, cwes = case
    rows = _rows_for(labels, projects)
    manifest, quality = manifest_with_attributes(
        rows, _attributes_for(labels, projects, cwes)
    )
    classifications = {
        row["id"]: status for row, status in zip(rows, statuses) if status is not None
    }
    baseline = build_report(
        manifest, quality, classifications, telemetry=telemetry(
            latency_seconds=baseline_latency
        )
    )
    changed = build_report(
        manifest, quality, classifications, telemetry=telemetry(
            latency_seconds=changed_latency
        )
    )

    expected_violation = {
        "manifest": "benchmark_manifest_id",
        "quality": "data_quality_report_id",
        "hashes": "evaluated_sample_hashes",
        "strata": "strata",
        "environment": "environment",
    }
    baseline_environment = Attribute(name="environment", value="env:baseline:v1")
    changed_environment = baseline_environment
    if tamper == "manifest":
        changed = changed.model_copy(
            update={"benchmark_manifest_id": "sha256:tampered-manifest"}
        )
    elif tamper == "quality":
        changed = changed.model_copy(
            update={"data_quality_report_id": "sha256:tampered-quality"}
        )
    elif tamper == "hashes":
        changed = changed.model_copy(update={"evaluated_sample_hashes": ("tampered",)})
    elif tamper == "strata":
        changed = changed.model_copy(update={"strata": ()})
    elif tamper == "environment":
        changed_environment = Attribute(name="environment", value="env:changed:v2")

    ok, violations = validate_experiment(
        baseline, changed, baseline_environment, changed_environment
    )
    if tamper == "none":
        assert ok and violations == ()
        experiment = build_optimization_experiment(
            baseline,
            changed,
            version="1",
            created_at=OFFSET_TIME,
            provenance=provenance(),
            baseline_configuration_id="base:default:v1",
            changed_configuration_id="opt:changed:v1",
            baseline_environment=baseline_environment,
            changed_environment=changed_environment,
        )
        differences = {
            item.name.removeprefix("diff:"): float(item.value)
            for item in experiment.measured_differences
        }
        assert set(differences) == set(TELEMETRY_DIFF_METRICS)
        assert differences["latency_seconds"] == changed_latency - baseline_latency
        assert experiment.baseline_metrics == baseline.verified_metrics
        assert experiment.evaluated_sample_hashes == baseline.evaluated_sample_hashes
    else:
        assert not ok
        assert expected_violation[tamper] in violations


@settings(max_examples=100, deadline=None)
@given(
    case=_evaluation_case(),
    baseline_latency=_NON_NEGATIVE,
    changed_latency=_NON_NEGATIVE,
    link=st.sampled_from(("none", "linked", "explicitly_missing")),
    completed=st.booleans(),
    stated_limitations=st.booleans(),
)
def test_property_11_evidence_gated_claims(
    case, baseline_latency, changed_latency, link, completed, stated_limitations
):
    """Feature: evidence-constrained-taint-spec-learning, Property 11: a superiority claim appears exactly when the metric improved, its linked experiment completed, and limitations are stated; otherwise the measured difference is reported with explicit missing evidence (Req 8.4-8.6)."""
    labels, statuses, projects, cwes = case
    rows = _rows_for(labels, projects)
    manifest, quality = manifest_with_attributes(
        rows, _attributes_for(labels, projects, cwes)
    )
    classifications = {
        row["id"]: status for row, status in zip(rows, statuses) if status is not None
    }
    baseline = build_report(
        manifest, quality, classifications, telemetry=telemetry(
            latency_seconds=baseline_latency
        )
    )
    changed = build_report(
        manifest, quality, classifications, telemetry=telemetry(
            latency_seconds=changed_latency
        )
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
    if link == "explicitly_missing":
        # Contract (test_optimization_report_missing_link_recorded): a metric in
        # ``missing_links`` declares its experiment linkage absent, so no link
        # is supplied for it.
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

    difference = changed_latency - baseline_latency
    if difference < 0:
        direction = "improvement"
    elif difference > 0:
        direction = "regression"
    else:
        direction = "no_change"
    expected_claim = (
        direction == "improvement"
        and link == "linked"
        and completed
        and stated_limitations
    )

    assert len(report.claims) == len(TELEMETRY_DIFF_METRICS)
    assert {c.metric for c in report.claims} == set(TELEMETRY_DIFF_METRICS)
    differences = {
        item.name.removeprefix("diff:"): float(item.value)
        for item in report.measured_differences
    }
    assert set(differences) == set(TELEMETRY_DIFF_METRICS)
    assert differences["latency_seconds"] == difference

    latency_claim = next(c for c in report.claims if c.metric == "latency_seconds")
    assert latency_claim.claim == expected_claim
    assert latency_claim.measured_difference == difference
    assert latency_claim.direction == direction
    if latency_claim.claim:
        assert latency_claim.missing_evidence == ()
        assert latency_claim.experiment_completed
        assert latency_claim.experiment_artifact_id is not None
        assert latency_claim.limitations
    else:
        assert not latency_claim.experiment_completed or not latency_claim.claim
        if direction == "improvement" and not latency_claim.claim:
            assert latency_claim.missing_evidence
        if not stated_limitations:
            assert "missing_limitations" in latency_claim.missing_evidence

    expected_missing = tuple(
        metric
        for metric in TELEMETRY_DIFF_METRICS
        if links.get(metric) is None and metric not in missing_links
    )
    assert report.missing_experiment_link == expected_missing
