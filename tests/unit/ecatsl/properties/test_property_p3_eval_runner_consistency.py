"""Feature: ecatsl-operationalization-and-bench-integration, Property P3 tests.

Property P3 (evaluation backfill consistency): for arbitrary verified
classification perturbations the eval_runner's backfilled report is
field-for-field identical to calling ``build_evaluation_report()`` directly
with the same inputs (the runner adds no evaluation computation), and a run
with zero completed experiments never claims superiority/optimization
(no completed experiment -> no claim).

Validates: Requirements 5.1/5.3 (tasks.md 5.4, label
``Feature: ecatsl-operationalization-and-bench-integration, Property P3``).
"""

import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from src.ecatsl.eval_dataset import build_manifest
from src.ecatsl.eval_runner import (
    _backfill_status,
    _counts_for,
    _telemetry_for,
    evidence_limitations_for,
    run_evaluation,
)
from src.ecatsl.evaluation import build_evaluation_report
from src.ecatsl.models import FindingStatus, OperationalComplexity

FIXED = datetime(2025, 1, 1, tzinfo=timezone.utc)

CLAIM_TOKENS = ("superior", "outperform", "optimiz", "better than", "improv")


def _fixed_clock():
    return FIXED


def make_entry(idx, workdir=""):
    """VulnGym-shaped manifest row (Python evidence via R1 suffix)."""
    return {
        "entry_id": f"entry-{idx:04d}",
        "project": "proj",
        "repo_url": "https://github.com/example/proj",
        "commit": f"c{idx:012d}",
        "vuln_ids": [f"CVE-2025-{idx:04d}"],
        "report_id": f"GHSA-test-{idx:04d}",
        "entry_point": {"file": f"src/app{idx}.py"},
        "critical_operation": {"file": f"src/lib{idx}.py"},
        "trace": [{"file": f"src/hop{idx}.py"}],
        "workdir": workdir,
    }


def stub_factory(confirmed_fraction: float, audit_failures: int = 0):
    """Deterministic stub service: stable per-sample confirm pattern.

    Mirrors the ServiceFactory contract: ``factory(ref) -> (service, repo)``
    with ``analyze`` returning the attributes the runner reads (findings
    statuses, audit_failures). No filesystem or network access.
    """

    def factory(repository_ref):
        class Repo:
            def close(self):
                pass

        class Svc:
            def analyze(self, request):
                bucket = sum(ord(c) for c in request.repository_ref) % 100
                confirmed = bucket / 100.0 < confirmed_fraction
                return SimpleNamespace(
                    status="completed",
                    findings=(
                        SimpleNamespace(
                            status=FindingStatus.CONFIRMED
                            if confirmed
                            else FindingStatus.UNCONFIRMED
                        ),
                    ),
                    audit_failures=tuple(
                        SimpleNamespace(kind="stub") for _ in range(audit_failures)
                    ),
                )

        return Svc(), Repo()

    return factory


def _complexity():
    return OperationalComplexity(
        configured_adapters=2,
        pipeline_stages=1,
        external_service_dependencies=0,
        manual_execution_steps=0,
    )


def _attr(report, name):
    for a in report.verified_metrics:
        if a.name == name:
            return a.value
    return None


@settings(max_examples=100, deadline=None)
@given(data=st.data())
def test_p3_runner_matches_reference_build_report(tmp_path_factory, data):
    """Req 5.1: the runner's report equals the direct reference, fieldwise."""
    n = data.draw(st.integers(min_value=1, max_value=10))
    fraction = data.draw(st.floats(min_value=0.0, max_value=1.0))
    failures = data.draw(st.integers(min_value=0, max_value=2))
    manifest = build_manifest(
        [make_entry(i, workdir=f"repo-{i}") for i in range(n)],
        clock=_fixed_clock, build_command="p3",
    )
    tmp_path = tmp_path_factory.mktemp("p3_consistency")
    path = tmp_path / "manifest.json"
    path.write_text(manifest.to_json(), encoding="utf-8", newline="\n")

    factory = stub_factory(fraction, failures)
    artifacts = run_evaluation(
        path, tmp_path / "out", clock=_fixed_clock,
        service_factory=factory, latency_seconds=0.5,
    )

    # Reference: same inputs fed straight into the shipped report builder.
    classifications = {o.sample_id: o.status for o in artifacts.outcomes}
    telemetry = _telemetry_for(
        artifacts.outcomes, latency_seconds=0.5, complexity=_complexity()
    )
    reference = build_evaluation_report(
        artifacts.manifest, artifacts.data_quality_report, classifications,
        version="1", created_at=FIXED,
        provenance=artifacts.evaluation_report.provenance,
        telemetry=telemetry, counts=_counts_for(artifacts.outcomes),
        evidence_limitations=evidence_limitations_for(artifacts.outcomes),
    )
    assert artifacts.evaluation_report == reference
    # Req 5.3: stated limitations mirror run facts (isolated/zero-analyzed).
    assert artifacts.evaluation_report.evidence_limitations == (
        evidence_limitations_for(artifacts.outcomes)
    )

    # Backfill is the sole status source: CONFIRMED only when the service
    # confirmed a finding (Path_Evidence gate); never inferred.
    for outcome in artifacts.outcomes:
        assert outcome.status in (FindingStatus.CONFIRMED, FindingStatus.UNCONFIRMED)
        if outcome.status is FindingStatus.CONFIRMED:
            assert outcome.confirmed_findings >= 1


@settings(max_examples=100, deadline=None)
@given(data=st.data())
def test_p3_backfill_status_follows_service_only(tmp_path_factory, data):
    """Req 5.1: _backfill_status maps service findings and nothing else."""
    confirmed_count = data.draw(st.integers(min_value=0, max_value=3))
    unconfirmed_count = data.draw(st.integers(min_value=0, max_value=3))
    findings = [
        SimpleNamespace(status=FindingStatus.CONFIRMED)
        for _ in range(confirmed_count)
    ] + [
        SimpleNamespace(status=FindingStatus.UNCONFIRMED)
        for _ in range(unconfirmed_count)
    ]
    result = SimpleNamespace(status="completed", findings=findings, audit_failures=())
    status = _backfill_status(result)
    if confirmed_count > 0:
        assert status is FindingStatus.CONFIRMED
    else:
        assert status is FindingStatus.UNCONFIRMED


@settings(max_examples=100, deadline=None)
@given(data=st.data())
def test_p3_no_completed_experiment_no_claim(tmp_path_factory, data):
    """Req 5.3: without completed experiments the report carries zero claim."""
    n = data.draw(st.integers(min_value=1, max_value=8))
    fraction = data.draw(st.floats(min_value=0.0, max_value=1.0))
    manifest = build_manifest(
        [make_entry(i, workdir=f"repo-{i}") for i in range(n)],
        clock=_fixed_clock, build_command="p3",
    )
    tmp_path = tmp_path_factory.mktemp("p3_noclaim")
    path = tmp_path / "manifest.json"
    path.write_text(manifest.to_json(), encoding="utf-8", newline="\n")

    artifacts = run_evaluation(
        path, tmp_path / "out", clock=_fixed_clock,
        service_factory=stub_factory(fraction, 0), latency_seconds=0.5,
    )
    # No experiment ran: evidence_limitations disclose the gap and the
    # verified metrics stay plain counts (no superiority attributes).
    assert artifacts.evaluation_report.evidence_limitations is not None
    names = [a.name for a in artifacts.evaluation_report.verified_metrics]
    for claim_name in ("superiority_claim", "optimization_claim", "winner"):
        assert claim_name not in names, claim_name
    for name in ("evaluation_report.json", "cost_report.json",
                 "data_quality_report.json"):
        payload = (tmp_path / "out" / name).read_text(encoding="utf-8").lower()
        for token in CLAIM_TOKENS:
            assert token not in payload, f"claim token '{token}' in {name}"


@settings(max_examples=100, deadline=None)
@given(data=st.data())
def test_p3_blank_workdir_isolation_is_truthful(tmp_path_factory, data):
    """Req 3.5->5.1: unanalyzable samples are isolated, audited, never invented."""
    n = data.draw(st.integers(min_value=1, max_value=8))
    blank_count = data.draw(st.integers(min_value=0, max_value=n))
    rows = [
        make_entry(i, workdir=("" if i < blank_count else f"repo-{i}"))
        for i in range(n)
    ]
    manifest = build_manifest(rows, clock=_fixed_clock, build_command="p3")
    tmp_path = tmp_path_factory.mktemp("p3_isolation")
    path = tmp_path / "manifest.json"
    path.write_text(manifest.to_json(), encoding="utf-8", newline="\n")

    # fraction=0.0 ensures any CONFIRMED could only come from a bypass.
    artifacts = run_evaluation(
        path, tmp_path / "out", clock=_fixed_clock,
        service_factory=stub_factory(0.0, 0), latency_seconds=0.5,
    )
    outcomes = {o.sample_id: o for o in artifacts.outcomes}
    isolated = set(artifacts.extra["isolated_samples"])
    assert len(artifacts.outcomes) == n
    assert len(isolated) == blank_count
    for idx in range(blank_count):
        outcome = outcomes[f"entry-{idx:04d}"]
        assert outcome.status is FindingStatus.UNCONFIRMED
        assert outcome.audit_failures == 1
    analyzed = 1 if blank_count < n else 0
    total_failures = sum(o.audit_failures for o in artifacts.outcomes)
    assert total_failures == blank_count
    assert artifacts.evaluation_report.telemetry.tooling_failures == total_failures
    # Zero-analyzed edge: every sample isolated, still zero-inclusive report.
    if analyzed == 0:
        rep = json.loads((tmp_path / "out" / "evaluation_report.json").read_text(
            encoding="utf-8"))
        assert rep["telemetry"]["llm_tokens"] == 0
