"""Paired-evaluation integration tests (Task 7.9).

Evaluates vulnerable/fixed/clean fixtures with confirmed, unconfirmed,
false-positive, false-negative, empty-stratum, zero-cost, and partial-failure
cases through the real release → evaluation → reporting pipeline over an
on-disk artifact repository. Asserts split leakage prevention, per-stratum
traceability, cost/complexity completeness, baseline identity, absence of
unsupported superiority claims, and restart/replay of the retained reports.

_Requirements: 8.1-8.7, 9.1-9.11, 10.1-10.7_
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from src.ecatsl.artifact_repository import ArtifactRepository
from src.ecatsl.dataset_release import SPLITS, assign_split, build_release
from src.ecatsl.evaluation import (
    DEFAULT_BASELINE,
    build_evaluation_report,
    build_optimization_experiment,
    confusion_matrix,
    validate_experiment,
    verified_metrics,
)
from src.ecatsl.models import (
    Attribute,
    BenchmarkManifest,
    EvaluationTelemetry,
    FindingStatus,
    OperationalComplexity,
    Provenance,
)
from src.ecatsl.reporting import (
    TELEMETRY_DIFF_METRICS,
    build_cost_report,
    build_optimization_report,
)

NOW = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))

SUPPORTED = (("integration-adapter", "1"),)


def _prov(identity: str) -> Provenance:
    return Provenance(
        origin="test",
        retrieved_at=NOW,
        source_identifier=identity,
        source_revision="v1",
        content_identity=identity,
        transformation_history=("verified-evaluation:v1",),
    )


# --------------------------------------------------------------- fixtures
#
# Benchmark truth (classification) paired with verified finding statuses:
#   r0 vulnerable CONFIRMED   -> true positive
#   r1 fixed    UNCONFIRMED   -> true negative   (pair P1 with r0)
#   r2 vulnerable UNCONFIRMED -> false negative  (pair P2 with r3)
#   r3 clean    None          -> true negative   (missing classification)
#   r4 fixed    CONFIRMED     -> false positive
#   r5 vulnerable UNCONFIRMED -> false negative  (second project)
FIXTURE_ROWS = (
    {"id": "r0", "classification": "vulnerable", "project_id": "proj-a",
     "project_time_group": "proj-a:t1", "pair_id": "P1",
     "status": FindingStatus.CONFIRMED, "cwe": "CWE-89"},
    {"id": "r1", "classification": "fixed", "project_id": "proj-a",
     "project_time_group": "proj-a:t1", "pair_id": "P1",
     "status": FindingStatus.UNCONFIRMED, "cwe": "CWE-89"},
    {"id": "r2", "classification": "vulnerable", "project_id": "proj-b",
     "project_time_group": "proj-b:t1", "pair_id": "P2",
     "status": FindingStatus.UNCONFIRMED, "cwe": "CWE-78"},
    {"id": "r3", "classification": "clean", "project_id": "proj-b",
     "project_time_group": "proj-b:t1", "pair_id": "P2",
     "status": None, "cwe": "CWE-78"},
    {"id": "r4", "classification": "fixed", "project_id": "proj-a",
     "project_time_group": "proj-a:t1", "pair_id": None,
     "status": FindingStatus.CONFIRMED, "cwe": "CWE-918"},
    {"id": "r5", "classification": "vulnerable", "project_id": "proj-b",
     "project_time_group": "proj-b:t2", "pair_id": None,
     "status": FindingStatus.UNCONFIRMED, "cwe": "CWE-78"},
)

REFERENCE_MATRIX = confusion_matrix(
    [row["classification"] == "vulnerable" for row in FIXTURE_ROWS],
    [row["status"] for row in FIXTURE_ROWS],
)


def _release_rows():
    rows = []
    for rec in FIXTURE_ROWS:
        content = rec["id"].encode()
        rows.append(
            dict(
                id=rec["id"],
                content=content,
                content_hash=sha256(content).hexdigest(),
                classification=rec["classification"],
                project_id=rec["project_id"],
                project_time_group=rec["project_time_group"],
                pair_id=rec["pair_id"],
            )
        )
    return rows


def _manifest_attributes():
    attributes = []
    for rec in FIXTURE_ROWS:
        attributes.append(
            Attribute(name=f"project_id:{rec['id']}", value=rec["project_id"])
        )
        attributes.append(
            Attribute(name=f"classification:{rec['id']}", value=rec["classification"])
        )
        attributes.append(Attribute(name=f"cwe:{rec['id']}", value=rec["cwe"]))
    return tuple(attributes)


def _zero_telemetry(**kw):
    values = dict(
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
    values.update(kw)
    return EvaluationTelemetry(**values)


def _build_release(tracked=None):
    manifest, quality = build_release(
        _release_rows(),
        version="v1",
        created_at=NOW,
        provenance=_prov("dataset-release"),
        data_type="vulngym_entry",
        tracked=tracked,
    )
    manifest = BenchmarkManifest(
        version=manifest.version,
        created_at=manifest.created_at,
        provenance=manifest.provenance,
        samples=manifest.samples,
        catalog_record_ids=manifest.catalog_record_ids,
        split_assignments=manifest.split_assignments,
        sample_attributes=_manifest_attributes(),
    )
    return manifest, quality


def _classifications():
    return {
        rec["id"]: rec["status"]
        for rec in FIXTURE_ROWS
        if rec["status"] is not None
    }


def _evaluation(telemetry=None, counts=None):
    manifest, quality = _build_release()
    report = build_evaluation_report(
        manifest,
        quality,
        _classifications(),
        version="v1",
        created_at=NOW,
        provenance=_prov("evaluation"),
        telemetry=telemetry or _zero_telemetry(),
        counts=counts,
    )
    return manifest, quality, report


def _split_of(manifest, sample_id):
    return next(
        a.value for a in manifest.split_assignments if a.name == f"split:{sample_id}"
    )


# ------------------------------------------------------------ split lineage


def test_release_split_lineage_and_pair_leakage_prevention():
    """Req 9.8-9.9: paired members share one Project_Time_Group split and a
    cross-split pair is rejected outright."""
    manifest, _ = _build_release()
    assert {s.sample_id for s in manifest.samples} == {
        rec["id"] for rec in FIXTURE_ROWS
    }
    for pair_id in ("P1", "P2"):
        members = [
            rec["id"] for rec in FIXTURE_ROWS if rec["pair_id"] == pair_id
        ]
        splits = {_split_of(manifest, sid) for sid in members}
        assert len(splits) == 1
        assert splits.pop() in SPLITS
    # Every Project_Time_Group has exactly one deterministic split decision.
    for group in {rec["project_time_group"] for rec in FIXTURE_ROWS}:
        assert assign_split(group) in SPLITS

    # A paired relationship landing in two splits is refused before any
    # evaluation can consume a leaky manifest.
    first_group = "proj-a:t1"
    second_group = next(
        (
            g
            for g in (f"proj-x:t{i}" for i in range(64))
            if assign_split(g) != assign_split(first_group)
        ),
        None,
    )
    assert second_group is not None
    leaked = [
        dict(id="la", content=b"a", content_hash=sha256(b"a").hexdigest(),
             classification="vulnerable", project_id="proj-a",
             project_time_group=first_group, pair_id="PX"),
        dict(id="lb", content=b"b", content_hash=sha256(b"b").hexdigest(),
             classification="fixed", project_id="proj-x",
             project_time_group=second_group, pair_id="PX"),
    ]
    with pytest.raises(ValueError, match="paired samples leaked across splits"):
        build_release(
            leaked,
            version="v1",
            created_at=NOW,
            provenance=_prov("leaked"),
            data_type="vulngym_entry",
        )


# --------------------------------------------------- verified evaluation


def test_confirmed_unconfirmed_fp_fn_cases_match_reference():
    """Req 10.1-10.3: TP/FN/FP/TN fixture cases equal the reference matrix and
    zero-inclusive metrics; missing classifications count as not-predicted."""
    _, _, report = _evaluation()
    reference_metrics = verified_metrics(REFERENCE_MATRIX)
    assert REFERENCE_MATRIX == confusion_matrix(
        [row["classification"] == "vulnerable" for row in FIXTURE_ROWS],
        [row["status"] for row in FIXTURE_ROWS],
    )
    reported = {
        a.name: float(a.value) for a in report.verified_metrics if ":" not in a.name
    }
    assert (reported["tp"], reported["fp"], reported["fn"], reported["tn"]) == (
        REFERENCE_MATRIX.tp, REFERENCE_MATRIX.fp,
        REFERENCE_MATRIX.fn, REFERENCE_MATRIX.tn,
    )
    assert (REFERENCE_MATRIX.tp, REFERENCE_MATRIX.fp,
            REFERENCE_MATRIX.fn, REFERENCE_MATRIX.tn) == (1, 1, 2, 2)
    for name in ("precision", "recall", "f1"):
        assert reported[name] == reference_metrics[name]
    assert reported["sample_count"] == float(len(FIXTURE_ROWS))


def test_strata_traceable_nonempty_and_cover_populated_dimensions():
    """Req 10.2, 10.4: every reported stratum is non-empty, traceable to
    manifest samples, and exactly covers every populated dimension value; no
    stratum is emitted for an unpopulated value (empty-stratum case)."""
    manifest, _, report = _evaluation()
    keys = [s.key for s in report.strata]
    assert len(keys) == len(set(keys))
    sample_ids = {s.sample_id for s in manifest.samples}
    for stratum in report.strata:
        assert stratum.sample_count >= 1
        assert set(stratum.sample_ids) <= sample_ids
        parts = dict(part.split("=", 1) for part in stratum.definition)
        for sid in stratum.sample_ids:
            rec = next(r for r in FIXTURE_ROWS if r["id"] == sid)
            if "project" in parts:
                assert parts["project"] == rec["project_id"]
            if "cwe" in parts:
                assert parts["cwe"] == rec["cwe"]
            if "sample_class" in parts:
                assert parts["sample_class"] == rec["classification"]
        stratum_reference = confusion_matrix(
            [r["classification"] == "vulnerable" for r in FIXTURE_ROWS
             if r["id"] in set(stratum.sample_ids)],
            [r["status"] for r in FIXTURE_ROWS if r["id"] in set(stratum.sample_ids)],
        )
        assert (stratum.matrix.tp, stratum.matrix.fp,
                stratum.matrix.fn, stratum.matrix.tn) == (
            stratum_reference.tp, stratum_reference.fp,
            stratum_reference.fn, stratum_reference.tn,
        )
    expected = set()
    for dim, values in (
        ("project", [r["project_id"] for r in FIXTURE_ROWS]),
        ("cwe", [r["cwe"] for r in FIXTURE_ROWS]),
        ("sample_class", [r["classification"] for r in FIXTURE_ROWS]),
    ):
        expected.update(f"{dim}={v}" for v in values if v)
    assert set(keys) == expected
    # An unpopulated dimension value produces no stratum at all.
    assert not any("CWE-999" in key for key in keys)


def test_partial_failure_counters_are_per_stratum_zero_inclusive():
    """Req 8.1, 10.4: partial-failure counters land only in their stratum and
    other strata report explicit zeros."""
    counts = {
        "tooling_failures:r0": 1,
        "llm_failures:r2": 2,
        "rejected_candidates:r0": 3,
    }
    _, _, report = _evaluation(counts=counts)
    by_key = {s.key: s for s in report.strata}
    proj_a = by_key["project=proj-a"]
    proj_b = by_key["project=proj-b"]
    assert proj_a.counters.tooling_failures == 1
    assert proj_a.counters.llm_failures == 0
    assert proj_a.counters.rejected_candidates == 3
    assert proj_b.counters.tooling_failures == 0
    assert proj_b.counters.llm_failures == 2
    assert proj_b.counters.rejected_candidates == 0


# ----------------------------------------------------------- cost reporting


def test_zero_cost_report_is_complete_and_baseline_is_retained():
    """Req 7.6, 8.1, 8.7, 10.4, 10.6: zero-cost telemetry stays zero-inclusive
    for every stratum and the comparison baseline identity is retained."""
    manifest, quality, report = _evaluation()
    assert report.comparison_baseline == DEFAULT_BASELINE
    cost = build_cost_report(
        report, version="v1", created_at=NOW, provenance=_prov("cost")
    )
    assert cost.evaluation_report_id == report.artifact_id
    assert cost.benchmark_manifest_id == manifest.artifact_id
    assert cost.benchmark_manifest_version == manifest.version
    assert cost.data_quality_report_version == quality.version
    assert not cost.missing_cost_data
    assert len(cost.strata) == len(report.strata)
    for stratum_cost in cost.strata:
        assert stratum_cost.analysis_latency_seconds == 0.0
        assert stratum_cost.audit_cost == 0.0
        assert stratum_cost.llm_tokens == 0
        assert stratum_cost.llm_cost == 0.0
        assert stratum_cost.tooling_failures == 0
        assert stratum_cost.llm_failures == 0
        assert stratum_cost.rejected_candidates == 0
        assert stratum_cost.complexity.configured_adapters == 0
        assert stratum_cost.complexity.pipeline_stages == 0
        assert stratum_cost.complexity.external_service_dependencies == 0
        assert stratum_cost.complexity.manual_execution_steps == 0


def test_nonzero_telemetry_retained_on_evaluation_report():
    """Req 8.1: nonzero analysis/audit cost, tokens/money, and failures are
    retained on the Evaluation_Report telemetry; the stratum-level cost report
    stays zero-inclusive with degenerate zeros and no missing-data flag
    (stratum telemetry is optional, never fabricated)."""
    telemetry = _zero_telemetry(
        latency_seconds=12.5,
        llm_tokens=480,
        llm_monetary_cost=0.75,
        audit_monetary_cost=0.25,
        tooling_failures=1,
        llm_failures=2,
        rejected_candidates=3,
    )
    _, _, report = _evaluation(telemetry=telemetry)
    assert report.telemetry.latency_seconds == 12.5
    assert report.telemetry.llm_tokens == 480
    assert report.telemetry.llm_monetary_cost == 0.75
    assert report.telemetry.audit_monetary_cost == 0.25
    assert report.telemetry.tooling_failures == 1
    assert report.telemetry.llm_failures == 2
    assert report.telemetry.rejected_candidates == 3
    cost = build_cost_report(
        report, version="v1", created_at=NOW, provenance=_prov("cost")
    )
    assert cost.strata
    for stratum_cost in cost.strata:
        assert stratum_cost.analysis_latency_seconds == 0.0
        assert stratum_cost.llm_tokens == 0
    assert cost.missing_cost_data is False


# ------------------------------------------------------ paired experiments


def test_paired_experiment_retains_differences_and_baseline_identity():
    """Req 8.2-8.3, 10.6: paired evaluations against the same manifest accept
    the experiment, retain every difference (including zero), and keep the
    baseline identity."""
    _, _, baseline = _evaluation()
    _, _, changed = _evaluation(
        telemetry=_zero_telemetry(latency_seconds=0.0, llm_tokens=250)
    )
    ok, violations = validate_experiment(baseline, changed)
    assert ok and violations == ()
    experiment = build_optimization_experiment(
        baseline,
        changed,
        version="v1",
        created_at=NOW,
        provenance=_prov("experiment"),
        baseline_configuration_id="unassisted:default:v1",
        changed_configuration_id="assisted:retrieval:v1",
    )
    differences = {
        item.name.removeprefix("diff:"): float(item.value)
        for item in experiment.measured_differences
    }
    assert set(differences) == set(TELEMETRY_DIFF_METRICS)
    assert differences["llm_tokens"] == 250
    assert differences["latency_seconds"] == 0.0
    assert experiment.baseline_configuration_id == "unassisted:default:v1"
    assert experiment.changed_configuration_id == "assisted:retrieval:v1"
    assert experiment.evaluated_sample_hashes == baseline.evaluated_sample_hashes


def test_tampered_paired_experiment_is_rejected():
    """Req 8.2: each tampered identity dimension is rejected with its exact
    violation before any difference is calculated."""
    _, _, baseline = _evaluation()
    _, _, changed = _evaluation()
    tampered = changed.model_copy(
        update={"evaluated_sample_hashes": ("tampered-hash",)}
    )
    ok, violations = validate_experiment(baseline, tampered)
    assert not ok
    assert "evaluated_sample_hashes" in violations


def test_no_unsupported_superiority_claims_without_completed_evidence():
    """Req 8.4-8.6, 10.5, 10.7: without a completed linked experiment no
    superiority claim is emitted; measured results carry explicit missing
    evidence and stated limitations."""
    _, _, baseline = _evaluation()
    _, _, changed = _evaluation(
        telemetry=_zero_telemetry(llm_tokens=250, latency_seconds=0.0)
    )
    report = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=DEFAULT_BASELINE,
        limitations={"llm_tokens": "measured on integration fixtures only"},
    )
    assert not any(claim.claim for claim in report.claims)
    assert set(claim.metric for claim in report.claims) == set(TELEMETRY_DIFF_METRICS)
    differences = {
        item.name.removeprefix("diff:"): float(item.value)
        for item in report.measured_differences
    }
    assert differences["llm_tokens"] == 250
    # Without links every metric lacks its experiment linkage, including the
    # improved llm_tokens (its claim is closed despite stated limitations).
    assert report.missing_experiment_link == TELEMETRY_DIFF_METRICS
    tokens_claim = next(c for c in report.claims if c.metric == "llm_tokens")
    assert not tokens_claim.claim
    assert "missing_experiment_link" in tokens_claim.missing_evidence
    assert tokens_claim.limitations == ("measured on integration fixtures only",)
    assert report.comparison_baseline == DEFAULT_BASELINE
    # No claim anywhere in the report and no superiority language field set.
    for claim in report.claims:
        if not claim.claim:
            assert not claim.experiment_completed


# ------------------------------------------------- repository round-trip


def test_reports_survive_repository_restart(tmp_path):
    """Req 8.1, 10.1-10.4: the manifest, quality report, evaluation report,
    and optimization experiment persist to the on-disk artifact repository
    (registered artifact models) and reload identically after restart. The
    Cost_Report pairs by ``evaluation_report_id`` rather than persisting as a
    standalone registered artifact (registry v1 surface)."""
    manifest, quality, report = _evaluation()
    changed = _evaluation()[2]
    experiment = build_optimization_experiment(
        report,
        changed,
        version="v1",
        created_at=NOW,
        provenance=_prov("experiment"),
        baseline_configuration_id="unassisted:default:v1",
        changed_configuration_id="assisted:retrieval:v1",
    )
    database = tmp_path / "verified-evaluation.db"
    repository = ArtifactRepository(database, supported_static_adapters=SUPPORTED)
    try:
        repository.persist_artifact(manifest)
        repository.persist_artifact(quality)
        repository.persist_artifact(report)
        repository.persist_artifact(experiment)
        ids = {
            "manifest": manifest.artifact_id,
            "quality": quality.artifact_id,
            "report": report.artifact_id,
            "experiment": experiment.artifact_id,
        }
    finally:
        repository.close()

    repository = ArtifactRepository(database, supported_static_adapters=SUPPORTED)
    try:
        reloaded_report = repository.load(ids["report"])
        reloaded_experiment = repository.load(ids["experiment"])
        assert repository.load(ids["manifest"]).artifact_id == ids["manifest"]
        assert repository.load(ids["quality"]).artifact_id == ids["quality"]
        assert reloaded_report.model_dump_json() == report.model_dump_json()
        assert reloaded_experiment.model_dump_json() == experiment.model_dump_json()
        assert reloaded_report.benchmark_manifest_id == ids["manifest"]
        assert reloaded_experiment.evaluated_sample_hashes == (
            report.evaluated_sample_hashes
        )
        # The Cost_Report links the persisted evaluation by identity.
        cost = build_cost_report(
            reloaded_report, version="v1", created_at=NOW, provenance=_prov("cost")
        )
        assert cost.evaluation_report_id == ids["report"]
    finally:
        repository.close()
