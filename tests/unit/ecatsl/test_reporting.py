"""Task 7.3: evidence-bounded cost and comparison reporting (Req 7.6, 8.1-8.7, 10.1-10.7)."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from src.ecatsl.dataset_release import build_release
from src.ecatsl.evaluation import build_evaluation_report
from src.ecatsl.models import (
    Attribute,
    ClaimAssessment,
    EvaluationTelemetry,
    FindingStatus,
    OperationalComplexity,
    Provenance,
    ReleaseTradeOff,
    StratumCost,
)
from src.ecatsl.reporting import (
    ZERO_COMPLEXITY,
    build_cost_report,
    build_optimization_report,
    build_release_configuration_report,
)

OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))
DIFF_METRICS = (
    "latency_seconds",
    "llm_tokens",
    "llm_monetary_cost",
    "audit_monetary_cost",
    "complexity.configured_adapters",
    "complexity.pipeline_stages",
    "complexity.external_service_dependencies",
    "complexity.manual_execution_steps",
)


def provenance() -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=OFFSET_TIME,
        source_identifier="bench/datasets/VulnGym",
        source_revision="v0.1.4",
        content_identity="dataset:v1",
    )


def row(rid, *, classification="vulnerable", project="proj-a", group=None, **extra):
    fields = {
        "id": rid,
        "content": rid.encode(),
        "content_hash": sha256(rid.encode()).hexdigest(),
        "classification": classification,
        "project_id": project,
        "project_time_group": group or f"{project}:t1",
    }
    fields.update(extra)
    return fields


def build_manifest(rows, **kw):
    return build_release(
        rows,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        data_type="vulngym_entry",
        **kw,
    )


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


def cost_of(report, s):
    return build_cost_report(
        report,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        **({"stratum_completeness": s} if s else {}),
    )


def experiment(baseline, changed, **kw):
    from src.ecatsl.evaluation import build_optimization_experiment

    kw.setdefault("version", "1")
    kw.setdefault("created_at", OFFSET_TIME)
    kw.setdefault("provenance", provenance())
    kw.setdefault("baseline_configuration_id", "unassisted:default:v1")
    kw.setdefault("changed_configuration_id", "assisted:v2")
    return build_optimization_experiment(baseline, changed, **kw)


def claim_map(claims):
    return {c.metric: c for c in claims}


# Req 10.4 / 8.7: zero-inclusive per-stratum cost reporting.


def test_cost_report_zero_inclusive_global_and_strata():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    report = build_report(manifest, quality, {"s1": FindingStatus.CONFIRMED})
    cost = build_cost_report(
        report, version="1", created_at=OFFSET_TIME, provenance=provenance()
    )
    assert cost.reuse_inventory_version == "0"
    assert cost.benchmark_manifest_id == manifest.artifact_id
    assert cost.benchmark_manifest_version == manifest.version
    assert cost.data_quality_report_version == quality.version
    assert len(cost.strata) == len(report.strata)
    for entry in cost.strata:
        assert entry.analysis_latency_seconds == 0.0
        assert entry.audit_cost == 0.0
        assert entry.llm_tokens == 0
        assert entry.llm_cost == 0.0
        assert entry.tooling_failures == 0
        assert entry.llm_failures == 0
        assert entry.rejected_candidates == 0
        assert entry.complexity == ZERO_COMPLEXITY
        assert entry.missing_cost_data is False
    assert cost.missing_cost_data is False


def test_cost_report_per_stratum_cost_fields():
    manifest, quality = build_manifest(
        [
            row("s1", classification="vulnerable"),
            row("s2", classification="clean"),
        ]
    )
    report = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED, "s2": FindingStatus.UNCONFIRMED},
        counts={
            "tooling_failures:s1": 2,
            "llm_failures:s2": 1,
            "rejected_candidates:s1": 3,
        },
    )
    cost = build_cost_report(
        report, version="1", created_at=OFFSET_TIME, provenance=provenance()
    )
    assert len(cost.strata) == report.strata.__len__()
    sample_class = {
        s.key: s
        for s in cost.strata
        if any(d.startswith("sample_class=") for d in s.definition)
    }
    vulnerable = sample_class["sample_class=vulnerable"]
    assert vulnerable.tooling_failures == 2
    assert vulnerable.rejected_candidates == 3
    assert vulnerable.llm_failures == 0
    clean = sample_class["sample_class=clean"]
    assert clean.llm_failures == 1
    assert clean.tooling_failures == 0
    assert clean.rejected_candidates == 0


def test_cost_report_missing_cost_data_flagged_not_omitted():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    report = build_report(manifest, quality, {"s1": FindingStatus.CONFIRMED})
    key = report.strata[0].key
    cost = cost_of(report, {key: {"tokens": False, "money": False}})
    entry = next(s for s in cost.strata if s.key == key)
    assert entry.missing_cost_data is True
    assert entry.llm_tokens == 0
    assert entry.llm_cost == 0.0
    assert cost.missing_cost_data is True


def test_stratum_cost_without_telemetry_is_degenerate():
    entry = StratumCost(
        definition=("sample_class=vulnerable",),
        sample_count=1,
        precision=1.0,
        recall=1.0,
        f1=1.0,
        analysis_latency_seconds=0.0,
        audit_cost=0.0,
        llm_tokens=0,
        llm_cost=0.0,
        tooling_failures=0,
        llm_failures=0,
        rejected_candidates=0,
        complexity=ZERO_COMPLEXITY,
        missing_cost_data=True,
    )
    assert entry.key == "sample_class=vulnerable"
    assert entry.missing_cost_data is True


# Req 8.4-8.6: evidence-gated claims on paired comparisons.


def test_optimization_report_zero_differences_no_claims():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    baseline = build_report(manifest, quality, {"s1": FindingStatus.CONFIRMED})
    changed = build_report(
        manifest, quality, {"s1": FindingStatus.CONFIRMED}, version="2"
    )
    comparison = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=Attribute(
            name="comparison_baseline", value="unassisted:default:v1"
        ),
    )
    assert all(
        a.value == "0" or float(a.value) == 0.0
        for a in comparison.measured_differences
    )
    assert all(c.claim is False for c in comparison.claims)
    assert all(
        c.direction == "no_change" for c in comparison.claims
    )
    assert set(comparison.missing_experiment_link) == set(DIFF_METRICS)


def test_optimization_report_improvement_without_experiment_no_claim():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    baseline = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        telemetry=telemetry(latency_seconds=10.0),
    )
    changed = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        version="2",
        telemetry=telemetry(latency_seconds=4.0),
    )
    comparison = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=Attribute(
            name="comparison_baseline", value="unassisted:default:v1"
        ),
    )
    by_metric = claim_map(comparison.claims)
    latency = by_metric["latency_seconds"]
    assert latency.measured_difference == pytest.approx(-6.0)
    assert latency.direction == "improvement"
    assert latency.claim is False
    assert "missing_experiment_link" in latency.missing_evidence
    assert "missing_limitations" in latency.missing_evidence
    assert comparison.evidence_limitations == ()


def test_optimization_report_claim_with_completed_experiment_and_limitations():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    baseline = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        telemetry=telemetry(latency_seconds=10.0),
    )
    changed = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        version="2",
        telemetry=telemetry(latency_seconds=4.0),
    )
    exp = experiment(baseline, changed)
    comparison = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=Attribute(
            name="comparison_baseline", value="unassisted:default:v1"
        ),
        experiment=exp,
        experiment_completed=True,
        experiment_links={"latency_seconds": exp.artifact_id},
        limitations={"latency_seconds": "single-sample fixture only"},
    )
    by_metric = claim_map(comparison.claims)
    latency = by_metric["latency_seconds"]
    assert latency.claim is True
    assert latency.direction == "improvement"
    assert latency.experiment_artifact_id == exp.artifact_id
    assert latency.experiment_completed is True
    assert latency.limitations == ("single-sample fixture only",)
    assert latency.missing_evidence == ()
    others = [m for m in DIFF_METRICS if m != "latency_seconds"]
    assert all(by_metric[m].claim is False for m in others)
    assert comparison.missing_experiment_link == tuple(
        m for m in DIFF_METRICS if m != "latency_seconds"
    )
    assert comparison.evidence_limitations == ("single-sample fixture only",)


def test_optimization_report_claim_blocked_when_experiment_incomplete():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    baseline = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        telemetry=telemetry(latency_seconds=10.0),
    )
    changed = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        version="2",
        telemetry=telemetry(latency_seconds=4.0),
    )
    exp = experiment(baseline, changed)
    comparison = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=Attribute(
            name="comparison_baseline", value="unassisted:default:v1"
        ),
        experiment=exp,
        experiment_completed=False,
        experiment_links={"latency_seconds": exp.artifact_id},
        limitations={"latency_seconds": "single-sample fixture only"},
    )
    latency = claim_map(comparison.claims)["latency_seconds"]
    assert latency.claim is False
    assert latency.experiment_completed is False
    assert "experiment_not_completed" in latency.missing_evidence


def test_optimization_report_claim_blocked_without_limitations():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    baseline = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        telemetry=telemetry(latency_seconds=10.0),
    )
    changed = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        version="2",
        telemetry=telemetry(latency_seconds=4.0),
    )
    exp = experiment(baseline, changed)
    comparison = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=Attribute(
            name="comparison_baseline", value="unassisted:default:v1"
        ),
        experiment=exp,
        experiment_completed=True,
        experiment_links={"latency_seconds": exp.artifact_id},
        limitations={},
    )
    latency = claim_map(comparison.claims)["latency_seconds"]
    assert latency.claim is False
    assert "missing_limitations" in latency.missing_evidence


def test_optimization_report_missing_link_recorded():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    baseline = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        telemetry=telemetry(latency_seconds=10.0),
    )
    changed = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        version="2",
        telemetry=telemetry(latency_seconds=4.0),
    )
    comparison = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=Attribute(
            name="comparison_baseline", value="unassisted:default:v1"
        ),
        missing_links=("latency_seconds",),
    )
    by_metric = claim_map(comparison.claims)
    latency = by_metric["latency_seconds"]
    assert latency.claim is False
    assert latency.experiment_artifact_id is None
    assert "latency_seconds" not in comparison.missing_experiment_link
    assert "llm_tokens" in comparison.missing_experiment_link


def test_optimization_report_identifies_paired_configurations():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    baseline = build_report(manifest, quality, {"s1": FindingStatus.CONFIRMED})
    changed = build_report(
        manifest, quality, {"s1": FindingStatus.CONFIRMED}, version="2"
    )
    exp = experiment(baseline, changed)
    comparison = build_optimization_report(
        baseline,
        changed,
        comparison_baseline=Attribute(
            name="comparison_baseline", value="unassisted:default:v1"
        ),
        experiment=exp,
        experiment_completed=True,
        experiment_links={"latency_seconds": exp.artifact_id},
        limitations={"latency_seconds": "fixture"},
    )
    assert comparison.baseline_configuration_id == "unassisted:default:v1"
    assert comparison.changed_configuration_id == "assisted:v2"
    assert comparison.comparison_baseline.value == "unassisted:default:v1"
    assert comparison.benchmark_manifest_id == manifest.artifact_id
    assert comparison.benchmark_manifest_version == manifest.version


# Req 10.5 / 10.7: no superiority language without verified evidence; claims
# identify supporting evidence and state limitations.


def test_claim_assessment_rejects_claim_without_experiment():
    with pytest.raises(ValueError, match="completed experiment|linked experiment"):
        ClaimAssessment(
            metric="latency_seconds",
            measured_difference=-6.0,
            direction="improvement",
            claim=True,
            limitations=("fixture",),
        )


def test_claim_assessment_rejects_claim_without_limitations():
    with pytest.raises(ValueError, match="limitations"):
        ClaimAssessment(
            metric="latency_seconds",
            measured_difference=-6.0,
            direction="improvement",
            claim=True,
            experiment_artifact_id="sha256:abc",
            limitations=(),
        )


def test_claim_assessment_rejects_claim_without_improvement():
    with pytest.raises(ValueError, match="improvement"):
        ClaimAssessment(
            metric="latency_seconds",
            measured_difference=0.0,
            direction="no_change",
            claim=True,
            experiment_artifact_id="sha256:abc",
            limitations=("fixture",),
        )


def test_claim_assessment_completed_requires_artifact_identity():
    with pytest.raises(ValueError, match="completed experiment"):
        ClaimAssessment(
            metric="latency_seconds",
            measured_difference=-6.0,
            direction="improvement",
            claim=False,
            experiment_completed=True,
            limitations=("fixture",),
        )


# Req 8.7: release-configuration trade-offs against completed experiments.


def test_release_configuration_report_links_completed_experiments():
    manifest, quality = build_manifest([row("s1", classification="vulnerable")])
    baseline = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        telemetry=telemetry(latency_seconds=10.0),
    )
    changed = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        version="2",
        telemetry=telemetry(latency_seconds=4.0),
    )
    exp = experiment(baseline, changed)
    trade_off = ReleaseTradeOff(
        selected_configuration_id="assisted:v2",
        applicable_configuration_id="unassisted:default:v1",
        metric="latency_seconds",
        selected_value=4.0,
        applicable_value=10.0,
        completed_experiment=True,
        experiment_artifact_id=exp.artifact_id,
        measured_results=(Attribute(name="diff:latency_seconds", value="-6.0"),),
        trade_offs=("lower latency for one extra confirmation stage",),
        limitations=("single-sample fixture only",),
    )
    release_report = build_release_configuration_report(
        "assisted:v2",
        (exp,),
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        manifest_id=manifest.artifact_id,
        manifest_version=manifest.version,
        trade_offs=(trade_off,),
    )
    assert release_report.configuration_id == "assisted:v2"
    assert [e.artifact_id for e in release_report.experiments] == [exp.artifact_id]
    assert release_report.trade_offs[0].completed_experiment is True
    assert release_report.trade_offs[0].experiment_artifact_id == exp.artifact_id
    assert release_report.benchmark_manifest_id == manifest.artifact_id


def test_release_trade_off_completed_requires_experiment_identity():
    with pytest.raises(ValueError, match="completed experiment requires"):
        ReleaseTradeOff(
            selected_configuration_id="assisted:v2",
            applicable_configuration_id="unassisted:default:v1",
            metric="latency_seconds",
            selected_value=4.0,
            applicable_value=10.0,
            completed_experiment=True,
            experiment_artifact_id=None,
        )


def test_baseline_comparison_differences_unique():
    from src.ecatsl.models import BaselineComparison

    with pytest.raises(ValueError, match="exactly once"):
        BaselineComparison(
            baseline_configuration_id="a",
            changed_configuration_id="b",
            comparison_baseline=Attribute(
                name="comparison_baseline", value="unassisted:default:v1"
            ),
            benchmark_manifest_id="m",
            benchmark_manifest_version="1",
            measured_differences=(
                Attribute(name="diff:latency_seconds", value="1"),
                Attribute(name="diff:latency_seconds", value="2"),
            ),
            evidence_limitations=(),
        )
