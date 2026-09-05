"""Task 7.2: verified vulnerable/fixed/clean evaluation (Req 7.6, 8.1-8.3, 9.11, 10.1-10.4, 10.6)."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from src.ecatsl.dataset_release import build_release
from src.ecatsl.evaluation import (
    DEFAULT_BASELINE,
    SAMPLE_CLASSES,
    STRATUM_DIMENSIONS,
    build_evaluation_report,
    build_optimization_experiment,
    confusion_matrix,
    validate_experiment,
    verified_metrics,
)
from src.ecatsl.models import (
    Attribute,
    BenchmarkManifest,
    ConfusionMatrix,
    EvaluationTelemetry,
    FindingStatus,
    OperationalComplexity,
    Provenance,
)

OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))


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


def build_manifest(rows):
    manifest, quality = build_release(
        rows,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        data_type="vulngym_entry",
    )
    return manifest, quality


def manifest_with_attributes(rows, attributes):
    """Build a manifest, then attach per-sample stratum attributes."""
    manifest, quality = build_manifest(rows)
    return (
        BenchmarkManifest(
            version=manifest.version,
            created_at=manifest.created_at,
            provenance=manifest.provenance,
            samples=manifest.samples,
            catalog_record_ids=manifest.catalog_record_ids,
            split_assignments=manifest.split_assignments,
            sample_attributes=tuple(attributes),
        ),
        quality,
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


def metric_value(report, name):
    return next(a.value for a in report.verified_metrics if a.name == name)


def test_confusion_matrix_verified_statuses_only():
    """Req 10.1: only CONFIRMED counts as predicted; UNCONFIRMED/missing do not."""
    labels = [True, True, False, False]
    statuses = [
        FindingStatus.CONFIRMED,
        FindingStatus.UNCONFIRMED,
        FindingStatus.CONFIRMED,
        FindingStatus.UNCONFIRMED,
    ]
    matrix = confusion_matrix(labels, statuses)
    assert (matrix.tp, matrix.fp, matrix.fn, matrix.tn) == (1, 1, 1, 1)
    # None (finding missing/unclassified) also counts as not-predicted.
    none_matrix = confusion_matrix([True, False], [None, None])
    assert (none_matrix.tp, none_matrix.fp, none_matrix.fn, none_matrix.tn) == (0, 0, 1, 1)
    with pytest.raises(ValueError):
        confusion_matrix([True], [FindingStatus.CONFIRMED, FindingStatus.CONFIRMED])


def test_metrics_zero_inclusive():
    """Req 10.1: zero denominators yield zero values, never errors."""
    assert verified_metrics(ConfusionMatrix(tp=0, fp=0, fn=0, tn=5)) == {
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
    }
    perfect = verified_metrics(ConfusionMatrix(tp=2, fp=0, fn=0, tn=1))
    assert perfect == {"precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_global_report_zero_cost_and_baseline_identity():
    """Req 10.1, 10.4, 10.6: zero values retained; baseline identified."""
    manifest, quality = build_manifest(
        [row("s1"), row("s2", classification="clean")]
    )
    report = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        telemetry=telemetry(),  # all-zero telemetry retained
    )
    assert report.benchmark_manifest_id == manifest.artifact_id
    assert report.benchmark_manifest_version == manifest.version
    assert report.data_quality_report_id == quality.artifact_id
    assert report.data_quality_report_version == quality.version
    assert report.comparison_baseline == DEFAULT_BASELINE
    assert metric_value(report, "tp") == "1"
    assert metric_value(report, "tn") == "1"
    assert metric_value(report, "sample_count") == "2"
    assert report.telemetry.llm_tokens == 0
    assert report.telemetry.audit_monetary_cost == 0.0
    assert report.evaluated_sample_hashes == tuple(
        s.content_hash for s in manifest.samples
    )


def test_strata_per_dimension_and_non_empty_only():
    """Req 10.2: every reported stratum contains >=1 sample; all dimensions used."""
    rows = [
        row("s1", project="p1"),
        row("s2", classification="clean", project="p1"),
        row("s3", project="p2", group="p2:t1"),
        row("s4", project="p2", group="p2:t2"),
    ]
    attributes = (
        Attribute(name="project_id:s1", value="p1"),
        Attribute(name="classification:s1", value="vulnerable"),
        Attribute(name="language:s1", value="python"),
        Attribute(name="project_id:s2", value="p1"),
        Attribute(name="classification:s2", value="clean"),
        Attribute(name="language:s2", value="python"),
        Attribute(name="project_id:s3", value="p2"),
        Attribute(name="classification:s3", value="vulnerable"),
        Attribute(name="language:s3", value="javascript"),
        Attribute(name="project_id:s4", value="p2"),
        Attribute(name="classification:s4", value="vulnerable"),
        Attribute(name="language:s4", value="javascript"),
    )
    manifest, quality = manifest_with_attributes(rows, attributes)
    report = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED, "s3": FindingStatus.CONFIRMED},
    )
    keys = {s.key for s in report.strata}
    # One stratum per populated dimension value (per-dimension reading).
    assert keys == {
        "project=p1",
        "project=p2",
        "sample_class=vulnerable",
        "sample_class=clean",
        "language=python",
        "language=javascript",
    }
    assert all(s.sample_count >= 1 for s in report.strata)
    javascript = next(s for s in report.strata if s.key == "language=javascript")
    assert javascript.sample_count == 2
    assert (javascript.matrix.tp, javascript.matrix.fn) == (1, 1)
    # Empty dimension values must not create strata.
    empty_manifest, empty_quality = manifest_with_attributes(
        rows, (Attribute(name="cwe:s1", value=""),)
    )
    empty_report = build_report(empty_manifest, empty_quality, {})
    assert all(
        not any(d.startswith("cwe=") for d in s.definition)
        for s in empty_report.strata
    )


def test_stratum_counters_zero_inclusive():
    """Req 10.4: per-stratum tooling/LLM failures and rejected candidates."""
    manifest, quality = build_manifest(
        [row("s1", project="p1"), row("s2", project="p2", group="p2:t1")]
    )
    report = build_report(
        manifest,
        quality,
        {},
        counts={"tooling_failures:s1": 2, "rejected_candidates:s1": 1},
    )
    by_key = {s.key: s for s in report.strata}
    s1 = next(v for k, v in by_key.items() if "project=p1" in k)
    s2 = next(v for k, v in by_key.items() if "project=p2" in k)
    assert s1.counters.tooling_failures == 2
    assert s1.counters.rejected_candidates == 1
    assert s1.counters.llm_failures == 0
    assert s2.counters.tooling_failures == 0
    assert s2.counters.rejected_candidates == 0


def test_validate_experiment_manifest_hash_and_strata_binding():
    """Req 8.2: same manifest identity/strata/sample hashes required."""
    manifest, quality = build_manifest([row("s1"), row("s2", classification="clean")])
    report_a = build_report(
        manifest, quality, {"s1": FindingStatus.CONFIRMED}, version="a"
    )
    report_b = build_report(
        manifest, quality, {}, version="b", telemetry=telemetry(latency_seconds=5.0)
    )
    ok, violations = validate_experiment(report_a, report_b)
    assert ok and violations == ()

    other_manifest, other_quality = build_manifest(
        [row("s1"), row("s3", classification="clean", project="p2", group="p2:t1")]
    )
    report_c = build_report(other_manifest, other_quality, {}, version="c")
    ok, violations = validate_experiment(report_a, report_c)
    assert not ok
    assert set(violations) == {
        "benchmark_manifest_id",
        "data_quality_report_id",
        "evaluated_sample_hashes",
        "strata",
    }


def test_validate_experiment_environment_binding():
    """Req 8.2: differing execution environment identities invalidate pairing."""
    manifest, quality = build_manifest([row("s1")])
    env_a = Attribute(name="environment", value="env-a")
    env_b = Attribute(name="environment", value="env-b")
    report_a = build_report(manifest, quality, {}, environment=env_a)
    report_b = build_report(manifest, quality, {}, environment=env_b)
    ok, violations = validate_experiment(report_a, report_b, env_a, env_b)
    assert not ok and "environment" in violations
    ok, _ = validate_experiment(report_a, report_b, env_a, env_a)
    assert ok


def test_optimization_experiment_records_differences():
    """Req 8.2-8.3: paired differences retained incl. zero differences."""
    manifest, quality = build_manifest([row("s1"), row("s2", classification="clean")])
    baseline = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        version="b",
        telemetry=telemetry(latency_seconds=10.0, llm_tokens=100, llm_monetary_cost=0.5),
    )
    changed = build_report(
        manifest,
        quality,
        {"s1": FindingStatus.CONFIRMED},
        version="c",
        telemetry=telemetry(latency_seconds=8.0, llm_tokens=100, llm_monetary_cost=0.5),
    )
    experiment = build_optimization_experiment(
        baseline,
        changed,
        version="1",
        created_at=OFFSET_TIME,
        provenance=provenance(),
        baseline_configuration_id="baseline:v1",
        changed_configuration_id="changed:v1",
    )
    assert experiment.benchmark_manifest_id == manifest.artifact_id
    diffs = {a.name: a.value for a in experiment.measured_differences}
    assert diffs["diff:latency_seconds"] == "-2.0"
    assert diffs["diff:llm_tokens"] == "0"  # zero difference retained
    assert experiment.baseline_metrics == baseline.verified_metrics
    assert experiment.changed_metrics == changed.verified_metrics
    assert experiment.evaluated_sample_hashes == baseline.evaluated_sample_hashes


def test_optimization_experiment_rejects_cross_manifest():
    """Req 8.2: pairing across manifests must fail without differences."""
    manifest_a, quality_a = build_manifest([row("s1")])
    manifest_b, quality_b = build_manifest([row("s2")])
    report_a = build_report(manifest_a, quality_a, {})
    report_b = build_report(manifest_b, quality_b, {})
    with pytest.raises(ValueError):
        build_optimization_experiment(
            report_a,
            report_b,
            version="1",
            created_at=OFFSET_TIME,
            provenance=provenance(),
            baseline_configuration_id="b",
            changed_configuration_id="c",
        )


def test_paired_samples_split_binding_via_release():
    """Req 9.11 context: evaluation binds the manifest the release produced."""
    manifest, quality = build_manifest(
        [
            row("s1", classification="vulnerable", group="g1"),
            row("s2", classification="fixed", group="g1", pair_id="pair-1"),
        ]
    )
    report = build_report(manifest, quality, {"s1": FindingStatus.CONFIRMED})
    assert report.benchmark_manifest_id == manifest.artifact_id
    assert len(report.evaluated_sample_hashes) == len(manifest.samples)
    assert SAMPLE_CLASSES == ("vulnerable", "fixed", "clean")
    assert STRATUM_DIMENSIONS == (
        "cwe",
        "language",
        "framework",
        "project",
        "sample_class",
    )
