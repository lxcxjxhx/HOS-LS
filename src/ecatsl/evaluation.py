"""Verified evaluation for vulnerable/fixed/clean benchmarks (Task 7.2).

Pure decision layer on the existing ecatsl artifact models (same pattern as
``dataset_release.py``): every function takes fully-typed inputs, computes
verified confusion matrices and precision/recall/F1 only from benchmark ground
truth plus verified finding classifications, and produces an immutable
``EvaluationReport`` artifact (Req 7.6, 8.1-8.3, 9.11, 10.1-10.4, 10.6).
"""
from typing import Iterable, Mapping, Optional, Tuple

from .models import (
    Attribute,
    BenchmarkManifest,
    ConfusionMatrix,
    DataQualityReport,
    EvaluationCounters,
    EvaluationReport,
    EvaluationTelemetry,
    FindingStatus,
    OptimizationExperiment,
    StratumMetrics,
)

SAMPLE_CLASSES = ("vulnerable", "fixed", "clean")
"""Paired benchmark sample classes (vulnerable / fixed-or-clean)."""

STRATUM_DIMENSIONS = ("cwe", "language", "framework", "project", "sample_class")
"""Evaluation_Stratum dimensions (Req 10.2)."""

DIMENSION_ALIASES = {
    "cwe": "cwe",
    "language": "language",
    "framework": "framework",
    "project": "project",
    "project_id": "project",
    "sample_class": "sample_class",
    "classification": "sample_class",
}
"""Manifest sample-attribute prefixes mapped to stratum dimensions.

``build_release`` records ``project_id``/``classification`` attributes; the
evaluation strata canonicalize them to the ``project``/``sample_class``
dimensions so release-built manifests stratify without extra plumbing.
"""

DEFAULT_BASELINE = Attribute(
    name="comparison_baseline", value="unassisted:default:v1"
)
"""Default Comparison_Baseline identity (Req 10.6) when none is supplied."""


def _attr(name: str, value) -> Attribute:
    return Attribute(name=name, value=str(value))


def confusion_matrix(labels, statuses) -> ConfusionMatrix:
    """Verified confusion matrix against benchmark ground truth.

    ``labels``/``statuses`` are paired by position: benchmark truth (True =
    vulnerable) and verified finding classification (FindingStatus or None).
    Only confirmed classifications count as predicted (Req 10.1);
    ``UNCONFIRMED`` and missing entries count as not-predicted.
    """
    if len(labels) != len(statuses):
        raise ValueError("labels and statuses must have the same length")
    tp = fp = fn = tn = 0
    for label, status in zip(labels, statuses):
        predicted = status is not None and getattr(
            status, "value", status
        ) == FindingStatus.CONFIRMED.value
        if label and predicted:
            tp += 1
        elif predicted:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1
    return ConfusionMatrix(tp=tp, fp=fp, fn=fn, tn=tn)


def verified_metrics(matrix: ConfusionMatrix) -> dict:
    """Zero-inclusive precision/recall/F1 from a confusion matrix (Req 10.1)."""
    tp, fp, fn = matrix.tp, matrix.fp, matrix.fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def _stratum_key(attributes: Mapping[str, str]) -> tuple:
    """One stratum per non-empty dimension value (``dim=value`` singletons).

    The task's "every non-empty CWE/language/framework/project/sample-class
    stratum" reads per-dimension: each populated dimension value forms its own
    stratum, avoiding combinatorial fragmentation of small benchmarks.
    """
    return tuple(
        f"{dim}={attributes[dim]}"
        for dim in STRATUM_DIMENSIONS
        if attributes.get(dim)
    )


def _labels_and_statuses(
    manifest: BenchmarkManifest,
    classifications: Mapping[str, FindingStatus],
) -> tuple:
    """Positionally aligned (labels, statuses, sample_ids) in manifest order."""
    labels = []
    statuses = []
    sample_ids = []
    for sample in manifest.samples:
        labels.append(sample.classification == SAMPLE_CLASSES[0])
        statuses.append(classifications.get(sample.sample_id))
        sample_ids.append(sample.sample_id)
    return labels, statuses, sample_ids


def _sample_attributes(manifest: BenchmarkManifest) -> dict:
    """Map ``sample_id -> {dimension: value}`` from manifest sample attributes.

    ``project_id``/``classification`` manifest attributes canonicalize to the
    ``project``/``sample_class`` stratum dimensions (see ``DIMENSION_ALIASES``).
    """
    attributes: dict = {}
    for attr in manifest.sample_attributes:
        if ":" not in attr.name:
            continue
        prefix, _, sample_id = attr.name.rpartition(":")
        dimension = DIMENSION_ALIASES.get(prefix)
        if dimension is not None:
            attributes.setdefault(sample_id, {})[dimension] = attr.value
    return attributes


def _counters_for(
    counts: Mapping[str, int],
    sample_ids: Iterable[str],
) -> EvaluationCounters:
    """Zero-inclusive per-stratum counters keyed by tracked sample id."""
    values = {
        kind: sum(counts.get(f"{kind}:{sid}", 0) for sid in sample_ids)
        for kind in ("tooling_failures", "llm_failures", "rejected_candidates")
    }
    return EvaluationCounters(**values)


def build_evaluation_report(
    manifest: BenchmarkManifest,
    quality: DataQualityReport,
    classifications: Mapping[str, FindingStatus],
    *,
    version: str,
    created_at,
    provenance,
    telemetry: EvaluationTelemetry,
    counts: Optional[Mapping[str, int]] = None,
    reuse_inventory_version: str = "0",
    baseline: Optional[Attribute] = None,
    environment: Optional[Attribute] = None,
    evidence_limitations: Tuple[str, ...] = (),
) -> EvaluationReport:
    """One verified Evaluation_Report artifact for a manifest (Req 10.1-10.4).

    ``classifications`` maps sample_id -> verified FindingStatus; samples
    without an entry count as not-predicted (UNCONFIRMED). ``telemetry`` is
    the global zero-inclusive cost telemetry. ``counts`` optionally maps
    ``"<kind>:<sample_id>"`` (kind in ``tooling_failures``, ``llm_failures``,
    ``rejected_candidates``) to per-sample counter values; every stratum then
    reports zero-inclusive counter sums (Req 10.4).
    """
    baseline = baseline or DEFAULT_BASELINE
    labels, statuses, sample_ids = _labels_and_statuses(manifest, classifications)
    matrix = confusion_matrix(labels, statuses)
    metrics = verified_metrics(matrix)
    per_sample = _sample_attributes(manifest)

    groups: dict = {}
    for index, sample_id in enumerate(sample_ids):
        for definition in _stratum_key(per_sample.get(sample_id, {})):
            groups.setdefault((definition,), []).append(index)

    strata_metrics = []
    counts = dict(counts or {})
    for key in sorted(groups):
        indices = groups[key]
        strata_matrix = confusion_matrix(
            [labels[i] for i in indices], [statuses[i] for i in indices]
        )
        stratum_metrics = verified_metrics(strata_matrix)
        stratum_ids = [sample_ids[i] for i in indices]
        strata_metrics.append(
            StratumMetrics(
                definition=key,
                sample_count=len(indices),
                sample_ids=tuple(stratum_ids),
                matrix=strata_matrix,
                precision=stratum_metrics["precision"],
                recall=stratum_metrics["recall"],
                f1=stratum_metrics["f1"],
                counters=_counters_for(counts, stratum_ids),
            )
        )

    confirmed = matrix.tp + matrix.fp
    metrics_attributes: tuple = (
        _attr("precision", metrics["precision"]),
        _attr("recall", metrics["recall"]),
        _attr("f1", metrics["f1"]),
        _attr("tp", matrix.tp),
        _attr("fp", matrix.fp),
        _attr("fn", matrix.fn),
        _attr("tn", matrix.tn),
        _attr("sample_count", len(sample_ids)),
        _attr("confirmed", confirmed),
    )
    metrics_attributes += tuple(
        _attr(f"stratum:{s.key}", f"samples={s.sample_count}")
        for s in strata_metrics
    )

    return EvaluationReport(
        version=version,
        created_at=created_at,
        provenance=provenance,
        benchmark_manifest_id=manifest.artifact_id,
        benchmark_manifest_version=manifest.version,
        data_quality_report_id=quality.artifact_id,
        data_quality_report_version=quality.version,
        verified_metrics=metrics_attributes,
        telemetry=telemetry,
        reuse_inventory_version=reuse_inventory_version,
        strata=tuple(strata_metrics),
        evaluated_sample_hashes=tuple(
            sample.content_hash for sample in manifest.samples
        ),
        comparison_baseline=baseline,
        environment=environment,
        evidence_limitations=tuple(evidence_limitations),
    )


def validate_experiment(
    baseline: EvaluationReport,
    changed: EvaluationReport,
    baseline_environment: Optional[Attribute] = None,
    changed_environment: Optional[Attribute] = None,
) -> tuple:
    """Paired-experiment validity precheck (Req 8.2, 10.6).

    Both evaluations must come from the same immutable Benchmark_Manifest
    (identity and version), the same Data_Quality_Report, the same sample
    hashes, and the same strata definitions before any difference is
    calculated. Returns ``(ok, violations)``.
    """
    violations = []
    if baseline.benchmark_manifest_id != changed.benchmark_manifest_id:
        violations.append("benchmark_manifest_id")
    if baseline.benchmark_manifest_version != changed.benchmark_manifest_version:
        violations.append("benchmark_manifest_version")
    if baseline.data_quality_report_id != changed.data_quality_report_id:
        violations.append("data_quality_report_id")
    if baseline.evaluated_sample_hashes != changed.evaluated_sample_hashes:
        violations.append("evaluated_sample_hashes")
    if tuple(s.definition for s in baseline.strata) != tuple(
        s.definition for s in changed.strata
    ):
        violations.append("strata")
    if (
        baseline_environment is not None
        and changed_environment is not None
        and baseline_environment.value != changed_environment.value
    ):
        violations.append("environment")
    return (not violations, tuple(violations))


def build_optimization_experiment(
    baseline: EvaluationReport,
    changed: EvaluationReport,
    *,
    version: str,
    created_at,
    provenance,
    baseline_configuration_id: str,
    changed_configuration_id: str,
    baseline_environment: Optional[Attribute] = None,
    changed_environment: Optional[Attribute] = None,
) -> OptimizationExperiment:
    """One paired Optimization_Experiment artifact (Req 8.2-8.3).

    Raises ``ValueError`` unless ``validate_experiment`` passes: same manifest
    identity/version, quality report, sample hashes, strata, and environment.
    Observed differences are retained for every telemetry dimension including
    zero differences (Req 8.3).
    """
    ok, violations = validate_experiment(
        baseline, changed, baseline_environment, changed_environment
    )
    if not ok:
        raise ValueError("invalid paired experiment: " + ",".join(violations))

    def _telemetry_values(report: EvaluationReport) -> dict:
        return {
            "latency_seconds": report.telemetry.latency_seconds,
            "llm_tokens": report.telemetry.llm_tokens,
            "llm_monetary_cost": report.telemetry.llm_monetary_cost,
            "audit_monetary_cost": report.telemetry.audit_monetary_cost,
            "complexity.configured_adapters": (
                report.telemetry.complexity.configured_adapters
            ),
            "complexity.pipeline_stages": report.telemetry.complexity.pipeline_stages,
            "complexity.external_service_dependencies": (
                report.telemetry.complexity.external_service_dependencies
            ),
            "complexity.manual_execution_steps": (
                report.telemetry.complexity.manual_execution_steps
            ),
        }

    baseline_values = _telemetry_values(baseline)
    changed_values = _telemetry_values(changed)
    differences = [
        _attr(f"diff:{metric}", changed_value - baseline_values[metric])
        for metric, changed_value in sorted(changed_values.items())
    ]

    return OptimizationExperiment(
        version=version,
        created_at=created_at,
        provenance=provenance,
        baseline_configuration_id=baseline_configuration_id,
        changed_configuration_id=changed_configuration_id,
        benchmark_manifest_id=baseline.benchmark_manifest_id,
        strata=tuple(s.key for s in baseline.strata),
        measured_differences=tuple(differences),
        baseline_metrics=baseline.verified_metrics,
        changed_metrics=changed.verified_metrics,
        evaluated_sample_hashes=baseline.evaluated_sample_hashes,
        environment=baseline_environment or changed_environment,
    )
