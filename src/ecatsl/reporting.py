"""Evidence-bounded cost and comparison reporting (Task 7.3).

Pure decision layer on the existing ecatsl artifact models (same pattern as
``dataset_release.py``/``evaluation.py``): reports verified metrics, analysis
and audit cost, LLM tokens/money, tooling/LLM failures, rejected candidates,
reuse inventory, and operational complexity for the evaluation and every
non-empty stratum (Req 7.6, 8.1, 8.7, 10.4); emits optimization or
superiority claims only when linked completed experiment evidence supports
them and limitations are stated, otherwise reports measured results with
explicit missing/insufficient evidence and no superiority language
(Req 8.4-8.6, 10.5, 10.7); and records release-configuration trade-offs
against completed optimization experiments (Req 8.7).
"""
from typing import Mapping, Optional, Sequence

from .models import (
    Attribute,
    BaselineComparison,
    ClaimAssessment,
    CostReport,
    EvaluationReport,
    OperationalComplexity,
    OptimizationExperiment,
    ReleaseConfigurationReport,
    ReleaseTradeOff,
    StratumCost,
    StratumMetrics,
)

ZERO_COMPLEXITY = OperationalComplexity(
    configured_adapters=0,
    pipeline_stages=0,
    external_service_dependencies=0,
    manual_execution_steps=0,
)
"""Zero-value operational complexity for degenerate strata (Req 10.4)."""

TELEMETRY_DIFF_METRICS = (
    "latency_seconds",
    "llm_tokens",
    "llm_monetary_cost",
    "audit_monetary_cost",
    "complexity.configured_adapters",
    "complexity.pipeline_stages",
    "complexity.external_service_dependencies",
    "complexity.manual_execution_steps",
)
"""Telemetry dimensions compared in paired experiments (Req 8.2-8.3).

All of these are cost dimensions: a measured decrease is the improvement
direction for the corresponding optimization metric.
"""


def _attr(name: str, value) -> Attribute:
    return Attribute(name=name, value=str(value))


def _stratum_cost(
    stratum: StratumMetrics,
    *,
    completeness: Optional[Mapping[str, bool]] = None,
) -> StratumCost:
    """Zero-inclusive per-stratum cost entry (Req 8.7, 10.4).

    ``completeness`` optionally flags which telemetry dimensions lack data
    for the stratum (``"latency"``, ``"tokens"``, ``"money"``, ``"audit"``);
    absent stratum telemetry is reported as zero-inclusive degenerate values
    with ``missing_cost_data`` set, never omitted.
    """
    missing = tuple(k for k, v in sorted((completeness or {}).items()) if not v)
    telemetry = stratum.telemetry
    if telemetry is None:
        return StratumCost(
            definition=stratum.definition,
            sample_count=stratum.sample_count,
            precision=stratum.precision,
            recall=stratum.recall,
            f1=stratum.f1,
            analysis_latency_seconds=0.0,
            audit_cost=0.0,
            llm_tokens=0,
            llm_cost=0.0,
            tooling_failures=stratum.counters.tooling_failures,
            llm_failures=stratum.counters.llm_failures,
            rejected_candidates=stratum.counters.rejected_candidates,
            complexity=ZERO_COMPLEXITY,
            missing_cost_data=bool(missing),
        )
    return StratumCost(
        definition=stratum.definition,
        sample_count=stratum.sample_count,
        precision=stratum.precision,
        recall=stratum.recall,
        f1=stratum.f1,
        analysis_latency_seconds=telemetry.latency_seconds,
        audit_cost=telemetry.audit_monetary_cost,
        llm_tokens=telemetry.llm_tokens,
        llm_cost=telemetry.llm_monetary_cost,
        tooling_failures=telemetry.tooling_failures + stratum.counters.tooling_failures,
        llm_failures=telemetry.llm_failures + stratum.counters.llm_failures,
        rejected_candidates=(
            telemetry.rejected_candidates + stratum.counters.rejected_candidates
        ),
        complexity=telemetry.complexity,
        missing_cost_data=bool(missing),
    )


def build_cost_report(
    report: EvaluationReport,
    *,
    version: str,
    created_at,
    provenance,
    stratum_completeness: Optional[Mapping[str, Mapping[str, bool]]] = None,
) -> CostReport:
    """One immutable Cost_Report artifact (Req 7.6, 8.1, 8.7, 10.4).

    Reports zero-inclusive verified metrics plus analysis/audit cost, LLM
    tokens/money, tooling/LLM failures, rejected candidates, reuse-inventory
    version, and operational complexity for the evaluation and every
    non-empty stratum. ``stratum_completeness`` maps ``stratum.key`` ->
    dimension -> ``False`` to flag missing cost data.
    """
    completeness = dict(stratum_completeness or {})
    strata = tuple(
        _stratum_cost(s, completeness=completeness.get(s.key)) for s in report.strata
    )
    return CostReport(
        version=version,
        created_at=created_at,
        provenance=provenance,
        evaluation_report_id=report.artifact_id,
        benchmark_manifest_id=report.benchmark_manifest_id,
        benchmark_manifest_version=report.benchmark_manifest_version or "",
        data_quality_report_version=report.data_quality_report_version or "",
        reuse_inventory_version=report.reuse_inventory_version,
        strata=strata,
        missing_cost_data=any(s.missing_cost_data for s in strata),
    )


def _telemetry_values(report: EvaluationReport) -> dict:
    telemetry = report.telemetry
    return {
        "latency_seconds": telemetry.latency_seconds,
        "llm_tokens": telemetry.llm_tokens,
        "llm_monetary_cost": telemetry.llm_monetary_cost,
        "audit_monetary_cost": telemetry.audit_monetary_cost,
        "complexity.configured_adapters": telemetry.complexity.configured_adapters,
        "complexity.pipeline_stages": telemetry.complexity.pipeline_stages,
        "complexity.external_service_dependencies": (
            telemetry.complexity.external_service_dependencies
        ),
        "complexity.manual_execution_steps": telemetry.complexity.manual_execution_steps,
    }


def _classify_difference(difference: float) -> str:
    """Cost metrics improve when they decrease; a rise is a regression."""
    if difference < 0:
        return "improvement"
    if difference > 0:
        return "regression"
    return "no_change"


def _claim_assessment(
    metric: str,
    difference: float,
    *,
    completed_experiment_ids: Sequence[str],
    experiment_links: Mapping[str, str],
    limitations: Mapping[str, str],
    missing_links: Sequence[str],
) -> ClaimAssessment:
    """Evidence-gated claim assessment for one optimization metric.

    A claim is emitted only when the metric improved, the linked
    Optimization_Experiment completed, and limitations are stated
    (Req 8.4-8.5, 8.7, 10.5, 10.7); otherwise the measured difference is
    reported with explicit missing evidence and no superiority language
    (Req 8.6, 10.5).
    """
    direction = _classify_difference(difference)
    linked_id = experiment_links.get(metric)
    completed = (
        linked_id is not None
        and linked_id in completed_experiment_ids
        and linked_id not in missing_links
    )
    stated_limitation = limitations.get(metric)
    claim = direction == "improvement" and completed and bool(stated_limitation)
    missing: list = []
    if linked_id is None:
        missing.append("missing_experiment_link")
        if direction == "improvement":
            missing.append("missing_experiment_artifact")
    elif not completed:
        missing.append("experiment_not_completed")
    if not stated_limitation:
        missing.append("missing_limitations")
    return ClaimAssessment(
        metric=metric,
        measured_difference=difference,
        direction=direction,
        claim=claim,
        experiment_artifact_id=linked_id,
        experiment_completed=completed,
        missing_evidence=tuple(missing),
        limitations=((stated_limitation,) if stated_limitation else ()),
    )


def build_optimization_report(
    baseline: EvaluationReport,
    changed: EvaluationReport,
    *,
    comparison_baseline: Attribute,
    experiment: Optional[OptimizationExperiment] = None,
    experiment_completed: bool = False,
    experiment_links: Optional[Mapping[str, str]] = None,
    limitations: Optional[Mapping[str, str]] = None,
    missing_links: Sequence[str] = (),
) -> BaselineComparison:
    """One paired baseline/changed comparison with evidence-gated claims.

    ``experiment`` (optional) is the validated Optimization_Experiment
    artifact pairing the two evaluations; ``experiment_completed`` records
    whether that experiment has completed; ``experiment_links`` maps each
    optimized metric to the experiment artifact identity supporting it;
    ``limitations`` maps each metric to its stated evidence limitation;
    ``missing_links`` lists metrics whose experiment linkage is explicitly
    missing (Req 8.5). A claim is emitted only when the metric improved, its
    linked experiment completed, and limitations are stated (Req 8.4, 8.7,
    10.5, 10.7); otherwise measured differences are reported without
    superiority language (Req 8.6, 10.5).
    """
    links = dict(experiment_links or {})
    limits = dict(limitations or {})
    experiment_id = experiment.artifact_id if experiment is not None else None
    completed_ids: tuple[str, ...] = (
        (experiment_id,) if experiment_id is not None and experiment_completed else ()
    )
    baseline_values = _telemetry_values(baseline)
    changed_values = _telemetry_values(changed)
    differences = [
        _attr(f"diff:{metric}", changed_values[metric] - baseline_values[metric])
        for metric in TELEMETRY_DIFF_METRICS
    ]

    claims = tuple(
        _claim_assessment(
            metric,
            changed_values[metric] - baseline_values[metric],
            completed_experiment_ids=completed_ids,
            experiment_links=links,
            limitations=limits,
            missing_links=missing_links,
        )
        for metric in TELEMETRY_DIFF_METRICS
    )
    missing = tuple(
        metric
        for metric in TELEMETRY_DIFF_METRICS
        if links.get(metric) is None and metric not in missing_links
    )

    return BaselineComparison(
        baseline_configuration_id=(
            experiment.baseline_configuration_id
            if experiment is not None
            else ""
        ),
        changed_configuration_id=(
            experiment.changed_configuration_id if experiment is not None else ""
        ),
        comparison_baseline=comparison_baseline,
        benchmark_manifest_id=baseline.benchmark_manifest_id,
        benchmark_manifest_version=baseline.benchmark_manifest_version or "",
        strata=tuple(s.key for s in baseline.strata),
        measured_differences=tuple(differences),
        claims=claims,
        missing_experiment_link=missing,
        evidence_limitations=tuple(
            limits[metric] for metric in TELEMETRY_DIFF_METRICS if limits.get(metric)
        ),
    )


def build_release_configuration_report(
    configuration_id: str,
    experiments: Sequence[OptimizationExperiment],
    *,
    version: str,
    created_at,
    provenance,
    manifest_id: str,
    manifest_version: str,
    trade_offs: Sequence[ReleaseTradeOff] = (),
) -> ReleaseConfigurationReport:
    """Release-configuration selection linked to completed experiments (Req 8.7)."""
    return ReleaseConfigurationReport(
        version=version,
        created_at=created_at,
        provenance=provenance,
        configuration_id=configuration_id,
        experiments=tuple(experiments),
        trade_offs=tuple(trade_offs),
        benchmark_manifest_id=manifest_id,
        benchmark_manifest_version=manifest_version,
    )
