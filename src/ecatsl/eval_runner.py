"""Real-evaluation runner (theme C-3, tasks 5.1/5.2).

Orchestrates the first real end-to-end evaluation: release emission from
the ``ecatsl_eval`` manifest -> per-sample ``ECATSLService.analyze`` ->
verified classification backfill -> ``build_evaluation_report()`` /
``build_cost_report()`` artifacts under ``bench/artifacts/ecatsl/<tag>/``.

Everything flows through the existing decision layer (``ECATSLService``,
``build_evaluation_report``, ``build_cost_report``). No new evaluation
computation, no bypass of the confirmation boundary (Req 5.1).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from src.ecatsl.eval_dataset import Clock, EvalManifest, emit_release
from src.ecatsl.models import (
    Attribute,
    BenchmarkManifest,
    DataQualityReport,
    CostReport,
    EvaluationReport,
    EvaluationTelemetry,
    FindingStatus,
    OperationalComplexity,
    Provenance,
)
from src.ecatsl.reporting import build_cost_report
from src.ecatsl.evaluation import build_evaluation_report
from src.ecatsl.service import AnalysisRequest, AnalysisResult

#: Version string stamped on every artifact produced by this runner.
RUNNER_VERSION = "1"

#: Replay stability note: a fixed injected clock plus a fixed
#: ``latency_seconds`` make all emitted report artifacts byte-identical
#: across replays (Req 5.5); the real measured latency is returned in
#: ``RunArtifacts.extra`` and never baked into the artifacts themselves.

#: Transformation history entry recorded in the run provenance.
TRANSFORMATION_HISTORY = ("eval_runner/v1: service-analyze + report-backfill",)

ServiceFactory = Callable[[str], Tuple[Any, Any]]
"""Factory mapping a repository_ref to ``(service, repository)``.

The repository is closed by the runner after each sample's analyze call.
"""


def _real_clock() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware(clock: Clock) -> datetime:
    now = clock()
    if now.tzinfo is None:
        raise ValueError("clock must return timezone-aware datetimes")
    return now


def _run_provenance(manifest: EvalManifest, now: datetime) -> Provenance:
    """Path-independent provenance: identity derives from the dataset release.

    ``source_identifier`` is the recorded upstream release string (includes
    the VulnGym version and submodule SHA), so replays from a different
    checkout path stay consistent (Req 4.3 semantics carried into 5.5).
    A blank ``source_release`` (e.g. a synthetic drill manifest) falls back
    to the derived content identity so provenance stays fully qualified.
    """
    identity = manifest.source_release or f"sha256:{manifest.built_at.isoformat()}"
    return Provenance(
        origin="ecatsl_eval_runner",
        retrieved_at=now,
        source_identifier=identity,
        source_revision=manifest.source_release or None,
        content_identity=f"sha256:{manifest.built_at.isoformat()}",
        transformation_history=TRANSFORMATION_HISTORY,
    )


def _default_service_factory(
    database_path: str,
    config_document: Optional[dict] = None,
):
    """Build a service factory reusing the shipped component wiring.

    Mirrors the CLI's ``_wired_service`` assembly (scope, SQLite catalog
    template provider, repository discovery, delegated InputTracer /
    SastPrefilter static adapters, shared artifact repository). Kept local
    so ``src/ecatsl`` does not depend on ``src/cli``; it wires the same
    existing components and adds no new evaluation path. Every value is
    validated through ``ECATSLConfig`` (extra=forbid) before wiring.
    """

    def factory(repository_ref: str) -> Tuple[Any, Any]:
        from src.analyzers.input_tracer import InputTracer
        from src.analyzers.sast_prefilter import SastPrefilter
        from src.ecatsl.artifact_repository import ArtifactRepository
        from src.ecatsl.candidate_ledger import CandidateLedger
        from src.ecatsl.config import ECATSLConfig
        from src.ecatsl.discovery import RepositoryDiscovery
        from src.ecatsl.models import AcceptancePolicy, ValidationPolicy
        from src.ecatsl.scope import initial_scope
        from src.ecatsl.service import (
            ECATSLService,
            build_sqlite_template_provider,
        )
        from src.ecatsl.static_adapters import (
            CodeQLSastAdapter,
            InputTracerAdapter,
        )

        document = dict(config_document or {})
        document.setdefault("database_path", database_path)
        config = ECATSLConfig.model_validate(document)
        now = _real_clock()
        provenance = Provenance(
            origin="ecatsl_eval_runner",
            retrieved_at=now,
            source_identifier="wiring",
            source_revision="wiring",
            content_identity="wiring",
            transformation_history=TRANSFORMATION_HISTORY,
        )
        repository = ArtifactRepository(
            config.database_path,
            supported_static_adapters=tuple(config.supported_static_adapters),
        )
        # Same adapter tuple as the CLI's `_wired_service` (Task 3.1). It is
        # typed as `Tuple[Any, ...]` exactly as the CLI declares it, so the
        # delegated adapters retain the shipped (non-`execute`) surface and no
        # new adapter contract is invented here. Any runtime adapter failure is
        # already isolated by the service into `audit_failures`.
        adapters: Tuple[Any, ...] = (
            InputTracerAdapter(InputTracer(repository_ref)),
            CodeQLSastAdapter(SastPrefilter()),
        )
        try:
            service = ECATSLService(
                scope=initial_scope(created_at=now, provenance=provenance),
                provenance=provenance,
                repository=repository,
                ledger=CandidateLedger(repository),
                acceptance_policy=AcceptancePolicy(
                    version=config.acceptance_policy_version,
                    created_at=now,
                    provenance=provenance,
                    conditions=("independent_evidence",),
                ),
                validation_policy=ValidationPolicy(
                    version=config.validation_policy_version,
                    created_at=now,
                    provenance=provenance,
                    result_mappings=(
                        Attribute(name="COMPLETE_PATH", value="PRESERVE"),
                        Attribute(name="NO_PATH", value="UNACCEPT"),
                        Attribute(name="*", value="UNACCEPT"),
                    ),
                ),
                discovery=RepositoryDiscovery(),
                template_provider=build_sqlite_template_provider(
                    config.database_path, scope_cwe_ids=tuple(config.cwe_ids)
                ),
                static_adapters=adapters,
                supported_static_adapters=tuple(config.supported_static_adapters),
                compiler_version=config.compiler_version,
            )
        except BaseException:
            repository.close()
            raise
        return service, repository

    return factory


def _request_for_sample(
    workdir: str,
    cwe_map: Optional[Tuple[str, ...]],
) -> AnalysisRequest:
    """One analysis request per dataset sample (same mapping as the CLI)."""
    return AnalysisRequest(
        repository_ref=workdir,
        language="python",
        cwe_ids=tuple(cwe_map or ()),
    )


def _backfill_status(result: AnalysisResult) -> FindingStatus:
    """Verified backfill: CONFIRMED only when the service confirmed a finding.

    The service's ``FindingClassification.status`` is the sole confirmation
    source (Path_Evidence gate); absence of any confirmed finding means
    UNCONFIRMED. Never inferred from anything else.
    """
    for finding in result.findings or ():
        if finding.status is FindingStatus.CONFIRMED:
            return FindingStatus.CONFIRMED
    return FindingStatus.UNCONFIRMED


@dataclass(frozen=True)
class SampleOutcome:
    """Per-sample bookkeeping: verified status plus zero-inclusive counters."""

    sample_id: str
    status: FindingStatus
    audit_failures: int
    findings_total: int
    confirmed_findings: int


@dataclass(frozen=True)
class RunArtifacts:
    """The complete output of one ``run_evaluation`` invocation."""

    evaluation_report: EvaluationReport
    cost_report: CostReport
    data_quality_report: DataQualityReport
    manifest: BenchmarkManifest
    outcomes: Tuple[SampleOutcome, ...] = ()
    output_dir: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


def _telemetry_for(
    outcomes: Tuple[SampleOutcome, ...],
    *,
    latency_seconds: float,
    complexity: OperationalComplexity,
) -> EvaluationTelemetry:
    """Zero-inclusive global telemetry (Req 10.4).

    ``tooling_failures`` counts per-sample audit failures recorded by the
    service; ``llm_failures``/``rejected_candidates`` stay 0 because this
    pipeline contains no LLM stage and performs no new rejection
    computation (zero-inclusive truth, never invented).
    """
    return EvaluationTelemetry(
        latency_seconds=latency_seconds,
        llm_tokens=0,
        llm_monetary_cost=0.0,
        complexity=complexity,
        audit_monetary_cost=0.0,
        audit_failures=sum(o.audit_failures for o in outcomes),
        tooling_failures=sum(o.audit_failures for o in outcomes),
        llm_failures=0,
        rejected_candidates=0,
    )


def _counts_for(outcomes: Tuple[SampleOutcome, ...]) -> Dict[str, int]:
    """Per-sample counters keyed ``"<kind>:<sample_id>"`` (Req 10.4)."""
    counts: Dict[str, int] = {}
    for outcome in outcomes:
        if outcome.audit_failures:
            counts[f"tooling_failures:{outcome.sample_id}"] = outcome.audit_failures
            counts[f"llm_failures:{outcome.sample_id}"] = 0
            counts[f"rejected_candidates:{outcome.sample_id}"] = 0
    return counts


def evidence_limitations_for(
    outcomes: Tuple[SampleOutcome, ...],
) -> Tuple[str, ...]:
    """Run-fact-derived ``evidence_limitations`` (Req 5.3, 8.4-8.6).

    Stated from what actually happened -- never invented, never empty when
    a real evidence gap exists. Isolated samples are disclosed as not
    analyzed; a run with zero analyzed samples discloses that no completed
    experiment exists, so every metric is a zero-inclusive count and not
    a comparison result.
    """
    limitations: list = []
    isolated = [o.sample_id for o in outcomes if o.audit_failures and not o.findings_total]
    analyzed = len(outcomes) - len(isolated)
    if isolated:
        limitations.append(
            f"no analysis performed for {len(isolated)} sample(s) with a blank "
            "workdir (no local repository): isolated per Req 3.5, "
            "classification UNCONFIRMED, one tooling failure each"
        )
    if analyzed == 0:
        limitations.append(
            "zero samples analyzed -> zero completed experiments; all "
            "metrics are zero-inclusive counts, not comparison results"
        )
    return tuple(limitations)


def _write_json(path: Path, artifact: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8", newline="\n")


def run_evaluation(
    manifest_path: str | Path,
    output_dir: str | Path,
    *,
    tag: Optional[str] = None,
    clock: Optional[Clock] = None,
    service_factory: Optional[ServiceFactory] = None,
    database_path: Optional[str] = None,
    config_document: Optional[dict] = None,
    version: str = RUNNER_VERSION,
    latency_seconds: Optional[float] = None,
    limit: Optional[int] = None,
) -> RunArtifacts:
    """Run the real-evaluation chain and persist artifacts (Req 5.1/5.2).

    Chain: ``emit_release`` (reuses ``build_release`` full semantics) ->
    per-sample ``ECATSLService.analyze`` -> verified backfill ->
    ``build_evaluation_report`` -> ``build_cost_report`` -> JSON artifacts
    under ``<output_dir>``. The clock is injected (production default: real
    UTC clock); a fixed clock plus a fixed ``latency_seconds`` makes the
    report artifacts byte-identical across replays (Req 5.5).

    ``limit`` (for drills) restricts the number of analyzed samples;
    classification backfill still covers every manifest sample, with
    un-analyzed samples counted as not-predicted (UNCONFIRMED) by
    ``build_evaluation_report``.

    A manifest sample with a blank ``workdir`` has no repository to
    analyze; it follows the shipped failure-isolation semantics (Req 3.5
    carried into 5.1): the analyze chain is skipped, the sample counts as
    one per-sample tooling failure (``tooling_failures:<sample_id>``) and
    its classification is UNCONFIRMED -- no Path_Evidence can exist, so
    CONFIRMED is never reachable. Isolated sample ids are recorded in
    ``RunArtifacts.extra["isolated_samples"]`` for audit.

    ``evidence_limitations`` are derived from run facts via
    ``evidence_limitations_for`` (Req 5.3): isolated samples and the
    zero-analyzed edge are disclosed in the report itself, keeping the
    missing-evidence marking complete on real data (Req 8.4-8.6).
    """
    run_clock: Clock = clock or _real_clock
    now = _require_aware(run_clock)
    factory = service_factory or _default_service_factory(
        database_path or "bench/ecatsl_eval.db",
        config_document,
    )

    benchmark_manifest, quality = emit_release(manifest_path, clock=run_clock)
    eval_manifest = EvalManifest.from_path(manifest_path)
    provenance = _run_provenance(eval_manifest, now)

    outcomes: list[SampleOutcome] = []
    isolated: list[str] = []
    started = time.perf_counter()
    for entry in eval_manifest.entries[:limit] if limit else eval_manifest.entries:
        if not entry.workdir.strip():
            # Failure isolation (Req 3.5 semantics): nothing to analyze, so
            # the analyze chain is skipped entirely. UNCONFIRMED is the only
            # honest status (no Path_Evidence); the skip is audited as one
            # per-sample tooling failure, never silently dropped.
            isolated.append(entry.sample_id)
            outcomes.append(
                SampleOutcome(
                    sample_id=entry.sample_id,
                    status=FindingStatus.UNCONFIRMED,
                    audit_failures=1,
                    findings_total=0,
                    confirmed_findings=0,
                )
            )
            continue
        service, repository = factory(entry.workdir)
        try:
            result = service.analyze(
                _request_for_sample(entry.workdir, entry.cwe_map)
            )
        finally:
            repository.close()
        outcomes.append(
            SampleOutcome(
                sample_id=entry.sample_id,
                status=_backfill_status(result),
                audit_failures=len(result.audit_failures or ()),
                findings_total=len(result.findings or ()),
                confirmed_findings=sum(
                    1
                    for f in result.findings or ()
                    if f.status is FindingStatus.CONFIRMED
                ),
            )
        )
    measured_latency = time.perf_counter() - started

    classifications = {o.sample_id: o.status for o in outcomes}
    complexity = OperationalComplexity(
        configured_adapters=2,
        pipeline_stages=1,
        external_service_dependencies=0,
        manual_execution_steps=0,
    )
    telemetry = _telemetry_for(
        tuple(outcomes),
        latency_seconds=(
            measured_latency if latency_seconds is None else float(latency_seconds)
        ),
        complexity=complexity,
    )
    evaluation_report = build_evaluation_report(
        benchmark_manifest,
        quality,
        classifications,
        version=version,
        created_at=now,
        provenance=provenance,
        telemetry=telemetry,
        counts=_counts_for(tuple(outcomes)),
        evidence_limitations=evidence_limitations_for(tuple(outcomes)),
    )
    cost_report = build_cost_report(
        evaluation_report,
        version=version,
        created_at=now,
        provenance=provenance,
    )

    resolved_dir = Path(output_dir) if tag is None else Path(output_dir) / tag
    _write_json(resolved_dir / "evaluation_report.json", evaluation_report)
    _write_json(resolved_dir / "cost_report.json", cost_report)
    _write_json(resolved_dir / "data_quality_report.json", quality)
    return RunArtifacts(
        evaluation_report=evaluation_report,
        cost_report=cost_report,
        data_quality_report=quality,
        manifest=benchmark_manifest,
        outcomes=tuple(outcomes),
        output_dir=str(resolved_dir),
        extra={
            "measured_latency_seconds": measured_latency,
            "isolated_samples": tuple(isolated),
        },
    )
