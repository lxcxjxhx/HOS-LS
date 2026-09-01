"""Deterministic stage identity, consolidation, execution isolation, and complexity.

Implements the Task 5.2 surface of the ECATSL plan (Requirements 7.1-7.6, 8.1):

- A pipeline-stage identity is the deterministic combination of versioned input
  artifact identities/types, transformation purpose, and versioned output
  artifact identities/types.
- Equal identities are consolidated deterministically: the first occurrence is
  canonical, every later equal occurrence is retained as a duplicate stage that
  records a ``pipeline_stage_consolidation`` audit decision. If consolidation
  persistence fails, both stages are retained and permitted to execute while the
  consolidation failure is audited.
- Stage execution isolates required versus optional failures: optional stages
  (catalog, discovery, RAG, LLM, one adapter) never bypass the scope, policy,
  compilation, or confirmation gates because those gates are required stages;
  a required-stage failure stops downstream execution. Per-stage timeout and
  cancellation boundaries are enforced between stages.
- Operational complexity is calculated from the actual assembled
  (post-consolidation) pipeline.
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Callable, Mapping, Optional, Sequence, Tuple

from .artifact_repository import ArtifactRepository, AuditFailureRecord
from .models import (
    Attribute,
    OperationalComplexity,
    PipelineStage,
    Provenance,
)

CONSOLIDATION_OPERATION = "pipeline_stage_consolidation"


def stage_identity(
    input_artifact_ids: Sequence[str],
    transformation_purpose: str,
    output_artifact_ids: Sequence[str],
) -> str:
    """Deterministic Pipeline_Stage_Identity over inputs, purpose, and outputs.

    Equal identities mean two stages perform the same transformation on the
    same versioned inputs to the same versioned outputs, so they are
    consolidatable regardless of ordering or surrounding context.
    """

    payload = {
        "inputs": tuple(input_artifact_ids),
        "purpose": transformation_purpose,
        "outputs": tuple(output_artifact_ids),
    }
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class StageDefinition:
    """One assembled pipeline stage: identity metadata plus an executable body.

    ``required=False`` marks assistance stages (catalog, discovery, RAG, LLM, a
    single adapter) whose failure must not block the required scope, policy,
    compilation, or confirmation gates. ``run`` receives the accumulated stage
    outputs (a mapping of earlier stage identities to their output artifact id
    tuples) and returns the output artifact ids produced by this stage.
    """

    transformation_purpose: str
    input_artifact_ids: Tuple[str, ...]
    output_artifact_ids: Tuple[str, ...]
    run: Optional[Callable[[Mapping[str, Tuple[str, ...]]], Tuple[str, ...]]] = None
    required: bool = True
    timeout_seconds: Optional[float] = None

    @property
    def identity(self) -> str:
        return stage_identity(
            self.input_artifact_ids, self.transformation_purpose, self.output_artifact_ids
        )


@dataclass(frozen=True)
class ConsolidationResult:
    canonical: Tuple[StageDefinition, ...]
    duplicates: Tuple[StageDefinition, ...]


def consolidate_stages(definitions: Sequence[StageDefinition]) -> ConsolidationResult:
    """Deterministically deduplicate equal stage identities.

    The first occurrence of an identity is canonical; every later equal
    occurrence is a duplicate. Order is preserved exactly as supplied, so equal
    inputs always produce equal results.
    """

    seen = set()
    canonical = []
    duplicates = []
    for definition in definitions:
        if definition.identity in seen:
            duplicates.append(definition)
        else:
            seen.add(definition.identity)
            canonical.append(definition)
    return ConsolidationResult(tuple(canonical), tuple(duplicates))


@dataclass(frozen=True)
class ConsolidationOutcome:
    """Result of persisting a consolidation.

    ``stages`` are the successfully persisted ``PipelineStage`` records (all
    canonical stages plus every duplicate whose decision persisted). When
    ``consolidation_failed`` is true, the affected duplicate definitions are
    retained in ``executed_definitions`` so both matching stages execute, and
    the consolidation failure is recorded in ``audit_failures``.
    """

    stages: Tuple[PipelineStage, ...]
    audit_failures: Tuple[AuditFailureRecord, ...]
    executed_definitions: Tuple[StageDefinition, ...]
    consolidation_failed: bool = False

    @property
    def stage_count(self) -> int:
        """Count of retained pipeline stages from the actual assembled pipeline."""

        return len(tuple(dict.fromkeys(stage.stage_identity for stage in self.stages)))


def persist_consolidation(
    repository: ArtifactRepository,
    definitions: Sequence[StageDefinition],
    *,
    provenance: Provenance,
    created_at: Optional[datetime] = None,
    version: str = "1",
) -> ConsolidationOutcome:
    """Persist the deterministic consolidation of ``definitions``.

    Canonical stages are persisted first. Each duplicate persists a
    ``pipeline_stage_consolidation`` audit decision (an ``AuditFailureRecord``)
    linked to its canonical stage and then the duplicate ``PipelineStage``
    record. If persisting a duplicate or its decision fails, the duplicate
    definition is retained for execution alongside its canonical stage, the
    consolidation failure is audited, and processing continues so a single bad
    stage never drops later required gates.
    """

    result = consolidate_stages(definitions)
    when = created_at or datetime.now(timezone.utc)
    canonical_id_by_identity: dict[str, str] = {}
    persisted_stages: list[PipelineStage] = []
    audit_failures: list[AuditFailureRecord] = []
    executed: list[StageDefinition] = list(result.canonical)
    consolidation_failed = False

    for definition in result.canonical:
        stage = _build_stage(definition, provenance=provenance, created_at=when, version=version)
        persisted = repository.persist_pipeline_stage(
            stage, idempotency_key=f"stage:{stage.artifact_id}"
        )
        persisted_stages.append(persisted)
        canonical_id_by_identity[definition.identity] = persisted.artifact_id

    for definition in result.duplicates:
        canonical_artifact_id = canonical_id_by_identity[definition.identity]
        try:
            decision = AuditFailureRecord(
                version=version,
                created_at=when,
                provenance=provenance,
                related_artifact_id=canonical_artifact_id,
                operation=CONSOLIDATION_OPERATION,
                missing_element=f"duplicate_stage:{definition.identity}",
                failure_data=(
                    Attribute(name="decision", value="consolidated_to_canonical"),
                    Attribute(name="canonical_stage", value=canonical_artifact_id),
                ),
            )
            persisted_decision = repository.record_failure(
                decision, idempotency_key=f"consolidation-decision:{definition.identity}"
            )
            duplicate_stage = _build_stage(
                definition,
                provenance=provenance,
                created_at=when,
                version=version,
                duplicate_of_artifact_id=canonical_artifact_id,
                consolidation_failure_artifact_id=persisted_decision.artifact_id,
            )
            persisted_stages.append(
                repository.persist_pipeline_stage(
                    duplicate_stage, idempotency_key=f"stage:{duplicate_stage.artifact_id}"
                )
            )
            audit_failures.append(persisted_decision)
        except Exception:
            # Consolidation persistence failed: retain and execute both stages.
            consolidation_failed = True
            executed.append(definition)
            try:
                failure = repository.record_failure(
                    AuditFailureRecord(
                        version=version,
                        created_at=when,
                        provenance=provenance,
                        related_artifact_id=canonical_artifact_id,
                        operation=CONSOLIDATION_OPERATION,
                        missing_element=f"consolidation_failure:{definition.identity}",
                        failure_data=(
                            Attribute(
                                name="error",
                                value="consolidation persistence failed",
                            ),
                        ),
                    ),
                    idempotency_key=f"consolidation-failure:{definition.identity}",
                )
                audit_failures.append(failure)
            except Exception:
                # Even the failure record could not be retained; the outcome
                # still keeps both stages executable and reports the flag.
                consolidation_failed = True

    return ConsolidationOutcome(
        stages=tuple(persisted_stages),
        audit_failures=tuple(audit_failures),
        executed_definitions=tuple(executed),
        consolidation_failed=consolidation_failed,
    )


def _build_stage(
    definition: StageDefinition,
    *,
    provenance: Provenance,
    created_at: datetime,
    version: str,
    duplicate_of_artifact_id: Optional[str] = None,
    consolidation_failure_artifact_id: Optional[str] = None,
) -> PipelineStage:
    return PipelineStage(
        version=version,
        created_at=created_at,
        provenance=provenance,
        stage_identity=definition.identity,
        input_artifact_ids=definition.input_artifact_ids,
        transformation_purpose=definition.transformation_purpose,
        output_artifact_ids=definition.output_artifact_ids,
        duplicate_of_artifact_id=duplicate_of_artifact_id,
        consolidation_failure_artifact_id=consolidation_failure_artifact_id,
    )


@dataclass(frozen=True)
class StageRunResult:
    definition: StageDefinition
    outcome: str
    output_artifact_ids: Tuple[str, ...] = ()
    error: Optional[str] = None
    latency_seconds: float = 0.0


@dataclass(frozen=True)
class PipelineRunResult:
    results: Tuple[StageRunResult, ...]
    stopped: bool = False
    cancelled: bool = False


class Pipeline:
    """Executes consolidated stages with required/optional failure isolation.

    Continuation rules: an optional stage (catalog, discovery, RAG, LLM, a
    single adapter) failure is retained in the result and execution continues;
    a required stage failure stops all downstream execution. A per-stage
    ``timeout_seconds`` boundary turns a hung stage into a failure; a
    ``should_cancel`` callback is consulted between stages and cancels pending
    work without running any further stage body.
    """

    def __init__(
        self,
        stages: Sequence[StageDefinition],
        *,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.stages = tuple(stages)
        self.should_cancel = should_cancel or (lambda: False)

    def run(self) -> PipelineRunResult:
        results: list[StageRunResult] = []
        accumulated: dict[str, Tuple[str, ...]] = {}
        for definition in self.stages:
            if self.should_cancel():
                results.append(
                    StageRunResult(definition=definition, outcome="CANCELLED")
                )
                return PipelineRunResult(tuple(results), cancelled=True)
            if definition.run is None:
                results.append(
                    StageRunResult(
                        definition=definition,
                        outcome="COMPLETED",
                        output_artifact_ids=definition.output_artifact_ids,
                    )
                )
                accumulated[definition.identity] = definition.output_artifact_ids
                continue
            outcome, output_ids, error, latency = self._execute(definition, accumulated)
            results.append(
                StageRunResult(
                    definition=definition,
                    outcome=outcome,
                    output_artifact_ids=output_ids,
                    error=error,
                    latency_seconds=latency,
                )
            )
            if outcome == "COMPLETED":
                accumulated[definition.identity] = output_ids
            elif definition.required:
                return PipelineRunResult(tuple(results), stopped=True)
        return PipelineRunResult(tuple(results))

    @staticmethod
    def _execute(
        definition: StageDefinition,
        accumulated: Mapping[str, Tuple[str, ...]],
    ) -> Tuple[str, Tuple[str, ...], Optional[str], float]:
        started = _monotonic()
        try:
            if definition.timeout_seconds is not None:
                pool = ThreadPoolExecutor(max_workers=1)
                future = pool.submit(definition.run, accumulated)
                try:
                    output = future.result(timeout=definition.timeout_seconds)
                except FutureTimeout:
                    future.cancel()
                    pool.shutdown(wait=False, cancel_futures=True)
                    return "TIMEOUT", (), "stage timed out", _monotonic() - started
                pool.shutdown(wait=True)
            else:
                output = definition.run(accumulated)
            return "COMPLETED", tuple(output), None, _monotonic() - started
        except Exception as error:
            return "FAILED", (), str(error), _monotonic() - started


def _monotonic() -> float:
    import time

    return time.monotonic()


def compute_complexity(
    assembled_stages: Sequence[StageDefinition],
    configured_adapters: Sequence[object] = (),
    external_service_dependencies: int = 0,
    manual_execution_steps: int = 0,
) -> OperationalComplexity:
    """Calculate complexity metrics from the actual assembled pipeline.

    ``pipeline_stages`` counts consolidated canonical stages (duplicates of an
    equal identity are not double counted), matching the retained
    ``ConsolidationOutcome.stage_count`` of the assembled pipeline.
    """

    consolidated = consolidate_stages(assembled_stages)
    return OperationalComplexity(
        configured_adapters=len(tuple(configured_adapters)),
        pipeline_stages=len(consolidated.canonical),
        external_service_dependencies=external_service_dependencies,
        manual_execution_steps=manual_execution_steps,
    )
