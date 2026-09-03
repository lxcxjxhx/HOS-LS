"""Task 5.2 tests: pipeline stage identity, consolidation, and execution isolation.

Covers deterministic stage identity, first-occurrence consolidation with a
recorded duplicate decision, consolidation-persistence failure retaining and
executing both stages with an audit record, required/optional failure
isolation, per-stage timeout and cancellation boundaries, and complexity
calculated from the actual assembled pipeline.
"""

from datetime import datetime, timezone

import pytest

from src.ecatsl.artifact_repository import (
    ArtifactRepository,
    OptionalMetadataPersistenceError,
)
from src.ecatsl.models import Provenance
from src.ecatsl.pipeline import (
    CONSOLIDATION_OPERATION,
    Pipeline,
    StageDefinition,
    compute_complexity,
    consolidate_stages,
    persist_consolidation,
    stage_identity,
)

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)


def _provenance(identity: str = "pipeline") -> Provenance:
    return Provenance(
        origin="task-5.2",
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="task-5.2",
        content_identity=identity,
        transformation_history=("pipeline-test",),
    )


def _stage(
    purpose: str,
    *,
    inputs=("in:v1",),
    outputs=("out:v1",),
    required: bool = True,
    timeout_seconds=None,
    run=None,
) -> StageDefinition:
    return StageDefinition(
        transformation_purpose=purpose,
        input_artifact_ids=tuple(inputs),
        output_artifact_ids=tuple(outputs),
        required=required,
        timeout_seconds=timeout_seconds,
        run=run,
    )


def _ok_run(outputs=("out:v1",)):
    def run(_accumulated):
        return tuple(outputs)

    return run


def test_stage_identity_is_deterministic_and_discriminating():
    first = stage_identity(("in:v1",), "scope gate", ("out:v1",))
    repeat = stage_identity(("in:v1",), "scope gate", ("out:v1",))
    different_purpose = stage_identity(("in:v1",), "confirmation", ("out:v1",))
    different_input = stage_identity(("in:v2",), "scope gate", ("out:v1",))
    different_output = stage_identity(("in:v1",), "scope gate", ("out:v2",))
    assert first == repeat
    assert len({first, different_purpose, different_input, different_output}) == 4
    assert _stage("scope gate").identity == stage_identity(
        ("in:v1",), "scope gate", ("out:v1",)
    )


def test_consolidate_stages_keeps_first_occurrence_and_lists_duplicates():
    a = _stage("scope gate")
    duplicate = _stage("scope gate")
    b = _stage("confirmation", inputs=("a:1", "b:1"))
    result = consolidate_stages([a, b, duplicate, a])
    assert tuple(item.identity for item in result.canonical) == (
        a.identity,
        b.identity,
    )
    assert tuple(item.identity for item in result.duplicates) == (
        duplicate.identity,
        a.identity,
    )


def test_persist_consolidation_records_canonical_and_duplicate_decision(tmp_path):
    database = tmp_path / "pipeline-normal.db"
    with ArtifactRepository(database) as repository:
        a = _stage("scope gate", outputs=("scope:v1",))
        duplicate = _stage("scope gate", outputs=("scope:v1",))
        b = _stage("confirmation", inputs=("scope:v1",), outputs=("finding:v1",))
        outcome = persist_consolidation(
            repository,
            [a, b, duplicate],
            provenance=_provenance(),
            created_at=NOW,
        )
        assert outcome.consolidation_failed is False
        assert len(outcome.stages) == 3
        assert len(outcome.audit_failures) == 1
        assert tuple(item.identity for item in outcome.executed_definitions) == (
            a.identity,
            b.identity,
        )
        assert outcome.stage_count == 2

        canonical = repository.find_canonical_pipeline_stage(a.identity)
        assert canonical is not None
        assert canonical.duplicate_of_artifact_id is None
        assert canonical.consolidation_failure_artifact_id is None

        decision = outcome.audit_failures[0]
        assert decision.operation == CONSOLIDATION_OPERATION
        assert decision.related_artifact_id == canonical.artifact_id
        assert decision.missing_element == f"duplicate_stage:{duplicate.identity}"

        duplicate_stages = [
            stage for stage in outcome.stages if stage.duplicate_of_artifact_id is not None
        ]
        assert len(duplicate_stages) == 1
        assert duplicate_stages[0].duplicate_of_artifact_id == canonical.artifact_id
        assert (
            duplicate_stages[0].consolidation_failure_artifact_id
            == decision.artifact_id
        )
        assert duplicate_stages[0].stage_identity == canonical.stage_identity

    # Idempotent replay on a fresh connection returns the same retained stages.
    with ArtifactRepository(database) as repository:
        replay = persist_consolidation(
            repository,
            [_stage("scope gate", outputs=("scope:v1",)),
             _stage("confirmation", inputs=("scope:v1",), outputs=("finding:v1",)),
             _stage("scope gate", outputs=("scope:v1",))],
            provenance=_provenance(),
            created_at=NOW,
        )
        assert tuple(stage.artifact_id for stage in replay.stages) == tuple(
            stage.artifact_id for stage in outcome.stages
        )
        assert replay.stage_count == outcome.stage_count


def test_consolidation_persistence_failure_retains_and_executes_both(tmp_path):
    database = tmp_path / "pipeline-consolidation-failure.db"

    def fail_consolidation(point, _transaction_id):
        if point == "pipeline_stage.consolidation_decision":
            raise OptionalMetadataPersistenceError("consolidation decision")

    with ArtifactRepository.for_testing(
        database, failure_hook=fail_consolidation
    ) as repository:
        a = _stage("scope gate")
        duplicate = _stage("scope gate")
        outcome = persist_consolidation(
            repository,
            [a, duplicate],
            provenance=_provenance(),
            created_at=NOW,
        )
        assert outcome.consolidation_failed is True
        # Both matching stages are retained for execution.
        assert tuple(item.identity for item in outcome.executed_definitions) == (
            a.identity,
            duplicate.identity,
        )
        # Only the canonical stage was persisted; the duplicate retention
        # failed, and the failure itself is audited.
        assert len(outcome.stages) == 1
        assert outcome.stages[0].duplicate_of_artifact_id is None
        assert any(
            failure.operation == CONSOLIDATION_OPERATION
            and failure.missing_element.startswith("consolidation_failure:")
            for failure in outcome.audit_failures
        )


def test_pipeline_optional_failure_continues_to_required_gates():
    def fail(_accumulated):
        raise RuntimeError("catalog outage")

    stages = [
        _stage("catalog retrieval", required=False, run=fail),
        _stage("scope gate", run=_ok_run()),
        _stage("confirmation", run=_ok_run(outputs=("finding:v1",))),
    ]
    result = Pipeline(stages).run()
    assert result.stopped is False
    assert tuple(item.outcome for item in result.results) == (
        "FAILED",
        "COMPLETED",
        "COMPLETED",
    )
    assert result.results[0].error == "catalog outage"
    assert result.results[2].output_artifact_ids == ("finding:v1",)


def test_pipeline_required_failure_stops_downstream():
    def fail(_accumulated):
        raise RuntimeError("policy persistence failed")

    stages = [
        _stage("policy gate", run=fail),
        _stage("compilation", run=_ok_run()),
    ]
    result = Pipeline(stages).run()
    assert result.stopped is True
    assert tuple(item.outcome for item in result.results) == ("FAILED",)
    # The compilation stage must never run after a required-gate failure.
    assert len(result.results) == 1


def test_pipeline_timeout_boundary_optional_continues_required_stops():
    def hang(_accumulated):
        import time

        time.sleep(30)

    optional = [
        _stage("discovery assistance", required=False, timeout_seconds=0.05, run=hang),
        _stage("scope gate", run=_ok_run()),
    ]
    result = Pipeline(optional).run()
    assert result.stopped is False
    assert tuple(item.outcome for item in result.results) == ("TIMEOUT", "COMPLETED")

    required = [
        _stage("compilation gate", required=True, timeout_seconds=0.05, run=hang),
        _stage("confirmation", run=_ok_run()),
    ]
    result = Pipeline(required).run()
    assert result.stopped is True
    assert tuple(item.outcome for item in result.results) == ("TIMEOUT",)


def test_pipeline_cancellation_prevents_further_stage_bodies():
    def record_run(records, label):
        def run(_accumulated):
            records.append(label)
            return (label,)

        return run

    records = []
    checks = [0]

    def should_cancel():
        checks[0] += 1
        # Cancel between the first and second stage, before any later body.
        return checks[0] > 1

    stages = [
        _stage("scope gate", run=record_run(records, "scope")),
        _stage("discovery assistance", required=False, run=record_run(records, "discovery")),
        _stage("confirmation", run=record_run(records, "confirmation")),
    ]
    result = Pipeline(stages, should_cancel=should_cancel).run()
    assert result.cancelled is True
    assert records == ["scope"]
    assert tuple(item.outcome for item in result.results) == (
        "COMPLETED",
        "CANCELLED",
    )
    assert len(result.results) == 2


def test_pipeline_passes_accumulated_outputs_to_downstream_stages():
    scope = _stage("scope gate", outputs=("scope:v1",))

    def consume(accumulated):
        return (accumulated[scope.identity][0], "derived:v1")

    stages = [
        scope,
        _stage("compilation", inputs=("scope:v1",), run=consume),
    ]
    result = Pipeline(stages).run()
    assert result.results[1].output_artifact_ids == ("scope:v1", "derived:v1")


def test_compute_complexity_counts_actual_assembled_pipeline():
    assembled = [
        _stage("scope gate"),
        _stage("scope gate"),  # duplicate identity, must not double count
        _stage("confirmation", inputs=("scope:v1",)),
        _stage("catalog retrieval", required=False),
    ]
    complexity = compute_complexity(
        assembled,
        configured_adapters=("codeql", "input-tracer"),
        external_service_dependencies=1,
        manual_execution_steps=2,
    )
    assert complexity.configured_adapters == 2
    assert complexity.pipeline_stages == 3
    assert complexity.external_service_dependencies == 1
    assert complexity.manual_execution_steps == 2

    # Stage count matches the persisted consolidation of the same definitions.
    assert (
        consolidate_stages(assembled).canonical.__len__() == complexity.pipeline_stages
    )
