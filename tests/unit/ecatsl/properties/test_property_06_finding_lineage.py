"""Feature: evidence-constrained-taint-spec-learning, Property 6 tests.

Property 6: Finding decisions retain available lineage without rollback.
Generate available lineage (candidate, specification, validation, adapter run,
path) and optional metadata-write failures and assert unchanged classification
plus exact missing-element flags. A partially failed lineage persistence
preserves the classification decision while enumerating each unavailable
metadata element; complete available lineage is retained without any failure
record.

Validates: Requirements 4.6, 4.7
"""

from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from src.ecatsl.artifact_repository import (
    ArtifactRepository,
    ClassificationPersistenceResult,
    OptionalMetadataPersistenceError,
)
from src.ecatsl.confirmation import FindingConfirmationService
from src.ecatsl.models import (
    Applicability,
    CandidateRecord,
    CandidateState,
    CandidateType,
    ConstrainedDeclarativeSpecification,
    FindingClassification,
    FindingStatus,
    PathEvidence,
    PathLocation,
    Provenance,
    SanitizerStatus,
    StaticAdapterRun,
    ValidationResult,
)

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

_SOURCE = PathLocation(location="app.py:2", symbol="request.args")
_PROPAGATION = (PathLocation(location="app.py:3", symbol="query"),)
_SINK = PathLocation(location="app.py:4", symbol="cursor.execute")


def _provenance(identity: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="property-6",
        content_identity=identity,
        transformation_history=("property-test:v6",),
    )


def _fields(identity: str) -> dict:
    return {
        "version": "1",
        "created_at": NOW,
        "predecessor_id": None,
        "provenance": _provenance(identity),
    }


def _candidate(identity: str = "candidate:1") -> CandidateRecord:
    return CandidateRecord(
        **_fields(identity),
        candidate_id=identity,
        candidate_type=CandidateType.SINK,
        confidence=0.8,
        evidence_ids=(),
        counterexample_ids=(),
        applicability=Applicability(
            language="python",
            api_signature="cursor.execute(query)",
            parameter_positions=(0,),
        ),
        cwe_id="CWE-89",
        state=CandidateState.ACCEPTED,
        update_cause="accepted",
        changed_data=(),
    )


def _specification(root: CandidateRecord) -> ConstrainedDeclarativeSpecification:
    return ConstrainedDeclarativeSpecification(
        **_fields("spec:1"),
        candidate_record_id=root.artifact_id,
        role=CandidateType.SINK,
        api_signature=root.applicability.api_signature,
        parameter_positions=root.applicability.parameter_positions,
        applicability=root.applicability,
        taint_semantics=("argument-0-is-sink",),
    )


def _validation(
    root: CandidateRecord, spec: ConstrainedDeclarativeSpecification
) -> ValidationResult:
    return ValidationResult(
        **_fields("validation:1"),
        kind="STATIC_PATH",
        outcome="PATH_FOUND",
        adapter_id="input-tracer",
        adapter_version="1",
        linked_artifact_ids=(root.artifact_id, spec.artifact_id),
        observed_data=(),
    )


def _adapter_run(
    root: CandidateRecord,
    spec: ConstrainedDeclarativeSpecification,
    validation: ValidationResult,
) -> StaticAdapterRun:
    return StaticAdapterRun(
        **_fields("run:1"),
        adapter_id="input-tracer",
        adapter_version="1",
        run_identity="run:property-6",
        candidate_record_ids=(root.artifact_id,),
        specification_ids=(spec.artifact_id,),
        validation_result_id=validation.artifact_id,
        input_artifact_ids=(root.artifact_id, spec.artifact_id),
    )


def _path() -> PathEvidence:
    return PathEvidence(
        **_fields("path:1"),
        adapter_id="input-tracer",
        adapter_version="1",
        supported_adapter=True,
        source=_SOURCE,
        source_provenance=_provenance("source-line"),
        propagation_steps=_PROPAGATION,
        sink=_SINK,
        sanitizer_status=SanitizerStatus.ABSENT,
        static_evidence_identity="static:property-6",
    )


def _persisted_lineage(repository: ArtifactRepository):
    root = _candidate()
    repository.create_candidate(root)
    spec = _specification(root)
    repository.persist_specification(spec)
    validation = _validation(root, spec)
    repository.retain_validation(root.artifact_id, validation)
    run = _adapter_run(root, spec, validation)
    repository.persist_static_adapter_run(run)
    path = _path()
    repository.persist_static_path(path, adapter_run_id=run.artifact_id)
    return root, spec, validation, run, path


@settings(max_examples=100, deadline=None)
@given(
    path_present=st.booleans(),
)
def test_property_06_classification_is_independent_of_lineage_availability(
    path_present: bool,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 6: pure classification depends only on the static path proof, never on lineage availability."""
    service = FindingConfirmationService()
    result = service.classify(
        provenance=_provenance("finding:property-6"),
        path=_path() if path_present else None,
        candidate_record_ids=("candidate:1",),
    )
    assert isinstance(result, FindingClassification)
    assert (result.status is FindingStatus.CONFIRMED) == path_present
    assert (result.path_evidence_id is not None) == path_present


@settings(max_examples=100, deadline=None)
@given(
    missing_specification=st.booleans(),
    missing_validation=st.booleans(),
    missing_support=st.booleans(),
)
def test_property_06_partial_lineage_failure_preserves_decision_and_flags(
    missing_specification: bool,
    missing_validation: bool,
    missing_support: bool,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 6: partial metadata failure preserves the decision and enumerates exact missing flags."""
    missing = []
    if missing_specification:
        missing.append("specification:spec:1")
    if missing_validation:
        missing.append("validation_result:validation:1")
    if missing_support:
        missing.append("explanatory_support:support:1")

    def fail_optional(point, _transaction_id):
        if point == "classification.optional_audit_metadata" and missing:
            raise OptionalMetadataPersistenceError(*missing)

    with ArtifactRepository.for_testing(
        ":memory:", failure_hook=fail_optional
    ) as repository:
        root, spec, validation, run, path = _persisted_lineage(repository)
        service = FindingConfirmationService(repository)
        result = service.classify(
            provenance=_provenance("finding:property-6"),
            path=path,
            candidate_record_ids=(root.artifact_id,),
            specification_ids=(spec.artifact_id,),
            validation_result_ids=(validation.artifact_id,),
            explanatory_support_ids=("support:1",) if missing_support else (),
        )
    assert isinstance(result, ClassificationPersistenceResult)
    assert result.classification.status is FindingStatus.CONFIRMED
    # The decision is preserved; missing elements are enumerated exactly once.
    assert sorted(result.classification.missing_metadata) == sorted(missing)
    assert len(result.failures) == len(missing)
    assert sorted(item.missing_element for item in result.failures) == sorted(missing)


def test_property_06_complete_lineage_is_retained_without_failure() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 6: complete available lineage is retained with no failure records."""
    with ArtifactRepository(":memory:") as repository:
        root, spec, validation, run, path = _persisted_lineage(repository)
        service = FindingConfirmationService(repository)
        result = service.classify(
            provenance=_provenance("finding:property-6"),
            path=path,
            candidate_record_ids=(root.artifact_id,),
            specification_ids=(spec.artifact_id,),
            validation_result_ids=(validation.artifact_id,),
        )
    assert isinstance(result, ClassificationPersistenceResult)
    assert result.classification.status is FindingStatus.CONFIRMED
    assert result.classification.missing_metadata == ()
    assert result.failures == ()