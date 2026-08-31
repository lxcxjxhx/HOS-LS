"""Task 4.5 tests: FindingConfirmationService exclusive static-path gate.

Covers the pure decision (no repository), repository-backed persistence with
partial-lineage failure retention, and the requirement that CWE/NVD records
are only ever explanatory support (never confirmation evidence).
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.ecatsl.artifact_repository import (
    ArtifactRepository,
    AuditFailureRecord,
    ClassificationPersistenceResult,
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

OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))
UTC_TIME = OFFSET_TIME.astimezone(timezone.utc)


def provenance(identity: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=OFFSET_TIME,
        source_identifier="repo/app.py",
        source_revision="abc123",
        content_identity=identity,
        transformation_history=("parsed:v1",),
    )


def artifact_fields(identity: str, *, version: str = "1", predecessor_id=None):
    return {
        "version": version,
        "created_at": OFFSET_TIME,
        "predecessor_id": predecessor_id,
        "provenance": provenance(identity),
    }


def candidate(
    candidate_id: str = "candidate-1",
    *,
    state: CandidateState = CandidateState.ACCEPTED,
) -> CandidateRecord:
    return CandidateRecord(
        **artifact_fields(f"{candidate_id}-1"),
        candidate_id=candidate_id,
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
        state=state,
        update_cause="accepted",
        changed_data=(),
    )


def specification(
    root: CandidateRecord, identity: str = "spec-1"
) -> ConstrainedDeclarativeSpecification:
    return ConstrainedDeclarativeSpecification(
        **artifact_fields(identity),
        candidate_record_id=root.artifact_id,
        role=CandidateType.SINK,
        api_signature="cursor.execute(query)",
        parameter_positions=(0,),
        applicability=root.applicability,
        taint_semantics=("argument-0-is-sink:spec",),
    )


def validation_result(
    root: CandidateRecord,
    identity: str = "validation-1",
    *,
    adapter_id="input-tracer",
    adapter_version="1",
    linked_artifact_ids=None,
) -> ValidationResult:
    if linked_artifact_ids is None:
        linked_artifact_ids = (root.artifact_id,)
    return ValidationResult(
        **artifact_fields(identity),
        kind="STATIC_PATH",
        outcome="PATH_FOUND",
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        linked_artifact_ids=tuple(linked_artifact_ids),
        observed_data=(),
    )


def path_evidence(
    root: CandidateRecord,
    identity: str = "path-1",
    *,
    sanitizer_status: SanitizerStatus = SanitizerStatus.ABSENT,
    propagation_steps=("app.py:2",),
    adapter_id="input-tracer",
    adapter_version="1",
) -> PathEvidence:
    return PathEvidence(
        **artifact_fields(identity),
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        supported_adapter=True,
        source=PathLocation(location="app.py:1", symbol="request.args"),
        source_provenance=provenance("source-line"),
        propagation_steps=tuple(
            PathLocation(location=item, symbol=None) for item in propagation_steps
        ),
        sink=PathLocation(location="app.py:3", symbol="cursor.execute"),
        sanitizer_status=sanitizer_status,
        static_evidence_identity="trace:1",
    )


def adapter_run(
    root: CandidateRecord,
    spec: ConstrainedDeclarativeSpecification,
    validation: ValidationResult,
    identity: str = "run-1",
    *,
    adapter_id="input-tracer",
    adapter_version="1",
) -> StaticAdapterRun:
    return StaticAdapterRun(
        **artifact_fields(identity),
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        run_identity="run:1",
        candidate_record_ids=(root.artifact_id,),
        specification_ids=(spec.artifact_id,),
        validation_result_id=validation.artifact_id,
        input_artifact_ids=(root.artifact_id, spec.artifact_id),
    )


def persisted_confirmation_lineage(repository: ArtifactRepository):
    """Persist candidate, spec, validation, adapter run, and path; return them."""
    root = candidate()
    repository.create_candidate(root)
    spec = specification(root)
    repository.persist_specification(spec)
    validation = validation_result(
        root, linked_artifact_ids=(root.artifact_id, spec.artifact_id)
    )
    repository.retain_validation(root.artifact_id, validation)
    run = adapter_run(root, spec, validation)
    repository.persist_static_adapter_run(run)
    path = path_evidence(root)
    repository.persist_static_path(path, adapter_run_id=run.artifact_id)
    return root, spec, validation, run, path


# ---------------------------------------------------------------------------
# Pure decision (no repository)
# ---------------------------------------------------------------------------


def test_pure_decision_confirms_only_complete_supported_path():
    root = candidate()
    service = FindingConfirmationService()
    path = path_evidence(root)

    result = service.classify(
        provenance=provenance("finding"),
        path=path,
        candidate_record_ids=(root.artifact_id,),
    )
    assert isinstance(result, FindingClassification)
    assert result.status is FindingStatus.CONFIRMED
    assert result.path_evidence_id == path.artifact_id
    assert result.candidate_record_ids == (root.artifact_id,)


def test_pure_decision_blocking_sanitizer_is_unconfirmed():
    root = candidate()
    service = FindingConfirmationService()
    path = path_evidence(root, sanitizer_status=SanitizerStatus.BLOCKING)

    result = service.classify(
        provenance=provenance("finding"),
        path=path,
        candidate_record_ids=(root.artifact_id,),
    )
    assert isinstance(result, FindingClassification)
    assert result.status is FindingStatus.UNCONFIRMED
    assert result.path_evidence_id is None


def test_pure_decision_failed_sanitizer_is_confirmed():
    root = candidate()
    service = FindingConfirmationService()
    path = path_evidence(root, sanitizer_status=SanitizerStatus.FAILED)

    result = service.classify(
        provenance=provenance("finding"),
        path=path,
        candidate_record_ids=(root.artifact_id,),
    )
    assert isinstance(result, FindingClassification)
    assert result.status is FindingStatus.CONFIRMED


def test_pure_decision_without_path_is_unconfirmed():
    root = candidate()
    service = FindingConfirmationService()
    result = service.classify(
        provenance=provenance("finding"),
        path=None,
        candidate_record_ids=(root.artifact_id,),
    )
    assert isinstance(result, FindingClassification)
    assert result.status is FindingStatus.UNCONFIRMED
    assert result.path_evidence_id is None


def test_pure_decision_explanatory_support_never_confirms():
    root = candidate()
    service = FindingConfirmationService()
    result = service.classify(
        provenance=provenance("finding"),
        explanatory_ids=(root.artifact_id,),
    )
    assert isinstance(result, FindingClassification)
    assert result.status is FindingStatus.UNCONFIRMED
    assert result.explanatory_support_ids == (root.artifact_id,)


def test_pure_decision_rejects_both_explanatory_aliases():
    service = FindingConfirmationService()
    with pytest.raises(ValueError, match="explanatory_support_ids or explanatory_ids"):
        service.classify(
            provenance=provenance("finding"),
            explanatory_support_ids=("a",),
            explanatory_ids=("b",),
        )


def test_pure_decision_retains_missing_metadata_without_duplicates():
    service = FindingConfirmationService()
    result = service.classify(
        provenance=provenance("finding"),
        missing_metadata=(
            "specification:x",
            "candidate_record:y",
            "specification:x",
        ),
    )
    assert isinstance(result, FindingClassification)
    assert result.missing_metadata == ("specification:x", "candidate_record:y")


# ---------------------------------------------------------------------------
# Repository persistence
# ---------------------------------------------------------------------------


def test_repository_persistence_confirms_complete_lineage(tmp_path):
    with ArtifactRepository(tmp_path / "confirmation.db") as repository:
        root, spec, validation, run, path = persisted_confirmation_lineage(repository)
        service = FindingConfirmationService(repository)

        result = service.classify(
            provenance=provenance("finding"),
            path=path,
            candidate_record_ids=(root.artifact_id,),
            specification_ids=(spec.artifact_id,),
            validation_result_ids=(validation.artifact_id,),
        )
        assert isinstance(result, ClassificationPersistenceResult)
        assert result.classification.status is FindingStatus.CONFIRMED
        assert result.classification.path_evidence_id == path.artifact_id
        assert result.failures == ()


def test_repository_persistence_retains_missing_lineage_flags(tmp_path):
    with ArtifactRepository(tmp_path / "confirmation.db") as repository:
        root = candidate()
        repository.create_candidate(root)
        service = FindingConfirmationService(repository)

        result = service.classify(
            provenance=provenance("finding"),
            candidate_record_ids=(root.artifact_id,),
            specification_ids=("spec-missing",),
            validation_result_ids=("validation-missing",),
            explanatory_support_ids=("support-missing",),
        )
        assert isinstance(result, ClassificationPersistenceResult)
        classification = result.classification
        assert classification.status is FindingStatus.UNCONFIRMED
        assert "specification:spec-missing" in classification.missing_metadata
        assert "validation_result:validation-missing" in classification.missing_metadata
        assert "explanatory_support:support-missing" in classification.missing_metadata
        assert len(result.failures) == 3
        assert all(item.operation == "finding_lineage" for item in result.failures)


def test_repository_persistence_blocks_cross_candidate_lineage(tmp_path):
    with ArtifactRepository(tmp_path / "confirmation.db") as repository:
        root, spec, validation, run, path = persisted_confirmation_lineage(repository)
        other = candidate("other")
        repository.create_candidate(other)
        service = FindingConfirmationService(repository)

        with pytest.raises(Exception, match="candidate lineage"):
            service.classify(
                provenance=provenance("finding"),
                path=path,
                candidate_record_ids=(other.artifact_id,),
                specification_ids=(spec.artifact_id,),
                validation_result_ids=(validation.artifact_id,),
            )


def test_repository_persistence_repeat_confirmation_is_append_only(tmp_path):
    with ArtifactRepository(tmp_path / "confirmation.db") as repository:
        root, spec, validation, run, path = persisted_confirmation_lineage(repository)
        service = FindingConfirmationService(repository)
        kwargs = dict(
            provenance=provenance("finding"),
            path=path,
            candidate_record_ids=(root.artifact_id,),
            specification_ids=(spec.artifact_id,),
            validation_result_ids=(validation.artifact_id,),
        )

        first = service.classify(**kwargs, idempotency_key="finding:1")
        second = service.classify(**kwargs, idempotency_key="finding:2")
        assert isinstance(first, ClassificationPersistenceResult)
        assert isinstance(second, ClassificationPersistenceResult)
        # Append-only: a second confirmation with its own key is a distinct artifact.
        assert second.classification.status is FindingStatus.CONFIRMED
        assert second.classification.path_evidence_id == path.artifact_id
        assert first.classification.artifact_id != second.classification.artifact_id
        assert second.failures == ()


def test_repository_persistence_unconfirmed_without_path(tmp_path):
    with ArtifactRepository(tmp_path / "confirmation.db") as repository:
        root = candidate()
        repository.create_candidate(root)
        service = FindingConfirmationService(repository)

        result = service.classify(
            provenance=provenance("finding"),
            candidate_record_ids=(root.artifact_id,),
        )
        assert isinstance(result, ClassificationPersistenceResult)
        assert result.classification.status is FindingStatus.UNCONFIRMED
        assert result.classification.path_evidence_id is None