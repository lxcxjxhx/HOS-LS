"""Focused unit tests for the task-2.2 append-only artifact repository."""

from datetime import datetime, timedelta, timezone
import multiprocessing
import os
import sqlite3
import threading
import time

import pytest

from src.ecatsl.artifact_repository import (
    ArtifactRepository,
    ArtifactRepositoryConfig,
    AuditFailureRecord,
    CompareAndAppendStatus,
    IdempotencyConflictError,
    ImmutableArtifactError,
    LineageError,
    OptionalMetadataPersistenceError,
    PolicyDecisionRecord,
    RepositoryTestInterruption,
    StalePredecessorError,
    TransactionState,
    UnsupportedArtifactTypeError,
    _request_hash,
)
from src.ecatsl.schema import ProcessLiveness, SQLiteWriteConfig, install_ecatsl_schema, MIGRATIONS
from src.ecatsl.models import (
    AcceptancePolicy,
    Applicability,
    Attribute,
    CandidateRecord,
    CandidateState,
    CandidateType,
    CatalogRecord,
    ConstrainedDeclarativeSpecification,
    Counterexample,
    Evidence,
    FindingClassification,
    FindingStatus,
    PathEvidence,
    PathLocation,
    Provenance,
    SanitizerStatus,
    StaticAdapterRun,
    ValidationResult,
    task_1_1_reuse_inventory,
)
from src.ecatsl.scope import INITIAL_CWES, initial_scope, revise_scope


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
    version: str = "1",
    predecessor_id=None,
    state: CandidateState = CandidateState.PROPOSED,
    confidence: float = 0.4,
    cause: str = "proposal",
) -> CandidateRecord:
    return CandidateRecord(
        **artifact_fields(
            f"{candidate_id}-{version}", version=version, predecessor_id=predecessor_id
        ),
        candidate_id=candidate_id,
        candidate_type=CandidateType.SINK,
        confidence=confidence,
        evidence_ids=(),
        counterexample_ids=(),
        applicability=Applicability(
            language="python",
            api_signature="cursor.execute(query)",
            parameter_positions=(0,),
        ),
        cwe_id="CWE-89",
        state=state,
        update_cause=cause,
        changed_data=(Attribute(name="confidence", value=str(confidence)),),
    )


def specification(root: CandidateRecord, identity: str = "specification"):
    return ConstrainedDeclarativeSpecification(
        **artifact_fields(identity),
        candidate_record_id=root.artifact_id,
        role=CandidateType.SINK,
        api_signature="cursor.execute(query)",
        parameter_positions=(0,),
        applicability=root.applicability,
        taint_semantics=(f"argument-0-is-sink:{identity}",),
    )


def retained_static_path(
    repository: ArtifactRepository,
    root: CandidateRecord,
    specifications,
    *,
    adapter_id="input-tracer",
    adapter_version="1",
):
    validation = ValidationResult(
        **artifact_fields("path-validation"),
        kind="STATIC_PATH",
        outcome="PATH_FOUND",
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        linked_artifact_ids=(root.artifact_id,) + tuple(
            item.artifact_id for item in specifications
        ),
    )
    repository.retain_validation(root.artifact_id, validation)
    run = StaticAdapterRun(
        **artifact_fields("adapter-run"),
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        run_identity="run:1",
        candidate_record_ids=(root.artifact_id,),
        specification_ids=tuple(item.artifact_id for item in specifications),
        validation_result_id=validation.artifact_id,
        input_artifact_ids=(root.artifact_id,) + tuple(
            item.artifact_id for item in specifications
        ),
    )
    repository.persist_static_adapter_run(run)
    path = PathEvidence(
        **artifact_fields("path"),
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        supported_adapter=True,
        source=PathLocation(location="app.py:1", symbol="request.args"),
        source_provenance=provenance("source-line"),
        propagation_steps=(PathLocation(location="app.py:2", symbol="query"),),
        sink=PathLocation(location="app.py:3", symbol="cursor.execute"),
        sanitizer_status=SanitizerStatus.ABSENT,
        static_evidence_identity="trace:1",
    )
    repository.persist_static_path(path, adapter_run_id=run.artifact_id)
    return validation, run, path


def test_generic_and_candidate_persistence_revalidates_canonical_utc_content(tmp_path):
    database = tmp_path / "repository.db"
    policy = AcceptancePolicy(
        **artifact_fields("policy"), conditions=("repository-evidence",)
    )
    root = candidate()

    with ArtifactRepository(database) as repository:
        assert repository.persist_artifact(policy) == policy
        assert repository.create_candidate(root) == root
        loaded = repository.load(root.artifact_id, CandidateRecord)

        assert loaded == root
        assert loaded.created_at == UTC_TIME
        assert loaded.provenance.retrieved_at == UTC_TIME
        row = repository.connection.execute(
            "SELECT canonical_payload, content_hash FROM ecatsl_artifact WHERE artifact_id = ?",
            (root.artifact_id,),
        ).fetchone()
        assert row == (root.canonical_json(), root.content_hash)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            repository.connection.execute(
                "UPDATE ecatsl_artifact SET version = 'changed' WHERE artifact_id = ?",
                (root.artifact_id,),
            )
        repository.connection.rollback()


def test_generic_persistence_rejects_every_projection_bearing_model(tmp_path):
    root = candidate()
    spec = specification(root)
    validation = ValidationResult(
        **artifact_fields("validation"), kind="NO_PATH", outcome="UNREACHABLE"
    )
    path = PathEvidence(
        **artifact_fields("path-bypass"),
        adapter_id="input-tracer",
        adapter_version="1",
        supported_adapter=True,
        source=PathLocation(location="a:1"),
        source_provenance=provenance("source"),
        propagation_steps=(PathLocation(location="a:2"),),
        sink=PathLocation(location="a:3"),
        sanitizer_status=SanitizerStatus.ABSENT,
        static_evidence_identity="manual",
    )
    artifacts = (
        root,
        Evidence(**artifact_fields("evidence"), evidence_kind="repository"),
        PolicyDecisionRecord(
            **artifact_fields("decision"),
            candidate_version_id=root.artifact_id,
            policy_kind="ACCEPTANCE",
            policy_version="1",
            outcome="ACCEPTED",
        ),
        validation,
        spec,
        path,
        StaticAdapterRun(
            **artifact_fields("run"),
            adapter_id="input-tracer",
            adapter_version="1",
            run_identity="run",
            candidate_record_ids=(root.artifact_id,),
            specification_ids=(spec.artifact_id,),
            validation_result_id=validation.artifact_id,
            input_artifact_ids=(root.artifact_id, spec.artifact_id),
        ),
        FindingClassification(
            **artifact_fields("confirmed-bypass"),
            status=FindingStatus.CONFIRMED,
            reason="self assertion",
            path_evidence_id=path.artifact_id,
        ),
        initial_scope(created_at=OFFSET_TIME, provenance=provenance("scope")),
        task_1_1_reuse_inventory(
            created_at=OFFSET_TIME, provenance=provenance("reuse")
        ),
        CatalogRecord(
            **artifact_fields("support"),
            record_type="CWE",
            canonical_identifier="CWE-89",
        ),
        AuditFailureRecord(
            **artifact_fields("failure"),
            operation="test",
            missing_element="x",
        ),
    )
    with ArtifactRepository(tmp_path / "bypass.db") as repository:
        for artifact in artifacts:
            with pytest.raises(UnsupportedArtifactTypeError, match="dedicated"):
                repository.persist_artifact(artifact)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_artifact"
        ).fetchone() == (0,)


def test_stale_candidate_predecessor_is_rejected_without_orphan_artifact(tmp_path):
    with ArtifactRepository(tmp_path / "stale.db") as repository:
        root = repository.create_candidate(candidate())
        current = candidate(version="2", predecessor_id=root.artifact_id, cause="evidence")
        repository.append_candidate(current, expected_predecessor_id=root.artifact_id)
        stale = candidate(
            version="2-stale", predecessor_id=root.artifact_id, cause="stale write"
        )

        with pytest.raises(StalePredecessorError):
            repository.append_candidate(stale, expected_predecessor_id=root.artifact_id)

        assert repository.connection.execute(
            "SELECT 1 FROM ecatsl_artifact WHERE artifact_id = ?", (stale.artifact_id,)
        ).fetchone() is None


def test_idempotent_replay_after_reopen_returns_prior_version_not_duplicate(tmp_path):
    database = tmp_path / "idempotent.db"
    with ArtifactRepository(database) as repository:
        root = repository.create_candidate(candidate(), idempotency_key="create-1")
        successor = candidate(
            version="2", predecessor_id=root.artifact_id, cause="new evidence"
        )
        first = repository.append_candidate(
            successor,
            expected_predecessor_id=root.artifact_id,
            idempotency_key="append-1",
        )

    with ArtifactRepository(database) as repository:
        replay = repository.append_candidate(
            successor,
            expected_predecessor_id=root.artifact_id,
            idempotency_key="append-1",
        )
        assert replay == first
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_candidate_version WHERE candidate_id = 'candidate-1'"
        ).fetchone() == (2,)

        changed = candidate(
            version="other", predecessor_id=root.artifact_id, cause="different request"
        )
        with pytest.raises(IdempotencyConflictError):
            repository.append_candidate(
                changed,
                expected_predecessor_id=root.artifact_id,
                idempotency_key="append-1",
            )


def test_policy_outcome_survives_optional_audit_failure_and_replay(tmp_path):
    database = tmp_path / "policy.db"
    root = candidate()
    successor = candidate(
        version="2",
        predecessor_id=root.artifact_id,
        state=CandidateState.ACCEPTED,
        cause="acceptance policy",
    )
    decision = PolicyDecisionRecord(
        **artifact_fields("policy-decision"),
        candidate_version_id=successor.artifact_id,
        policy_kind="ACCEPTANCE",
        policy_version="acceptance-1",
        outcome="ACCEPTED",
        audit_metadata=(Attribute(name="condition", value="static-evidence"),),
    )
    invalid_optional_failure = AuditFailureRecord(
        **artifact_fields("audit-failure"),
        related_artifact_id="sha256:" + "f" * 64,
        operation="policy_audit",
        missing_element="catalog_revision",
        failure_data=(Attribute(name="error", value="metadata unavailable"),),
    )

    with ArtifactRepository(database) as repository:
        repository.create_candidate(root)
        first = repository.persist_policy_outcome(
            decision,
            candidate=successor,
            expected_predecessor_id=root.artifact_id,
            audit_failures=(invalid_optional_failure,),
            idempotency_key="policy-1",
        )
        assert first.candidate is not None
        assert first.candidate.state is CandidateState.ACCEPTED
        assert first.candidate.missing_audit_elements == ("catalog_revision",)
        assert first.decision.outcome == "ACCEPTED"
        assert first.decision.missing_audit_elements == ("catalog_revision",)
        assert first.failures[0].related_artifact_id == first.decision.artifact_id

    with ArtifactRepository(database) as repository:
        replay = repository.persist_policy_outcome(
            decision,
            candidate=successor,
            expected_predecessor_id=root.artifact_id,
            audit_failures=(invalid_optional_failure,),
            idempotency_key="policy-1",
        )
        assert replay == first
        assert repository.connection.execute(
            "SELECT outcome, missing_audit_elements_json FROM ecatsl_policy_decision"
        ).fetchone() == ("ACCEPTED", '["catalog_revision"]')
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_audit_failure"
        ).fetchone() == (1,)


def test_validation_and_counterexample_are_retained_together(tmp_path):
    with ArtifactRepository(tmp_path / "validation.db") as repository:
        root = repository.create_candidate(candidate())
        validation = ValidationResult(
            **artifact_fields("validation"),
            kind="NO_PATH",
            outcome="UNREACHABLE",
            adapter_id="input-tracer",
            adapter_version="1",
            linked_artifact_ids=(root.artifact_id,),
        )
        counterexample = Counterexample(
            **artifact_fields("counterexample"),
            evidence_kind="STATIC_NO_PATH",
            payload=(Attribute(name="sink", value="cursor.execute"),),
            contradicts="candidate taint role",
        )

        result = repository.retain_validation(
            root.artifact_id, validation, counterexamples=(counterexample,)
        )

        assert result.validation == validation
        assert result.counterexamples == (counterexample,)
        assert repository.connection.execute(
            "SELECT candidate_version_id, result_kind FROM ecatsl_validation_result"
        ).fetchone() == (root.artifact_id, "NO_PATH")


def test_authorized_path_and_classification_retain_complete_typed_lineage(tmp_path):
    with ArtifactRepository(tmp_path / "classification.db") as repository:
        root = repository.create_candidate(candidate())
        specs = (specification(root, "spec-1"), specification(root, "spec-2"))
        for item in specs:
            repository.persist_specification(item)
        validation, run, path = retained_static_path(repository, root, specs)
        supports = (
            CatalogRecord(
                **artifact_fields("catalog-1"),
                record_type="CWE",
                canonical_identifier="CWE-89",
            ),
            CatalogRecord(
                **artifact_fields("catalog-2"),
                record_type="CVE",
                canonical_identifier="CVE-2026-1",
            ),
        )
        for support in supports:
            repository.persist_explanatory_support(support)
        classification = FindingClassification(
            **artifact_fields("classification"),
            status=FindingStatus.CONFIRMED,
            reason="complete supported static path",
            path_evidence_id=path.artifact_id,
            candidate_record_ids=(root.artifact_id,),
            specification_ids=tuple(item.artifact_id for item in specs),
            validation_result_ids=(validation.artifact_id,),
            explanatory_support_ids=tuple(item.artifact_id for item in supports),
        )

        result = repository.persist_classification(classification)

        assert result.classification == classification
        assert result.failures == ()
        assert repository.connection.execute(
            "SELECT specification_artifact_id FROM ecatsl_finding_specification ORDER BY rowid"
        ).fetchall() == [(item.artifact_id,) for item in specs]
        assert repository.connection.execute(
            "SELECT explanatory_support_artifact_id "
            "FROM ecatsl_finding_explanatory_support ORDER BY rowid"
        ).fetchall() == [(item.artifact_id,) for item in supports]
        assert repository.connection.execute(
            "SELECT adapter_run_artifact_id FROM ecatsl_path_evidence"
        ).fetchone() == (run.artifact_id,)


def test_self_asserted_path_and_adapter_identity_mismatches_cannot_confirm(tmp_path):
    with ArtifactRepository(tmp_path / "path-boundary.db") as repository:
        root = repository.create_candidate(candidate())
        spec = repository.persist_specification(specification(root))
        validation = ValidationResult(
            **artifact_fields("validation"),
            kind="STATIC_PATH",
            outcome="PATH_FOUND",
            adapter_id="unknown",
            adapter_version="9",
            linked_artifact_ids=(root.artifact_id, spec.artifact_id),
        )
        repository.retain_validation(root.artifact_id, validation)
        unknown_run = StaticAdapterRun(
            **artifact_fields("unknown-run"),
            adapter_id="unknown",
            adapter_version="9",
            run_identity="run:unknown",
            candidate_record_ids=(root.artifact_id,),
            specification_ids=(spec.artifact_id,),
            validation_result_id=validation.artifact_id,
            input_artifact_ids=(root.artifact_id, spec.artifact_id),
        )
        with pytest.raises(LineageError, match="unsupported static adapter"):
            repository.persist_static_adapter_run(unknown_run)

        good_validation = ValidationResult(
            **artifact_fields("good-validation"),
            kind="STATIC_PATH",
            outcome="PATH_FOUND",
            adapter_id="input-tracer",
            adapter_version="1",
            linked_artifact_ids=(root.artifact_id, spec.artifact_id),
        )
        repository.retain_validation(root.artifact_id, good_validation)
        run = StaticAdapterRun(
            **artifact_fields("good-run"),
            adapter_id="input-tracer",
            adapter_version="1",
            run_identity="run:good",
            candidate_record_ids=(root.artifact_id,),
            specification_ids=(spec.artifact_id,),
            validation_result_id=good_validation.artifact_id,
            input_artifact_ids=(root.artifact_id, spec.artifact_id),
        )
        repository.persist_static_adapter_run(run)
        mismatched_path = PathEvidence(
            **artifact_fields("mismatch"),
            adapter_id="input-tracer",
            adapter_version="2",
            supported_adapter=True,
            source=PathLocation(location="a:1"),
            source_provenance=provenance("source"),
            propagation_steps=(PathLocation(location="a:2"),),
            sink=PathLocation(location="a:3"),
            sanitizer_status=SanitizerStatus.ABSENT,
            static_evidence_identity="manual",
        )
        with pytest.raises(LineageError, match="does not match"):
            repository.persist_static_path(mismatched_path, adapter_run_id=run.artifact_id)

        manual = mismatched_path.model_copy(
            update={"adapter_version": "1", "provenance": provenance("manual")}
        )
        with repository._atomic():
            repository._insert_artifact(manual)
        classification = FindingClassification(
            **artifact_fields("manual-confirmation"),
            status=FindingStatus.CONFIRMED,
            reason="manual path",
            path_evidence_id=manual.artifact_id,
            candidate_record_ids=(root.artifact_id,),
            specification_ids=(spec.artifact_id,),
            validation_result_ids=(good_validation.artifact_id,),
        )
        with pytest.raises(LineageError, match="authorized static-path binding"):
            repository.persist_classification(classification)


def test_classification_survives_missing_optional_lineage_and_replay(tmp_path):
    database = tmp_path / "missing-lineage.db"
    root = candidate()
    missing_spec = "sha256:" + "a" * 64
    missing_validation = "sha256:" + "b" * 64
    missing_support = "sha256:" + "c" * 64
    classification = FindingClassification(
        **artifact_fields("partial-classification"),
        status=FindingStatus.UNCONFIRMED,
        reason="no static path",
        candidate_record_ids=(root.artifact_id,),
        specification_ids=(missing_spec,),
        validation_result_ids=(missing_validation,),
        explanatory_support_ids=(missing_support,),
    )
    with ArtifactRepository(database) as repository:
        repository.create_candidate(root)
        first = repository.persist_classification(
            classification, idempotency_key="classification-1"
        )
        assert first.classification.status is FindingStatus.UNCONFIRMED
        assert first.classification.missing_metadata == (
            f"specification:{missing_spec}",
            f"validation_result:{missing_validation}",
            f"explanatory_support:{missing_support}",
        )
        assert tuple(item.missing_element for item in first.failures) == (
            first.classification.missing_metadata
        )

    with ArtifactRepository(database) as repository:
        replay = repository.persist_classification(
            classification, idempotency_key="classification-1"
        )
        assert replay == first
        assert repository.load(
            first.classification.artifact_id, FindingClassification
        ).status is FindingStatus.UNCONFIRMED
        assert repository.connection.execute(
            "SELECT missing_element FROM ecatsl_finding_missing_metadata ORDER BY rowid"
        ).fetchall() == [(item,) for item in first.classification.missing_metadata]


def test_finding_lineage_rejects_wrong_kinds_and_cross_candidate_links(tmp_path):
    with ArtifactRepository(tmp_path / "typed-lineage.db") as repository:
        first = repository.create_candidate(candidate("candidate-a"))
        second = repository.create_candidate(candidate("candidate-b"))
        second_spec = repository.persist_specification(
            specification(second, "second-spec")
        )
        policy = repository.persist_artifact(
            AcceptancePolicy(**artifact_fields("policy"), conditions=("x",))
        )
        wrong_kind = FindingClassification(
            **artifact_fields("wrong-kind"),
            status=FindingStatus.UNCONFIRMED,
            reason="bad metadata",
            candidate_record_ids=(first.artifact_id,),
            specification_ids=(policy.artifact_id,),
        )
        with pytest.raises(LineageError, match="wrong artifact kind"):
            repository.persist_classification(wrong_kind)

        crossed = FindingClassification(
            **artifact_fields("crossed"),
            status=FindingStatus.UNCONFIRMED,
            reason="crossed metadata",
            candidate_record_ids=(first.artifact_id,),
            specification_ids=(second_spec.artifact_id,),
        )
        with pytest.raises(LineageError, match="crosses candidate"):
            repository.persist_classification(crossed)


def test_scope_and_reuse_revisions_persist_predecessor_lineage(tmp_path):
    with ArtifactRepository(tmp_path / "scope-reuse.db") as repository:
        scope_v1 = initial_scope(created_at=OFFSET_TIME, provenance=provenance("scope-v1"))
        repository.persist_scope_revision(scope_v1, idempotency_key="scope-1")
        scope_v2 = revise_scope(
            scope_v1,
            language="python",
            cwe_ids=INITIAL_CWES[:2],
            provenance=provenance("scope-v2"),
            created_at=OFFSET_TIME,
        )
        repository.persist_scope_revision(
            scope_v2,
            expected_predecessor_id=scope_v1.artifact_id,
            idempotency_key="scope-2",
        )

        reuse_v1 = task_1_1_reuse_inventory(
            created_at=OFFSET_TIME, provenance=provenance("reuse-v1")
        )
        repository.persist_reuse_revision(reuse_v1)
        reuse_v2 = reuse_v1.model_copy(
            update={
                "version": "1.1.2",
                "predecessor_id": reuse_v1.artifact_id,
                "created_at": OFFSET_TIME,
                "provenance": provenance("reuse-v2"),
            }
        )
        repository.persist_reuse_revision(
            reuse_v2, expected_predecessor_id=reuse_v1.artifact_id
        )

        assert repository.connection.execute(
            "SELECT scope_version, predecessor_id FROM ecatsl_scope_version ORDER BY rowid"
        ).fetchall() == [("1", None), ("2", scope_v1.artifact_id)]
        assert repository.connection.execute(
            "SELECT inventory_version, predecessor_id "
            "FROM ecatsl_reuse_inventory_version ORDER BY rowid"
        ).fetchall() == [("1.1.1", None), ("1.1.2", reuse_v1.artifact_id)]


def test_closed_registry_rejects_unknown_type_and_corrupted_rows(tmp_path):
    database = tmp_path / "registry.db"
    policy = AcceptancePolicy(**artifact_fields("policy"), conditions=("x",))
    with ArtifactRepository(database) as repository:
        repository.persist_artifact(policy)
        repository.connection.execute("DROP TRIGGER ecatsl_artifact_reject_update")
        repository.connection.execute(
            "UPDATE ecatsl_artifact SET artifact_type = 'evil.module:Payload' "
            "WHERE artifact_id = ?",
            (policy.artifact_id,),
        )
        repository.connection.commit()
        with pytest.raises(UnsupportedArtifactTypeError, match="unknown"):
            repository.load(policy.artifact_id)

    corrupt_database = tmp_path / "corrupt-payload.db"
    with ArtifactRepository(corrupt_database) as repository:
        repository.persist_artifact(policy)
        repository.connection.execute("DROP TRIGGER ecatsl_artifact_reject_update")
        repository.connection.execute(
            "UPDATE ecatsl_artifact SET canonical_payload = '{}' WHERE artifact_id = ?",
            (policy.artifact_id,),
        )
        repository.connection.commit()
        with pytest.raises(ImmutableArtifactError, match="payload is invalid"):
            repository.load(policy.artifact_id)


def test_corrupted_idempotency_result_list_is_rejected(tmp_path):
    database = tmp_path / "corrupt-replay.db"
    policy = AcceptancePolicy(**artifact_fields("policy"), conditions=("x",))
    with ArtifactRepository(database) as repository:
        repository.persist_artifact(policy, idempotency_key="policy")
        repository.connection.execute("DROP TRIGGER ecatsl_idempotency_key_reject_update")
        repository.connection.execute(
            "UPDATE ecatsl_idempotency_key SET result_artifact_ids_json = '{}'"
        )
        repository.connection.commit()
        with pytest.raises(ImmutableArtifactError, match="result list"):
            repository.persist_artifact(policy, idempotency_key="policy")


def test_idempotency_replay_rejects_valid_same_type_artifact_substitution(tmp_path):
    database = tmp_path / "substituted-replay.db"
    requested = AcceptancePolicy(**artifact_fields("requested"), conditions=("x",))
    substitute = AcceptancePolicy(**artifact_fields("substitute"), conditions=("y",))
    with ArtifactRepository(database) as repository:
        repository.persist_artifact(requested, idempotency_key="policy")
        repository.persist_artifact(substitute)
        repository.connection.execute("DROP TRIGGER ecatsl_idempotency_key_reject_update")
        repository.connection.execute(
            "UPDATE ecatsl_idempotency_key SET result_artifact_ids_json = ?",
            ('["' + substitute.artifact_id + '"]',),
        )
        repository.connection.commit()
        with pytest.raises(ImmutableArtifactError, match="result identities"):
            repository.persist_artifact(requested, idempotency_key="policy")


def test_explicit_creation_failure_record_is_persisted(tmp_path):
    with ArtifactRepository(tmp_path / "failure.db") as repository:
        failure = AuditFailureRecord(
            **artifact_fields("candidate-create-failure"),
            operation="candidate_creation",
            missing_element="candidate_record",
            failure_data=(Attribute(name="error", value="validation failed"),),
        )
        assert repository.record_creation_failure(failure) == failure
        assert repository.connection.execute(
            "SELECT operation, missing_element FROM ecatsl_audit_failure"
        ).fetchone() == ("candidate_creation", "candidate_record")


def _concurrent_config(*, interrupted_after_seconds=30.0):
    return ArtifactRepositoryConfig(
        sqlite_write=SQLiteWriteConfig(
            busy_timeout_ms=10,
            lock_retry_attempts=20,
            lock_retry_initial_seconds=0.002,
            lock_retry_max_seconds=0.02,
        ),
        interrupted_after_seconds=interrupted_after_seconds,
    )


def test_concurrent_compare_and_append_has_one_winner_and_explicit_conflict(tmp_path):
    database = tmp_path / "concurrent-append.db"
    with ArtifactRepository(database) as repository:
        root = repository.create_candidate(candidate())

    successors = (
        candidate(
            version="2-a", predecessor_id=root.artifact_id,
            confidence=0.6, cause="writer-a"
        ),
        candidate(
            version="2-b", predecessor_id=root.artifact_id,
            confidence=0.7, cause="writer-b"
        ),
    )
    barrier = threading.Barrier(2)
    results = []
    errors = []
    result_lock = threading.Lock()

    def write(successor):
        try:
            with ArtifactRepository(database, config=_concurrent_config()) as repository:
                barrier.wait(timeout=5)
                result = repository.compare_and_append_candidate(
                    successor,
                    expected_predecessor_id=root.artifact_id,
                    idempotency_key=f"append-{successor.version}",
                )
            with result_lock:
                results.append(result)
        except BaseException as error:  # preserve worker failures for the main test
            with result_lock:
                errors.append(error)

    threads = [threading.Thread(target=write, args=(item,)) for item in successors]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert sorted(result.status.value for result in results) == ["APPENDED", "CONFLICT"]
    conflict = next(
        result for result in results
        if result.status is CompareAndAppendStatus.CONFLICT
    )
    winner = next(
        result for result in results
        if result.status is CompareAndAppendStatus.APPENDED
    )
    assert winner.record is not None
    assert conflict.actual_head_id == winner.record.artifact_id
    with ArtifactRepository(database) as repository:
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_candidate_version WHERE candidate_id = ?",
            (root.candidate_id,),
        ).fetchone() == (2,)


def test_bounded_lock_retry_waits_for_separate_writer_then_commits(tmp_path):
    database = tmp_path / "lock-retry.db"
    policy = AcceptancePolicy(**artifact_fields("lock-policy"), conditions=("x",))
    with ArtifactRepository(database, config=_concurrent_config()):
        pass
    locker = sqlite3.connect(database, timeout=0)
    errors = []
    try:
        locker.execute("BEGIN IMMEDIATE")

        def persist():
            try:
                with ArtifactRepository(database, config=_concurrent_config()) as repository:
                    repository.persist_artifact(policy, idempotency_key="lock-policy")
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=persist)
        thread.start()
        time.sleep(0.06)
        locker.rollback()
        thread.join(timeout=10)

        assert not thread.is_alive()
        assert errors == []
        with ArtifactRepository(database) as repository:
            assert repository.load(policy.artifact_id, AcceptancePolicy) == policy
            assert repository.transaction_state(
                "persist_artifact", "lock-policy"
            ).state is TransactionState.COMMITTED
    finally:
        if locker.in_transaction:
            locker.rollback()
        locker.close()


def test_interrupted_operation_recovers_and_idempotently_replays_after_restart(tmp_path):
    database = tmp_path / "interrupted-operation.db"
    root = candidate()
    fired = False

    def interrupt_once(point, _transaction_id):
        nonlocal fired
        if point == "transaction.after_started" and not fired:
            fired = True
            raise RepositoryTestInterruption("simulated process loss")

    repository = ArtifactRepository.for_testing(
        database,
        failure_hook=interrupt_once,
        config=_concurrent_config(interrupted_after_seconds=0),
    )
    try:
        with pytest.raises(RepositoryTestInterruption):
            repository.create_candidate(root, idempotency_key="restart-create")
        assert repository.transaction_state(
            "create_candidate", "restart-create"
        ).state is TransactionState.STARTED
    finally:
        repository.close()

    with ArtifactRepository(
        database, config=_concurrent_config(interrupted_after_seconds=0)
    ) as recovered:
        assert recovered.transaction_state(
            "create_candidate", "restart-create"
        ).state is TransactionState.INTERRUPTED
        assert recovered.create_candidate(
            root, idempotency_key="restart-create"
        ) == root
        assert recovered.transaction_state(
            "create_candidate", "restart-create"
        ).state is TransactionState.COMMITTED

    with ArtifactRepository(database, config=_concurrent_config()) as replay_repository:
        assert replay_repository.create_candidate(
            root, idempotency_key="restart-create"
        ) == root
        assert replay_repository.transaction_state(
            "create_candidate", "restart-create"
        ).state is TransactionState.COMMITTED
        assert replay_repository.connection.execute(
            "SELECT state FROM ecatsl_transaction_event "
            "WHERE transaction_id = ("
            "SELECT transaction_id FROM ecatsl_transaction "
            "WHERE operation = 'create_candidate' AND idempotency_key = 'restart-create'"
            ") ORDER BY sequence"
        ).fetchall() == [
            ("STARTED",),
            ("INTERRUPTED",),
            ("STARTED",),
            ("COMMITTED",),
            ("STARTED",),
            ("REPLAYED",),
        ]
        assert replay_repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_candidate_version"
        ).fetchone() == (1,)


def test_failed_operation_is_journaled_and_same_logical_request_can_retry(tmp_path):
    database = tmp_path / "failed-retry.db"
    root = candidate()
    spec = specification(root, "failed-then-retried")
    with ArtifactRepository(database) as repository:
        with pytest.raises(LineageError):
            repository.persist_specification(spec, idempotency_key="spec-retry")
        assert repository.transaction_state(
            "persist_specification", "spec-retry"
        ).state is TransactionState.FAILED

        repository.create_candidate(root)
        assert repository.persist_specification(
            spec, idempotency_key="spec-retry"
        ) == spec
        assert repository.transaction_state(
            "persist_specification", "spec-retry"
        ).state is TransactionState.COMMITTED
        assert repository.connection.execute(
            "SELECT state FROM ecatsl_transaction_event WHERE transaction_id = ("
            "SELECT transaction_id FROM ecatsl_transaction "
            "WHERE operation = 'persist_specification' AND idempotency_key = 'spec-retry'"
            ") ORDER BY sequence"
        ).fetchall() == [
            ("STARTED",), ("FAILED",), ("STARTED",), ("COMMITTED",)
        ]


def test_test_only_optional_audit_failure_preserves_policy_outcome_with_exact_flags(tmp_path):
    database = tmp_path / "policy-optional-failure.db"
    root = candidate()
    successor = candidate(
        version="2",
        predecessor_id=root.artifact_id,
        state=CandidateState.ACCEPTED,
        cause="acceptance policy",
    )
    decision = PolicyDecisionRecord(
        **artifact_fields("injected-policy-decision"),
        candidate_version_id=successor.artifact_id,
        policy_kind="ACCEPTANCE",
        policy_version="acceptance-1",
        outcome="ACCEPTED",
        audit_metadata=(Attribute(name="catalog_revision", value="rev-1"),),
    )

    def fail_optional(point, _transaction_id):
        if point == "policy.optional_audit_metadata":
            raise OptionalMetadataPersistenceError(
                "catalog_revision", "transformation_history"
            )

    with ArtifactRepository.for_testing(
        database, failure_hook=fail_optional
    ) as repository:
        repository.create_candidate(root)
        result = repository.persist_policy_outcome(
            decision,
            candidate=successor,
            expected_predecessor_id=root.artifact_id,
            idempotency_key="policy-optional",
        )
        assert result.candidate is not None
        assert result.candidate.state is CandidateState.ACCEPTED
        assert result.candidate.missing_audit_elements == (
            "catalog_revision", "transformation_history"
        )
        assert result.decision.outcome == "ACCEPTED"
        assert result.decision.missing_audit_elements == (
            "catalog_revision", "transformation_history"
        )
        assert tuple(item.missing_element for item in result.failures) == (
            "catalog_revision", "transformation_history"
        )

    with ArtifactRepository(database) as repository:
        replay = repository.persist_policy_outcome(
            decision,
            candidate=successor,
            expected_predecessor_id=root.artifact_id,
            idempotency_key="policy-optional",
        )
        assert replay == result
        assert repository.transaction_state(
            "persist_policy_outcome", "policy-optional"
        ).state is TransactionState.COMMITTED


def test_test_only_classification_metadata_failure_preserves_decision_and_replays(tmp_path):
    database = tmp_path / "classification-optional-failure.db"
    classification = FindingClassification(
        **artifact_fields("classification-audit-failure"),
        status=FindingStatus.UNCONFIRMED,
        reason="no qualifying static path",
    )

    def fail_optional(point, _transaction_id):
        if point == "classification.optional_audit_metadata":
            raise OptionalMetadataPersistenceError(
                "candidate_snapshot", "review_context"
            )

    with ArtifactRepository.for_testing(
        database, failure_hook=fail_optional
    ) as repository:
        result = repository.persist_classification(
            classification, idempotency_key="classification-optional"
        )
        assert result.classification.status is FindingStatus.UNCONFIRMED
        assert result.classification.missing_metadata == (
            "candidate_snapshot", "review_context"
        )
        assert tuple(item.missing_element for item in result.failures) == (
            "candidate_snapshot", "review_context"
        )

    with ArtifactRepository(database) as repository:
        replay = repository.persist_classification(
            classification, idempotency_key="classification-optional"
        )
        assert replay == result
        assert repository.transaction_state(
            "persist_classification", "classification-optional"
        ).state is TransactionState.COMMITTED


def _abrupt_exit_after_writer(database):
    def exit_process(point, _invocation_id):
        if point == "transaction.after_writer_acquired":
            os._exit(17)

    repository = ArtifactRepository.for_testing(
        database,
        failure_hook=exit_process,
        config=_concurrent_config(interrupted_after_seconds=0),
    )
    repository.create_candidate(candidate(), idempotency_key="abrupt-create")


def test_inflight_base_exception_rolls_back_writer_and_retains_started_attempt(tmp_path):
    database = tmp_path / "base-exception-after-writer.db"
    root = candidate()
    fired = False

    def interrupt_after_writer(point, _invocation_id):
        nonlocal fired
        if point == "transaction.after_writer_acquired" and not fired:
            fired = True
            raise RepositoryTestInterruption("cancel after writer acquisition")

    repository = ArtifactRepository.for_testing(
        database,
        failure_hook=interrupt_after_writer,
        config=_concurrent_config(interrupted_after_seconds=0),
    )
    try:
        with pytest.raises(RepositoryTestInterruption):
            repository.create_candidate(root, idempotency_key="inflight-create")
        assert not repository.connection.in_transaction
        state = repository.transaction_state("create_candidate", "inflight-create")
        assert state is not None
        assert state.state is TransactionState.STARTED
        assert state.latest_attempt_state is TransactionState.STARTED

        independent = sqlite3.connect(database, timeout=0)
        try:
            independent.execute("BEGIN IMMEDIATE")
            independent.rollback()
        finally:
            independent.close()
    finally:
        repository.close()

    with ArtifactRepository(
        database, config=_concurrent_config(interrupted_after_seconds=0)
    ) as recovered:
        state = recovered.transaction_state("create_candidate", "inflight-create")
        assert state is not None
        assert state.state is TransactionState.INTERRUPTED
        assert recovered.create_candidate(
            root, idempotency_key="inflight-create"
        ) == root


def test_subprocess_abrupt_exit_releases_lock_and_recovers_owned_attempt(tmp_path):
    database = tmp_path / "abrupt-process.db"
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_abrupt_exit_after_writer, args=(database,))
    process.start()
    process.join(timeout=20)
    assert not process.is_alive()
    assert process.exitcode == 17

    with ArtifactRepository(
        database, config=_concurrent_config(interrupted_after_seconds=0)
    ) as repository:
        state = repository.transaction_state("create_candidate", "abrupt-create")
        assert state is not None
        assert state.state is TransactionState.INTERRUPTED
        assert repository.create_candidate(
            candidate(), idempotency_key="abrupt-create"
        ) == candidate()


def test_concurrent_constructor_does_not_interrupt_live_attempt(tmp_path):
    database = tmp_path / "live-owner.db"
    started = threading.Event()
    release = threading.Event()
    errors = []

    def pause_after_started(point, _invocation_id):
        if point == "transaction.after_started":
            started.set()
            assert release.wait(timeout=10)

    def write():
        try:
            with ArtifactRepository.for_testing(
                database,
                failure_hook=pause_after_started,
                config=_concurrent_config(interrupted_after_seconds=0),
            ) as repository:
                repository.create_candidate(
                    candidate(), idempotency_key="live-create"
                )
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=write)
    thread.start()
    assert started.wait(timeout=10)
    with ArtifactRepository(
        database, config=_concurrent_config(interrupted_after_seconds=0)
    ) as observer:
        state = observer.transaction_state("create_candidate", "live-create")
        assert state is not None
        assert state.state is TransactionState.STARTED
        assert state.latest_attempt_state is TransactionState.STARTED
    release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert errors == []
    with ArtifactRepository(database) as repository:
        assert repository.transaction_state(
            "create_candidate", "live-create"
        ).state is TransactionState.COMMITTED


def test_replay_failure_is_attempt_local_and_policy_result_is_semantically_bound(tmp_path):
    database = tmp_path / "policy-replay-isolation.db"
    root = candidate()
    first_decision = PolicyDecisionRecord(
        **artifact_fields("first-policy-result"),
        candidate_version_id=root.artifact_id,
        policy_kind="ACCEPTANCE",
        policy_version="acceptance-1",
        outcome="ACCEPTED",
        input_artifact_ids=(),
        audit_metadata=(Attribute(name="basis", value="first"),),
    )
    substitute_decision = PolicyDecisionRecord(
        **artifact_fields("substitute-policy-result"),
        candidate_version_id=root.artifact_id,
        policy_kind="VALIDATION",
        policy_version="validation-9",
        outcome="REJECTED",
        input_artifact_ids=(),
        audit_metadata=(Attribute(name="basis", value="substitute"),),
    )
    with ArtifactRepository(database) as repository:
        repository.create_candidate(root)
        committed = repository.persist_policy_outcome(
            first_decision, idempotency_key="policy-first"
        )
        substitute = repository.persist_policy_outcome(
            substitute_decision, idempotency_key="policy-substitute"
        )
        repository.connection.execute(
            "DROP TRIGGER ecatsl_idempotency_key_reject_update"
        )
        repository.connection.execute(
            """
            UPDATE ecatsl_idempotency_key
            SET result_artifact_ids_json = ?
            WHERE operation = 'persist_policy_outcome'
              AND idempotency_key = 'policy-first'
            """,
            (_canonical_result_ids(substitute),),
        )
        repository.connection.commit()

        with pytest.raises(ImmutableArtifactError, match="policy kind, version, outcome"):
            repository.persist_policy_outcome(
                first_decision, idempotency_key="policy-first"
            )

        state = repository.transaction_state(
            "persist_policy_outcome", "policy-first"
        )
        assert state is not None
        assert state.state is TransactionState.COMMITTED
        assert state.latest_attempt_state is TransactionState.FAILED
        assert repository.load(
            committed.decision.artifact_id, PolicyDecisionRecord
        ) == committed.decision


def _canonical_result_ids(result):
    import json

    artifacts = ((result.candidate,) if result.candidate is not None else ())
    artifacts += (result.decision,) + result.failures
    return json.dumps(
        [item.artifact_id for item in artifacts],
        sort_keys=True,
        separators=(",", ":"),
    )


def test_no_key_writes_do_not_create_retry_journal_rows(tmp_path):
    with ArtifactRepository(tmp_path / "no-key.db") as repository:
        root = repository.create_candidate(candidate())
        repository.persist_artifact(
            AcceptancePolicy(**artifact_fields("no-key-policy"), conditions=("x",))
        )
        repository.persist_specification(specification(root, "no-key-spec"))
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_transaction"
        ).fetchone() == (0,)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_transaction_attempt"
        ).fetchone() == (0,)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_transaction_event"
        ).fetchone() == (0,)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_transaction_result"
        ).fetchone() == (0,)


def test_compare_and_append_replay_returns_all_committed_result_fields(tmp_path):
    database = tmp_path / "compare-replay-fields.db"
    with ArtifactRepository(database) as repository:
        root = repository.create_candidate(candidate())
        successor = candidate(
            version="2",
            predecessor_id=root.artifact_id,
            confidence=0.8,
            cause="new evidence",
        )
        appended = repository.compare_and_append_candidate(
            successor,
            expected_predecessor_id=root.artifact_id,
            idempotency_key="append-fields",
        )
        replayed = repository.compare_and_append_candidate(
            successor,
            expected_predecessor_id=root.artifact_id,
            idempotency_key="append-fields",
        )

        assert appended.status is CompareAndAppendStatus.APPENDED
        assert appended.record == successor
        assert appended.expected_head_id == root.artifact_id
        assert appended.actual_head_id == successor.artifact_id
        assert appended.replayed is False
        assert replayed.status is CompareAndAppendStatus.REPLAYED
        assert replayed.record == successor
        assert replayed.expected_head_id == root.artifact_id
        assert replayed.actual_head_id == successor.artifact_id
        assert replayed.replayed is True


@pytest.mark.parametrize("legacy_version", [2, 3, 4])
def test_legacy_committed_idempotency_replay_remains_logically_committed(
    tmp_path, legacy_version
):
    import json

    database = tmp_path / f"legacy-v{legacy_version}-idempotency.db"
    policy = AcceptancePolicy(
        **artifact_fields(f"legacy-policy-v{legacy_version}"), conditions=("x",)
    )
    request_hash = _request_hash(policy)
    connection = sqlite3.connect(database)
    try:
        assert install_ecatsl_schema(
            connection, migrations=MIGRATIONS[:legacy_version]
        ) == legacy_version
        connection.execute(
            """
            INSERT INTO ecatsl_artifact
                (artifact_id, artifact_type, version, content_hash,
                 canonical_payload, created_at, predecessor_id)
            VALUES (?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                policy.artifact_id,
                "src.ecatsl.models:AcceptancePolicy",
                policy.version,
                policy.content_hash,
                policy.canonical_json(),
                policy.created_at.isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO ecatsl_idempotency_key
                (operation, idempotency_key, request_hash,
                 result_artifact_ids_json, committed_at)
            VALUES ('persist_artifact', 'legacy-policy', ?, ?,
                    '2026-01-01T00:00:00+00:00')
            """,
            (request_hash, json.dumps([policy.artifact_id])),
        )
        connection.commit()
        assert install_ecatsl_schema(connection) == len(MIGRATIONS)
        assert connection.execute(
            "SELECT transaction_id FROM ecatsl_idempotency_key"
        ).fetchone() == (None,)
    finally:
        connection.close()

    with ArtifactRepository(database) as repository:
        assert repository.persist_artifact(
            policy, idempotency_key="legacy-policy"
        ) == policy
        replayed = repository.transaction_state(
            "persist_artifact", "legacy-policy"
        )
        assert replayed is not None
        assert replayed.state is TransactionState.COMMITTED
        assert replayed.latest_attempt_state is TransactionState.REPLAYED

        repository.connection.execute(
            "DROP TRIGGER ecatsl_idempotency_key_reject_update"
        )
        repository.connection.execute(
            "UPDATE ecatsl_idempotency_key "
            "SET result_artifact_ids_json = ?",
            ('["sha256:' + 'f' * 64 + '"]',),
        )
        repository.connection.commit()
        with pytest.raises(ImmutableArtifactError, match="result identities"):
            repository.persist_artifact(policy, idempotency_key="legacy-policy")

        failed_replay = repository.transaction_state(
            "persist_artifact", "legacy-policy"
        )
        assert failed_replay is not None
        assert failed_replay.state is TransactionState.COMMITTED
        assert failed_replay.latest_attempt_state is TransactionState.FAILED


def test_duplicate_policy_failure_elements_are_rejected_before_first_write_and_replay(
    tmp_path,
):
    database = tmp_path / "duplicate-policy-failures.db"
    root = candidate()
    decision = PolicyDecisionRecord(
        **artifact_fields("duplicate-failure-decision"),
        candidate_version_id=root.artifact_id,
        policy_kind="ACCEPTANCE",
        policy_version="acceptance-1",
        outcome="UNACCEPTED",
    )
    failures = (
        AuditFailureRecord(
            **artifact_fields("duplicate-failure-a"),
            operation="policy_audit",
            missing_element="catalog_revision",
            failure_data=(Attribute(name="error", value="first"),),
        ),
        AuditFailureRecord(
            **artifact_fields("duplicate-failure-b"),
            operation="policy_audit",
            missing_element="catalog_revision",
            failure_data=(Attribute(name="error", value="second"),),
        ),
    )
    with ArtifactRepository(database) as repository:
        repository.create_candidate(root)
        before = repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_artifact"
        ).fetchone()
        for _ in range(2):
            with pytest.raises(ValueError, match="unique missing_element"):
                repository.persist_policy_outcome(
                    decision,
                    audit_failures=failures,
                    idempotency_key="duplicate-failures",
                )
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_artifact"
        ).fetchone() == before
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_policy_decision"
        ).fetchone() == (0,)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_audit_failure"
        ).fetchone() == (0,)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_idempotency_key"
        ).fetchone() == (0,)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_transaction"
        ).fetchone() == (0,)


def test_unknown_process_liveness_never_recovers_attempt_but_confirmed_death_does(
    tmp_path,
):
    database = tmp_path / "unknown-owner-liveness.db"
    with ArtifactRepository(database) as repository:
        repository.connection.execute(
            """
            INSERT INTO ecatsl_transaction
                (transaction_id, operation, idempotency_key, request_hash, started_at)
            VALUES ('tx:unknown-owner', 'unknown_owner', 'unknown-key', ?,
                    '2026-01-01T00:00:00+00:00')
            """,
            ("d" * 64,),
        )
        repository.connection.execute(
            """
            INSERT INTO ecatsl_transaction_attempt
                (attempt_id, transaction_id, owner_pid, owner_token, started_at)
            VALUES ('attempt:unknown-owner', 'tx:unknown-owner', 424242,
                    'foreign-process-token', '2026-01-01T00:00:00+00:00')
            """
        )
        repository.connection.execute(
            """
            INSERT INTO ecatsl_transaction_event
                (transaction_id, sequence, state, occurred_at, attempt_id)
            VALUES ('tx:unknown-owner', 1, 'STARTED',
                    '2026-01-01T00:00:00+00:00', 'attempt:unknown-owner')
            """
        )
        repository.connection.commit()

    with ArtifactRepository.for_testing(
        database,
        failure_hook=lambda _point, _transaction_id: None,
        process_probe=lambda _pid: ProcessLiveness.UNKNOWN,
        config=_concurrent_config(interrupted_after_seconds=0),
    ) as unknown:
        state = unknown.transaction_state("unknown_owner", "unknown-key")
        assert state is not None
        assert state.state is TransactionState.STARTED
        assert unknown.recover_interrupted_transactions(
            stale_after_seconds=0
        ) == ()

    with ArtifactRepository.for_testing(
        database,
        failure_hook=lambda _point, _transaction_id: None,
        process_probe=lambda _pid: ProcessLiveness.DEAD,
        config=_concurrent_config(interrupted_after_seconds=0),
    ) as dead:
        state = dead.transaction_state("unknown_owner", "unknown-key")
        assert state is not None
        assert state.state is TransactionState.INTERRUPTED
        assert state.latest_attempt_state is TransactionState.INTERRUPTED
