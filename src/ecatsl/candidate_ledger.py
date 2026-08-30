"""Append-only candidate lifecycle orchestration for ECATSL.

The ledger owns lifecycle sequencing but delegates durability, compare-and-append,
and audit-failure handling to :class:`ArtifactRepository`. Policy functions remain
pure and never mutate a candidate in memory or in SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
from typing import Optional, Sequence, Tuple

from .artifact_repository import (
    ArtifactRepository,
    AuditFailureRecord,
    PolicyDecisionRecord,
    PolicyPersistenceResult,
    ValidationRetentionResult,
)
from .models import (
    AcceptancePolicy,
    Attribute,
    CandidateRecord,
    CandidateState,
    Counterexample,
    Evidence,
    Provenance,
    ValidationPolicy,
    ValidationResult,
)
from .policies import PolicyEvaluation, apply_validation as evaluate_validation
from .policies import evaluate_acceptance as evaluate_acceptance_policy


@dataclass(frozen=True)
class CandidatePolicyResult:
    """The durable result of applying one policy to a candidate."""

    candidate: CandidateRecord
    evaluation: PolicyEvaluation
    persistence: PolicyPersistenceResult


@dataclass(frozen=True)
class CandidateValidationResult:
    """The retained validation and the resulting candidate successor."""

    candidate: CandidateRecord
    evaluation: PolicyEvaluation
    validation: ValidationRetentionResult
    persistence: PolicyPersistenceResult


class CandidateLedger:
    """Coordinate immutable candidate creation and policy-bounded successors."""

    def __init__(self, repository: ArtifactRepository) -> None:
        self.repository = repository

    @staticmethod
    def _version_successor(version: str) -> str:
        try:
            return str(int(version) + 1)
        except ValueError:
            return f"{version}.successor"

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @classmethod
    def _provenance(cls, candidate: CandidateRecord, identity: str) -> Provenance:
        return Provenance(
            origin="ecatsl:candidate-ledger",
            retrieved_at=cls._now(),
            source_identifier=f"candidate:{candidate.candidate_id}",
            source_revision="candidate-ledger:v1",
            content_identity=identity,
            transformation_history=("candidate-lifecycle:v1",),
        )

    @classmethod
    def _failure(
        cls,
        candidate: CandidateRecord,
        operation: str,
        error: BaseException,
    ) -> AuditFailureRecord:
        identity = sha256(
            f"{operation}\0{candidate.artifact_id}\0{type(error).__name__}\0{error}".encode()
        ).hexdigest()
        return AuditFailureRecord(
            version=candidate.version,
            created_at=cls._now(),
            provenance=cls._provenance(candidate, f"failure:{identity}"),
            related_artifact_id=candidate.artifact_id,
            operation=operation,
            missing_element="candidate_lifecycle",
            failure_data=(
                Attribute(name="error_type", value=type(error).__name__),
                Attribute(name="error", value=str(error)),
            ),
        )

    def _record_failure(self, candidate: CandidateRecord, operation: str, error: BaseException) -> None:
        """Best-effort failure retention without masking the lifecycle error."""
        try:
            self.repository.record_failure(
                self._failure(candidate, operation, error),
                idempotency_key=f"candidate-failure:{operation}:{candidate.artifact_id}:{type(error).__name__}",
            )
        except Exception as audit_error:
            error.add_note(
                "candidate lifecycle failure audit could not be retained: "
                f"{type(audit_error).__name__}: {audit_error}"
            )

    def create_proposal(
        self,
        record: CandidateRecord,
        *,
        evidence: Sequence[Evidence] = (),
        idempotency_key: Optional[str] = None,
    ) -> CandidateRecord:
        """Persist a root proposal, rejecting and auditing creation failures."""
        try:
            for item in evidence:
                self.repository.persist_evidence(item, idempotency_key=f"candidate-evidence:{item.artifact_id}")
            return self.repository.create_candidate(record, idempotency_key=idempotency_key)
        except Exception as error:
            self._record_failure(record, "candidate_creation", error)
            raise

    # Short alias matching the ledger contract used by the design document.
    create = create_proposal

    @classmethod
    def _successor(
        cls,
        candidate: CandidateRecord,
        *,
        state: CandidateState,
        confidence: float,
        cause: str,
        evidence_ids: Sequence[str] = (),
        counterexample_ids: Sequence[str] = (),
        acceptance_policy_version: Optional[str] = None,
        validation_policy_version: Optional[str] = None,
        changed_data: Sequence[Attribute] = (),
        missing_audit_elements: Sequence[str] = (),
    ) -> CandidateRecord:
        return candidate.model_copy(
            update={
                "version": cls._version_successor(candidate.version),
                "created_at": cls._now(),
                "predecessor_id": candidate.artifact_id,
                "provenance": cls._provenance(
                    candidate,
                    f"successor:{candidate.artifact_id}:{cause}",
                ),
                "state": state,
                "confidence": confidence,
                "evidence_ids": tuple(dict.fromkeys((*candidate.evidence_ids, *evidence_ids))),
                "counterexample_ids": tuple(
                    dict.fromkeys((*candidate.counterexample_ids, *counterexample_ids))
                ),
                "acceptance_policy_version": (
                    acceptance_policy_version
                    if acceptance_policy_version is not None
                    else candidate.acceptance_policy_version
                ),
                "validation_policy_version": (
                    validation_policy_version
                    if validation_policy_version is not None
                    else candidate.validation_policy_version
                ),
                "update_cause": cause,
                "changed_data": tuple(changed_data),
                "missing_audit_elements": tuple(
                    dict.fromkeys((*candidate.missing_audit_elements, *missing_audit_elements))
                ),
            }
        )

    @classmethod
    def _decision(
        cls,
        candidate: CandidateRecord,
        evaluation: PolicyEvaluation,
    ) -> PolicyDecisionRecord:
        return PolicyDecisionRecord(
            version=evaluation.policy_version,
            created_at=cls._now(),
            provenance=cls._provenance(
                candidate,
                f"policy:{evaluation.kind.value}:{evaluation.policy_version}:{candidate.artifact_id}",
            ),
            candidate_version_id=candidate.artifact_id,
            policy_kind=evaluation.kind.value,
            policy_version=evaluation.policy_version,
            outcome=evaluation.outcome,
            input_artifact_ids=evaluation.input_artifact_ids,
            audit_metadata=evaluation.audit_metadata
            + tuple(
                Attribute(name="unmet_condition", value=item)
                for item in evaluation.unmet_conditions
            ),
        )

    def _persist_policy(
        self,
        previous: CandidateRecord,
        successor: CandidateRecord,
        evaluation: PolicyEvaluation,
        *,
        expected_predecessor_id: str,
        idempotency_key: Optional[str],
    ) -> PolicyPersistenceResult:
        decision = self._decision(previous, evaluation)
        return self.repository.persist_policy_outcome(
            decision,
            candidate=successor,
            expected_predecessor_id=expected_predecessor_id,
            idempotency_key=idempotency_key,
        )

    def apply_acceptance(
        self,
        candidate: CandidateRecord,
        policy: AcceptancePolicy,
        *,
        evidence: Sequence[Evidence] = (),
        counterexamples: Sequence[Counterexample] = (),
        idempotency_key: Optional[str] = None,
    ) -> CandidatePolicyResult:
        """Evaluate and append an acceptance-policy successor."""
        try:
            self.repository.persist_artifact(
                policy, idempotency_key=f"acceptance-policy:{policy.artifact_id}"
            )
            for item in (*evidence, *counterexamples):
                self.repository.persist_evidence(
                    item, idempotency_key=f"candidate-evidence:{item.artifact_id}"
                )
            new_evidence = tuple(
                item for item in evidence if item.artifact_id not in candidate.evidence_ids
            )
            new_counterexamples = tuple(
                item
                for item in counterexamples
                if item.artifact_id not in candidate.counterexample_ids
            )
            evaluation_candidate = candidate
            if new_evidence or new_counterexamples:
                # Evaluate the prospective content, but do not commit an
                # evidence-only head. The final policy successor below carries
                # all evidence and is the only candidate-head mutation.
                evaluation_candidate = candidate.model_copy(
                    update={
                        "evidence_ids": tuple(
                            dict.fromkeys(
                                (*candidate.evidence_ids,
                                 *(item.artifact_id for item in new_evidence))
                            )
                        ),
                        "counterexample_ids": tuple(
                            dict.fromkeys(
                                (*candidate.counterexample_ids,
                                 *(item.artifact_id for item in new_counterexamples))
                            )
                        ),
                    }
                )
            evaluation = evaluate_acceptance_policy(
                evaluation_candidate,
                policy,
                evidence=evidence,
                counterexamples=counterexamples,
            )
            if evaluation_candidate.artifact_id != candidate.artifact_id:
                evaluation = replace(
                    evaluation,
                    candidate_record_id=candidate.artifact_id,
                    input_artifact_ids=tuple(
                        candidate.artifact_id
                        if item == evaluation_candidate.artifact_id
                        else item
                        for item in evaluation.input_artifact_ids
                    ),
                )
            successor = self._successor(
                candidate,
                state=evaluation.resulting_state,
                confidence=evaluation.resulting_confidence,
                cause="acceptance_policy",
                evidence_ids=tuple(item.artifact_id for item in evidence),
                counterexample_ids=tuple(item.artifact_id for item in counterexamples),
                acceptance_policy_version=policy.version,
                changed_data=(
                    Attribute(name="policy_outcome", value=evaluation.outcome),
                    Attribute(name="policy_version", value=policy.version),
                ),
            )
            persistence = self._persist_policy(
                candidate,
                successor,
                evaluation,
                expected_predecessor_id=candidate.artifact_id,
                idempotency_key=idempotency_key,
            )
            assert persistence.candidate is not None
            return CandidatePolicyResult(persistence.candidate, evaluation, persistence)
        except Exception as error:
            self._record_failure(candidate, "acceptance_policy_application", error)
            raise

    def recheck_before_compilation(
        self,
        candidate: CandidateRecord,
        policy: AcceptancePolicy,
        *,
        evidence: Sequence[Evidence],
        counterexamples: Sequence[Counterexample] = (),
        idempotency_key: Optional[str] = None,
    ) -> CandidatePolicyResult:
        """Re-evaluate the recorded acceptance policy at the compilation boundary."""
        if candidate.state is not CandidateState.ACCEPTED:
            raise ValueError("compilation recheck requires an accepted candidate")
        if candidate.acceptance_policy_version != policy.version:
            raise ValueError(
                "compilation recheck policy must match the candidate's recorded acceptance policy"
            )
        return self.apply_acceptance(
            candidate,
            policy,
            evidence=evidence,
            counterexamples=counterexamples,
            idempotency_key=idempotency_key,
        )

    # Explicit alias for callers that use the requirement wording.
    recheck_acceptance = recheck_before_compilation

    def apply_validation(
        self,
        candidate: CandidateRecord,
        validation: ValidationResult,
        policy: ValidationPolicy,
        *,
        counterexamples: Sequence[Counterexample] = (),
        idempotency_key: Optional[str] = None,
    ) -> CandidateValidationResult:
        """Retain validation feedback and append the policy-prescribed successor."""
        try:
            retained = self.repository.retain_validation(
                candidate.artifact_id,
                validation,
                counterexamples=counterexamples,
                idempotency_key=f"validation:{validation.artifact_id}",
            )
            self.repository.persist_artifact(
                policy, idempotency_key=f"validation-policy:{policy.artifact_id}"
            )
            evaluation = evaluate_validation(candidate, validation, policy)
            successor = self._successor(
                candidate,
                state=evaluation.resulting_state,
                confidence=evaluation.resulting_confidence,
                cause="validation_policy",
                counterexample_ids=tuple(item.artifact_id for item in counterexamples),
                validation_policy_version=policy.version,
                changed_data=(
                    Attribute(name="validation_kind", value=validation.kind),
                    Attribute(name="validation_outcome", value=validation.outcome),
                    Attribute(name="policy_outcome", value=evaluation.outcome),
                    Attribute(name="policy_version", value=policy.version),
                ),
            )
            persistence = self._persist_policy(
                candidate,
                successor,
                evaluation,
                expected_predecessor_id=candidate.artifact_id,
                idempotency_key=idempotency_key,
            )
            assert persistence.candidate is not None
            return CandidateValidationResult(
                persistence.candidate, evaluation, retained, persistence
            )
        except Exception as error:
            self._record_failure(candidate, "validation_policy_application", error)
            raise

    # Compatibility alias matching the concise lifecycle verb in the design.
    apply = apply_acceptance

    def append(self, successor: CandidateRecord, *, idempotency_key: Optional[str] = None) -> CandidateRecord:
        """Append a pre-built successor using compare-and-append semantics."""
        if successor.predecessor_id is None:
            return self.create_proposal(successor, idempotency_key=idempotency_key)
        try:
            return self.repository.append_candidate(
                successor,
                expected_predecessor_id=successor.predecessor_id,
                idempotency_key=idempotency_key,
            )
        except Exception as error:
            self._record_failure(successor, "candidate_persistence", error)
            raise
