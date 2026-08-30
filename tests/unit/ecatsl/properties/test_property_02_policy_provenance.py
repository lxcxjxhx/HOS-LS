"""Feature: evidence-constrained-taint-spec-learning, Property 2 tests."""

from datetime import datetime, timezone
from typing import Optional

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from src.ecatsl.artifact_repository import ArtifactRepository, PolicyDecisionRecord
from src.ecatsl.candidate_ledger import CandidateLedger
from src.ecatsl.models import (
    AcceptancePolicy,
    Applicability,
    Attribute,
    CandidateRecord,
    CandidateState,
    CandidateType,
    Evidence,
    Provenance,
    ValidationPolicy,
    ValidationResult,
)


NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)
_SAFE_TEXT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=24,
)


def _provenance(
    identity: str,
    *,
    origin: str,
    source_identifier: str,
    source_revision: Optional[str],
    history: tuple[str, ...],
) -> Provenance:
    return Provenance(
        origin=origin,
        retrieved_at=NOW,
        source_identifier=source_identifier,
        source_revision=source_revision,
        content_identity=identity,
        transformation_history=history,
    )


@settings(max_examples=100, deadline=None)
@given(
    origin=st.sampled_from(("repository", "validation", "input-tracer")),
    source_identifier=_SAFE_TEXT,
    source_revision=st.one_of(st.none(), _SAFE_TEXT),
    content_identity=_SAFE_TEXT,
    transformations=st.lists(_SAFE_TEXT, max_size=4, unique=True),
    candidate_number=st.integers(min_value=1, max_value=10_000),
    additional_evidence_count=st.integers(min_value=0, max_value=2),
)
def test_property_02_evidence_and_policy_provenance_is_complete(
    origin: str,
    source_identifier: str,
    source_revision: Optional[str],
    content_identity: str,
    transformations: list[str],
    candidate_number: int,
    additional_evidence_count: int,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 2: Evidence and policy provenance is complete."""
    history = tuple(transformations)
    evidence_provenance = _provenance(
        content_identity,
        origin=origin,
        source_identifier=source_identifier,
        source_revision=source_revision,
        history=history,
    )
    evidence = Evidence(
        version="1",
        created_at=NOW,
        provenance=evidence_provenance,
        evidence_kind="REPOSITORY",
        payload=(Attribute(name="taint_semantics", value="argument-0-is-sink"),),
    )
    additional_evidence = tuple(
        Evidence(
            version="1",
            created_at=NOW,
            provenance=_provenance(
                f"{content_identity}:additional:{index}",
                origin=origin,
                source_identifier=f"{source_identifier}:additional:{index}",
                source_revision=source_revision,
                history=history,
            ),
            evidence_kind="REPOSITORY",
        )
        for index in range(additional_evidence_count)
    )
    evidence_items = (evidence, *additional_evidence)
    candidate_provenance = _provenance(
        f"candidate:{candidate_number}",
        origin="repository",
        source_identifier=f"candidate:{candidate_number}",
        source_revision="property-2",
        history=("candidate-proposal:v1",),
    )
    root = CandidateRecord(
        version="1",
        created_at=NOW,
        provenance=candidate_provenance,
        candidate_id=f"candidate:{candidate_number}",
        candidate_type=CandidateType.SINK,
        confidence=0.8,
        evidence_ids=tuple(item.artifact_id for item in evidence_items),
        applicability=Applicability(
            language="python",
            api_signature="cursor.execute(query)",
            parameter_positions=(0,),
        ),
        cwe_id="CWE-89",
        state=CandidateState.PROPOSED,
        update_cause="proposal",
    )
    acceptance_policy = AcceptancePolicy(
        version="acceptance-v1",
        created_at=NOW,
        provenance=_provenance(
            f"acceptance:{candidate_number}",
            origin="repository",
            source_identifier="policy:acceptance",
            source_revision="v1",
            history=("policy-definition:v1",),
        ),
        conditions=("independent_evidence",),
    )
    validation_policy = ValidationPolicy(
        version="validation-v1",
        created_at=NOW,
        provenance=_provenance(
            f"validation-policy:{candidate_number}",
            origin="repository",
            source_identifier="policy:validation",
            source_revision="v1",
            history=("policy-definition:v1",),
        ),
        result_mappings=(Attribute(name="NO_PATH", value="UNACCEPT"),),
    )

    with ArtifactRepository(":memory:") as repository:
        ledger = CandidateLedger(repository)
        ledger.create(root, evidence=evidence_items)
        retained_evidence = repository.load(evidence.artifact_id, Evidence)
        assert retained_evidence.provenance == evidence_provenance
        assert retained_evidence.provenance.origin == origin
        assert retained_evidence.provenance.retrieved_at == NOW
        assert retained_evidence.provenance.source_identifier == source_identifier
        assert retained_evidence.provenance.source_revision == source_revision
        assert retained_evidence.provenance.content_identity == content_identity
        assert retained_evidence.provenance.transformation_history == history

        acceptance_result = ledger.apply_acceptance(
            root,
            acceptance_policy,
            evidence=evidence_items,
        )
        acceptance_decision = acceptance_result.persistence.decision
        assert isinstance(acceptance_decision, PolicyDecisionRecord)
        assert acceptance_decision.policy_version == acceptance_policy.version
        assert acceptance_decision.outcome == acceptance_result.evaluation.outcome
        assert acceptance_decision.input_artifact_ids == tuple(
            sorted((root.artifact_id, acceptance_policy.artifact_id, *root.evidence_ids))
        )
        assert acceptance_decision.provenance.origin == "ecatsl:candidate-ledger"
        assert acceptance_decision.provenance.retrieved_at.tzinfo is not None
        assert acceptance_decision.provenance.source_identifier == f"candidate:{root.candidate_id}"
        assert acceptance_decision.provenance.source_revision == "candidate-ledger:v1"
        assert acceptance_decision.provenance.content_identity == (
            f"policy:ACCEPTANCE:{acceptance_policy.version}:{root.artifact_id}"
        )
        assert acceptance_decision.provenance.transformation_history == (
            "candidate-lifecycle:v1",
        )
        assert acceptance_result.candidate.acceptance_policy_version == acceptance_policy.version
        assert acceptance_result.candidate.provenance.origin == "ecatsl:candidate-ledger"
        assert acceptance_result.candidate.provenance.retrieved_at.tzinfo is not None
        assert acceptance_result.candidate.provenance.source_identifier == f"candidate:{root.candidate_id}"
        assert acceptance_result.candidate.provenance.source_revision == "candidate-ledger:v1"
        assert acceptance_result.candidate.provenance.content_identity == (
            f"successor:{root.artifact_id}:acceptance_policy"
        )
        assert acceptance_result.candidate.provenance.transformation_history == (
            "candidate-lifecycle:v1",
        )

        validation = ValidationResult(
            version="1",
            created_at=NOW,
            provenance=_provenance(
                f"validation:{candidate_number}",
                origin="validation",
                source_identifier="adapter:fixture",
                source_revision="adapter-v1",
                history=("normalized:v1",),
            ),
            kind="NO_PATH",
            outcome="UNREACHABLE",
        )
        validation_result = ledger.apply_validation(
            acceptance_result.candidate,
            validation,
            validation_policy,
        )
        validation_decision = validation_result.persistence.decision
        assert isinstance(validation_decision, PolicyDecisionRecord)
        assert validation_decision.policy_version == validation_policy.version
        assert validation_decision.outcome == validation_result.evaluation.outcome
        assert validation_decision.input_artifact_ids == tuple(
            sorted(
                (
                    acceptance_result.candidate.artifact_id,
                    validation.artifact_id,
                    validation_policy.artifact_id,
                )
            )
        )
        assert validation_result.candidate.validation_policy_version == validation_policy.version
        assert validation_result.candidate.provenance.origin == "ecatsl:candidate-ledger"
        assert validation_result.candidate.provenance.retrieved_at.tzinfo is not None
        assert validation_decision.provenance.source_identifier == (
            f"candidate:{acceptance_result.candidate.candidate_id}"
        )
        assert validation_decision.provenance.source_revision == "candidate-ledger:v1"
        assert validation_decision.provenance.content_identity == (
            "policy:VALIDATION:"
            f"{validation_policy.version}:{acceptance_result.candidate.artifact_id}"
        )
        assert validation_decision.provenance.transformation_history == (
            "candidate-lifecycle:v1",
        )
        assert validation_result.candidate.provenance.source_identifier == (
            f"candidate:{acceptance_result.candidate.candidate_id}"
        )
        assert validation_result.candidate.provenance.source_revision == "candidate-ledger:v1"
        assert validation_result.candidate.provenance.content_identity == (
            f"successor:{acceptance_result.candidate.artifact_id}:validation_policy"
        )
        assert validation_result.candidate.provenance.transformation_history == (
            "candidate-lifecycle:v1",
        )
