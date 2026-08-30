"""Feature: evidence-constrained-taint-spec-learning, Property 1 tests."""

from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from src.ecatsl.artifact_repository import ArtifactRepository
from src.ecatsl.candidate_ledger import CandidateLedger
from src.ecatsl.compiler import DeclarativeCompiler
from src.ecatsl.models import (
    AcceptancePolicy,
    Applicability,
    Attribute,
    CandidateRecord,
    CandidateState,
    CandidateType,
    Counterexample,
    Evidence,
    Provenance,
    ValidationPolicy,
    ValidationResult,
)


NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


def _provenance(identity: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="property-1",
        content_identity=identity,
        transformation_history=("property-test:v1",),
    )


def _fields(identity: str) -> dict:
    return {"version": "1", "created_at": NOW, "provenance": _provenance(identity)}


@settings(max_examples=100, deadline=None)
@given(
    confidence=st.floats(
        min_value=0.0,
        max_value=1.0,
        allow_nan=False,
        allow_infinity=False,
    ),
    candidate_number=st.integers(min_value=1, max_value=10_000),
    validation_action=st.sampled_from(("UNACCEPT", "REJECT")),
)
def test_property_01_candidate_lifecycle_is_append_only_and_policy_bounded(
    confidence: float,
    candidate_number: int,
    validation_action: str,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 1: Candidate lifecycle is append-only and policy-bounded."""
    semantics = "argument-0-is-sink"
    evidence = Evidence(
        **_fields(f"evidence:{candidate_number}"),
        evidence_kind="REPOSITORY",
        payload=(Attribute(name="taint_semantics", value=semantics),),
    )
    root = CandidateRecord(
        **_fields(f"candidate:{candidate_number}"),
        candidate_id=f"candidate:{candidate_number}",
        candidate_type=CandidateType.SINK,
        confidence=confidence,
        evidence_ids=(evidence.artifact_id,),
        applicability=Applicability(
            language="python",
            api_signature="cursor.execute(query)",
            parameter_positions=(0,),
        ),
        cwe_id="CWE-89",
        state=CandidateState.PROPOSED,
        update_cause="proposal",
    )
    acceptance = AcceptancePolicy(
        **_fields(f"acceptance:{candidate_number}"),
        conditions=("independent_evidence", "no_counterexamples", "minimum_confidence:0.5"),
    )
    validation_policy = ValidationPolicy(
        **_fields(f"validation-policy:{candidate_number}"),
        result_mappings=(Attribute(name="NO_PATH", value=validation_action),),
    )
    compilation_input = {
        "role": CandidateType.SINK,
        "api_signature": root.applicability.api_signature,
        "parameter_positions": root.applicability.parameter_positions,
        "applicability": root.applicability,
        "taint_semantics": (semantics,),
    }

    with ArtifactRepository(":memory:") as repository:
        ledger = CandidateLedger(repository)
        compiler = DeclarativeCompiler(repository)
        assert ledger.create(root, evidence=(evidence,)) == root

        accepted_result = ledger.apply_acceptance(root, acceptance, evidence=(evidence,))
        accepted = accepted_result.candidate
        expected_accepted = confidence >= 0.5

        assert accepted.predecessor_id == root.artifact_id
        assert accepted.update_cause == "acceptance_policy"
        assert accepted.changed_data == (
            Attribute(name="policy_outcome", value=accepted_result.evaluation.outcome),
            Attribute(name="policy_version", value=acceptance.version),
        )
        assert accepted.state is (
            CandidateState.ACCEPTED if expected_accepted else CandidateState.UNACCEPTED
        )
        assert repository.load(root.artifact_id, CandidateRecord) == root
        assert accepted_result.evaluation.policy_version == acceptance.version

        before_validation = compiler.compile(accepted, compilation_input, evidence=(evidence,))
        assert before_validation.compiled is expected_accepted

        if not expected_accepted:
            return

        no_path = ValidationResult(
            **_fields(f"validation:{candidate_number}"),
            kind="NO_PATH",
            outcome="UNREACHABLE",
        )
        counterexample = Counterexample(
            **_fields(f"counterexample:{candidate_number}"),
            evidence_kind="NO_PATH",
            contradicts="candidate applicability has no reachable path",
        )
        invalidated_result = ledger.apply_validation(
            accepted,
            no_path,
            validation_policy,
            counterexamples=(counterexample,),
        )
        invalidated = invalidated_result.candidate

        assert invalidated.predecessor_id == accepted.artifact_id
        assert invalidated.update_cause == "validation_policy"
        assert invalidated.changed_data == (
            Attribute(name="validation_kind", value=no_path.kind),
            Attribute(name="validation_outcome", value=no_path.outcome),
            Attribute(name="policy_outcome", value=invalidated_result.evaluation.outcome),
            Attribute(name="policy_version", value=validation_policy.version),
        )
        expected_invalidated_state = (
            CandidateState.REJECTED if validation_action == "REJECT" else CandidateState.UNACCEPTED
        )
        assert invalidated.state is expected_invalidated_state
        assert invalidated.confidence == (0.0 if validation_action == "REJECT" else accepted.confidence)
        assert counterexample.artifact_id in invalidated.counterexample_ids
        assert repository.load(accepted.artifact_id, CandidateRecord) == accepted
        assert invalidated_result.evaluation.policy_version == validation_policy.version
        assert compiler.compile(invalidated, compilation_input, evidence=(evidence,)).rejected
