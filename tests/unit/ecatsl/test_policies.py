"""Focused tests for deterministic, non-confirmatory ECATSL policies."""

from datetime import datetime, timezone

import pytest

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
from src.ecatsl.policies import (
    PolicyConfigurationError,
    PolicyKind,
    apply_validation,
    evaluate_acceptance,
)


NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


def provenance(identity: str, *, origin: str = "repository") -> Provenance:
    return Provenance(
        origin=origin,
        retrieved_at=NOW,
        source_identifier=f"source:{identity}",
        source_revision="v1",
        content_identity=identity,
        transformation_history=("normalized:v1",),
    )


def fields(identity: str, *, origin: str = "repository") -> dict:
    return {
        "version": "1",
        "created_at": NOW,
        "provenance": provenance(identity, origin=origin),
    }


def evidence(identity: str, *, origin: str = "repository", kind: str = "REPOSITORY") -> Evidence:
    return Evidence(**fields(identity, origin=origin), evidence_kind=kind)


def candidate(
    evidence_ids=(),
    counterexample_ids=(),
    *,
    state: CandidateState = CandidateState.PROPOSED,
    confidence: float = 0.8,
) -> CandidateRecord:
    return CandidateRecord(
        **fields("candidate"),
        candidate_id="candidate:execute",
        candidate_type=CandidateType.SINK,
        confidence=confidence,
        evidence_ids=tuple(evidence_ids),
        counterexample_ids=tuple(counterexample_ids),
        applicability=Applicability(
            language="python",
            api_signature="cursor.execute(query)",
            parameter_positions=(0,),
        ),
        cwe_id="CWE-89",
        state=state,
        update_cause="policy evaluation",
    )


def acceptance_policy(*conditions: str) -> AcceptancePolicy:
    return AcceptancePolicy(**fields("acceptance-policy"), conditions=conditions)


def validation_policy(*mappings: tuple[str, str]) -> ValidationPolicy:
    return ValidationPolicy(
        **fields("validation-policy"),
        result_mappings=tuple(Attribute(name=name, value=value) for name, value in mappings),
    )


def validation(kind: str, outcome: str) -> ValidationResult:
    return ValidationResult(
        **fields(f"validation:{kind}:{outcome}"),
        kind=kind,
        outcome=outcome,
        adapter_id="input-tracer",
        adapter_version="1",
    )


def test_acceptance_is_deterministic_and_records_exact_sorted_inputs():
    repository_evidence = evidence("repository-evidence")
    record = candidate(evidence_ids=(repository_evidence.artifact_id,))
    policy = acceptance_policy(
        "no_counterexamples",
        "minimum_confidence:0.7",
        "evidence_kind:REPOSITORY",
        "independent_evidence",
    )

    first = evaluate_acceptance(record, policy, evidence=(repository_evidence,))
    replay = evaluate_acceptance(record, policy, evidence=(repository_evidence,))

    assert replay == first
    assert first.kind is PolicyKind.ACCEPTANCE
    assert first.policy_version == policy.version
    assert first.outcome == "ACCEPTED"
    assert first.resulting_state is CandidateState.ACCEPTED
    assert first.resulting_confidence == record.confidence
    assert first.input_artifact_ids == tuple(sorted((
        record.artifact_id,
        policy.artifact_id,
        repository_evidence.artifact_id,
    )))
    assert first.unmet_conditions == ()


@pytest.mark.parametrize(
    "origin",
    [
        "catalog",
        "nvd",
        "rag",
        "llm",
        "discovery",
        "openai",
        "anthropic",
        "hybrid-retriever",
        "unrecognized-external-producer",
    ],
)
def test_non_confirmatory_origins_cannot_satisfy_independent_evidence(origin):
    non_confirmatory = evidence(f"{origin}-evidence", origin=origin, kind="HYPOTHESIS")
    record = candidate(evidence_ids=(non_confirmatory.artifact_id,))

    result = evaluate_acceptance(
        record,
        acceptance_policy("independent_evidence"),
        evidence=(non_confirmatory,),
    )

    assert result.resulting_state is CandidateState.UNACCEPTED
    assert result.outcome == "UNACCEPTED"
    assert result.unmet_conditions == ("independent_evidence",)
    assert not hasattr(result, "confirmed")


@pytest.mark.parametrize("origin", ["catalog", "openai", "hybrid-retriever"])
def test_non_confirmatory_origin_is_only_usable_when_explicitly_requested(origin):
    origin_evidence = evidence(f"{origin}-evidence", origin=origin, kind="HYPOTHESIS")
    record = candidate(evidence_ids=(origin_evidence.artifact_id,))

    result = evaluate_acceptance(
        record,
        acceptance_policy(f"origin:{origin}"),
        evidence=(origin_evidence,),
    )

    assert result.resulting_state is CandidateState.ACCEPTED
    assert result.audit_metadata[1] == Attribute(
        name="independent_evidence", value="false"
    )
    assert not hasattr(result, "path_evidence_id")


@pytest.mark.parametrize("condition", ["confirmation", "controllability", "static_path"])
def test_acceptance_rejects_proof_bearing_conditions(condition):
    repository_evidence = evidence("repository-evidence")
    record = candidate(evidence_ids=(repository_evidence.artifact_id,))

    with pytest.raises(PolicyConfigurationError, match="confirmation"):
        evaluate_acceptance(
            record,
            acceptance_policy(condition),
            evidence=(repository_evidence,),
        )


def test_acceptance_requires_linked_inputs_and_preserves_rejected_state():
    unlinked = evidence("unlinked")
    with pytest.raises(PolicyConfigurationError, match="not linked"):
        evaluate_acceptance(
            candidate(), acceptance_policy("independent_evidence"), evidence=(unlinked,)
        )

    linked = evidence("linked")
    rejected = candidate(
        evidence_ids=(linked.artifact_id,), state=CandidateState.REJECTED
    )
    result = evaluate_acceptance(
        rejected, acceptance_policy("independent_evidence"), evidence=(linked,)
    )
    assert result.resulting_state is CandidateState.REJECTED
    assert result.unmet_conditions == ("candidate_rejected",)


@pytest.mark.parametrize(
    ("kind", "mapping", "expected_state", "expected_confidence"),
    [
        ("COMPILATION_ERROR", "REJECT", CandidateState.REJECTED, 0.0),
        ("NO_PATH", "UNACCEPT:0.2", CandidateState.UNACCEPTED, 0.2),
        ("PARAMETER_MISMATCH", "UNACCEPT", CandidateState.UNACCEPTED, 0.8),
        ("SANITIZER_EVIDENCE", "REJECT", CandidateState.REJECTED, 0.0),
        ("ROLE_INVALIDATION", "REJECT:0.1", CandidateState.REJECTED, 0.1),
    ],
)
def test_validation_policy_maps_required_feedback_deterministically(
    kind, mapping, expected_state, expected_confidence
):
    record = candidate(state=CandidateState.ACCEPTED)
    result = validation(kind, "adapter-result")
    policy = validation_policy((kind, mapping))

    first = apply_validation(record, result, policy)
    replay = apply_validation(record, result, policy)

    assert replay == first
    assert first.kind is PolicyKind.VALIDATION
    assert first.resulting_state is expected_state
    assert first.resulting_confidence == expected_confidence
    assert first.input_artifact_ids == tuple(sorted((
        record.artifact_id, result.artifact_id, policy.artifact_id,
    )))


def test_unmapped_validation_is_conservative_and_rejected_candidates_cannot_promote():
    policy = validation_policy(("NO_PATH", "REJECT"))
    unmapped = apply_validation(candidate(state=CandidateState.ACCEPTED), validation("OTHER", "x"), policy)
    assert unmapped.outcome == "UNACCEPTED_UNMAPPED_VALIDATION"
    assert unmapped.resulting_state is CandidateState.UNACCEPTED

    rejected = apply_validation(candidate(state=CandidateState.REJECTED), validation("NO_PATH", "x"), policy)
    assert rejected.outcome == "REJECTED"
    assert rejected.resulting_state is CandidateState.REJECTED
    assert rejected.resulting_confidence == 0.0


def test_validation_rejects_ambiguous_or_unsupported_mappings():
    record = candidate()
    result = validation("NO_PATH", "UNREACHABLE")
    with pytest.raises(PolicyConfigurationError, match="unique names"):
        apply_validation(record, result, validation_policy(("NO_PATH", "REJECT"), ("NO_PATH", "UNACCEPT")))
    with pytest.raises(PolicyConfigurationError, match="unsupported validation"):
        apply_validation(record, result, validation_policy(("NO_PATH", "ACCEPT")))
