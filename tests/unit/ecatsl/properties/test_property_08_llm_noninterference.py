"""Feature: evidence-constrained-taint-spec-learning, Property 8 tests.

Property 8: LLM output cannot bypass evidence acceptance. Generate
failed/assertion-only LLM results and insufficient independent evidence; assert
the candidate remains unaccepted. LLM-origin evidence is never independent, so
acceptance conditions that require independent evidence or no counterexamples
stay unmet regardless of LLM assertion content.

Validates: Requirements 5.7
"""

from datetime import datetime, timezone
from typing import Optional, Sequence, Tuple

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from src.ecatsl.confirmation import FindingConfirmationService
from src.ecatsl.models import (
    AcceptancePolicy,
    Applicability,
    Attribute,
    CandidateRecord,
    CandidateState,
    CandidateType,
    Counterexample,
    Evidence,
    FindingClassification,
    FindingStatus,
    Provenance,
)
from src.ecatsl.policies import (
    PolicyEvaluation,
    evaluate_acceptance,
)

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

_OUTCOMES = ("FAILED", "ASSERTION_ONLY")

APPLICABILITY = Applicability(
    language="python",
    api_signature="cursor.execute(query)",
    parameter_positions=(0,),
)


def _provenance(identity: str, *, origin: str = "llm") -> Provenance:
    return Provenance(
        origin=origin,
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="property-8",
        content_identity=identity,
        transformation_history=("property-test:v8",),
    )


def _fields(identity: str, *, origin: str = "llm") -> dict:
    return {
        "version": "1",
        "created_at": NOW,
        "predecessor_id": None,
        "provenance": _provenance(identity, origin=origin),
    }


def _candidate(
    identity: str = "candidate:1",
    *,
    evidence_ids: Sequence[str] = (),
    counterexample_ids: Sequence[str] = (),
) -> CandidateRecord:
    return CandidateRecord(
        **_fields(identity, origin="repository"),
        candidate_id=identity,
        candidate_type=CandidateType.SINK,
        confidence=0.8,
        evidence_ids=tuple(evidence_ids),
        counterexample_ids=tuple(counterexample_ids),
        applicability=APPLICABILITY,
        cwe_id="CWE-89",
        state=CandidateState.PROPOSED,
        update_cause="property-8",
        changed_data=(),
    )


def _llm_evidence(identity: str, *, outcome: str) -> Evidence:
    return Evidence(
        **_fields(identity, origin="llm"),
        evidence_kind="LLM_RESOLUTION",
        payload=(
            Attribute(name="outcome", value=outcome),
            Attribute(name="asserted_result", value="the-pattern-is-confirmed"),
        ),
    )


def _repository_evidence(identity: str = "evidence:repo") -> Evidence:
    return Evidence(
        **_fields(identity, origin="repository"),
        evidence_kind="REPOSITORY",
        payload=(Attribute(name="taint_semantics", value="argument-0-is-sink"),),
    )


def _counterexample(identity: str = "counterexample:1") -> Counterexample:
    return Counterexample(
        **_fields(identity, origin="validation"),
        evidence_kind="NO_PATH",
        contradicts="declared sink has no reachable static path",
    )


def _acceptance_policy(identity: str = "acceptance:1") -> AcceptancePolicy:
    return AcceptancePolicy(
        **_fields(identity, origin="policy"),
        conditions=("independent_evidence", "no_counterexamples", "minimum_confidence:0.5"),
    )


@settings(max_examples=100, deadline=None)
@given(
    llm_outcome=st.sampled_from(_OUTCOMES),
    has_repository_evidence=st.booleans(),
    has_counterexample=st.booleans(),
)
def test_property_08_llm_assertion_never_satisfies_independent_evidence(
    llm_outcome: str,
    has_repository_evidence: bool,
    has_counterexample: bool,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 8: LLM output cannot satisfy independent-evidence acceptance."""
    evidence = [_llm_evidence("evidence:llm", outcome=llm_outcome)]
    if has_repository_evidence:
        evidence.append(_repository_evidence())
    counterexamples = (_counterexample(),) if has_counterexample else ()
    candidate = _candidate(
        evidence_ids=tuple(item.artifact_id for item in evidence),
        counterexample_ids=tuple(item.artifact_id for item in counterexamples),
    )
    policy = _acceptance_policy()

    evaluation = evaluate_acceptance(
        candidate, policy, evidence=tuple(evidence), counterexamples=counterexamples
    )
    assert isinstance(evaluation, PolicyEvaluation)
    # LLM evidence is never independent, so the independent-evidence condition
    # is satisfied only by repository/static evidence.
    expected_accepted = (
        has_repository_evidence and not has_counterexample and candidate.confidence >= 0.5
    )
    assert (evaluation.resulting_state is CandidateState.ACCEPTED) == expected_accepted
    assert evaluation.outcome == ("ACCEPTED" if expected_accepted else "UNACCEPTED")
    if not has_repository_evidence:
        assert "independent_evidence" in evaluation.unmet_conditions
    if has_counterexample:
        assert "no_counterexamples" in evaluation.unmet_conditions


@settings(max_examples=100, deadline=None)
@given(
    llm_outcome=st.sampled_from(_OUTCOMES),
    llm_confidence=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
)
def test_property_08_llm_output_cannot_raise_confidence_past_acceptance(
    llm_outcome: str,
    llm_confidence: float,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 8: LLM assertion content and confidence never upgrade acceptance."""
    evidence = (_llm_evidence("evidence:llm-high", outcome=llm_outcome),)
    candidate = _candidate(evidence_ids=(evidence[0].artifact_id,))
    policy = _acceptance_policy()
    # Even a high-confidence LLM assertion with a claimed confirmation cannot
    # become independent evidence, so acceptance stays unmet.
    evaluation = evaluate_acceptance(
        candidate, policy, evidence=evidence, counterexamples=()
    )
    assert evaluation.resulting_state is CandidateState.UNACCEPTED
    assert "independent_evidence" in evaluation.unmet_conditions


def test_property_08_failed_llm_never_linked_as_path_evidence() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 8: failed LLM telemetry is retained but never becomes a static path."""
    service = FindingConfirmationService()
    result = service.classify(
        provenance=_provenance("finding:property-8", origin="llm"),
        path=None,
        explanatory_support_ids=("evidence:llm-attempt",),
    )
    assert isinstance(result, FindingClassification)
    assert result.status is FindingStatus.UNCONFIRMED
    assert result.path_evidence_id is None
    assert result.explanatory_support_ids == ("evidence:llm-attempt",)