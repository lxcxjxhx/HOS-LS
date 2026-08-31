"""Feature: evidence-constrained-taint-spec-learning, Property 4 tests.

Property 4: Invalid declarative inputs are rejected and retained.
For any compilation input with executable logic, callbacks, runtime generation,
unknown fields, or unsupported semantics, validation rejects the input and
retains a linked ValidationResult and CandidateRecord rather than emitting a
specification.

Validates: Requirements 2.5, 2.6
"""

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
    Evidence,
    Provenance,
    ValidationResult,
)

NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)

_SAFE_TERM = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=24,
)
_SEMANTICS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_:",
    min_size=1,
    max_size=32,
)
_INVALID_FORMS = (
    "executable",
    "callback",
    "runtime_generation",
    "unknown_field",
    "unsupported_semantics",
)


def _fields(identity: str) -> dict:
    return {
        "version": "1",
        "created_at": NOW,
        "provenance": Provenance(
            origin="repository",
            retrieved_at=NOW,
            source_identifier=f"fixture:{identity}",
            source_revision="property-4",
            content_identity=identity,
            transformation_history=("property-test:v1",),
        ),
    }


def _evidence(identity: str) -> Evidence:
    return Evidence(
        **_fields(identity),
        evidence_kind="REPOSITORY",
        payload=(Attribute(name="taint_semantics", value="argument-0-is-sink"),),
    )


def _candidate(*, identity: str, candidate_number: int, evidence_id: str) -> CandidateRecord:
    return CandidateRecord(
        **_fields(identity),
        candidate_id=f"candidate:{candidate_number}",
        candidate_type=CandidateType.SINK,
        confidence=0.8,
        evidence_ids=(evidence_id,),
        applicability=Applicability(
            language="python",
            api_signature="cursor.execute(query)",
            parameter_positions=(0,),
        ),
        cwe_id="CWE-89",
        state=CandidateState.PROPOSED,
        update_cause="proposal",
    )


def _invalid_input(form: str, *, semantics: str) -> dict:
    base = {
        "role": CandidateType.SINK,
        "api_signature": "cursor.execute(query)",
        "parameter_positions": (0,),
        "applicability": Applicability(
            language="python",
            api_signature="cursor.execute(query)",
            parameter_positions=(0,),
        ),
        "taint_semantics": (semantics,),
    }
    if form == "executable":
        return {**base, "taint_semantics": ("__import__('os')",)}
    if form == "callback":
        return {**base, "callback": "lambda x: x"}
    if form == "runtime_generation":
        return {**base, "runtime_code": "generated_module()"}
    if form == "unknown_field":
        return {**base, "mystery_field": "mystery"}
    if form == "unsupported_semantics":
        # Semantics not backed by retained evidence.
        return {**base, "taint_semantics": ("no_evidence_semantics",)}
    raise AssertionError(f"unknown invalid form: {form}")


@settings(max_examples=100, deadline=None)
@given(
    candidate_number=st.integers(min_value=1, max_value=10_000),
    invalid_form=st.sampled_from(_INVALID_FORMS),
)
def test_property_04_invalid_declarative_inputs_are_rejected_and_retained(
    candidate_number: int,
    invalid_form: str,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 4: Invalid declarative inputs are rejected and retained."""
    semantics = "argument-0-is-sink"
    evidence = _evidence(f"evidence:{candidate_number}")
    root = _candidate(
        identity=f"candidate:{candidate_number}",
        candidate_number=candidate_number,
        evidence_id=evidence.artifact_id,
    )
    acceptance = AcceptancePolicy(
        **_fields(f"acceptance:{candidate_number}"),
        conditions=("independent_evidence", "no_counterexamples", "minimum_confidence:0.5"),
    )
    invalid_input = _invalid_input(invalid_form, semantics=semantics)

    with ArtifactRepository(":memory:") as repository:
        ledger = CandidateLedger(repository)
        compiler = DeclarativeCompiler(repository)
        ledger.create(root, evidence=(evidence,))
        accepted = ledger.apply_acceptance(root, acceptance, evidence=(evidence,)).candidate

        result = compiler.compile(accepted, invalid_input, evidence=(evidence,))
        assert not result.compiled
        assert result.specification is None
        assert result.validation_results
        for validation in result.validation_results:
            assert isinstance(validation, ValidationResult)
            assert validation.linked_artifact_ids
            assert accepted.artifact_id in validation.linked_artifact_ids
            retained = repository.load(validation.artifact_id, ValidationResult)
            assert retained is not None
            assert retained.outcome
        # The candidate record and evidence remain retained.
        assert repository.load(accepted.artifact_id, CandidateRecord) is not None
        assert repository.load(evidence.artifact_id, Evidence) is not None
        # No specification was emitted or retained.
        assert result.specification is None
