"""Feature: evidence-constrained-taint-spec-learning, Property 3 tests.

Property 3: Compilation is closed over safe eligible declarations.
For any candidate set, compilation emits only accepted candidates with valid
inputs, and every output contains only declared taint role, API signature,
parameter positions, applicability, and evidence-supported semantics;
unaccepted/rejected candidates cannot occur in output.

Validates: Requirements 2.1, 2.2, 2.4
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
)


NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)

_ALLOWED_SPEC_FIELDS = frozenset(
    {
        "role",
        "api_signature",
        "parameter_positions",
        "applicability",
        "taint_semantics",
    }
)
_SAFE_TEXT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=24,
)
_SAFE_SEMANTICS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_:",
    min_size=1,
    max_size=32,
)
_STATES_WITHOUT_ACCEPTANCE = (
    CandidateState.PROPOSED,
    CandidateState.UNACCEPTED,
    CandidateState.REJECTED,
)


def _fields(identity: str) -> dict:
    return {
        "version": "1",
        "created_at": NOW,
        "provenance": Provenance(
            origin="repository",
            retrieved_at=NOW,
            source_identifier=f"fixture:{identity}",
            source_revision="property-3",
            content_identity=identity,
            transformation_history=("property-test:v1",),
        ),
    }


def _evidence(semantics: str, identity: str) -> Evidence:
    return Evidence(
        **_fields(identity),
        evidence_kind="REPOSITORY",
        payload=(Attribute(name="taint_semantics", value=semantics),),
    )


def _candidate(
    *,
    identity: str,
    candidate_number: int,
    state: CandidateState,
    evidence_ids: tuple[str, ...],
    semantics: str,
    signature: str = "cursor.execute(query)",
) -> CandidateRecord:
    return CandidateRecord(
        **_fields(identity),
        candidate_id=f"candidate:{candidate_number}",
        candidate_type=CandidateType.SINK,
        confidence=0.8,
        evidence_ids=evidence_ids,
        applicability=Applicability(
            language="python",
            api_signature=signature,
            parameter_positions=(0,),
        ),
        cwe_id="CWE-89",
        state=state,
        update_cause="proposal",
    )


@settings(max_examples=100, deadline=None)
@given(
    candidate_number=st.integers(min_value=1, max_value=10_000),
    extra_semantics=st.lists(_SAFE_SEMANTICS, min_size=0, max_size=3, unique=True),
    invalid_signature=st.one_of(
        st.text(min_size=1, max_size=40),
        st.sampled_from(("cursor.execute", "eval(expression)", "__import__('os')")),
    ),
    role_name=st.text(min_size=1, max_size=24),
)
def test_property_03_compilation_is_closed_over_safe_eligible_declarations(
    candidate_number: int,
    extra_semantics: list[str],
    invalid_signature: str,
    role_name: str,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 3: Compilation
    is closed over safe eligible declarations."""
    semantics = "argument-0-is-sink"
    supported_semantics = tuple(dict.fromkeys((semantics, *extra_semantics)))
    base_evidence = _evidence(semantics, f"evidence:{candidate_number}")
    extra_evidence = tuple(
        _evidence(item, f"evidence:{candidate_number}:{index}")
        for index, item in enumerate(extra_semantics)
    )
    evidence_items = (base_evidence, *extra_evidence)

    accepted = _candidate(
        identity=f"candidate:{candidate_number}",
        candidate_number=candidate_number,
        state=CandidateState.PROPOSED,
        evidence_ids=tuple(item.artifact_id for item in evidence_items),
        semantics=semantics,
    )
    proposed = _candidate(
        identity=f"candidate:{candidate_number + 1}",
        candidate_number=candidate_number + 1,
        state=CandidateState.PROPOSED,
        evidence_ids=(base_evidence.artifact_id,),
        semantics=semantics,
    )
    rejected = _candidate(
        identity=f"candidate:{candidate_number + 2}",
        candidate_number=candidate_number + 2,
        state=CandidateState.REJECTED,
        evidence_ids=(base_evidence.artifact_id,),
        semantics=semantics,
    )
    unaccepted = _candidate(
        identity=f"candidate:{candidate_number + 3}",
        candidate_number=candidate_number + 3,
        state=CandidateState.UNACCEPTED,
        evidence_ids=(base_evidence.artifact_id,),
        semantics=semantics,
    )

    acceptance = AcceptancePolicy(
        **_fields(f"acceptance:{candidate_number}"),
        conditions=("independent_evidence", "no_counterexamples", "minimum_confidence:0.5"),
    )
    valid_input = {
        "role": CandidateType.SINK,
        "api_signature": accepted.applicability.api_signature,
        "parameter_positions": accepted.applicability.parameter_positions,
        "applicability": accepted.applicability,
        "taint_semantics": supported_semantics,
    }
    invalid_inputs = {
        "executable": {
            "role": CandidateType.SINK,
            "api_signature": "cursor.execute(query)",
            "parameter_positions": (0,),
            "applicability": accepted.applicability,
            "taint_semantics": ("__import__('os')",),
        },
        "callback": {
            "role": CandidateType.SINK,
            "api_signature": "cursor.execute(query)",
            "parameter_positions": (0,),
            "applicability": accepted.applicability,
            "taint_semantics": ("callback = lambda x: x",),
        },
        "runtime_generation": {
            "role": CandidateType.SINK,
            "api_signature": "cursor.execute(query)",
            "parameter_positions": (0,),
            "applicability": accepted.applicability,
            "taint_semantics": ("compile(expression)",),
        },
        "unknown": {
            "role": CandidateType.SINK,
            "api_signature": "cursor.execute(query)",
            "parameter_positions": (0,),
            "applicability": accepted.applicability,
            "taint_semantics": ("unknown_semantics",),
        },
    }

    with ArtifactRepository(":memory:") as repository:
        ledger = CandidateLedger(repository)
        compiler = DeclarativeCompiler(repository)
        for item in evidence_items:
            repository.persist_evidence(item, idempotency_key=f"candidate-evidence:{item.artifact_id}")
        for record in (accepted, proposed, rejected, unaccepted):
            ledger.create(record, evidence=(base_evidence,) if record is accepted else ())

        accepted_result = ledger.apply_acceptance(accepted, acceptance, evidence=evidence_items)
        accepted_ok = accepted_result.candidate

        # Only the accepted, valid declaration compiles.
        compiled = compiler.compile(accepted_ok, valid_input, evidence=evidence_items)
        assert compiled.compiled
        assert compiled.specification is not None
        assert compiled.specification.candidate_record_id == accepted_ok.artifact_id
        assert compiled.specification.role is CandidateType.SINK
        assert compiled.specification.api_signature == accepted.applicability.api_signature
        assert compiled.specification.parameter_positions == (0,)
        assert compiled.specification.applicability == accepted.applicability
        assert set(compiled.specification.taint_semantics) == set(supported_semantics)
        # Output contains only the allowlisted declarative fields plus the
        # immutable Artifact metadata; never executable/callback/generated fields.
        spec_fields = set(compiled.specification.model_fields_set)
        model_fields = set(type(compiled.specification).model_fields)
        unsafe_field_names = {
            "callback",
            "callbacks",
            "code",
            "executable",
            "executable_logic",
            "generated_code",
            "runtime_generation",
            "runtime_code",
            "source_code",
        }
        assert not (model_fields & unsafe_field_names)
        assert not (spec_fields & unsafe_field_names)
        assert _ALLOWED_SPEC_FIELDS <= model_fields
        assert _ALLOWED_SPEC_FIELDS <= spec_fields

        # Non-accepted candidates never compile.
        for record in (proposed, unaccepted, rejected):
            result = compiler.compile(record, valid_input, evidence=(base_evidence,))
            assert not result.compiled
            assert result.specification is None

        # Invalid declarations never compile; retained validation artifacts exist.
        for kind, input_data in invalid_inputs.items():
            result = compiler.compile(accepted_ok, input_data, evidence=evidence_items)
            assert not result.compiled
            assert result.validation_results
            assert all(
                validation.kind in {"INPUT_VALIDATION", "COMPILATION_EXCLUSION"}
                for validation in result.validation_results
            )
            for validation in result.validation_results:
                retained = repository.load(validation.artifact_id, type(validation))
                assert retained is not None

        # The untrusted/invalid signature is never accepted into a specification.
        invalid_sig_input = dict(valid_input, api_signature=invalid_signature)
        invalid_result = compiler.compile(accepted_ok, invalid_sig_input, evidence=evidence_items)
        assert not invalid_result.compiled
        assert invalid_result.specification is None
