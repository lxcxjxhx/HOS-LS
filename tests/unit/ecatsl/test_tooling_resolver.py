"""Task 5.1 tests: ToolingFirstResolver tooling-first gate and LLM suppression.

Covers terminal-outcome validation, early-stop suppression of LLM fallback on
any RESOLVED capability, fallback only after all-terminal-unresolved, failure
retention, persisted telemetry, and deterministic ordering.
"""

from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from src.ecatsl.artifact_repository import ArtifactRepository
from src.ecatsl.models import (
    LLMResolutionAttempt,
    Provenance,
    ToolingResolutionRecord,
)
from src.ecatsl.tooling_resolver import (
    TERMINAL_OUTCOMES,
    CapabilityRun,
    ToolingFirstResolver,
    ToolingFirstResolverError,
    ToolingResolutionBundle,
)

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

_OUTCOMES = ("RESOLVED", "UNRESOLVED", "INAPPLICABLE", "UNAVAILABLE", "FAILED")


def _provenance(identity: str) -> Provenance:
    return Provenance(
        origin="tooling-first",
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="task-5.1",
        content_identity=identity,
        transformation_history=("property-test:t5-1",),
    )


def _capability(identity: str, outcome: str):
    def run(input_identity: str) -> CapabilityRun:
        return CapabilityRun(
            identity=identity,
            version="1",
            input_identity=input_identity,
            outcome=outcome,
            latency_seconds=0.5,
            monetary_cost=0.0 if outcome != "FAILED" else 1.5,
            failure_data="boom" if outcome == "FAILED" else None,
        )

    return run


def _llm_attempt(records, *, outcome="UNRESOLVED-THEN-ASSERTED"):
    return LLMResolutionAttempt(
        version="1",
        created_at=NOW,
        provenance=_provenance("llm:attempt"),
        model_identity="model:gpt-x",
        input_identity="input:api-1",
        output_identity="output:llm-1",
        token_count=120,
        monetary_cost=0.02,
        latency_seconds=3.0,
        outcome=outcome,
        unresolved_tooling_record_ids=tuple(r.artifact_id for r in records),
        failure_data="assertion-only" if outcome != "RESOLVED" else None,
    )


@settings(max_examples=100, deadline=None)
@given(
    outcomes=st.lists(st.sampled_from(_OUTCOMES), min_size=1, max_size=5),
)
def test_property_5_1_tooling_first_gate(outcomes) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 7: tooling resolution gates LLM fallback."""
    capabilities = tuple(
        _capability(f"cap:{index}", outcome) for index, outcome in enumerate(outcomes)
    )
    llm_calls = []

    def llm(records):
        llm_calls.append(tuple(records))
        return _llm_attempt(records)

    resolver = ToolingFirstResolver(
        capabilities=capabilities,
        llm=llm,
        provenance=_provenance("finding:5-1"),
    )
    bundle = resolver.resolve("input:api-1", created_at=NOW)

    assert isinstance(bundle, ToolingResolutionBundle)
    # Every executed capability produced a terminal record.
    assert bundle.records
    assert all(record.outcome in TERMINAL_OUTCOMES for record in bundle.records)
    # Early stop: only capabilities up to the first RESOLVED were executed.
    executed = [record.capability_id for record in bundle.records]
    expected_executed = []
    for index, outcome in enumerate(outcomes):
        if outcome == "RESOLVED":
            expected_executed.append(f"cap:{index}")
            break
        expected_executed.append(f"cap:{index}")
    assert executed == expected_executed
    # LLM fallback is suppressed whenever any capability resolved.
    assert len(llm_calls) == 0 if "RESOLVED" in outcomes else len(llm_calls) == 1
    if "RESOLVED" in outcomes:
        assert bundle.unknown_api is False
        assert bundle.llm_attempt is None
    else:
        assert bundle.unknown_api is True
        assert bundle.llm_attempt is not None
        assert bundle.llm_attempt.unresolved_tooling_record_ids == tuple(
            record.artifact_id for record in bundle.records
        )


def test_property_5_1_non_terminal_outcome_is_rejected() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 7: non-terminal outcomes are invalid."""
    resolver = ToolingFirstResolver(
        capabilities=(_capability("cap:bad", "HALF_DONE"),),
        provenance=_provenance("finding:5-1-invalid"),
    )
    with pytest.raises(ToolingFirstResolverError, match="non-terminal"):
        resolver.resolve("input:api-2", created_at=NOW)


def test_property_5_1_records_are_persisted_with_telemetry() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 7: tooling records and LLM attempts persist telemetry."""
    with ArtifactRepository(":memory:") as repository:
        resolver = ToolingFirstResolver(
            capabilities=(
                _capability("cap:sast", "UNRESOLVED"),
                _capability("cap:tracer", "FAILED"),
            ),
            llm=_llm_attempt,
            repository=repository,
            provenance=_provenance("finding:5-1-persist"),
        )
        bundle = resolver.resolve("input:api-3", created_at=NOW)
        assert bundle.unknown_api is True
        assert bundle.llm_attempt is not None
        for record in bundle.records:
            persisted = repository.load(record.artifact_id, ToolingResolutionRecord)
            assert persisted == record
            assert persisted.latency_seconds == 0.5
            if record.outcome == "FAILED":
                assert persisted.failure_data == "boom"
                assert persisted.monetary_cost == 1.5
        attempt = bundle.llm_attempt
        persisted_attempt = repository.load(attempt.artifact_id, LLMResolutionAttempt)
        assert persisted_attempt == attempt
        assert persisted_attempt.token_count == 120
        assert persisted_attempt.monetary_cost == 0.02
        assert persisted_attempt.outcome == "UNRESOLVED-THEN-ASSERTED"
        assert persisted_attempt.failure_data == "assertion-only"


def test_property_5_1_capability_exception_retained_as_failed() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 7: adapter exceptions are retained as FAILED telemetry, not fatal."""
    def explode(_input_identity: str) -> CapabilityRun:
        raise RuntimeError("capability crashed")

    with ArtifactRepository(":memory:") as repository:
        resolver = ToolingFirstResolver(
            capabilities=(explode,),
            repository=repository,
            provenance=_provenance("finding:5-1-exception"),
        )
        bundle = resolver.resolve("input:api-4", created_at=NOW)
    assert len(bundle.records) == 1
    record = bundle.records[0]
    assert record.outcome == "FAILED"
    assert record.failure_data is not None
    assert record.failure_data.startswith("RuntimeError:")
    # FAILED is terminal and unresolved: the API is Unknown and fallback is
    # permitted, but no LLM handler was configured so no attempt is spawned.
    assert bundle.unknown_api is True
    assert bundle.llm_attempt is None