"""Feature: evidence-constrained-taint-spec-learning, Property 7 tests.

Property 7: Tooling resolution gates LLM fallback. Generate applicable tool
sets, terminal outcomes, and retention failures; assert ordered execution up
to the first `RESOLVED`, LLM-suppression whenever any capability resolves, and
`Unknown_API` eligibility only when every applicable capability ended
terminal-unresolved. `FAILED`/exception outcomes are retained as terminal
telemetry and never treated as resolution.

Validates: Requirements 5.1-5.4
"""

from datetime import datetime, timezone
from typing import Sequence, Tuple

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
        source_revision="property-7",
        content_identity=identity,
        transformation_history=("property-test:v7",),
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
        provenance=_provenance("llm:property-7"),
        model_identity="model:gpt-x",
        input_identity="input:api-1",
        output_identity="output:llm-1",
        token_count=120,
        monetary_cost=0.02,
        latency_seconds=3.0,
        outcome=outcome,
        unresolved_tooling_record_ids=tuple(record.artifact_id for record in records),
        failure_data="assertion-only" if outcome != "RESOLVED" else None,
    )


@settings(max_examples=100, deadline=None)
@given(
    outcomes=st.lists(st.sampled_from(_OUTCOMES), min_size=1, max_size=5),
)
def test_property_07_tooling_first_gate(outcomes) -> None:
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
        provenance=_provenance("finding:property-7"),
    )
    bundle = resolver.resolve("input:api-1", created_at=NOW)

    assert isinstance(bundle, ToolingResolutionBundle)
    assert bundle.records
    assert all(record.outcome in TERMINAL_OUTCOMES for record in bundle.records)
    # Ordered execution stops right after the first RESOLVED.
    executed = [record.capability_id for record in bundle.records]
    expected_executed = []
    for index, outcome in enumerate(outcomes):
        expected_executed.append(f"cap:{index}")
        if outcome == "RESOLVED":
            break
    assert executed == expected_executed
    # LLM fallback is suppressed whenever any capability resolved.
    assert len(llm_calls) == 0 if "RESOLVED" in outcomes else len(llm_calls) == 1
    if "RESOLVED" in outcomes:
        assert bundle.unknown_api is False
        assert bundle.resolved is True
        assert bundle.llm_attempt is None
    else:
        assert bundle.unknown_api is True
        assert bundle.resolved is False
        assert bundle.llm_attempt is not None
        assert bundle.llm_attempt.unresolved_tooling_record_ids == tuple(
            record.artifact_id for record in bundle.records
        )


def test_property_07_non_terminal_outcome_is_rejected() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 7: non-terminal outcomes are invalid resolver output."""
    resolver = ToolingFirstResolver(
        capabilities=(_capability("cap:bad", "HALF_DONE"),),
        provenance=_provenance("finding:property-7-invalid"),
    )
    with pytest.raises(ToolingFirstResolverError, match="non-terminal"):
        resolver.resolve("input:api-2", created_at=NOW)


def test_property_07_exception_retained_as_failed_telemetry() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 7: capability exceptions are retained as FAILED terminal telemetry."""
    def explode(_input_identity: str) -> CapabilityRun:
        raise RuntimeError("capability crashed")

    with ArtifactRepository(":memory:") as repository:
        resolver = ToolingFirstResolver(
            capabilities=(explode,),
            repository=repository,
            provenance=_provenance("finding:property-7-exception"),
        )
        bundle = resolver.resolve("input:api-3", created_at=NOW)
    assert len(bundle.records) == 1
    record = bundle.records[0]
    assert record.outcome == "FAILED"
    assert record.failure_data is not None
    assert record.failure_data.startswith("RuntimeError:")
    # FAILED is terminal and unresolved: Unknown_API, fallback permitted when configured.
    assert bundle.unknown_api is True
    assert bundle.resolved is False
    assert bundle.llm_attempt is None  # no LLM handler configured


def test_property_07_records_persist_with_telemetry() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 7: tooling records and LLM attempts persist telemetry."""
    with ArtifactRepository(":memory:") as repository:
        resolver = ToolingFirstResolver(
            capabilities=(
                _capability("cap:sast", "UNRESOLVED"),
                _capability("cap:tracer", "FAILED"),
            ),
            llm=_llm_attempt,
            repository=repository,
            provenance=_provenance("finding:property-7-persist"),
        )
        bundle = resolver.resolve("input:api-4", created_at=NOW)
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