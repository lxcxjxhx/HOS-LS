"""Feature: evidence-constrained-taint-spec-learning, Property 5 tests.

Property 5: Complete supported static paths are necessary and sufficient for
confirmation. Generate path completeness, source provenance, and sanitizer
states and assert confirmation exactly at the static proof boundary: a
complete supported path (non-empty ordered propagation, source provenance,
sink, sanitizer ABSENT/FAILED) is confirmed and every other combination of a
missing or incompatible element stays unconfirmed. The model contracts make
it impossible to synthesize a missing path element: unsupported producers,
empty propagation, and empty source provenance are rejected at construction,
and catalog/discovery/LLM hints never upgrade into path elements.

Validates: Requirements 4.1-4.3, 4.5, 4.8, 11.12
"""

from datetime import datetime, timezone
from typing import Optional, Tuple

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from src.ecatsl.confirmation import FindingConfirmationService
from src.ecatsl.models import (
    FindingClassification,
    FindingStatus,
    PathEvidence,
    PathLocation,
    Provenance,
    SanitizerStatus,
)

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

_SOURCE = PathLocation(location="app.py:2", symbol="request.args")
_PROPAGATION = (PathLocation(location="app.py:3", symbol="query"),)
_SINK = PathLocation(location="app.py:4", symbol="cursor.execute")


def _provenance(identity: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="property-5",
        content_identity=identity,
        transformation_history=("property-test:v5",),
    )


def _fields(identity: str) -> dict:
    return {
        "version": "1",
        "created_at": NOW,
        "predecessor_id": None,
        "provenance": _provenance(identity),
    }


def make_path(
    *,
    identity: str,
    propagation_steps: Tuple[PathLocation, ...],
    sanitizer_status: SanitizerStatus,
) -> PathEvidence:
    """Build a supported PathEvidence whose proof boundary is generated."""
    return PathEvidence(
        **_fields(identity),
        adapter_id="input-tracer",
        adapter_version="1",
        supported_adapter=True,
        source=_SOURCE,
        source_provenance=_provenance("source-line"),
        propagation_steps=propagation_steps,
        sink=_SINK,
        sanitizer_status=sanitizer_status,
        static_evidence_identity=f"static:{identity}",
    )


@settings(max_examples=100, deadline=None)
@given(
    path_present=st.booleans(),
    sanitizer_state=st.sampled_from(
        (SanitizerStatus.ABSENT, SanitizerStatus.FAILED, SanitizerStatus.BLOCKING)
    ),
)
def test_property_05_confirmation_exactly_at_static_proof_boundary(
    path_present: bool,
    sanitizer_state: SanitizerStatus,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 5: complete supported static paths are necessary and sufficient."""
    service = FindingConfirmationService()
    if not path_present:
        path = None
    else:
        path = make_path(
            identity="path:property-5",
            propagation_steps=_PROPAGATION,
            sanitizer_status=sanitizer_state,
        )
    # Incomplete/unsupported paths cannot even be modeled: PathEvidence
    # requires supported_adapter=True and non-empty propagation at construction.
    expected = bool(
        path is not None
        and path.sanitizer_status
        in (SanitizerStatus.ABSENT, SanitizerStatus.FAILED)
    )

    result = service.classify(
        provenance=_provenance("finding:property-5"),
        path=path,
        candidate_record_ids=("candidate:1",),
    )
    assert isinstance(result, FindingClassification)
    assert (result.status is FindingStatus.CONFIRMED) == expected
    if path is not None:
        assert (result.path_evidence_id == path.artifact_id) == expected
    else:
        assert result.path_evidence_id is None
    if expected:
        assert result.reason == "supported complete static path"
    else:
        assert result.reason == "no qualifying supported static path"


@settings(max_examples=100, deadline=None)
@given(
    support_ids=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=12),
        min_size=1,
        max_size=6,
    ),
)
def test_property_05_without_path_never_confirms(support_ids) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 5: hints without a path never confirm."""
    service = FindingConfirmationService()
    result = service.classify(
        provenance=_provenance("finding:hint-only"),
        path=None,
        explanatory_support_ids=tuple(support_ids),
    )
    assert isinstance(result, FindingClassification)
    assert result.status is FindingStatus.UNCONFIRMED
    assert result.path_evidence_id is None
    assert result.explanatory_support_ids == tuple(support_ids)


def test_property_05_model_rejects_missing_path_elements() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 5: missing path elements cannot be synthesized."""
    # An unsupported producer can never be modeled as confirmatory PathEvidence.
    with pytest.raises(Exception):
        PathEvidence(
            **_fields("path:unsupported-producer"),
            adapter_id="unsupported-tool",
            adapter_version="1",
            supported_adapter=False,
            source=_SOURCE,
            source_provenance=_provenance("source-line"),
            propagation_steps=_PROPAGATION,
            sink=_SINK,
            sanitizer_status=SanitizerStatus.ABSENT,
            static_evidence_identity="static:unsupported",
        )
    # Empty provenance identity is rejected at construction.
    with pytest.raises(Exception):
        Provenance(
            origin="repository",
            retrieved_at=NOW,
            source_identifier="fixture:empty",
            source_revision="property-5",
            content_identity="",
            transformation_history=(),
        )
    # Empty propagation is rejected at construction.
    with pytest.raises(Exception):
        PathEvidence(
            **_fields("path:empty-propagation"),
            adapter_id="input-tracer",
            adapter_version="1",
            supported_adapter=True,
            source=_SOURCE,
            source_provenance=_provenance("source-line"),
            propagation_steps=(),
            sink=_SINK,
            sanitizer_status=SanitizerStatus.ABSENT,
            static_evidence_identity="static:empty",
        )