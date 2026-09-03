"""Feature: evidence-constrained-taint-spec-learning, Property 10 tests.

Property 10: Reuse and stage consolidation are deterministic. Generate
ordered reuse candidates and stage identities; assert first-match selection,
duplicate consolidation, and recorded failure behavior.

- Reuse (Requirement 7.2): when an ordered candidate list contains a matching
  HOS-LS component, the first identified matching component is the one
  selected; any other selection is rejected, and a matched capability cannot
  also declare a capability gap. An unmatched capability must record the gap
  and the distinct responsibility of the new abstraction.
- Stage identity and consolidation (Requirement 7.4): equal ordered
  inputs/purpose/outputs produce one deterministic identity; the first
  occurrence of an identity is canonical, every later equal occurrence is a
  recorded duplicate decision linked to its canonical stage; when the
  consolidation persistence fails, both matching stages are retained for
  execution and the consolidation failure itself is audited.

Validates: Requirements 7.2, 7.4
"""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, given, settings, strategies as st
from hypothesis.strategies import composite

from src.ecatsl.artifact_repository import (
    ArtifactRepository,
    OptionalMetadataPersistenceError,
)
from src.ecatsl.models import (
    Provenance,
    ReuseCandidate,
    ReuseInventory,
    ReuseInventoryEntry,
    task_1_1_reuse_inventory,
)
from src.ecatsl.pipeline import (
    CONSOLIDATION_OPERATION,
    StageDefinition,
    consolidate_stages,
    persist_consolidation,
    stage_identity,
)

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_PURPOSE_ALPHABET = "abcdefghijklmnopqrstuvwxyz -"
_COMPONENT_ALPHABET = "abcdefghijklmnopqrstuvwxyz.0123456789"


def _prov(identity: str, *, origin: str = "property-10") -> Provenance:
    return Provenance(
        origin=origin,
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="property-10",
        content_identity=identity,
        transformation_history=("property-test:v10",),
    )


def _candidates() -> st.SearchStrategy:
    """Ordered reuse candidates: unique component ids with match flags."""

    return st.lists(
        st.tuples(
            st.text(alphabet=_COMPONENT_ALPHABET, min_size=1, max_size=16),
            st.booleans(),
        ),
        min_size=1,
        max_size=5,
        unique_by=lambda item: item[0],
    )


def _entry_from_candidates(capability, candidates, selected, *, gap=None,
                           responsibility=None) -> ReuseInventoryEntry:
    return ReuseInventoryEntry(
        capability=capability,
        introduced_abstractions=("ECATSLAbstraction",),
        required_interface="satisfy the ECATSL capability contract",
        evaluated_components=tuple(
            ReuseCandidate(component_id=cid, matches_required_interface=matches)
            for cid, matches in candidates
        ),
        selected_component=selected,
        capability_gap=gap,
        distinct_responsibility=responsibility,
    )


@settings(max_examples=100, deadline=None)
@given(candidates=_candidates())
def test_property_10_reuse_first_match_selection(candidates) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 10: the first identified matching component is selected and every deviation is rejected."""
    matches = [cid for cid, flag in candidates if flag]
    first_matching = matches[0] if matches else None

    if first_matching is not None:
        # Requirement 7.2: the first matching candidate is the selection.
        entry = _entry_from_candidates(
            "repository code discovery", candidates, first_matching
        )
        assert entry.selected_component == first_matching
        assert entry.capability_gap is None
        # A later matching component is never selected.
        if len(matches) > 1:
            with pytest.raises(ValueError, match="first matching"):
                _entry_from_candidates(
                    "repository code discovery", candidates, matches[1]
                )
        # A matched capability cannot declare a capability gap.
        with pytest.raises(ValueError, match="capability gap"):
            _entry_from_candidates(
                "repository code discovery",
                candidates,
                first_matching,
                gap="documented gap",
                responsibility="distinct responsibility",
            )
        # Omitting the selection on a matched capability is rejected too.
        with pytest.raises(ValueError, match="first matching"):
            _entry_from_candidates(
                "repository code discovery", candidates, None,
                gap="documented gap", responsibility="distinct responsibility",
            )
    else:
        # Unmatched candidates require a documented gap and responsibility.
        entry = _entry_from_candidates(
            "repository call-graph discovery",
            candidates,
            None,
            gap="no existing component exposes repository code calls",
            responsibility="provide a repository call-graph adapter",
        )
        assert entry.selected_component is None
        assert entry.capability_gap is not None
        assert entry.distinct_responsibility is not None
        # Selecting an unmatched component is rejected.
        with pytest.raises(ValueError, match="cannot select"):
            _entry_from_candidates(
                "repository call-graph discovery",
                candidates,
                candidates[0][0],
                gap="documented gap",
                responsibility="distinct responsibility",
            )
        # An undocumented gap is rejected.
        with pytest.raises(ValueError, match="documented gap"):
            _entry_from_candidates(
                "repository call-graph discovery", candidates, None,
                responsibility="distinct responsibility",
            )


def test_property_10_shipped_reuse_inventory_is_deterministic() -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 10: the shipped reuse baseline selects the first matching component and is reproducible."""
    first = task_1_1_reuse_inventory(created_at=NOW, provenance=_prov("inventory"))
    repeat = task_1_1_reuse_inventory(created_at=NOW, provenance=_prov("inventory"))
    assert [entry.model_dump(mode="json") for entry in repeat.entries] == [
        entry.model_dump(mode="json") for entry in first.entries
    ]
    matched = 0
    gapped = 0
    for entry in first.entries:
        first_matching = next(
            (
                candidate.component_id
                for candidate in entry.evaluated_components
                if candidate.matches_required_interface
            ),
            None,
        )
        if first_matching is not None:
            matched += 1
            assert entry.selected_component == first_matching
            assert entry.capability_gap is None
        else:
            gapped += 1
            assert entry.selected_component is None
            assert entry.capability_gap is not None
            assert entry.distinct_responsibility is not None
    # The baseline exercises both arms: matched reuse and documented gaps.
    assert matched > 0
    assert gapped > 0


def _artifact_ids() -> st.SearchStrategy:
    return st.lists(
        st.text(alphabet=_ID_ALPHABET, min_size=1, max_size=8),
        min_size=1,
        max_size=3,
    ).map(tuple)


@settings(max_examples=100, deadline=None)
@given(
    inputs=st.lists(
        st.text(alphabet=_ID_ALPHABET, min_size=1, max_size=8),
        min_size=2,
        max_size=3,
    ).map(tuple),
    purpose=st.text(alphabet=_PURPOSE_ALPHABET, min_size=1, max_size=20),
    outputs=_artifact_ids(),
)
def test_property_10_stage_identity_is_deterministic(
    inputs, purpose, outputs
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 10: equal ordered inputs/purpose/outputs yield one identity and every difference changes it."""
    # Ordering matters, so require a reorderable (non-palindromic) input list.
    assume(tuple(reversed(inputs)) != inputs)
    first = stage_identity(inputs, purpose, outputs)
    repeat = stage_identity(tuple(inputs), purpose, tuple(outputs))
    assert first == repeat
    assert len(first) == 64  # deterministic sha256 hex digest
    assert int(first, 16) >= 0  # valid hex
    # Changing the purpose, an input, an output, or their order changes it.
    identities = {
        first,
        stage_identity(inputs, purpose + "X", outputs),
        stage_identity(inputs + ("extra-id",), purpose, outputs),
        stage_identity(inputs, purpose, outputs + ("extra-id",)),
        stage_identity(tuple(reversed(inputs)), purpose, outputs),
    }
    assert len(identities) == 5
    # StageDefinition exposes the same deterministic identity.
    definition = StageDefinition(
        transformation_purpose=purpose,
        input_artifact_ids=inputs,
        output_artifact_ids=outputs,
    )
    assert definition.identity == first


def _logical_triples(count: int) -> st.SearchStrategy:
    """Exactly ``count`` distinct ordered (inputs, purpose, outputs) triples."""

    return st.lists(
        st.tuples(_artifact_ids(),
                  st.text(alphabet=_PURPOSE_ALPHABET, min_size=1, max_size=16),
                  _artifact_ids()),
        min_size=count,
        max_size=count,
        unique_by=lambda triple: (triple[0], triple[1], triple[2]),
    )


@composite
def _ordered_stage_plan(draw):
    """An ordered stage plan: distinct logical triples plus occurrence indices.

    Indices pick logical stages in order; a repeated index is a later equal
    occurrence of that stage identity.
    """

    count = draw(st.integers(min_value=1, max_value=4))
    triples = draw(_logical_triples(count))
    indices = draw(
        st.lists(
            st.integers(min_value=0, max_value=count - 1),
            min_size=1,
            max_size=8,
        )
    )
    return triples, tuple(indices)


def _stage_for(triple) -> StageDefinition:
    inputs, purpose, outputs = triple
    return StageDefinition(
        transformation_purpose=purpose,
        input_artifact_ids=tuple(inputs),
        output_artifact_ids=tuple(outputs),
    )


def _first_occurrence_split(indices):
    """Reference split into first-occurrence and later-occurrence positions."""

    seen = set()
    canonical = []
    duplicates = []
    for index in indices:
        if index in seen:
            duplicates.append(index)
        else:
            seen.add(index)
            canonical.append(index)
    return canonical, duplicates


@settings(max_examples=100, deadline=None)
@given(plan=_ordered_stage_plan())
def test_property_10_consolidation_is_first_occurrence_deterministic(
    plan,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 10: consolidation keeps the first occurrence canonical and lists every later equal occurrence."""
    triples, indices = plan
    definitions = [_stage_for(triples[index]) for index in indices]
    canonical, duplicates = _first_occurrence_split(indices)

    result = consolidate_stages(definitions)
    assert [definition.identity for definition in result.canonical] == [
        stage_identity(triples[index][0], triples[index][1], triples[index][2])
        for index in canonical
    ]
    assert [definition.identity for definition in result.duplicates] == [
        stage_identity(triples[index][0], triples[index][1], triples[index][2])
        for index in duplicates
    ]
    # No identity is canonical twice; every duplicate repeats a canonical one.
    canonical_ids = [definition.identity for definition in result.canonical]
    assert len(canonical_ids) == len(set(canonical_ids))
    duplicate_ids = [definition.identity for definition in result.duplicates]
    assert set(duplicate_ids).issubset(set(canonical_ids))
    # No occurrence is lost or added across the deterministic split.
    split_ids = [definition.identity for definition in result.canonical] + [
        definition.identity for definition in result.duplicates
    ]
    assert sorted(split_ids) == sorted(
        definition.identity for definition in definitions
    )
    # Deterministic: equal inputs produce the equal consolidated result.
    replay = consolidate_stages(definitions)
    assert tuple(item.identity for item in replay.canonical) == tuple(
        item.identity for item in result.canonical
    )
    assert tuple(item.identity for item in replay.duplicates) == tuple(
        item.identity for item in result.duplicates
    )


@settings(max_examples=15, deadline=None)
@given(plan=_ordered_stage_plan())
def test_property_10_persisted_consolidation_records_duplicate_decisions(
    plan,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 10: persistence retains one canonical stage per identity and records each duplicate decision linked to its canonical stage."""
    triples, indices = plan
    definitions = [_stage_for(triples[index]) for index in indices]
    canonical, duplicates = _first_occurrence_split(indices)
    provenance = _prov("consolidate")
    with tempfile.TemporaryDirectory() as tmp:
        database = Path(tmp) / "property-10.db"
        with ArtifactRepository(database) as repository:
            outcome = persist_consolidation(
                repository,
                definitions,
                provenance=provenance,
                created_at=NOW,
            )
            assert outcome.consolidation_failed is False
            assert outcome.stage_count == len(canonical)
            # Without a failure, only canonical stages execute.
            assert tuple(item.identity for item in outcome.executed_definitions) == tuple(
                stage_identity(triples[index][0], triples[index][1], triples[index][2])
                for index in canonical
            )
            # Exactly one audit decision per later equal occurrence.
            assert len(outcome.audit_failures) == len(duplicates)
            expected_duplicate_identities = [
                stage_identity(triples[index][0], triples[index][1], triples[index][2])
                for index in duplicates
            ]
            assert {failure.missing_element for failure in outcome.audit_failures} == {
                f"duplicate_stage:{identity}" for identity in expected_duplicate_identities
            }
            assert all(
                failure.operation == CONSOLIDATION_OPERATION
                for failure in outcome.audit_failures
            )
            # Canonical stage exists for every distinct identity.
            canonical_artifact_ids = {}
            for index in canonical:
                identity = stage_identity(
                    triples[index][0], triples[index][1], triples[index][2]
                )
                persisted = repository.find_canonical_pipeline_stage(identity)
                assert persisted is not None
                assert persisted.duplicate_of_artifact_id is None
                assert persisted.consolidation_failure_artifact_id is None
                canonical_artifact_ids[identity] = persisted.artifact_id
            # Each persisted duplicate references its canonical stage and the
            # audit decision that recorded the consolidation.
            decisions_by_element = {
                failure.missing_element: failure
                for failure in outcome.audit_failures
            }
            duplicate_stages = [
                stage
                for stage in outcome.stages
                if stage.duplicate_of_artifact_id is not None
            ]
            assert len(duplicate_stages) == len(duplicates)
            for duplicate_stage in duplicate_stages:
                decision = decisions_by_element[
                    f"duplicate_stage:{duplicate_stage.stage_identity}"
                ]
                assert (
                    duplicate_stage.duplicate_of_artifact_id
                    == canonical_artifact_ids[duplicate_stage.stage_identity]
                )
                assert decision.related_artifact_id == canonical_artifact_ids[
                    duplicate_stage.stage_identity
                ]
                assert (
                    duplicate_stage.consolidation_failure_artifact_id
                    == decision.artifact_id
                )
            # Deterministic replay on the same repository returns identical ids.
            replay = persist_consolidation(
                repository,
                definitions,
                provenance=provenance,
                created_at=NOW,
            )
            assert tuple(stage.artifact_id for stage in replay.stages) == tuple(
                stage.artifact_id for stage in outcome.stages
            )
            assert tuple(
                failure.artifact_id for failure in replay.audit_failures
            ) == tuple(failure.artifact_id for failure in outcome.audit_failures)


@settings(max_examples=15, deadline=None)
@given(triples=_logical_triples(1))
def test_property_10_consolidation_failure_retains_and_executes_both(
    triples,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 10: a consolidation-persistence failure retains both matching stages for execution and records the failure."""
    triple = triples[0]
    canonical = _stage_for(triple)
    duplicate = _stage_for(triple)
    identity = canonical.identity
    assert duplicate.identity == identity

    def fail_duplicate_persistence(point, _transaction_id):
        if point == "pipeline_stage.consolidation_decision":
            raise OptionalMetadataPersistenceError("consolidation decision")

    with tempfile.TemporaryDirectory() as tmp:
        database = Path(tmp) / "property-10-failure.db"
        with ArtifactRepository.for_testing(
            database, failure_hook=fail_duplicate_persistence
        ) as repository:
            outcome = persist_consolidation(
                repository,
                [canonical, duplicate],
                provenance=_prov("consolidate-failure"),
                created_at=NOW,
            )
            assert outcome.consolidation_failed is True
            # Requirement 7.5 fallback: both matching stages are retained.
            assert [item.identity for item in outcome.executed_definitions] == [
                identity,
                identity,
            ]
            # Only the canonical stage persisted; the duplicate retention
            # failed and that failure itself is audited.
            assert len(outcome.stages) == 1
            assert outcome.stages[0].duplicate_of_artifact_id is None
            persisted_canonical = repository.find_canonical_pipeline_stage(identity)
            assert persisted_canonical is not None
            assert persisted_canonical.artifact_id == outcome.stages[0].artifact_id
            # The consolidation failure is recorded against the canonical stage.
            assert len(outcome.audit_failures) == 1
            failure = outcome.audit_failures[0]
            assert failure.operation == CONSOLIDATION_OPERATION
            assert failure.missing_element == f"consolidation_failure:{identity}"
            assert failure.related_artifact_id == persisted_canonical.artifact_id
