"""Feature: evidence-constrained-taint-spec-learning, Property 18 tests.

Property 18: Generic discovery is allowed; brittle per-route enumeration is
rejected. Generate strategy traits and repository evidence and assert rejection
exactly when all prohibited route-maintenance traits hold simultaneously.

Validates: Requirements 11.10-11.11
"""

from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from src.ecatsl.discovery import DiscoveryPolicy  # noqa: E402
from src.ecatsl.models import DiscoveryStrategy, Provenance  # noqa: E402

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)


def _provenance(identity: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="property-18",
        content_identity=identity,
    )


def _strategy(traits: dict) -> DiscoveryStrategy:
    return DiscoveryStrategy(
        version="1",
        created_at=NOW,
        provenance=_provenance("strategy:property-18"),
        strategy_kind=str(traits.get("strategy_kind", "route-list")),
        evidence_inputs=(),
        enumerates_individual_routes=bool(traits["enumerates_individual_routes"]),
        hard_coded=bool(traits["hard_coded"]),
        generalizes_across_evidence=bool(traits["generalizes_across_evidence"]),
        requires_user_route_maintenance=bool(
            traits["requires_user_route_maintenance"]
        ),
    )


@settings(max_examples=100, deadline=None)
@given(
    enumerates=st.booleans(),
    hard_coded=st.booleans(),
    generalizes=st.booleans(),
    user_maintained=st.booleans(),
    strategy_kind=st.sampled_from(
        ("route-list", "ast-structure", "config-scan", "call-graph", "template")
    ),
)
def test_property_18_rejection_exactly_when_all_prohibited_traits_hold(
    enumerates: bool,
    hard_coded: bool,
    generalizes: bool,
    user_maintained: bool,
    strategy_kind: str,
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 18: discovery strategies are rejected exactly when enumerated per-route, hard-coded, non-generalizing, and user-maintained all hold."""
    policy = DiscoveryPolicy()
    traits = {
        "enumerates_individual_routes": enumerates,
        "hard_coded": hard_coded,
        "generalizes_across_evidence": generalizes,
        "requires_user_route_maintenance": user_maintained,
        "strategy_kind": strategy_kind,
    }
    allowed, reason = policy.validate(_strategy(traits))
    all_prohibited = enumerates and hard_coded and not generalizes and user_maintained
    assert allowed is (not all_prohibited)
    if all_prohibited:
        assert "per-route" in reason
    else:
        assert reason == "allowed generic discovery"
    # Deterministic: identical traits always receive the identical decision.
    assert policy.validate(_strategy(traits)) == (allowed, reason)


@settings(max_examples=100, deadline=None)
@given(
    enumerates=st.booleans(),
    hard_coded=st.booleans(),
    generalizes=st.booleans(),
    user_maintained=st.booleans(),
)
def test_property_18_trait_mapping_validation_matches_artifact_validation(
    enumerates: bool, hard_coded: bool, generalizes: bool, user_maintained: bool
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 18: strategy-trait mappings and strategy artifacts receive identical policy decisions."""
    policy = DiscoveryPolicy()
    traits = {
        "enumerates_individual_routes": enumerates,
        "hard_coded": hard_coded,
        "generalizes_across_evidence": generalizes,
        "requires_user_route_maintenance": user_maintained,
    }
    artifact_decision = policy.validate(_strategy(traits))
    mapping_decision = policy.validate(traits)
    assert artifact_decision == mapping_decision


@settings(max_examples=100, deadline=None)
@given(
    extra_evidence=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8),
        max_size=3,
    ),
)
def test_property_18_generic_strategies_with_repository_evidence_are_allowed(
    extra_evidence: list[str],
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 18: structural, configuration, call-graph, static, and template strategies with repository evidence are always allowed."""
    policy = DiscoveryPolicy()
    generic_kinds = (
        "ast-structure",
        "config-scan",
        "call-graph",
        "static-output",
        "semantic-template",
    )
    for strategy_kind in generic_kinds:
        strategy = DiscoveryStrategy(
            version="1",
            created_at=NOW,
            provenance=_provenance("strategy:generic"),
            strategy_kind=strategy_kind,
            evidence_inputs=tuple(extra_evidence),
            data_profile_version="profile/v1" if extra_evidence else None,
            enumerates_individual_routes=False,
            hard_coded=False,
            generalizes_across_evidence=True,
            requires_user_route_maintenance=False,
        )
        allowed, reason = policy.validate(strategy)
        assert allowed is True
        assert reason == "allowed generic discovery"
