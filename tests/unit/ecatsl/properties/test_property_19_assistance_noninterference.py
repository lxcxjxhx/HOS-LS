"""Feature: evidence-constrained-taint-spec-learning, Property 19 tests.

Property 19: Assisted analysis preserves all proof boundaries. Generate
catalog/discovery-assisted hypotheses and assert provenance, scope, reuse, and
policy constraints plus no confirmation without Property 5 evidence (a complete
supported static path).

Validates: Requirements 11.13
"""

from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from src.ecatsl.confirmation import FindingConfirmationService  # noqa: E402
from src.ecatsl.discovery import DERIVATION_KINDS, RepositoryDiscovery  # noqa: E402
from src.ecatsl.models import (  # noqa: E402
    Applicability,
    CandidateHypothesis,
    CandidateType,
    FindingStatus,
    Provenance,
    TaintTemplate,
)
from src.ecatsl.scope import INITIAL_CWES, check_scope, initial_scope  # noqa: E402

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)


def _provenance(identity: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="property-19",
        content_identity=identity,
        transformation_history=("property-test:v19",),
    )


def _template(cwe_id: str, language: str = "python") -> TaintTemplate:
    return TaintTemplate(
        version="1",
        created_at=NOW,
        provenance=_provenance(f"template:{cwe_id}"),
        cwe_id=cwe_id,
        role=CandidateType.SOURCE,
        api_shape="cursor.execute(query)",
        applicability=Applicability(
            language=language, api_signature="cursor.execute(query)"
        ),
        semantic_features=("sql", "injection"),
    )


@settings(max_examples=100, deadline=None)
@given(
    cwe_id=st.sampled_from(("CWE-89", "CWE-78", "CWE-918")),
    language=st.sampled_from(("python", "java")),
    entrypoint_only=st.booleans(),
)
def test_property_19_assisted_hypotheses_are_nonconfirmatory_and_provenance_linked(
    cwe_id: str, language: str, entrypoint_only: bool
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 19: catalog/discovery-assisted hypotheses stay non-confirmatory and retain both discovery and catalog provenance."""
    discovery = RepositoryDiscovery(language=language)
    if entrypoint_only:
        code = "@app.route('/x')\ndef handler():\n    return 1\n"
    else:
        code = "def helper(value):\n    return value\n"
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as work:
        (Path(work) / "module.py").write_text(code)
        observations = discovery.discover(work, _provenance("discovery"))
    assert observations
    assert all(
        observation.derivation_kind in DERIVATION_KINDS
        for observation in observations
    )
    assert all(observation.confirmatory is False for observation in observations)

    hypotheses = discovery.rank(
        observations, (_template(cwe_id, language),), _provenance("ranking")
    )
    assert hypotheses
    for hypothesis in hypotheses:
        assert isinstance(hypothesis, CandidateHypothesis)
        assert hypothesis.confirmatory is False
        assert hypothesis.cwe_id == cwe_id
        assert hypothesis.ranking_profile_version == "discovery-rank/v2"
        # Both the discovery observation and the catalog template are retained.
        assert len(hypothesis.evidence_ids) == 2
        assert all(hypothesis.evidence_ids)
        assert hypothesis.applicability.language == language


@settings(max_examples=100, deadline=None)
@given(
    requested=st.sampled_from(
        ("CWE-89", "CWE-78", "CWE-918", "CWE-22", "CWE-1", "CWE-200")
    ),
    language=st.sampled_from(("python", "java", "go")),
)
def test_property_19_scope_gate_blocks_out_of_scope_assistance(
    requested: str, language: str
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 19: assistance for a weakness or language outside the documented initial scope is short-circuited by the versioned scope gate."""
    scope = initial_scope(created_at=NOW, provenance=_provenance("scope"))
    requested_cwes = (requested,) if requested in INITIAL_CWES else (requested, "CWE-89")
    result = check_scope(
        scope,
        language,
        requested_cwes,
        created_at=NOW,
        provenance=_provenance("scope-check"),
    )
    in_scope = (
        language == scope.language
        and all(cwe in INITIAL_CWES for cwe in requested_cwes)
    )
    assert (result.status.value == "IN_SCOPE") is in_scope
    assert result.downstream_processing_allowed is in_scope


@settings(max_examples=100, deadline=None)
@given(
    candidate_id=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=3, max_size=12
    ),
    catalog_evidence=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz:", min_size=3, max_size=10),
        min_size=1,
        max_size=3,
    ),
)
def test_property_19_no_confirmation_without_static_path_evidence(
    candidate_id: str, catalog_evidence: list[str]
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 19: catalog or discovery assistance alone never confirms a finding; classification stays unconfirmed without Property 5 evidence."""
    service = FindingConfirmationService()
    result = service.classify(
        provenance=_provenance("finding:property-19"),
        path=None,
        candidate_record_ids=(f"candidate:{candidate_id}",),
        explanatory_support_ids=tuple(catalog_evidence),
    )
    assert result.status is FindingStatus.UNCONFIRMED
    assert result.path_evidence_id is None
    # Deterministic: the same assisted inputs never confirm on replay.
    replay = service.classify(
        provenance=_provenance("finding:property-19"),
        path=None,
        candidate_record_ids=(f"candidate:{candidate_id}",),
        explanatory_support_ids=tuple(catalog_evidence),
    )
    assert replay.status is FindingStatus.UNCONFIRMED
    assert replay.path_evidence_id is None
