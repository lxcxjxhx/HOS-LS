"""Feature: evidence-constrained-taint-spec-learning, Property 9 tests.

Property 9: Scope gating short-circuits downstream work. Generate unsupported
languages/CWEs and scope revisions; assert the versioned scope gate returns an
out-of-scope result with downstream processing disabled and no candidate,
specification, adapter, or finding artifact is produced, and that maintainer
scope revisions create a predecessor-linked, versioned definition that
re-gates subsequent requests (retaining an incomplete definition with full
provenance when version creation fails).

Validates: Requirements 6.3, 6.4
"""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, given, settings, strategies as st

from src.ecatsl.artifact_repository import ArtifactRepository
from src.ecatsl.candidate_ledger import CandidateLedger
from src.ecatsl.models import (
    AcceptancePolicy,
    Attribute,
    Provenance,
    ValidationPolicy,
)
from src.ecatsl.scope import (
    ScopeStatus,
    check_scope,
    initial_scope,
    revise_scope,
)
from src.ecatsl.service import AnalysisRequest, ECATSLService

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

INITIAL_LANGUAGE = "python"
INITIAL_CWES = ("CWE-89", "CWE-78", "CWE-918")
# Universe mixes in-scope CWE-89/CWE-78/CWE-918 with out-of-scope mappings.
CWE_UNIVERSE = ("CWE-89", "CWE-78", "CWE-918", "CWE-79", "CWE-22", "CWE-352")
LANGUAGE_UNIVERSE = ("python", "java", "javascript", "go", "ruby", "cpp")

_CWE_SETS = st.lists(
    st.sampled_from(CWE_UNIVERSE), min_size=2, max_size=3, unique=True
).map(tuple)


def _prov(identity: str, *, origin: str = "property-9") -> Provenance:
    return Provenance(
        origin=origin,
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="property-9",
        content_identity=identity,
        transformation_history=("property-test:v9",),
    )


def _in_scope(language: str, cwe_ids: tuple) -> bool:
    return language.strip().lower() == INITIAL_LANGUAGE and set(cwe_ids).issubset(
        INITIAL_CWES
    )


@settings(max_examples=100, deadline=None)
@given(
    language=st.sampled_from(
        ("python", "Python", " python ", "java", "javascript", "go", "ruby")
    ),
    cwe_ids=st.lists(
        st.sampled_from(CWE_UNIVERSE), min_size=1, max_size=3, unique=True
    ).map(tuple),
)
def test_property_09_scope_gate_boundary(language: str, cwe_ids: tuple) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 9: scope gate admits only the documented language and CWE set."""
    scope = initial_scope(created_at=NOW, provenance=_prov("scope-v1"))
    expected = _in_scope(language, cwe_ids)

    result = check_scope(
        scope,
        language,
        cwe_ids,
        created_at=NOW,
        provenance=_prov("gate"),
    )
    assert result.status is (
        ScopeStatus.IN_SCOPE if expected else ScopeStatus.OUT_OF_SCOPE
    )
    # An out-of-scope request must not be allowed to continue downstream.
    assert result.downstream_processing_allowed is expected
    assert result.scope_definition_id == scope.artifact_id
    if expected:
        assert result.reason is None
    else:
        assert result.reason is not None
        assert "unsupported" in result.reason


class _ProbeDiscovery:
    """Non-confirmatory discovery that records whether the orchestrator ran it.

    A short-circuiting scope gate must never reach discovery, so ``calls``
    stays unchanged across every out-of-scope ``analyze``.
    """

    def __init__(self) -> None:
        self.calls = 0

    def discover(self, root: str, provenance: Provenance) -> tuple:
        self.calls += 1
        return ()

    def rank(self, observations, templates, provenance: Provenance) -> tuple:
        self.calls += 1
        return ()


@settings(max_examples=40, deadline=None)
@given(
    language=st.sampled_from(LANGUAGE_UNIVERSE),
    cwe_ids=st.lists(
        st.sampled_from(CWE_UNIVERSE), min_size=1, max_size=3, unique=True
    ).map(tuple),
)
def test_property_09_out_of_scope_produces_no_downstream_artifacts(
    language: str, cwe_ids: tuple
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 9: an out-of-scope request yields no candidate, specification, adapter, or finding artifacts."""
    if _in_scope(language, cwe_ids):
        # In-scope requests are allowed past the gate; the gate-boundary sweep
        # covers that side. Only genuinely unsupported requests are analyzed.
        return
    discovery = _ProbeDiscovery()
    with tempfile.TemporaryDirectory() as tmp:
        database = Path(tmp) / "property-09.db"
        with ArtifactRepository(database, supported_static_adapters=()) as repository:
            ledger = CandidateLedger(repository)
            service = ECATSLService(
                scope=initial_scope(created_at=NOW, provenance=_prov("scope-v1")),
                provenance=_prov("service"),
                repository=repository,
                ledger=ledger,
                acceptance_policy=AcceptancePolicy(
                    version="1",
                    created_at=NOW,
                    provenance=_prov("acceptance", origin="policy"),
                    conditions=("independent_evidence",),
                ),
                validation_policy=ValidationPolicy(
                    version="1",
                    created_at=NOW,
                    provenance=_prov("validation", origin="policy"),
                    result_mappings=(
                        Attribute(name="COMPLETE_PATH", value="PRESERVE"),
                        Attribute(name="NO_PATH", value="UNACCEPT"),
                        Attribute(name="*", value="UNACCEPT"),
                    ),
                ),
                discovery=discovery,
            )
            before = discovery.calls
            result = service.analyze(
                AnalysisRequest(
                    repository_ref="repo://demo", language=language, cwe_ids=cwe_ids
                )
            )
            assert result.status == "OUT_OF_SCOPE"
            assert result.scope_result is not None
            assert result.scope_result.status is ScopeStatus.OUT_OF_SCOPE
            assert result.scope_result.downstream_processing_allowed is False
            # No candidate, specification, adapter run, or finding artifacts.
            assert result.hypotheses == ()
            assert result.candidates == ()
            assert result.specifications == ()
            assert result.findings == ()
            assert result.stage_records == ()
            assert result.complexity is None
            # Discovery would be the first downstream capability; it never ran.
            assert discovery.calls == before


@settings(max_examples=100, deadline=None)
@given(
    language=st.sampled_from(LANGUAGE_UNIVERSE),
    cwe_ids=_CWE_SETS,
)
def test_property_09_scope_revision_versions_and_regates(
    language: str, cwe_ids: tuple
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 9: maintainer scope revisions are versioned, predecessor-linked, and re-gate requests."""
    current = initial_scope(created_at=NOW, provenance=_prov("scope-v1"))
    # Keep the revision outside the shipped scope so the superseded definition
    # must gate it out while the revision gates it in.
    assume(not _in_scope(language, cwe_ids))

    revision = revise_scope(
        current,
        language=language,
        cwe_ids=cwe_ids,
        provenance=_prov("scope-v2"),
    )
    assert revision.predecessor_id == current.artifact_id
    assert revision.version == str(int(current.version) + 1)
    assert revision.versioning_complete is True
    assert revision.versioning_error is None
    assert revision.language == language
    assert tuple(revision.cwe_ids) == cwe_ids
    # The revised definition admits its own language/CWE set...
    admitted = check_scope(
        revision,
        language,
        cwe_ids,
        created_at=NOW,
        provenance=_prov("gate-v2"),
    )
    assert admitted.status is ScopeStatus.IN_SCOPE
    assert admitted.downstream_processing_allowed is True
    # ...while the superseded shipped scope still gates the same request out.
    rejected = check_scope(
        current,
        language,
        cwe_ids,
        created_at=NOW,
        provenance=_prov("gate-v1"),
    )
    assert rejected.status is ScopeStatus.OUT_OF_SCOPE
    assert rejected.downstream_processing_allowed is False
    assert rejected.scope_definition_id == current.artifact_id


@settings(max_examples=50, deadline=None)
@given(
    error_type=st.sampled_from((RuntimeError, ValueError, KeyError)),
    language=st.sampled_from(LANGUAGE_UNIVERSE),
)
def test_property_09_versioning_failure_retains_incomplete_scope(
    error_type: type, language: str
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 9: a failed scope-version creation retains provenance with an incomplete versioning state."""
    current = initial_scope(created_at=NOW, provenance=_prov("scope-v1"))

    def failing_factory(_scope) -> str:
        raise error_type("versioning unavailable")

    revision = revise_scope(
        current,
        language=language,
        cwe_ids=("CWE-89", "CWE-78"),
        provenance=_prov("scope-failed"),
        version_factory=failing_factory,
    )
    # Requirement 6.5: version-creation failure must not lose the change.
    assert revision.versioning_complete is False
    assert "versioning unavailable" in revision.versioning_error
    assert revision.predecessor_id == current.artifact_id
    assert revision.language == language
    assert tuple(revision.cwe_ids) == ("CWE-89", "CWE-78")
    assert revision.version == current.version + ".incomplete"
    assert revision.provenance.source_identifier == "fixture:scope-failed"
