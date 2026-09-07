"""Focused tests for task 1.1 ECATSL foundations."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.ecatsl.models import (
    CandidateHypothesis,
    CandidateType,
    DiscoveryObservation,
    PathEvidence,
    PathLocation,
    Provenance,
    ReuseCandidate,
    ReuseInventoryEntry,
    SanitizerStatus,
    TASK_1_1_REUSE_CAPABILITIES,
    task_1_1_reuse_inventory,
)
from src.ecatsl.scope import (
    INITIAL_CWES,
    ScopeStatus,
    check_scope,
    initial_scope,
    revise_scope,
)


NOW = datetime(2025, 1, 2, 3, 4, tzinfo=timezone.utc)


def provenance(identity: str = "content-1") -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier="repo/file.py",
        source_revision="abc123",
        content_identity=identity,
        transformation_history=("parsed:v1",),
    )


def artifact_fields():
    return {"version": "1", "created_at": NOW, "provenance": provenance()}


def test_artifacts_are_frozen_content_addressed_and_canonically_serialized():
    observation = DiscoveryObservation(
        **artifact_fields(),
        derivation_kind="repository_code",
        locations=("app.py:10",),
        source_content_identities=("sha256:source",),
        producer="generic-parser",
        producer_version="1",
    )
    same = DiscoveryObservation.model_validate_json(observation.canonical_json())

    assert observation.artifact_id == "sha256:" + observation.content_hash
    assert same == observation
    assert same.canonical_json() == observation.canonical_json()
    with pytest.raises(ValidationError):
        observation.producer = "changed"


def test_artifact_copy_updates_recompute_identity_and_reject_stale_identity():
    observation = DiscoveryObservation(
        **artifact_fields(),
        derivation_kind="repository_code",
        locations=("app.py:10",),
        source_content_identities=("sha256:source",),
        producer="generic-parser",
        producer_version="1",
    )

    changed = observation.model_copy(update={"producer": "new-parser"})
    nested_change = observation.model_copy(
        update={"provenance": observation.provenance.model_copy(update={"origin": "archive"})}
    )
    legacy_change = observation.copy(update={"producer_version": "2"})

    for copied in (changed, nested_change, legacy_change):
        reconstructed = DiscoveryObservation.model_validate_json(copied.canonical_json())
        assert copied == reconstructed
        assert copied.artifact_id == "sha256:" + copied.content_hash
        assert copied.artifact_id != observation.artifact_id

    with pytest.raises(ValidationError):
        observation.model_copy(
            update={
                "producer": "tampered",
                "artifact_id": observation.artifact_id,
                "content_hash": observation.content_hash,
            }
        )


def test_discovery_and_catalog_style_hypotheses_cannot_be_confirmatory():
    applicability = {
        "language": "python",
        "api_signature": "db.execute(query)",
        "parameter_positions": (0,),
    }
    hypothesis = CandidateHypothesis(
        **artifact_fields(),
        candidate_type=CandidateType.SINK,
        api_signature="db.execute(query)",
        applicability=applicability,
        cwe_id="CWE-89",
        evidence_ids=("catalog:1", "discovery:1"),
        ranking_score=0.8,
        ranking_profile_version="1",
    )

    assert hypothesis.confirmatory is False
    with pytest.raises(ValidationError):
        CandidateHypothesis(
            **artifact_fields(),
            candidate_type=CandidateType.SINK,
            api_signature="db.execute(query)",
            applicability=applicability,
            cwe_id="CWE-89",
            evidence_ids=("catalog:1",),
            ranking_score=0.8,
            ranking_profile_version="1",
            confirmatory=True,
        )


def test_path_evidence_requires_supported_adapter_and_complete_ordered_path():
    path = PathEvidence(
        **artifact_fields(),
        adapter_id="input-tracer",
        adapter_version="1",
        supported_adapter=True,
        source=PathLocation(location="app.py:1", symbol="request.args"),
        source_provenance=provenance("source-line-hash"),
        propagation_steps=(PathLocation(location="app.py:2", symbol="query"),),
        sink=PathLocation(location="app.py:3", symbol="cursor.execute"),
        sanitizer_status=SanitizerStatus.ABSENT,
        static_evidence_identity="trace:123",
    )

    assert tuple(step.location for step in path.propagation_steps) == ("app.py:2",)
    with pytest.raises(ValidationError):
        PathEvidence(
            **artifact_fields(),
            adapter_id="input-tracer",
            adapter_version="1",
            supported_adapter=False,
            source=PathLocation(location="app.py:1"),
            source_provenance=provenance(),
            propagation_steps=(),
            sink=PathLocation(location="app.py:3"),
            sanitizer_status=SanitizerStatus.ABSENT,
            static_evidence_identity="trace:bad",
        )


def test_reuse_entry_requires_first_matching_component_or_documented_gap():
    candidates = (
        ReuseCandidate(component_id="InputTracer", matches_required_interface=True),
        ReuseCandidate(component_id="SastPrefilter", matches_required_interface=True),
    )
    entry = ReuseInventoryEntry(
        capability="controllability",
        introduced_abstractions=("PathEvidence",),
        required_interface="trace source to sink",
        evaluated_components=candidates,
        selected_component="InputTracer",
    )
    assert entry.selected_component == "InputTracer"

    with pytest.raises(ValidationError):
        ReuseInventoryEntry(
            capability="controllability",
            introduced_abstractions=("PathEvidence",),
            required_interface="trace source to sink",
            evaluated_components=candidates,
            selected_component="SastPrefilter",
        )

    gap = ReuseInventoryEntry(
        capability="candidate ledger",
        introduced_abstractions=("CandidateRecord",),
        required_interface="append-only artifact history",
        evaluated_components=(),
        capability_gap="no append-only ECATSL ledger exists",
        distinct_responsibility="persist immutable candidate versions",
    )
    assert gap.capability_gap


def test_task_1_1_reuse_inventory_records_verified_reuse_and_precise_gaps():
    inventory = task_1_1_reuse_inventory(created_at=NOW, provenance=provenance("reuse"))

    assert inventory.version == "1.1.1"
    assert inventory.artifact_id == "sha256:" + inventory.content_hash
    assert tuple(entry.capability for entry in inventory.entries) == TASK_1_1_REUSE_CAPABILITIES

    entries = {entry.capability: entry for entry in inventory.entries}

    def evaluated(capability):
        return tuple(
            candidate.component_id for candidate in entries[capability].evaluated_components
        )

    assert entries["catalog import"].selected_component == (
        "src.nvd.catalog_import.CatalogImporter"
    )
    assert evaluated("catalog import") == (
        "src.nvd.catalog_import.CatalogImporter",
        "src.nvd.etl_batch_import.BatchImportManager",
    )
    assert entries["LLM fallback execution"].selected_component == (
        "src.ai.pure_ai_analyzer.PureAIAnalyzer"
    )
    assert evaluated("LLM fallback execution") == (
        "src.ai.pure_ai_analyzer.PureAIAnalyzer",
        "src.ai.pure_ai.multi_agent_pipeline.MultiAgentPipeline",
    )
    assert entries["RAG retrieval"].selected_component == (
        "src.ai.pure_ai.rag.hybrid_retriever.HybridRetriever"
    )
    assert entries["tooling telemetry"].selected_component == (
        "src.ai.token_tracker.TokenTracker"
    )
    assert entries["artifact persistence"].selected_component == (
        "src.db.connection.DatabaseManager"
    )
    assert evaluated("artifact persistence") == (
        "src.db.connection.DatabaseManager",
        "src.nvd.db.sqlite_connection.SQLiteConnection",
    )
    assert entries["artifact schema validation"].selected_component == "pydantic.BaseModel"

    assert entries["repository code discovery"].selected_component == (
        "src.analyzers.ast_analyzer.ASTAnalyzer"
    )
    assert entries["repository configuration discovery"].selected_component == (
        "src.analyzers.config_scanner.ConfigScanner"
    )
    assert entries["static discovery observations"].selected_component == (
        "src.analyzers.sast_prefilter.SastPrefilter"
    )

    graph_gap = entries["repository call-graph discovery"]
    assert graph_gap.selected_component is None
    assert evaluated("repository call-graph discovery") == (
        "src.analyzers.dependency_chain_analyzer.DependencyChainAnalyzer",
        "src.ai.pure_ai.rag.graph_integrator.RAGGraphIntegrator",
    )
    assert "not repository code calls" in graph_gap.capability_gap

    identity_gap = entries["artifact identity contracts"]
    assert evaluated("artifact identity contracts") == ("pydantic.BaseModel",)
    assert "does not assign ECATSL content identities" in identity_gap.capability_gap

    for entry in inventory.entries:
        matches = tuple(
            candidate.component_id
            for candidate in entry.evaluated_components
            if candidate.matches_required_interface
        )
        if matches:
            assert entry.selected_component == matches[0]
            assert entry.capability_gap is None
        else:
            assert entry.selected_component is None
            assert entry.capability_gap
        assert entry.required_interface
        assert entry.distinct_responsibility


def test_initial_scope_and_out_of_scope_gate_short_circuit_downstream_work():
    scope = initial_scope(created_at=NOW, provenance=provenance())
    assert scope.language == "python"
    assert scope.cwe_ids == ("CWE-89", "CWE-78", "CWE-918") == INITIAL_CWES

    result = check_scope(
        scope,
        "javascript",
        ("CWE-89",),
        created_at=NOW,
        provenance=provenance("request"),
    )
    assert result.status is ScopeStatus.OUT_OF_SCOPE
    assert result.downstream_processing_allowed is False

    unsupported_cwe = check_scope(
        scope,
        "python",
        ("CWE-79",),
        created_at=NOW,
        provenance=provenance("request-2"),
    )
    assert unsupported_cwe.status is ScopeStatus.OUT_OF_SCOPE


def test_scope_revision_is_predecessor_linked_and_retains_failed_versioning():
    scope = initial_scope(created_at=NOW, provenance=provenance())
    revised = revise_scope(
        scope,
        language="python",
        cwe_ids=("CWE-89", "CWE-78"),
        provenance=provenance("scope-change"),
        created_at=NOW,
    )
    assert revised.predecessor_id == scope.artifact_id
    assert revised.version == "2"
    assert revised.versioning_complete is True

    def fail_version(_scope):
        raise RuntimeError("version allocation unavailable")

    incomplete = revise_scope(
        scope,
        language="python",
        cwe_ids=INITIAL_CWES,
        provenance=provenance("failed-scope-change"),
        created_at=NOW,
        version_factory=fail_version,
    )
    assert incomplete.predecessor_id == scope.artifact_id
    assert incomplete.versioning_complete is False
    assert incomplete.versioning_error == "version allocation unavailable"
