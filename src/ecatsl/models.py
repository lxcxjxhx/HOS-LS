"""Immutable, content-addressed data contracts for ECATSL."""

from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Literal, Mapping, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ImmutableModel(BaseModel):
    """Strict immutable model with immutable collection types."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class Attribute(ImmutableModel):
    """A small, canonically serializable metadata value."""

    name: str = Field(min_length=1)
    value: str


class Provenance(ImmutableModel):
    origin: str = Field(min_length=1)
    retrieved_at: datetime
    source_identifier: str = Field(min_length=1)
    source_revision: Optional[str] = None
    content_identity: str = Field(min_length=1)
    transformation_history: Tuple[str, ...] = ()

    @model_validator(mode="after")
    def normalize_time(self) -> "Provenance":
        if self.retrieved_at.tzinfo is None:
            raise ValueError("retrieved_at must be timezone-aware")
        object.__setattr__(self, "retrieved_at", self.retrieved_at.astimezone(timezone.utc))
        return self


class Artifact(ImmutableModel):
    """Base for immutable artifacts whose identity is their canonical content hash."""

    artifact_id: str = ""
    version: str = Field(min_length=1)
    created_at: datetime
    predecessor_id: Optional[str] = None
    provenance: Provenance
    content_hash: str = ""

    @model_validator(mode="after")
    def assign_content_identity(self) -> "Artifact":
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        object.__setattr__(self, "created_at", self.created_at.astimezone(timezone.utc))
        content = self.model_dump(
            mode="json", exclude={"artifact_id", "content_hash"}, exclude_none=False
        )
        digest = sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if self.content_hash and self.content_hash != digest:
            raise ValueError("content_hash does not match canonical artifact content")
        expected_id = "sha256:" + digest
        if self.artifact_id and self.artifact_id != expected_id:
            raise ValueError("artifact_id does not match canonical artifact content")
        object.__setattr__(self, "content_hash", digest)
        object.__setattr__(self, "artifact_id", expected_id)
        return self

    def canonical_json(self) -> str:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )

    def model_copy(
        self, *, update: Optional[Mapping[str, Any]] = None, deep: bool = False
    ) -> "Artifact":
        """Revalidate copies so changed content always receives a matching identity."""
        data = self.model_dump(
            mode="python", exclude={"artifact_id", "content_hash"}, round_trip=True
        )
        if update:
            data.update(update)
        return type(self).model_validate(data)

    def copy(
        self,
        *,
        include: Any = None,
        exclude: Any = None,
        update: Optional[Mapping[str, Any]] = None,
        deep: bool = False,
    ) -> "Artifact":
        """Keep Pydantic's legacy copy/update path subject to artifact validation."""
        if include is not None or exclude is not None:
            raise TypeError("partial copies are not supported for content-addressed artifacts")
        return self.model_copy(update=update, deep=deep)


class CandidateType(str, Enum):
    SOURCE = "SOURCE"
    SINK = "SINK"
    SANITIZER = "SANITIZER"
    PRECONDITION = "PRECONDITION"


class CandidateState(str, Enum):
    PROPOSED = "PROPOSED"
    UNACCEPTED = "UNACCEPTED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class SanitizerStatus(str, Enum):
    ABSENT = "ABSENT"
    FAILED = "FAILED"
    BLOCKING = "BLOCKING"


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"


class Applicability(ImmutableModel):
    language: str = Field(min_length=1)
    frameworks: Tuple[str, ...] = ()
    api_signature: str = Field(min_length=1)
    parameter_positions: Tuple[int, ...] = ()
    scope_conditions: Tuple[str, ...] = ()


class Evidence(Artifact):
    evidence_kind: str = Field(min_length=1)
    payload: Tuple[Attribute, ...] = ()


class Counterexample(Evidence):
    contradicts: str = Field(min_length=1)


class CandidateRecord(Artifact):
    candidate_id: str = Field(min_length=1)
    candidate_type: CandidateType
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: Tuple[str, ...]
    counterexample_ids: Tuple[str, ...] = ()
    applicability: Applicability
    cwe_id: str = Field(pattern=r"^CWE-\d+$")
    state: CandidateState
    acceptance_policy_version: Optional[str] = None
    validation_policy_version: Optional[str] = None
    update_cause: str = Field(min_length=1)
    changed_data: Tuple[Attribute, ...] = ()
    missing_audit_elements: Tuple[str, ...] = ()


class NonConfirmatoryArtifact(Artifact):
    confirmatory: Literal[False] = False


class DiscoveryObservation(NonConfirmatoryArtifact):
    derivation_kind: str = Field(min_length=1)
    locations: Tuple[str, ...]
    source_content_identities: Tuple[str, ...]
    producer: str = Field(min_length=1)
    producer_version: str = Field(min_length=1)
    context: Tuple[Attribute, ...] = ()


class CandidateHypothesis(NonConfirmatoryArtifact):
    candidate_type: CandidateType
    api_signature: str = Field(min_length=1)
    applicability: Applicability
    cwe_id: str = Field(pattern=r"^CWE-\d+$")
    evidence_ids: Tuple[str, ...]
    ranking_score: float
    ranking_profile_version: str = Field(min_length=1)


class DiscoveryStrategy(NonConfirmatoryArtifact):
    strategy_kind: str = Field(min_length=1)
    evidence_inputs: Tuple[str, ...]
    data_profile_version: Optional[str] = None
    enumerates_individual_routes: bool = False
    hard_coded: bool = False
    generalizes_across_evidence: bool = True
    requires_user_route_maintenance: bool = False


class AcceptancePolicy(Artifact):
    conditions: Tuple[str, ...]


class ValidationPolicy(Artifact):
    result_mappings: Tuple[Attribute, ...]


class ConstrainedDeclarativeSpecification(Artifact):
    candidate_record_id: str = Field(min_length=1)
    role: CandidateType
    api_signature: str = Field(min_length=1)
    parameter_positions: Tuple[int, ...]
    applicability: Applicability
    taint_semantics: Tuple[str, ...]


class ValidationResult(Artifact):
    kind: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    adapter_id: Optional[str] = None
    adapter_version: Optional[str] = None
    linked_artifact_ids: Tuple[str, ...] = ()
    observed_data: Tuple[Attribute, ...] = ()


class PathLocation(ImmutableModel):
    location: str = Field(min_length=1)
    symbol: Optional[str] = None


class PathEvidence(Artifact):
    adapter_id: str = Field(min_length=1)
    adapter_version: str = Field(min_length=1)
    supported_adapter: Literal[True]
    source: PathLocation
    source_provenance: Provenance
    propagation_steps: Tuple[PathLocation, ...] = Field(min_length=1)
    sink: PathLocation
    sanitizer_status: SanitizerStatus
    static_evidence_identity: str = Field(min_length=1)


class StaticAdapterRun(Artifact):
    """Persisted identity and inputs for one configured static-adapter execution."""

    adapter_id: str = Field(min_length=1)
    adapter_version: str = Field(min_length=1)
    run_identity: str = Field(min_length=1)
    candidate_record_ids: Tuple[str, ...] = Field(min_length=1)
    specification_ids: Tuple[str, ...] = Field(min_length=1)
    validation_result_id: str = Field(min_length=1)
    input_artifact_ids: Tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def inputs_cover_bound_lineage(self) -> "StaticAdapterRun":
        required = set(self.candidate_record_ids + self.specification_ids)
        if not required.issubset(self.input_artifact_ids):
            raise ValueError("adapter run inputs must include every candidate and specification")
        return self


class FindingClassification(Artifact):
    status: FindingStatus
    reason: str = Field(min_length=1)
    path_evidence_id: Optional[str] = None
    candidate_record_ids: Tuple[str, ...] = ()
    specification_ids: Tuple[str, ...] = ()
    validation_result_ids: Tuple[str, ...] = ()
    explanatory_support_ids: Tuple[str, ...] = ()
    missing_metadata: Tuple[str, ...] = ()


class CatalogRecord(NonConfirmatoryArtifact):
    record_type: str = Field(min_length=1)
    canonical_identifier: str = Field(min_length=1)
    catalog_evidence: Literal[True] = True


class CatalogImport(NonConfirmatoryArtifact):
    source_kind: str = Field(min_length=1)
    import_tool_version: str = Field(min_length=1)
    license_metadata: Optional[str] = None


class NormalizedCatalogRecord(CatalogRecord):
    normalization_profile_version: str = Field(min_length=1)
    normalized_content_identity: str = Field(min_length=1)
    duplicate_source_ids: Tuple[str, ...] = ()


class IngestionRun(NonConfirmatoryArtifact):
    catalog_import_ids: Tuple[str, ...]
    normalization_profile_version: str = Field(min_length=1)
    counts: Tuple[Attribute, ...]


class TaintTemplate(NonConfirmatoryArtifact):
    cwe_id: str = Field(pattern=r"^CWE-\d+$")
    role: CandidateType
    api_shape: str = Field(min_length=1)
    parameter_shape: Tuple[int, ...] = ()
    applicability: Applicability
    semantic_features: Tuple[str, ...] = ()


class TemplateRetrieval(NonConfirmatoryArtifact):
    cwe_id: str = Field(pattern=r"^CWE-\d+$")
    query_identity: str = Field(min_length=1)
    ranking_profile_version: str = Field(min_length=1)
    template_ids: Tuple[str, ...]
    scores: Tuple[float, ...]

    @model_validator(mode="after")
    def matching_scores(self) -> "TemplateRetrieval":
        if len(self.template_ids) != len(self.scores):
            raise ValueError("each retrieved template requires a score")
        return self


class ReuseCandidate(ImmutableModel):
    component_id: str = Field(min_length=1)
    matches_required_interface: bool


class ReuseInventoryEntry(ImmutableModel):
    capability: str = Field(min_length=1)
    introduced_abstractions: Tuple[str, ...] = Field(min_length=1)
    required_interface: str = Field(min_length=1)
    evaluated_components: Tuple[ReuseCandidate, ...]
    selected_component: Optional[str] = None
    capability_gap: Optional[str] = None
    distinct_responsibility: Optional[str] = None

    @model_validator(mode="after")
    def select_first_match_or_gap(self) -> "ReuseInventoryEntry":
        first = next(
            (item.component_id for item in self.evaluated_components if item.matches_required_interface),
            None,
        )
        if first is not None:
            if self.selected_component != first:
                raise ValueError("selected_component must be the first matching HOS-LS component")
            if self.capability_gap is not None:
                raise ValueError("a matched component cannot also declare a capability gap")
        elif not self.capability_gap or not self.distinct_responsibility:
            raise ValueError("an unmatched capability requires a documented gap and responsibility")
        elif self.selected_component is not None:
            raise ValueError("an unmatched capability cannot select a component")
        return self


class ReuseInventory(Artifact):
    entries: Tuple[ReuseInventoryEntry, ...]


TASK_1_1_REUSE_ABSTRACTIONS = {
    "artifact schema validation": ("ImmutableModel", "Attribute", "Provenance"),
    "artifact identity contracts": ("Artifact",),
    "candidate and evidence contracts": (
        "CandidateType",
        "CandidateState",
        "Applicability",
        "Evidence",
        "Counterexample",
        "CandidateRecord",
    ),
    "discovery contracts": (
        "NonConfirmatoryArtifact",
        "DiscoveryObservation",
        "CandidateHypothesis",
        "DiscoveryStrategy",
    ),
    "repository code discovery": ("DiscoveryObservation", "CandidateHypothesis"),
    "repository configuration discovery": ("DiscoveryObservation", "CandidateHypothesis"),
    "repository call-graph discovery": ("DiscoveryObservation", "CandidateHypothesis"),
    "static discovery observations": ("DiscoveryObservation", "CandidateHypothesis"),
    "policy and declarative specification contracts": (
        "AcceptancePolicy",
        "ValidationPolicy",
        "ConstrainedDeclarativeSpecification",
        "ValidationResult",
    ),
    "static analysis execution": ("PathLocation", "PathEvidence"),
    "controllability tracing": ("SanitizerStatus",),
    "finding normalization": ("FindingStatus", "FindingClassification"),
    "catalog import": (
        "CatalogRecord",
        "CatalogImport",
        "NormalizedCatalogRecord",
        "IngestionRun",
    ),
    "catalog query": ("TaintTemplate", "TemplateRetrieval"),
    "RAG retrieval": ("TaintTemplate", "TemplateRetrieval"),
    "scope gating": ("ScopeDefinition", "ScopeResult", "ScopeStatus"),
    "reuse governance": ("ReuseCandidate", "ReuseInventoryEntry", "ReuseInventory"),
    "tooling telemetry": ("ToolingResolutionRecord",),
    "LLM fallback execution": ("LLMResolutionAttempt",),
    "artifact persistence": ("Artifact", "CandidateRecord", "ReuseInventory"),
    "benchmark and data-quality contracts": (
        "BenchmarkSample",
        "BenchmarkManifest",
        "DataQualityReport",
    ),
    "evaluation and reporting contracts": (
        "OperationalComplexity",
        "EvaluationTelemetry",
        "OptimizationExperiment",
        "EvaluationReport",
    ),
}

TASK_1_1_REUSE_CAPABILITIES = tuple(TASK_1_1_REUSE_ABSTRACTIONS)


def _reuse_candidate(component_id: str, matches: bool) -> ReuseCandidate:
    return ReuseCandidate(
        component_id=component_id,
        matches_required_interface=matches,
    )


def task_1_1_reuse_inventory(
    *, created_at: datetime, provenance: Provenance
) -> ReuseInventory:
    """Build the audited, repository-verified task-1.1 reuse baseline."""
    decisions = {
        "artifact schema validation": {
            "required": "validate frozen typed records and serialize them deterministically",
            "candidates": (_reuse_candidate("pydantic.BaseModel", True),),
            "selected": "pydantic.BaseModel",
            "responsibility": "add ECATSL domain schemas and immutable collection fields",
        },
        "artifact identity contracts": {
            "required": "derive and validate canonical content hashes and artifact identities",
            "candidates": (_reuse_candidate("pydantic.BaseModel", False),),
            "gap": "Pydantic validates and serializes models but does not assign ECATSL content identities",
            "responsibility": "derive canonical hashes and reject stale artifact identities",
        },
        "candidate and evidence contracts": {
            "required": "represent versioned ECATSL candidate, evidence, and provenance semantics",
            "candidates": (),
            "gap": "no existing HOS-LS model represents the ECATSL candidate and evidence lifecycle",
            "responsibility": "define the typed candidate and evidence records",
        },
        "discovery contracts": {
            "required": "normalize discovery output as provenance-bearing non-confirmatory records",
            "candidates": (
                _reuse_candidate("src.analyzers.ast_analyzer.ASTAnalyzer", False),
                _reuse_candidate("src.analyzers.config_scanner.ConfigScanner", False),
                _reuse_candidate("src.analyzers.sast_prefilter.SastPrefilter", False),
            ),
            "gap": "existing discovery outputs lack a shared provenance-bearing non-confirmatory contract",
            "responsibility": "normalize reusable discovery outputs without granting proof authority",
        },
        "repository code discovery": {
            "required": "parse repository code and expose structural observations",
            "candidates": (_reuse_candidate("src.analyzers.ast_analyzer.ASTAnalyzer", True),),
            "selected": "src.analyzers.ast_analyzer.ASTAnalyzer",
            "responsibility": "adapt structural results into DiscoveryObservation records",
        },
        "repository configuration discovery": {
            "required": "discover evidence from repository-contained configuration files",
            "candidates": (_reuse_candidate("src.analyzers.config_scanner.ConfigScanner", True),),
            "selected": "src.analyzers.config_scanner.ConfigScanner",
            "responsibility": "adapt configuration findings without treating route metadata as proof",
        },
        "repository call-graph discovery": {
            "required": "traverse a repository code call graph for generic entrypoint discovery",
            "candidates": (
                _reuse_candidate(
                    "src.analyzers.dependency_chain_analyzer.DependencyChainAnalyzer", False
                ),
                _reuse_candidate("src.ai.pure_ai.rag.graph_integrator.RAGGraphIntegrator", False),
            ),
            "gap": "the inspected graph components model package dependencies or vulnerability knowledge, not repository code calls",
            "responsibility": "provide a repository call-graph adapter only when a compatible graph is available",
        },
        "static discovery observations": {
            "required": "execute existing static analysis and expose normalized SAST observations",
            "candidates": (_reuse_candidate("src.analyzers.sast_prefilter.SastPrefilter", True),),
            "selected": "src.analyzers.sast_prefilter.SastPrefilter",
            "responsibility": "label static discovery observations as non-confirmatory until adapted to PathEvidence",
        },
        "policy and declarative specification contracts": {
            "required": "represent versioned ECATSL policies and constrained declarations",
            "candidates": (),
            "gap": "no existing HOS-LS contract represents ECATSL policy versions or constrained taint declarations",
            "responsibility": "define policy and declarative-only specification records",
        },
        "static analysis execution": {
            "required": "execute existing CodeQL/SAST analysis",
            "candidates": (_reuse_candidate("src.analyzers.sast_prefilter.SastPrefilter", True),),
            "selected": "src.analyzers.sast_prefilter.SastPrefilter",
            "responsibility": "normalize only qualifying supported results into PathEvidence",
        },
        "controllability tracing": {
            "required": "trace controllability and injection prerequisites",
            "candidates": (_reuse_candidate("src.analyzers.input_tracer.InputTracer", True),),
            "selected": "src.analyzers.input_tracer.InputTracer",
            "responsibility": "adapt complete qualifying traces into the stricter PathEvidence record",
        },
        "finding normalization": {
            "required": "convert scanner findings to a common representation",
            "candidates": (
                _reuse_candidate("src.analyzers.verification_adapter.VerificationAdapter", True),
            ),
            "selected": "src.analyzers.verification_adapter.VerificationAdapter",
            "responsibility": "apply the stricter ECATSL static-path confirmation predicate afterward",
        },
        "catalog import": {
            "required": "import catalog data into the existing local SQLite path",
            "candidates": (
                _reuse_candidate("src.nvd.catalog_import.CatalogImporter", True),
                _reuse_candidate("src.nvd.etl_batch_import.BatchImportManager", True),
            ),
            "selected": "src.nvd.catalog_import.CatalogImporter",
            "responsibility": "add versioned ECATSL metadata while retaining batch ETL compatibility",
        },
        "catalog query": {
            "required": "query local SQLite CWE and CVE knowledge",
            "candidates": (_reuse_candidate("src.nvd.nvd_query_adapter.NVDQueryAdapter", True),),
            "selected": "src.nvd.nvd_query_adapter.NVDQueryAdapter",
            "responsibility": "adapt query results into non-confirmatory template retrieval records",
        },
        "RAG retrieval": {
            "required": "retrieve ranked local knowledge using existing hybrid RAG",
            "candidates": (
                _reuse_candidate("src.ai.pure_ai.rag.hybrid_retriever.HybridRetriever", True),
            ),
            "selected": "src.ai.pure_ai.rag.hybrid_retriever.HybridRetriever",
            "responsibility": "record retrieval provenance and keep results non-confirmatory",
        },
        "scope gating": {
            "required": "apply a versioned Python/CWE request gate before downstream work",
            "candidates": (),
            "gap": "no existing HOS-LS component provides the required versioned language/CWE gate",
            "responsibility": "short-circuit unsupported requests and version scope changes",
        },
        "reuse governance": {
            "required": "record ordered first-match reuse decisions before implementation",
            "candidates": (),
            "gap": "no existing HOS-LS component records versioned ordered reuse decisions",
            "responsibility": "retain selected components or precise capability gaps",
        },
        "tooling telemetry": {
            "required": "record model identity, tokens, duration, and success for AI calls",
            "candidates": (_reuse_candidate("src.ai.token_tracker.TokenTracker", True),),
            "selected": "src.ai.token_tracker.TokenTracker",
            "responsibility": "link existing telemetry to immutable tooling outcomes and candidate provenance",
        },
        "LLM fallback execution": {
            "required": "run the existing PureAI multi-agent analysis capability",
            "candidates": (
                _reuse_candidate("src.ai.pure_ai_analyzer.PureAIAnalyzer", True),
                _reuse_candidate("src.ai.pure_ai.multi_agent_pipeline.MultiAgentPipeline", True),
            ),
            "selected": "src.ai.pure_ai_analyzer.PureAIAnalyzer",
            "responsibility": "gate invocation on terminal unresolved tooling and retain attempt lineage",
        },
        "artifact persistence": {
            "required": "provide an existing SQLite execution and transaction boundary",
            "candidates": (
                _reuse_candidate("src.db.connection.DatabaseManager", True),
                _reuse_candidate("src.nvd.db.sqlite_connection.SQLiteConnection", True),
            ),
            "selected": "src.db.connection.DatabaseManager",
            "responsibility": "add append-only ECATSL tables and repository semantics without a new store",
        },
        "benchmark and data-quality contracts": {
            "required": "load, classify, and stratify existing benchmark inputs",
            "candidates": (_reuse_candidate("bench.prepare_benchmark_data", True),),
            "selected": "bench.prepare_benchmark_data",
            "responsibility": "add immutable manifests, integrity outcomes, lineage, and exclusions",
        },
        "evaluation and reporting contracts": {
            "required": "produce immutable ECATSL metrics, experiments, and claim-evidence reports",
            "candidates": (_reuse_candidate("bench.benchmark", False),),
            "gap": "bench.benchmark emits scorecards but not immutable ECATSL experiment and claim-evidence records",
            "responsibility": "represent verified metrics, complexity, experiments, and evidence limitations",
        },
    }

    entries = []
    for capability in TASK_1_1_REUSE_CAPABILITIES:
        decision = decisions[capability]
        entries.append(
            ReuseInventoryEntry(
                capability=capability,
                introduced_abstractions=TASK_1_1_REUSE_ABSTRACTIONS[capability],
                required_interface=decision["required"],
                evaluated_components=decision["candidates"],
                selected_component=decision.get("selected"),
                capability_gap=decision.get("gap"),
                distinct_responsibility=decision["responsibility"],
            )
        )
    return ReuseInventory(
        version="1.1.1",
        created_at=created_at,
        provenance=provenance,
        entries=tuple(entries),
    )


class ToolingResolutionRecord(Artifact):
    capability_id: str = Field(min_length=1)
    capability_version: str = Field(min_length=1)
    input_identity: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    latency_seconds: float = Field(ge=0.0)
    monetary_cost: Optional[float] = Field(default=None, ge=0.0)
    failure_data: Optional[str] = None


class LLMResolutionAttempt(Artifact):
    model_identity: str = Field(min_length=1)
    input_identity: str = Field(min_length=1)
    output_identity: Optional[str] = None
    token_count: int = Field(ge=0)
    monetary_cost: float = Field(ge=0.0)
    latency_seconds: float = Field(ge=0.0)
    outcome: str = Field(min_length=1)
    unresolved_tooling_record_ids: Tuple[str, ...]
    failure_data: Optional[str] = None


class PipelineStage(Artifact):
    """One deterministic stage in the assembled ECATSL pipeline.

    ``stage_identity`` is the deterministic consolidation key: two stages with
    the same identity, inputs, purpose, and outputs are duplicates. The first
    occurrence is canonical; equal later occurrences are retained with
    ``duplicate_of_artifact_id`` pointing at the canonical stage. When
    consolidation persistence fails, both stages are retained and
    ``consolidation_failure_artifact_id`` links the audit-failure record.
    """

    stage_identity: str = Field(min_length=1)
    input_artifact_ids: Tuple[str, ...]
    transformation_purpose: str = Field(min_length=1)
    output_artifact_ids: Tuple[str, ...]
    duplicate_of_artifact_id: Optional[str] = None
    consolidation_failure_artifact_id: Optional[str] = None

    @model_validator(mode="after")
    def consolidation_binding_is_consistent(self) -> "PipelineStage":
        if self.duplicate_of_artifact_id is None and self.consolidation_failure_artifact_id is not None:
            raise ValueError("a consolidation failure requires a duplicate binding")
        if self.duplicate_of_artifact_id is not None and self.consolidation_failure_artifact_id is None:
            raise ValueError("a duplicate stage must record its consolidation outcome")
        if self.duplicate_of_artifact_id == self.artifact_id:
            raise ValueError("a stage cannot duplicate itself")
        return self


class BenchmarkSample(ImmutableModel):
    sample_id: str = Field(min_length=1)
    classification: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    project_time_group: str = Field(min_length=1)
    content_hash: str = Field(min_length=1)
    pair_id: Optional[str] = None


class BenchmarkManifest(Artifact):
    samples: Tuple[BenchmarkSample, ...]
    catalog_record_ids: Tuple[str, ...] = ()
    split_assignments: Tuple[Attribute, ...] = ()


class DataQualityReport(Artifact):
    completeness: Tuple[Attribute, ...]
    validity: Tuple[Attribute, ...]
    integrity_results: Tuple[Attribute, ...]
    duplicate_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)
    exclusion_reasons: Tuple[str, ...] = ()


class OperationalComplexity(ImmutableModel):
    configured_adapters: int = Field(ge=0)
    pipeline_stages: int = Field(ge=0)
    external_service_dependencies: int = Field(ge=0)
    manual_execution_steps: int = Field(ge=0)


class EvaluationTelemetry(ImmutableModel):
    latency_seconds: float = Field(ge=0.0)
    llm_tokens: int = Field(ge=0)
    llm_monetary_cost: float = Field(ge=0.0)
    complexity: OperationalComplexity


class OptimizationExperiment(Artifact):
    baseline_configuration_id: str = Field(min_length=1)
    changed_configuration_id: str = Field(min_length=1)
    benchmark_manifest_id: str = Field(min_length=1)
    strata: Tuple[str, ...]
    measured_differences: Tuple[Attribute, ...]


class EvaluationReport(Artifact):
    benchmark_manifest_id: str = Field(min_length=1)
    data_quality_report_id: str = Field(min_length=1)
    verified_metrics: Tuple[Attribute, ...]
    telemetry: EvaluationTelemetry
    reuse_inventory_version: str = Field(min_length=1)
    evidence_limitations: Tuple[str, ...] = ()
