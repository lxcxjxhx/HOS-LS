"""Evidence-Constrained Adaptive Taint Specification Learning.

Production surface (task 8.1). Catalog, RAG, LLM, template, and discovery
knowledge are non-confirmatory; only a complete ``PathEvidence`` normalized
by a supported static adapter may confirm a finding.
"""

from .artifact_repository import ArtifactRepository, AuditFailureRecord
from .candidate_ledger import CandidateLedger
from .compiler import DeclarativeCompiler
from .config import (
    ECATSLConfig,
    SUPPORTED_RANKING_PROFILES,
    SUPPORTED_STATIC_ADAPTER_IDS,
)
from .confirmation import FindingConfirmationService
from .discovery import DiscoveryPolicy, RepositoryDiscovery
from .models import (
    AcceptancePolicy,
    PathEvidence,
    Provenance,
    ValidationPolicy,
)
from .policies import evaluate_acceptance, apply_validation
from .scope import (
    INITIAL_CWES,
    INITIAL_LANGUAGE,
    ScopeDefinition,
    ScopeResult,
    ScopeStatus,
    check_scope,
    initial_scope,
    revise_scope,
)
from .service import (
    AnalysisRequest,
    AnalysisResult,
    CompiledCandidate,
    ECATSLService,
    ValidationOutcome,
)
from .static_adapters import (
    CodeQLSastAdapter,
    InputTracerAdapter,
    NormalizationOutcome,
    NormalizationResult,
    supported as adapter_supported,
)
from .static_validation import StaticValidationService
from .tooling_resolver import (
    CapabilityRun,
    ToolingFirstResolver,
    ToolingFirstResolverError,
    ToolingResolutionBundle,
)

__all__ = [
    # Scope (requirements 6.1-6.3)
    "INITIAL_CWES",
    "INITIAL_LANGUAGE",
    "ScopeDefinition",
    "ScopeResult",
    "ScopeStatus",
    "check_scope",
    "initial_scope",
    "revise_scope",
    # Configuration and validation (task 8.1)
    "ECATSLConfig",
    "SUPPORTED_RANKING_PROFILES",
    "SUPPORTED_STATIC_ADAPTER_IDS",
    # Service and pipeline contracts (tasks 5.3, 5.4)
    "ECATSLService",
    "AnalysisRequest",
    "AnalysisResult",
    "CompiledCandidate",
    "ValidationOutcome",
    # Persistence and contracts
    "ArtifactRepository",
    "AuditFailureRecord",
    "CandidateLedger",
    "DeclarativeCompiler",
    "FindingConfirmationService",
    "StaticValidationService",
    "PathEvidence",
    "Provenance",
    "AcceptancePolicy",
    "ValidationPolicy",
    "evaluate_acceptance",
    "apply_validation",
    # Static adapter surface (task 4.x)
    "InputTracerAdapter",
    "CodeQLSastAdapter",
    "NormalizationOutcome",
    "NormalizationResult",
    "adapter_supported",
    # Tooling-first resolution (task 5.1)
    "ToolingFirstResolver",
    "ToolingFirstResolverError",
    "ToolingResolutionBundle",
    "CapabilityRun",
    # Generic discovery (task 6.x)
    "RepositoryDiscovery",
    "DiscoveryPolicy",
]
