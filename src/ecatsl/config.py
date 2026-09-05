"""ECATSL configuration validation (task 8.1 production surface).

Validates scope, policy versions, SQLite configuration, supported static
adapter declarations, and deterministic ranking profiles at construction
time.  Catalog, discovery, LLM, RAG, and template providers are
non-confirmatory and can never be configured as confirmation providers.
User-authored brittle per-route enumeration is rejected while generic
repository/config/call-graph/static/template discovery strategies stay
allowed (requirements 2.7-2.8, 6.1-6.3, 11.10-11.13).
"""

from pydantic import BaseModel, ConfigDict, model_validator

from .scope import INITIAL_CWES, INITIAL_LANGUAGE

#: Adapter identities shipped by ``src/ecatsl/static_adapters.py``.
SUPPORTED_STATIC_ADAPTER_IDS = ("input-tracer", "codeql-sast")

#: Deterministic ranking profiles shipped by ``src/nvd/nvd_query_adapter.py``
#: (template-ranking/v1) and ``src/ecatsl/discovery.py``
#: (discovery-ranking/v1).
SUPPORTED_RANKING_PROFILES = ("template-ranking/v1", "discovery-ranking/v1")

#: Provider kinds that are hypotheses/explanatory support only and must never
#: be configured as the confirmation provider.
_NON_CONFIRMATORY_PROVIDER_KINDS = frozenset(
    {"catalog", "discovery", "llm", "rag", "template"}
)


class ECATSLConfig(BaseModel):
    """Validated production configuration for wiring ``ECATSLService``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    database_path: str
    language: str = INITIAL_LANGUAGE
    cwe_ids: tuple[str, ...] = INITIAL_CWES
    acceptance_policy_version: str = "1"
    validation_policy_version: str = "1"
    compiler_version: str = "1"
    discovery_strategies: tuple[dict, ...] = ()
    confirmation_provider: str = "static_adapter"
    supported_static_adapters: tuple[tuple[str, str], ...] = (
        ("input-tracer", "1"),
        ("codeql-sast", "1"),
    )
    ranking_profiles: tuple[str, ...] = ("template-ranking/v1",)

    @model_validator(mode="after")
    def boundaries(self):
        # Requirement 6.1-6.3: exactly the shipped narrow initial scope.
        if self.language != INITIAL_LANGUAGE or tuple(self.cwe_ids) != INITIAL_CWES:
            raise ValueError("unsupported initial scope")
        # Requirement 7.x: reuse the shared SQLite catalog path; no external
        # catalog store is permitted.
        if not self.database_path.strip():
            raise ValueError("database_path must identify the shared SQLite catalog")
        # Requirement 4.1-4.3: only supported static adapters may confirm.
        if self.confirmation_provider != "static_adapter":
            raise ValueError("only static adapters may confirm")
        provider_kind = self.confirmation_provider.split(":", 1)[0].strip().lower()
        if provider_kind in _NON_CONFIRMATORY_PROVIDER_KINDS:
            raise ValueError(
                f"{provider_kind} providers are non-confirmatory and cannot confirm"
            )
        # Requirement 11.10-11.11: generic strategies allowed, brittle
        # user-maintained per-route enumeration rejected.
        for item in self.discovery_strategies:
            if not isinstance(item, dict) or not str(item.get("strategy", "")).strip():
                raise ValueError("discovery strategies require a generic strategy name")
            if item.get("routes"):
                raise ValueError("user-authored per-route configuration unsupported")
        # Requirement 2.7-2.8: supported adapters are explicit identity/version
        # allowlist entries against the shipped adapter surface.
        for entry in self.supported_static_adapters:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 2
                or not str(entry[0]).strip()
                or not str(entry[1]).strip()
            ):
                raise ValueError(
                    "supported static adapters must be (identity, version) pairs"
                )
            if entry[0] not in SUPPORTED_STATIC_ADAPTER_IDS:
                raise ValueError(f"unsupported static adapter: {entry[0]}")
        if not self.acceptance_policy_version.strip():
            raise ValueError("acceptance_policy_version must be non-blank")
        if not self.validation_policy_version.strip():
            raise ValueError("validation_policy_version must be non-blank")
        # Deterministic ranking profiles only (requirements 11.8-11.9).
        for profile in self.ranking_profiles:
            if profile not in SUPPORTED_RANKING_PROFILES:
                raise ValueError(f"unsupported ranking profile: {profile}")
        return self
