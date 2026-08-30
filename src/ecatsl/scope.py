"""Versioned initial-scope definition and short-circuit gate for ECATSL."""

from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional, Tuple

from pydantic import Field

from .models import Artifact, Provenance


INITIAL_LANGUAGE = "python"
INITIAL_CWES = ("CWE-89", "CWE-78", "CWE-918")


class ScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class ScopeDefinition(Artifact):
    language: str = Field(min_length=1)
    cwe_ids: Tuple[str, ...] = Field(min_length=2, max_length=3)
    versioning_complete: bool = True
    versioning_error: Optional[str] = None


class ScopeResult(Artifact):
    status: ScopeStatus
    requested_language: str = Field(min_length=1)
    requested_cwe_ids: Tuple[str, ...]
    reason: Optional[str] = None
    downstream_processing_allowed: bool
    scope_definition_id: str = Field(min_length=1)


def initial_scope(*, created_at: datetime, provenance: Provenance) -> ScopeDefinition:
    """Return the shipped Python-only scope with exactly the three approved CWEs."""
    return ScopeDefinition(
        version="1",
        created_at=created_at,
        provenance=provenance,
        language=INITIAL_LANGUAGE,
        cwe_ids=INITIAL_CWES,
    )


def check_scope(
    scope: ScopeDefinition,
    language: str,
    cwe_ids: Tuple[str, ...],
    *,
    created_at: datetime,
    provenance: Provenance,
) -> ScopeResult:
    """Gate a request before any candidate, compiler, adapter, or finding work."""
    normalized_language = language.strip().lower()
    unsupported = tuple(cwe for cwe in cwe_ids if cwe not in scope.cwe_ids)
    in_scope = normalized_language == scope.language and not unsupported
    reason = None
    if normalized_language != scope.language:
        reason = "unsupported language: " + language
    elif unsupported:
        reason = "unsupported CWE mappings: " + ", ".join(unsupported)
    return ScopeResult(
        version=scope.version,
        created_at=created_at,
        provenance=provenance,
        status=ScopeStatus.IN_SCOPE if in_scope else ScopeStatus.OUT_OF_SCOPE,
        requested_language=language,
        requested_cwe_ids=cwe_ids,
        reason=reason,
        downstream_processing_allowed=in_scope,
        scope_definition_id=scope.artifact_id,
    )


def revise_scope(
    current: ScopeDefinition,
    *,
    language: str,
    cwe_ids: Tuple[str, ...],
    provenance: Provenance,
    created_at: Optional[datetime] = None,
    version_factory: Callable[[ScopeDefinition], str] = lambda scope: str(int(scope.version) + 1),
) -> ScopeDefinition:
    """Create a predecessor-linked revision, retaining provenance if versioning fails."""
    timestamp = created_at or datetime.now(timezone.utc)
    try:
        version = version_factory(current)
        return ScopeDefinition(
            version=version,
            created_at=timestamp,
            predecessor_id=current.artifact_id,
            provenance=provenance,
            language=language,
            cwe_ids=cwe_ids,
        )
    except Exception as exc:
        return ScopeDefinition(
            version=current.version + ".incomplete",
            created_at=timestamp,
            predecessor_id=current.artifact_id,
            provenance=provenance,
            language=language,
            cwe_ids=cwe_ids,
            versioning_complete=False,
            versioning_error=str(exc),
        )
