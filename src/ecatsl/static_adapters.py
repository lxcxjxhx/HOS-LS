"""Supported static-adapter and normalization contracts (ECATSL).

Task 4.1: Define supported adapter identity/version/support checks and
normalization outcomes for compilation errors, no path, parameter mismatch,
sanitizer evidence, incomplete path, unsupported output, and complete static
path. Normalization defaults to a retained non-confirmatory ``ValidationResult``
and never infers missing path elements from discovery, catalog, RAG, or LLM data.

Only complete, normalized ``PathEvidence`` produced by a supported static
adapter may confirm a finding (requirements 4.1-4.3, 4.5, 4.8, 11.12).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any, Optional, Protocol, Sequence, Tuple, runtime_checkable

from .models import (
    PathEvidence,
    PathLocation,
    Provenance,
    SanitizerStatus,
    ValidationResult,
)


class NormalizationOutcome(str, Enum):
    """Terminal normalization outcomes for one static-adapter result.

    Only ``COMPLETE_PATH`` may carry confirmatory ``PathEvidence``; every other
    outcome retains a non-confirmatory ``ValidationResult``.
    """

    COMPILATION_ERROR = "COMPILATION_ERROR"
    NO_PATH = "NO_PATH"
    PARAMETER_MISMATCH = "PARAMETER_MISMATCH"
    SANITIZER_EVIDENCE = "SANITIZER_EVIDENCE"
    INCOMPLETE_PATH = "INCOMPLETE_PATH"
    UNSUPPORTED_OUTPUT = "UNSUPPORTED_OUTPUT"
    COMPLETE_PATH = "COMPLETE_PATH"


_CONFIRMATORY_OUTCOME = NormalizationOutcome.COMPLETE_PATH


@dataclass(frozen=True)
class NormalizationResult:
    """One normalized adapter result.

    ``validation`` is always retained; ``path_evidence`` is present only for a
    complete supported static path. Missing elements are never synthesized.
    """

    outcome: NormalizationOutcome
    validation: ValidationResult
    path_evidence: Optional[PathEvidence] = None
    reason: str = ""
    raw_output_identity: str = ""
    observed_location_identities: Tuple[str, ...] = ()

    @property
    def confirmatory(self) -> bool:
        return self.outcome is _CONFIRMATORY_OUTCOME and self.path_evidence is not None


def _raw_output_identity(raw: Any) -> str:
    """Content-hash of the raw adapter output for provenance retention."""
    try:
        digest = sha256(
            str(raw).encode("utf-8", errors="replace")
        ).hexdigest()
    except Exception:
        digest = sha256(b"<unrepr-able>").hexdigest()
    return f"sha256:{digest}"


def build_path_evidence(
    *,
    adapter_id: str,
    adapter_version: str,
    provenance: Provenance,
    source: PathLocation,
    source_provenance: Provenance,
    propagation_steps: Sequence[PathLocation],
    sink: PathLocation,
    sanitizer_status: SanitizerStatus,
    static_evidence_identity: str,
) -> PathEvidence:
    """Construct ``PathEvidence`` only when every strict precondition holds.

    Requirements 4.1-4.2: ordered non-empty propagation, source provenance,
    sink, sanitizer status, and raw static evidence identity must all be present
    before constructing the existing ``PathEvidence`` model. Any missing element
    raises ``ValueError`` so callers retain a non-confirmatory result instead.
    """
    if not adapter_id.strip():
        raise ValueError("adapter_id must identify a supported static adapter")
    if not adapter_version.strip():
        raise ValueError("adapter_version must identify a supported adapter version")
    if not static_evidence_identity.strip():
        raise ValueError("raw static evidence identity is required")
    steps = tuple(propagation_steps)
    if not steps:
        raise ValueError("ordered non-empty propagation is required")
    if any(step is None or not step.location.strip() for step in steps):
        raise ValueError("every propagation step must carry a non-blank location")
    if source is None or not source.location.strip():
        raise ValueError("a non-blank source location is required")
    if sink is None or not sink.location.strip():
        raise ValueError("a non-blank sink location is required")
    if source_provenance is None:
        raise ValueError("source provenance is required")
    return PathEvidence(
        version="1",
        created_at=datetime.now(timezone.utc),
        provenance=provenance,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        supported_adapter=True,
        source=source,
        source_provenance=source_provenance,
        propagation_steps=steps,
        sink=sink,
        sanitizer_status=sanitizer_status,
        static_evidence_identity=static_evidence_identity,
    )


@runtime_checkable
class StaticAdapterContract(Protocol):
    """Supported static adapter contract (identity, support, normalization)."""

    adapter_id: str
    adapter_version: str

    def supports(
        self, applicability: Any, semantics: Sequence[str]
    ) -> bool:
        """Return True only for declared role/API/positions this adapter serves."""
        ...

    def normalize(self, raw: Any, *, provenance: Provenance) -> NormalizationResult:
        """Normalize raw adapter output to a retained non-confirmatory result or
        complete ``PathEvidence``. Never infer missing path elements."""
        ...


def supported(adapter: StaticAdapterContract, supported_set: Sequence[Tuple[str, str]]) -> bool:
    """True when the adapter identity/version is explicitly allowlisted."""
    return (adapter.adapter_id, adapter.adapter_version) in set(supported_set)


# Keep module importable and delegating-only: actual InputTracer/SastPrefilter
# delegation lives in the concrete adapters (tasks 4.2/4.3) so this contract file
# never imports scanners or tracing implementations.
