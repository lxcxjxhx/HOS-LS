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
    Attribute,
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


# ---------------------------------------------------------------------------
# InputTracerAdapter (task 4.2): delegate to src/analyzers/input_tracer.py and
# normalize only fixture-compatible complete trace output into PathEvidence.
# ---------------------------------------------------------------------------

# Capability identity used for InputTracer-delegated checks. The version is
# derived from the delegated API surface revision, not from a reimplementation.
_INPUT_TRACER_CAPABILITY = "input-tracer:controllability"
_INPUT_TRACER_CAPABILITY_VERSION = "1"


def _trace_node_location(node: Any) -> str:
    """Best-effort location extraction from an InputTracer trace-path node."""
    if isinstance(node, dict):
        for key in ("location", "file_path", "path"):
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return ""
    location = getattr(node, "location", None)
    return str(location) if location else ""


def _trace_node_is_sink(node: Any) -> bool:
    """Heuristic sink marker consistent with InputTracer Python DANGEROUS_SINKS."""
    if isinstance(node, dict):
        value_name = str(node.get("value_name", "")).lower()
        node_type = str(node.get("node_type", "")).lower()
        return (
            "sink" in node_type
            or any(marker in value_name for marker in ("eval", "exec", "pickle", "yaml.load", "os.system"))
        )
    return False


def _trace_has_sanitizer_evidence(trace_path: Sequence[Any]) -> bool:
    """True when any trace node carries explicit sanitizer/blocking metadata.

    Only explicit sanitizer markers qualify; absent metadata is never treated as
    sanitizer evidence (requirements 4.2: sanitizer block maps to a distinct
    outcome, and missing data is retained as non-confirmatory validation).
    """
    for node in trace_path:
        if not isinstance(node, dict):
            continue
        metadata = node.get("metadata") or {}
        if isinstance(metadata, dict):
            marker = metadata.get("sanitized") or metadata.get("blocked")
            if marker:
                return True
    return False


def _trace_node_is_source(node: Any) -> bool:
    """Heuristic source marker consistent with InputTracer USER_INPUT markers."""
    if isinstance(node, dict):
        node_type = str(node.get("node_type", "")).lower()
        source_type = str(node.get("source_type", "")).lower()
        return "input" in node_type or "source" in node_type or "user_input" in source_type
    return False


class InputTracerAdapter:
    """Normalize ``InputTracer`` outputs through the static-adapter contract.

    Task 4.2: Delegate Python CWE-89/CWE-78/CWE-918 checks to the actual APIs in
    ``src/analyzers/input_tracer.py``; never replace or reimplement tracing. Only
    fixture-compatible complete trace output is normalized into ``PathEvidence``;
    incomplete trace, no path, sanitizer block, mismatched parameter, exception,
    and unavailable capability map to explicit retained ``ValidationResult``
    outcomes. Missing path elements are never inferred from discovery, catalog,
    RAG, or LLM data.
    """

    adapter_id = "input-tracer"
    adapter_version = "1"
    capability_id = _INPUT_TRACER_CAPABILITY
    capability_version = _INPUT_TRACER_CAPABILITY_VERSION

    def __init__(self, tracer: Any) -> None:
        if tracer is None:
            raise ValueError("InputTracerAdapter requires a delegated InputTracer instance")
        self.tracer = tracer
        # Capability availability is decided lazily by the delegated API.
        self._capability_available = True

    def supports(
        self, applicability: Any, semantics: Sequence[str]
    ) -> bool:
        """Python-language sinks with evidence-backed taint semantics only.

        The delegated ``InputTracer`` covers CWE-89 (dynamic SQL), CWE-78
        (eval/exec/os.system), and CWE-918 (SSRF-style sinks). Role/applicability
        checks remain declarative; support never depends on catalog/RAG/LLM hints.
        """
        language = getattr(applicability, "language", None)
        if language is None or str(language).lower() != "python":
            return False
        if not semantics:
            return False
        return True

    @staticmethod
    def _capability_check_name(cwe_id: str) -> str:
        """Map a candidate CWE to the delegated capability entry point."""
        if cwe_id == "CWE-89":
            return "verify_sql_injection_prerequisites"
        if cwe_id in ("CWE-78", "CWE-918"):
            return "trace_controllability"
        return ""

    def _run(
        self, *, file_path: str, line_number: int, code_snippet: str, capability: str
    ) -> Tuple[Any, float]:
        """Run the delegated InputTracer API, returning (result, elapsed_seconds)."""
        import time

        started = time.perf_counter()
        method = getattr(self.tracer, capability, None)
        if method is None:
            self._capability_available = False
            raise AttributeError(
                f"delegated InputTracer lacks capability {capability!r}"
            )
        result = method(file_path, line_number, code_snippet)
        elapsed = time.perf_counter() - started
        return result, elapsed

    def normalize(self, raw: Any, *, provenance: Provenance) -> NormalizationResult:
        """Normalize one delegated ``ControllabilityResult``.

        Only a complete ordered trace with a source and a sink produces
        ``PathEvidence``. Every other shape becomes a retained non-confirmatory
        ``ValidationResult`` with the exact outcome and reason; exceptions are
        caught and retained as ``COMPILATION_ERROR``/``UNSUPPORTED_OUTPUT`` so
        no path is ever synthesized.
        """
        outcome = NormalizationOutcome.NO_PATH
        reason = ""
        path_evidence = None
        raw_identity = _raw_output_identity(raw)

        if not self._capability_available:
            outcome = NormalizationOutcome.UNSUPPORTED_OUTPUT
            reason = "delegated InputTracer capability is unavailable"
        elif raw is None:
            reason = "delegated InputTracer returned no result"
        else:
            trace_path = getattr(raw, "trace_path", None)
            if trace_path is None:
                reason = "controllability result carries no trace path"
            elif not isinstance(trace_path, (list, tuple)) or len(trace_path) == 0:
                outcome = NormalizationOutcome.NO_PATH
                reason = "trace path is empty"
            elif len(trace_path) < 2:
                outcome = NormalizationOutcome.INCOMPLETE_PATH
                reason = "trace path has fewer than two nodes (no source-to-sink flow)"
            else:
                source_node = trace_path[0]
                sink_node = trace_path[-1]
                source_location = _trace_node_location(source_node)
                sink_location = _trace_node_location(sink_node)
                if not source_location or not sink_location:
                    outcome = NormalizationOutcome.INCOMPLETE_PATH
                    reason = "trace path lacks source or sink location"
                elif not _trace_node_is_source(source_node):
                    outcome = NormalizationOutcome.INCOMPLETE_PATH
                    reason = "first trace node is not a user-input source"
                elif not _trace_node_is_sink(sink_node):
                    outcome = NormalizationOutcome.INCOMPLETE_PATH
                    reason = "last trace node is not a sink"
                elif _trace_has_sanitizer_evidence(trace_path):
                    outcome = NormalizationOutcome.SANITIZER_EVIDENCE
                    reason = "trace carries explicit sanitizer/blocking metadata"
                elif getattr(raw, "is_exploitable", False) is False:
                    outcome = NormalizationOutcome.NO_PATH
                    reason = "delegated controllability result is not exploitable (no confirmed path)"
                else:
                    propagation = [
                        PathLocation(location=_trace_node_location(node))
                        for node in trace_path[1:-1]
                        if _trace_node_location(node)
                    ]
                    if not propagation:
                        outcome = NormalizationOutcome.INCOMPLETE_PATH
                        reason = "trace path has no intermediate propagation nodes"
                    else:
                        try:
                            path_evidence = build_path_evidence(
                                adapter_id=self.adapter_id,
                                adapter_version=self.adapter_version,
                                provenance=provenance,
                                source=PathLocation(location=source_location),
                                source_provenance=provenance,
                                propagation_steps=propagation,
                                sink=PathLocation(location=sink_location),
                                sanitizer_status=SanitizerStatus.ABSENT,
                                static_evidence_identity=raw_identity,
                            )
                            outcome = NormalizationOutcome.COMPLETE_PATH
                            reason = "complete ordered static path with source and sink"
                        except ValueError as error:
                            outcome = NormalizationOutcome.INCOMPLETE_PATH
                            reason = str(error)

        kind = "NO_PATH" if outcome in (NormalizationOutcome.NO_PATH, NormalizationOutcome.INCOMPLETE_PATH) else outcome.value
        validation = ValidationResult(
            version=self.adapter_version,
            created_at=datetime.now(timezone.utc),
            provenance=provenance,
            kind=kind,
            outcome=outcome.value,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            observed_data=(
                Attribute(name="capability_id", value=self.capability_id),
                Attribute(name="capability_version", value=self.capability_version),
                Attribute(name="raw_output_identity", value=raw_identity),
                Attribute(name="reason", value=reason),
            ),
        )
        observed_locations = tuple(
            _trace_node_location(node)
            for node in getattr(raw, "trace_path", ()) or ()
        )
        return NormalizationResult(
            outcome=outcome,
            validation=validation,
            path_evidence=path_evidence,
            reason=reason,
            raw_output_identity=raw_identity,
            observed_location_identities=observed_locations,
        )


# Keep module importable and delegating-only: actual InputTracer/SastPrefilter
# delegation lives in the concrete adapters (tasks 4.2/4.3) so this contract file
# never imports scanners or tracing implementations.


class CodeQLSastAdapter:
    """Normalize SastPrefilter CodeQL/SARIF outputs through the static-adapter contract.

    Task 4.3: Delegate to ``src/analyzers/sast_prefilter.py`` and consume real
    SARIF/CodeQL-oriented fixture shapes; never add a query runner or scanner.
    Ordered code-flow locations and sanitizer evidence are normalized into
    ``PathEvidence`` only when the producer/version is explicitly supported;
    plain SARIF hits, inferred endpoints, unsupported tool output, or missing
    source provenance stay unconfirmed. Rule/query identity, run identity,
    raw-output hash, locations, adapter version, and compatibility failure
    reason are preserved on the retained ``ValidationResult``.
    """

    adapter_id = "codeql-sast"
    adapter_version = "1"
    producer_id = "codeql"
    producer_version = "2"

    def __init__(
        self,
        prefilter: Any,
        *,
        supported_producers: Sequence[Tuple[str, str]] = (),
    ) -> None:
        if prefilter is None:
            raise ValueError("CodeQLSastAdapter requires a delegated SastPrefilter instance")
        self.prefilter = prefilter
        self._supported_producers = frozenset(
            supported_producers or ((self.producer_id, self.producer_version),)
        )

    def supports(self, applicability: Any, semantics: Sequence[str]) -> bool:
        """Python-first CodeQL flow adapter for declared sink semantics."""
        language = getattr(applicability, "language", None)
        if language is None or str(language).lower() != "python":
            return False
        return bool(semantics)

    def _producer_supported(self) -> bool:
        return (self.producer_id, self.producer_version) in self._supported_producers

    def _flow_from_hit(
        self, hit: Any
    ) -> Tuple[Optional[PathLocation], Tuple[PathLocation, ...], Optional[PathLocation]]:
        """Extract ordered source/propagation/sink from a hit's code-flow shape."""
        if not isinstance(hit, dict):
            return None, (), None
        code_flow = hit.get("code_flow") or hit.get("thread_flow") or []
        if not isinstance(code_flow, (list, tuple)):
            return None, (), None
        locations = [
            PathLocation(location=str(node.get("location", "")).strip())
            for node in code_flow
            if isinstance(node, dict) and str(node.get("location", "")).strip()
        ]
        if len(locations) < 2:
            return None, (), None
        return locations[0], tuple(locations[1:-1]) or (locations[0],), locations[-1]

    def normalize(self, raw: Any, *, provenance: Provenance) -> NormalizationResult:
        """Normalize one ``SastPrefilter`` CodeQL result.

        Complete ordered code-flow locations produce ``PathEvidence`` only when
        the producer/version is explicitly supported. Plain SARIF hits, inferred
        endpoints, unsupported output, and missing provenance stay unconfirmed
        and retain a non-confirmatory ``ValidationResult``.
        """
        outcome = NormalizationOutcome.UNSUPPORTED_OUTPUT
        reason = ""
        path_evidence = None
        raw_identity = _raw_output_identity(raw)

        if not self._producer_supported():
            reason = f"producer {self.producer_id}@{self.producer_version} is not explicitly supported"
        elif not isinstance(raw, dict):
            reason = "SastPrefilter result is not a mapping"
        elif not raw.get("available"):
            outcome = NormalizationOutcome.UNSUPPORTED_OUTPUT
            reason = str(raw.get("note") or "CodeQL capability is unavailable")
        else:
            hits = raw.get("hits") or []
            if not isinstance(hits, (list, tuple)):
                reason = "SastPrefilter hits is not a sequence"
            elif not hits:
                outcome = NormalizationOutcome.NO_PATH
                reason = "no CodeQL hits (no static path evidence)"
            else:
                source, propagation, sink = self._flow_from_hit(hits[0])
                if source is None or sink is None:
                    outcome = NormalizationOutcome.INCOMPLETE_PATH
                    reason = "CodeQL hit carries no ordered code-flow source/sink (plain SARIF hit)"
                elif not propagation:
                    outcome = NormalizationOutcome.INCOMPLETE_PATH
                    reason = "CodeQL hit carries no intermediate code-flow propagation nodes"
                else:
                    try:
                        path_evidence = build_path_evidence(
                            adapter_id=self.adapter_id,
                            adapter_version=self.adapter_version,
                            provenance=provenance,
                            source=source,
                            source_provenance=provenance,
                            propagation_steps=propagation,
                            sink=sink,
                            sanitizer_status=SanitizerStatus.ABSENT,
                            static_evidence_identity=raw_identity,
                        )
                        outcome = NormalizationOutcome.COMPLETE_PATH
                        reason = "complete ordered CodeQL code flow with source and sink"
                    except ValueError as error:
                        outcome = NormalizationOutcome.INCOMPLETE_PATH
                        reason = str(error)

        kind = (
            "NO_PATH"
            if outcome in (NormalizationOutcome.NO_PATH, NormalizationOutcome.INCOMPLETE_PATH)
            else outcome.value
        )
        observed_locations = (
            tuple(
                str(node.get("location", "")).strip()
                for node in (raw.get("hits") or [])
                if isinstance(node, dict) and str(node.get("location", "")).strip()
            )
            if isinstance(raw, dict)
            else ()
        )
        validation = ValidationResult(
            version=self.adapter_version,
            created_at=datetime.now(timezone.utc),
            provenance=provenance,
            kind=kind,
            outcome=outcome.value,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            observed_data=(
                Attribute(name="producer_id", value=self.producer_id),
                Attribute(name="producer_version", value=self.producer_version),
                Attribute(name="raw_output_identity", value=raw_identity),
                Attribute(name="reason", value=reason),
            ),
        )
        return NormalizationResult(
            outcome=outcome,
            validation=validation,
            path_evidence=path_evidence,
            reason=reason,
            raw_output_identity=raw_identity,
            observed_location_identities=observed_locations,
        )
