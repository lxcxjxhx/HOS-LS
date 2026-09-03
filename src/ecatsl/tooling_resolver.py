"""Tooling-first API resolution gate.

Task 5.1: adapt existing SAST/CodeQL, InputTracer, PureAI multi-agent, RAG,
and local NVD/CWE capabilities behind terminal validated records (RESOLVED,
UNRESOLVED, INAPPLICABLE, UNAVAILABLE, FAILED). LLM fallback is suppressed
whenever any applicable existing capability resolves the API role and
applicability; fallback is allowed only after every applicable capability has
a terminal unresolved outcome. Every tooling record and any LLM attempt is
retained with validated identity, timing, cost, and failure telemetry, and
failed/assertion-only LLM output stays unaccepted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional, Sequence, Tuple

from .artifact_repository import ArtifactRepository
from .models import (
    Attribute,
    LLMResolutionAttempt,
    Provenance,
    ToolingResolutionRecord,
)

TERMINAL_OUTCOMES = ("RESOLVED", "UNRESOLVED", "INAPPLICABLE", "UNAVAILABLE", "FAILED")

_TERMINAL_SET = frozenset(TERMINAL_OUTCOMES)


class ToolingFirstResolverError(RuntimeError):
    """A capability produced an outcome that is not a valid terminal resolution."""


@dataclass(frozen=True)
class ToolingResolutionBundle:
    records: Tuple[ToolingResolutionRecord, ...]
    unknown_api: bool
    llm_attempt: Optional[LLMResolutionAttempt] = None

    @property
    def resolved(self) -> bool:
        return any(record.outcome == "RESOLVED" for record in self.records)


@dataclass(frozen=True)
class CapabilityRun:
    identity: str
    version: str
    input_identity: str
    outcome: str
    latency_seconds: float
    monetary_cost: float = 0.0
    failure_data: Optional[str] = None


CapabilityExecutor = Callable[[str], CapabilityRun]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ToolingFirstResolver:
    """Resolve every applicable capability in order and gate LLM fallback."""

    def __init__(
        self,
        *,
        capabilities: Sequence[CapabilityExecutor],
        llm: Optional[Callable[[Sequence[ToolingResolutionRecord]], LLMResolutionAttempt]] = None,
        repository: Optional[ArtifactRepository] = None,
        provenance: Optional[Provenance] = None,
        version: str = "1",
    ) -> None:
        if not capabilities:
            raise ValueError("tooling-first resolution requires at least one capability")
        self.capabilities = tuple(capabilities)
        self.llm = llm
        self.repository = repository
        self.provenance = provenance
        self.version = version

    def _persist(self, artifact) -> None:
        if self.repository is not None:
            self.repository.persist_artifact(artifact)

    def resolve(
        self,
        input_identity: str,
        *,
        created_at: Optional[datetime] = None,
    ) -> ToolingResolutionBundle:
        """Run capabilities in declared order and gate LLM fallback at the terminal edge.

        Resolution stops early as soon as a capability resolves the API; LLM
        fallback is then suppressed. Fallback is allowed only when every
        applicable capability has a terminal unresolved outcome.
        """
        now = created_at or _utc_now()
        provenance = self.provenance or Provenance(
            origin="tooling-first-resolver",
            retrieved_at=now,
            source_identifier=f"input:{input_identity}",
            source_revision=self.version,
            content_identity=f"resolution:{input_identity}:{self.version}",
            transformation_history=(f"tooling-first:v{self.version}",),
        )
        records = []
        resolved = False
        terminal_all = True
        for capability in self.capabilities:
            record = self._run_capability(capability, input_identity, now, provenance)
            records.append(record)
            if record.outcome == "RESOLVED":
                resolved = True
                break  # tooling-first: stop forwarding work after a resolution.
            if record.outcome not in _TERMINAL_SET:
                terminal_all = False
                break
        # Only a fully terminal, unresolved run may attempt LLM fallback.
        unknown_api = terminal_all and not resolved
        llm_attempt = None
        if unknown_api and self.llm is not None:
            llm_attempt = self.llm(tuple(records))
            if self.repository is not None:
                self.repository.persist_artifact(llm_attempt)
        return ToolingResolutionBundle(tuple(records), unknown_api, llm_attempt)

    def _run_capability(
        self,
        capability: CapabilityExecutor,
        input_identity: str,
        created_at: datetime,
        provenance: Provenance,
    ) -> ToolingResolutionRecord:
        try:
            run = capability(input_identity)
        except Exception as error:  # capability failure is retained, not fatal
            run = CapabilityRun(
                identity="unknown",
                version="unknown",
                input_identity=input_identity,
                outcome="FAILED",
                latency_seconds=0.0,
                monetary_cost=0.0,
                failure_data=f"{type(error).__name__}: {error}",
            )
        if run.outcome not in _TERMINAL_SET:
            raise ToolingFirstResolverError(
                f"capability {run.identity} produced non-terminal outcome {run.outcome!r}"
            )
        record = ToolingResolutionRecord(
            version="1",
            created_at=created_at,
            provenance=provenance,
            capability_id=run.identity,
            capability_version=run.version,
            input_identity=run.input_identity,
            outcome=run.outcome,
            latency_seconds=run.latency_seconds,
            monetary_cost=run.monetary_cost,
            failure_data=run.failure_data,
        )
        self._persist(record)
        return record