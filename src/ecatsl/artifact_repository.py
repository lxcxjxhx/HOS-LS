"""Crash-safe append-only SQLite repository for immutable ECATSL artifacts.

Writes use bounded ``BEGIN IMMEDIATE`` acquisition, durable logical-operation
journals, exact idempotent replay, and compare-and-append conflict reporting.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterator, Optional, Sequence, Tuple, Type, TypeVar, Union
from uuid import uuid4

from pydantic import Field

from .models import (
    AcceptancePolicy,
    Artifact,
    Attribute,
    BenchmarkManifest,
    CandidateHypothesis,
    CandidateRecord,
    CatalogImport,
    CatalogRecord,
    ConstrainedDeclarativeSpecification,
    Counterexample,
    DataQualityReport,
    DiscoveryObservation,
    DiscoveryStrategy,
    EvaluationReport,
    Evidence,
    FindingClassification,
    FindingStatus,
    IngestionRun,
    LLMResolutionAttempt,
    NormalizedCatalogRecord,
    OptimizationExperiment,
    PathEvidence,
    ReuseInventory,
    SanitizerStatus,
    StaticAdapterRun,
    TaintTemplate,
    TemplateRetrieval,
    ToolingResolutionRecord,
    ValidationPolicy,
    ValidationResult,
)
from .schema import (
    ProcessLiveness,
    ProcessLivenessProbe,
    SQLiteWriteConfig,
    _PROCESS_OWNER_TOKEN,
    _owner_liveness,
    _pid_liveness,
    _register_attempt,
    _unregister_attempt,
    begin_immediate_with_retry,
    install_ecatsl_schema,
)
from .scope import ScopeDefinition, ScopeResult


ArtifactT = TypeVar("ArtifactT", bound=Artifact)
DatabaseTarget = Union[str, Path, sqlite3.Connection]

MODEL_REGISTRY_VERSION = "1"
SUPPORTED_ADAPTER_REGISTRY_VERSION = "1"
DEFAULT_SUPPORTED_STATIC_ADAPTERS = frozenset(
    {("input-tracer", "1"), ("sast-prefilter-codeql", "1")}
)


class ArtifactRepositoryError(RuntimeError):
    """Base error for repository contract violations."""


class ImmutableArtifactError(ArtifactRepositoryError):
    """An operation attempted to replace or mutate committed content."""


class StalePredecessorError(ArtifactRepositoryError):
    """A successor did not reference the current entity head."""


class CompareAndAppendStatus(str, Enum):
    APPENDED = "APPENDED"
    REPLAYED = "REPLAYED"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True)
class CompareAndAppendResult:
    status: CompareAndAppendStatus
    record: Optional[CandidateRecord]
    expected_head_id: str
    actual_head_id: Optional[str]
    replayed: bool = False


class CompareAndAppendConflictError(StalePredecessorError):
    """Explicit compare-and-append conflict carrying the observed head."""

    def __init__(self, result: CompareAndAppendResult) -> None:
        self.result = result
        super().__init__(
            f"candidate compare-and-append expected {result.expected_head_id!r}, "
            f"observed {result.actual_head_id!r}"
        )


class RepositoryTestInterruption(BaseException):
    """Test-only process interruption; intentionally bypasses failure finalization."""


class OptionalMetadataPersistenceError(RuntimeError):
    """Failure-injection signal naming exact optional elements that were not retained."""

    def __init__(self, *missing_elements: str) -> None:
        if not missing_elements or any(not item for item in missing_elements):
            raise ValueError("optional metadata failure requires exact missing elements")
        self.missing_elements = tuple(missing_elements)
        super().__init__(", ".join(self.missing_elements))


class TransactionState(str, Enum):
    STARTED = "STARTED"
    COMMITTED = "COMMITTED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"
    REPLAYED = "REPLAYED"


@dataclass(frozen=True)
class TransactionJournalState:
    transaction_id: str
    operation: str
    idempotency_key: Optional[str]
    request_hash: str
    state: TransactionState
    sequence: int
    attempt_id: Optional[str] = None
    latest_attempt_state: Optional[TransactionState] = None


@dataclass(frozen=True)
class ArtifactRepositoryConfig:
    sqlite_write: SQLiteWriteConfig = field(default_factory=SQLiteWriteConfig)
    interrupted_after_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.interrupted_after_seconds < 0:
            raise ValueError("interrupted_after_seconds must be non-negative")


RepositoryFailureHook = Callable[[str, str], None]


class IdempotencyConflictError(ArtifactRepositoryError):
    """An idempotency key was reused for a different logical request."""


class LineageError(ArtifactRepositoryError):
    """Required artifact lineage is absent or has the wrong kind."""


class UnsupportedArtifactTypeError(ArtifactRepositoryError):
    """An artifact is outside the closed model registry or needs a typed API."""


class PolicyDecisionRecord(Artifact):
    """Persisted policy outcome and its complete audit metadata."""

    candidate_version_id: str = Field(min_length=1)
    policy_kind: str = Field(pattern=r"^(ACCEPTANCE|VALIDATION)$")
    policy_version: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    input_artifact_ids: Tuple[str, ...] = ()
    audit_metadata: Tuple[Attribute, ...] = ()
    missing_audit_elements: Tuple[str, ...] = ()


class AuditFailureRecord(Artifact):
    """Explicit, immutable creation or persistence failure record."""

    related_artifact_id: Optional[str] = None
    operation: str = Field(min_length=1)
    missing_element: str = Field(min_length=1)
    failure_data: Tuple[Attribute, ...] = ()


@dataclass(frozen=True)
class PolicyPersistenceResult:
    candidate: Optional[CandidateRecord]
    decision: PolicyDecisionRecord
    failures: Tuple[AuditFailureRecord, ...]


@dataclass(frozen=True)
class ValidationRetentionResult:
    validation: ValidationResult
    counterexamples: Tuple[Counterexample, ...]


@dataclass(frozen=True)
class ClassificationPersistenceResult:
    classification: FindingClassification
    failures: Tuple[AuditFailureRecord, ...]


# This is deliberately explicit. Database values never select a Python module.
_REGISTERED_MODELS: Tuple[Type[Artifact], ...] = (
    AcceptancePolicy,
    AuditFailureRecord,
    BenchmarkManifest,
    CandidateHypothesis,
    CandidateRecord,
    CatalogImport,
    CatalogRecord,
    ConstrainedDeclarativeSpecification,
    Counterexample,
    DataQualityReport,
    DiscoveryObservation,
    DiscoveryStrategy,
    EvaluationReport,
    Evidence,
    FindingClassification,
    IngestionRun,
    LLMResolutionAttempt,
    NormalizedCatalogRecord,
    OptimizationExperiment,
    PathEvidence,
    PolicyDecisionRecord,
    ReuseInventory,
    ScopeDefinition,
    ScopeResult,
    StaticAdapterRun,
    TaintTemplate,
    TemplateRetrieval,
    ToolingResolutionRecord,
    ValidationPolicy,
    ValidationResult,
)
_MODEL_BY_DISCRIMINATOR = {
    f"ecatsl.model/v{MODEL_REGISTRY_VERSION}/{model.__name__}": model
    for model in _REGISTERED_MODELS
}
_DISCRIMINATOR_BY_MODEL = {model: key for key, model in _MODEL_BY_DISCRIMINATOR.items()}
# Aliases preserve rows written before the discriminator registry and common
# package-root moves without ever importing a name read from SQLite.
_MODEL_ALIASES = {
    alias: model
    for model in _REGISTERED_MODELS
    for alias in (
        f"{model.__module__}:{model.__qualname__}",
        f"ecatsl.models:{model.__qualname__}",
        f"src.ecatsl.models:{model.__qualname__}",
        f"ecatsl.scope:{model.__qualname__}",
        f"src.ecatsl.scope:{model.__qualname__}",
        f"ecatsl.artifact_repository:{model.__qualname__}",
        f"src.ecatsl.artifact_repository:{model.__qualname__}",
    )
}

_SPECIALIZED_TYPES = (
    AuditFailureRecord,
    CandidateRecord,
    CatalogRecord,
    ConstrainedDeclarativeSpecification,
    Evidence,
    FindingClassification,
    PathEvidence,
    PolicyDecisionRecord,
    ReuseInventory,
    ScopeDefinition,
    StaticAdapterRun,
    ValidationResult,
)


def _canonical_json(value: Any) -> str:
    if isinstance(value, Artifact):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _request_hash(value: Any) -> str:
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _artifact_discriminator(artifact: Artifact) -> str:
    try:
        return _DISCRIMINATOR_BY_MODEL[type(artifact)]
    except KeyError as exc:
        raise UnsupportedArtifactTypeError(
            f"{type(artifact).__name__} is not in ECATSL model registry v{MODEL_REGISTRY_VERSION}"
        ) from exc


def _unique(values: Sequence[str]) -> Tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _reject_duplicate_failure_elements(
    failures: Sequence["AuditFailureRecord"],
) -> None:
    elements = tuple(item.missing_element for item in failures)
    if len(elements) != len(set(elements)):
        raise ValueError("policy audit failures require unique missing_element values")


class ArtifactRepository:
    """Persist typed artifacts into the shared append-only SQLite schema."""

    def __init__(
        self,
        target: DatabaseTarget,
        *,
        supported_static_adapters: Optional[Sequence[Tuple[str, str]]] = None,
        config: Optional[ArtifactRepositoryConfig] = None,
    ) -> None:
        self._initialize(
            target,
            supported_static_adapters=supported_static_adapters,
            config=config,
            process_probe=_pid_liveness,
        )

    def _initialize(
        self,
        target: DatabaseTarget,
        *,
        supported_static_adapters: Optional[Sequence[Tuple[str, str]]],
        config: Optional[ArtifactRepositoryConfig],
        process_probe: ProcessLivenessProbe,
    ) -> None:
        self.config = config or ArtifactRepositoryConfig()
        self._process_probe = process_probe
        self._test_failure_hook: Optional[RepositoryFailureHook] = None
        self._active_transaction_id: Optional[str] = None
        self._active_attempt_id: Optional[str] = None
        self._active_invocation_id: Optional[str] = None
        self._active_transaction_replayed = False
        self._owns_connection = not isinstance(target, sqlite3.Connection)
        if isinstance(target, sqlite3.Connection):
            self.connection = target
        else:
            path = Path(target).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(path, timeout=0)
        configured = (
            DEFAULT_SUPPORTED_STATIC_ADAPTERS
            if supported_static_adapters is None
            else frozenset(supported_static_adapters)
        )
        if any(not adapter_id or not version for adapter_id, version in configured):
            raise ValueError("supported adapter identities and versions must be non-empty")
        self.supported_static_adapters = configured
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute(
            f"PRAGMA busy_timeout = {self.config.sqlite_write.busy_timeout_ms}"
        )
        install_ecatsl_schema(
            self.connection, write_config=self.config.sqlite_write
        )
        self.recover_interrupted_transactions(
            stale_after_seconds=self.config.interrupted_after_seconds
        )

    @classmethod
    def for_testing(
        cls,
        target: DatabaseTarget,
        *,
        failure_hook: RepositoryFailureHook,
        supported_static_adapters: Optional[Sequence[Tuple[str, str]]] = None,
        config: Optional[ArtifactRepositoryConfig] = None,
        process_probe: ProcessLivenessProbe = _pid_liveness,
    ) -> "ArtifactRepository":
        """Construct with deterministic hooks through an explicit test-only boundary."""

        repository = cls.__new__(cls)
        repository._initialize(
            target,
            supported_static_adapters=supported_static_adapters,
            config=config,
            process_probe=process_probe,
        )
        repository._test_failure_hook = failure_hook
        return repository

    def close(self) -> None:
        if self._owns_connection:
            self.connection.close()

    def __enter__(self) -> "ArtifactRepository":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _call_test_hook(self, point: str, transaction_id: str) -> None:
        if self._test_failure_hook is not None:
            self._test_failure_hook(point, transaction_id)

    @staticmethod
    def _transaction_id(
        operation: str, idempotency_key: Optional[str], request_hash: str
    ) -> str:
        if idempotency_key is None:
            return "tx:" + uuid4().hex
        return "tx:" + sha256(
            f"{operation}\0{idempotency_key}\0{request_hash}".encode("utf-8")
        ).hexdigest()

    def _append_transaction_event(
        self,
        transaction_id: str,
        attempt_id: str,
        state: TransactionState,
        failure: Optional[BaseException] = None,
    ) -> None:
        row = self.connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM ecatsl_transaction_event "
            "WHERE transaction_id = ?",
            (transaction_id,),
        ).fetchone()
        sequence = int(row[0]) + 1
        self.connection.execute(
            """
            INSERT INTO ecatsl_transaction_event
                (transaction_id, sequence, state, occurred_at,
                 failure_type, failure_message, attempt_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transaction_id,
                sequence,
                state.value,
                datetime.now(timezone.utc).isoformat(),
                type(failure).__name__ if failure is not None else None,
                str(failure) if failure is not None else None,
                attempt_id,
            ),
        )

    def _prepare_transaction(
        self, operation: str, idempotency_key: str, request_hash: str
    ) -> Tuple[str, str]:
        transaction_id = self._transaction_id(operation, idempotency_key, request_hash)
        attempt_id = "attempt:" + uuid4().hex
        _register_attempt(attempt_id)
        begin_immediate_with_retry(self.connection, self.config.sqlite_write)
        try:
            row = self.connection.execute(
                """
                SELECT transaction_id, request_hash FROM ecatsl_transaction
                WHERE operation = ? AND idempotency_key = ?
                """,
                (operation, idempotency_key),
            ).fetchone()
            if row is None:
                self.connection.execute(
                    """
                    INSERT INTO ecatsl_transaction
                        (transaction_id, operation, idempotency_key,
                         request_hash, started_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        transaction_id,
                        operation,
                        idempotency_key,
                        request_hash,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            else:
                transaction_id = str(row[0])
                if str(row[1]) != request_hash:
                    raise IdempotencyConflictError(
                        f"idempotency key {idempotency_key!r} was already used for {operation}"
                    )
            self.connection.execute(
                """
                INSERT INTO ecatsl_transaction_attempt
                    (attempt_id, transaction_id, owner_pid, owner_token, started_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    transaction_id,
                    os.getpid(),
                    _PROCESS_OWNER_TOKEN,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._append_transaction_event(
                transaction_id, attempt_id, TransactionState.STARTED
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            _unregister_attempt(attempt_id)
            raise
        return transaction_id, attempt_id

    def _record_transaction_failure(
        self, transaction_id: str, attempt_id: str, error: Exception
    ) -> None:
        begin_immediate_with_retry(self.connection, self.config.sqlite_write)
        try:
            self._append_transaction_event(
                transaction_id, attempt_id, TransactionState.FAILED, error
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    @contextmanager
    def _atomic(
        self,
        operation: str = "internal",
        idempotency_key: Optional[str] = None,
        request_hash: Optional[str] = None,
    ) -> Iterator[None]:
        if self.connection.in_transaction or self._active_invocation_id is not None:
            raise ArtifactRepositoryError("repository operation requires an idle connection")
        fingerprint = request_hash or _request_hash(
            {"operation": operation, "nonce": uuid4().hex}
        )
        invocation_id = "invocation:" + uuid4().hex
        transaction_id: Optional[str] = None
        attempt_id: Optional[str] = None
        if idempotency_key is not None:
            transaction_id, attempt_id = self._prepare_transaction(
                operation, idempotency_key, fingerprint
            )
            invocation_id = attempt_id
        self._active_invocation_id = invocation_id
        self._active_transaction_id = transaction_id
        self._active_attempt_id = attempt_id
        self._active_transaction_replayed = False
        try:
            if transaction_id is not None:
                self._call_test_hook("transaction.after_started", invocation_id)
            begin_immediate_with_retry(self.connection, self.config.sqlite_write)
            self._call_test_hook("transaction.after_writer_acquired", invocation_id)
            yield
            self._call_test_hook("transaction.before_commit", invocation_id)
            if transaction_id is not None and attempt_id is not None:
                final_state = (
                    TransactionState.REPLAYED
                    if self._active_transaction_replayed
                    else TransactionState.COMMITTED
                )
                self._append_transaction_event(
                    transaction_id, attempt_id, final_state
                )
            self.connection.commit()
        except BaseException as error:
            # Every in-flight writer is rolled back. Cancellation/process-style
            # interruptions remain durable STARTED attempts for owner-death recovery.
            self.connection.rollback()
            if (
                transaction_id is not None
                and attempt_id is not None
                and isinstance(error, Exception)
            ):
                self._record_transaction_failure(transaction_id, attempt_id, error)
            raise
        finally:
            if attempt_id is not None:
                _unregister_attempt(attempt_id)
            self._active_transaction_id = None
            self._active_attempt_id = None
            self._active_invocation_id = None
            self._active_transaction_replayed = False

    def recover_interrupted_transactions(
        self, *, stale_after_seconds: float = 0.0
    ) -> Tuple[str, ...]:
        """Interrupt only stale attempts whose owning process is proven dead."""

        if stale_after_seconds < 0:
            raise ValueError("stale_after_seconds must be non-negative")
        if self.connection.in_transaction:
            raise ArtifactRepositoryError("recovery requires an idle connection")
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)
        begin_immediate_with_retry(self.connection, self.config.sqlite_write)
        try:
            rows = self.connection.execute(
                """
                SELECT attempt.transaction_id, attempt.attempt_id,
                       attempt.owner_pid, attempt.owner_token, started.occurred_at
                FROM ecatsl_transaction_attempt AS attempt
                JOIN ecatsl_transaction_event AS started
                  ON started.attempt_id = attempt.attempt_id
                 AND started.state = 'STARTED'
                LEFT JOIN ecatsl_transaction_event AS terminal
                  ON terminal.attempt_id = attempt.attempt_id
                 AND terminal.state <> 'STARTED'
                WHERE terminal.event_id IS NULL
                """
            ).fetchall()
            recovered = []
            for transaction_id, attempt_id, owner_pid, owner_token, occurred_at in rows:
                event_time = datetime.fromisoformat(str(occurred_at))
                if event_time <= cutoff and _owner_liveness(
                    int(owner_pid),
                    str(owner_token),
                    str(attempt_id),
                    process_probe=self._process_probe,
                ) is ProcessLiveness.DEAD:
                    self._append_transaction_event(
                        str(transaction_id),
                        str(attempt_id),
                        TransactionState.INTERRUPTED,
                    )
                    recovered.append(str(transaction_id))
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        return tuple(recovered)

    def transaction_state(
        self, operation: str, idempotency_key: str
    ) -> Optional[TransactionJournalState]:
        row = self.connection.execute(
            """
            SELECT tx.transaction_id, tx.operation, tx.idempotency_key,
                   tx.request_hash, event.state, event.sequence, event.attempt_id,
                   EXISTS(
                       SELECT 1 FROM ecatsl_idempotency_key AS idem
                       WHERE idem.transaction_id = tx.transaction_id
                          OR (
                              idem.transaction_id IS NULL
                              AND idem.operation = tx.operation
                              AND idem.idempotency_key = tx.idempotency_key
                              AND idem.request_hash = tx.request_hash
                          )
                   ) OR EXISTS(
                       SELECT 1 FROM ecatsl_transaction_result AS result
                       WHERE result.transaction_id = tx.transaction_id
                   ) AS has_durable_result
            FROM ecatsl_transaction AS tx
            JOIN ecatsl_transaction_event AS event
              ON event.transaction_id = tx.transaction_id
            WHERE tx.operation = ? AND tx.idempotency_key = ?
            ORDER BY event.sequence DESC LIMIT 1
            """,
            (operation, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        attempt_state = TransactionState(str(row[4]))
        logical_state = (
            TransactionState.COMMITTED if bool(row[7]) else attempt_state
        )
        return TransactionJournalState(
            transaction_id=str(row[0]),
            operation=str(row[1]),
            idempotency_key=str(row[2]) if row[2] is not None else None,
            request_hash=str(row[3]),
            state=logical_state,
            sequence=int(row[5]),
            attempt_id=str(row[6]) if row[6] is not None else None,
            latest_attempt_state=attempt_state,
        )

    def _insert_artifact(self, artifact: Artifact) -> bool:
        payload = artifact.canonical_json()
        discriminator = _artifact_discriminator(artifact)
        existing = self.connection.execute(
            """
            SELECT artifact_type, content_hash, canonical_payload, created_at, predecessor_id
            FROM ecatsl_artifact WHERE artifact_id = ?
            """,
            (artifact.artifact_id,),
        ).fetchone()
        values = (
            discriminator,
            artifact.content_hash,
            payload,
            artifact.created_at.isoformat(),
            artifact.predecessor_id,
        )
        if existing is not None:
            existing_type = str(existing[0])
            resolved = self._resolve_model(existing_type)
            equivalent = (
                resolved is type(artifact)
                and str(existing[1]) == artifact.content_hash
                and str(existing[2]) == payload
                and str(existing[3]) == artifact.created_at.isoformat()
                and existing[4] == artifact.predecessor_id
            )
            if not equivalent:
                raise ImmutableArtifactError(
                    f"artifact {artifact.artifact_id} is already committed with different data"
                )
            return False
        self.connection.execute(
            """
            INSERT INTO ecatsl_artifact
                (artifact_id, artifact_type, version, content_hash, canonical_payload,
                 created_at, predecessor_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.artifact_id,
                discriminator,
                artifact.version,
                artifact.content_hash,
                payload,
                artifact.created_at.isoformat(),
                artifact.predecessor_id,
            ),
        )
        return True

    @staticmethod
    def _resolve_model(stored_type: str) -> Type[Artifact]:
        model = _MODEL_BY_DISCRIMINATOR.get(stored_type) or _MODEL_ALIASES.get(stored_type)
        if model is None:
            raise UnsupportedArtifactTypeError(
                f"unknown ECATSL model discriminator {stored_type!r}"
            )
        return model

    def _load_in_transaction(
        self, artifact_id: str, model_type: Optional[Type[ArtifactT]] = None
    ) -> ArtifactT:
        row = self.connection.execute(
            """
            SELECT artifact_id, artifact_type, version, content_hash, canonical_payload,
                   created_at, predecessor_id
            FROM ecatsl_artifact WHERE artifact_id = ?
            """,
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise LineageError(f"artifact {artifact_id} does not exist")
        row_id, stored_type, version, content_hash, payload, created_at, predecessor_id = row
        resolved = self._resolve_model(str(stored_type))
        if model_type is not None and resolved is not model_type:
            raise LineageError(
                f"artifact {artifact_id} is {resolved.__name__}, expected {model_type.__name__}"
            )
        try:
            artifact = resolved.model_validate_json(str(payload))
        except Exception as exc:
            raise ImmutableArtifactError(f"artifact {artifact_id} payload is invalid") from exc
        if (
            str(row_id) != artifact_id
            or artifact.artifact_id != artifact_id
            or artifact.content_hash != str(content_hash)
            or artifact.version != str(version)
            or artifact.created_at.isoformat() != str(created_at)
            or artifact.predecessor_id != predecessor_id
            or artifact.canonical_json() != str(payload)
        ):
            raise ImmutableArtifactError(f"artifact {artifact_id} row identity is corrupted")
        return artifact  # type: ignore[return-value]

    def load(
        self, artifact_id: str, model_type: Optional[Type[ArtifactT]] = None
    ) -> ArtifactT:
        """Load and cross-check canonical committed content through the closed registry."""
        return self._load_in_transaction(artifact_id, model_type)

    def _lookup_idempotency(
        self,
        operation: str,
        key: Optional[str],
        request_hash: str,
        expected_result_ids: Optional[Sequence[str]] = None,
    ) -> Optional[Tuple[Artifact, ...]]:
        if key is None:
            return None
        if not key.strip():
            raise ValueError("idempotency_key must not be blank")
        row = self.connection.execute(
            """
            SELECT request_hash, result_artifact_ids_json
            FROM ecatsl_idempotency_key
            WHERE operation = ? AND idempotency_key = ?
            """,
            (operation, key),
        ).fetchone()
        if row is None:
            return None
        if str(row[0]) != request_hash:
            raise IdempotencyConflictError(
                f"idempotency key {key!r} was already used for {operation}"
            )
        try:
            artifact_ids = json.loads(str(row[1]))
        except (TypeError, ValueError) as exc:
            raise ImmutableArtifactError("idempotency result list is corrupted") from exc
        if (
            not isinstance(artifact_ids, list)
            or not artifact_ids
            or any(not isinstance(item, str) or not item for item in artifact_ids)
            or len(set(artifact_ids)) != len(artifact_ids)
        ):
            raise ImmutableArtifactError("idempotency result list is corrupted")
        if (
            expected_result_ids is not None
            and tuple(artifact_ids) != tuple(expected_result_ids)
        ):
            raise ImmutableArtifactError(
                "idempotency result identities do not match the committed request"
            )
        if self._active_transaction_id is not None:
            self._active_transaction_replayed = True
        return tuple(self._load_in_transaction(artifact_id) for artifact_id in artifact_ids)

    def _remember_idempotency(
        self,
        operation: str,
        key: Optional[str],
        request_hash: str,
        results: Sequence[Artifact],
    ) -> None:
        if key is None:
            return
        if self._active_transaction_id is None:
            raise ArtifactRepositoryError("idempotency requires an active transaction")
        self.connection.execute(
            """
            INSERT INTO ecatsl_idempotency_key
                (operation, idempotency_key, request_hash,
                 result_artifact_ids_json, committed_at, transaction_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                operation,
                key,
                request_hash,
                _canonical_json([artifact.artifact_id for artifact in results]),
                datetime.now(timezone.utc).isoformat(),
                self._active_transaction_id,
            ),
        )

    def persist_artifact(
        self, artifact: ArtifactT, *, idempotency_key: Optional[str] = None
    ) -> ArtifactT:
        """Persist only artifacts that intentionally have no semantic projection."""
        if isinstance(artifact, _SPECIALIZED_TYPES):
            raise UnsupportedArtifactTypeError(
                f"{type(artifact).__name__} requires its dedicated persistence API"
            )
        operation = "persist_artifact"
        fingerprint = _request_hash(artifact)
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (artifact.artifact_id,)
            )
            if replay is not None:
                return self._expect(replay[0], type(artifact))
            self._insert_artifact(artifact)
            self._remember_idempotency(operation, idempotency_key, fingerprint, (artifact,))
        return artifact

    def _candidate_head(self, candidate_id: str) -> Optional[str]:
        row = self.connection.execute(
            """
            SELECT current.artifact_id
            FROM ecatsl_candidate_version AS current
            LEFT JOIN ecatsl_candidate_version AS successor
              ON successor.candidate_id = current.candidate_id
             AND successor.predecessor_id = current.artifact_id
            WHERE current.candidate_id = ? AND successor.artifact_id IS NULL
            """,
            (candidate_id,),
        ).fetchone()
        return str(row[0]) if row is not None else None

    def _insert_candidate_projection(self, record: CandidateRecord) -> None:
        for artifact_id in record.evidence_ids + record.counterexample_ids:
            self._require_artifact(artifact_id)
        self.connection.execute(
            """
            INSERT INTO ecatsl_candidate_version
                (artifact_id, candidate_id, candidate_version, candidate_type,
                 confidence, state, cwe_id, predecessor_id, update_cause,
                 changed_data_json, missing_audit_elements_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.artifact_id,
                record.candidate_id,
                record.version,
                record.candidate_type.value,
                record.confidence,
                record.state.value,
                record.cwe_id,
                record.predecessor_id,
                record.update_cause,
                _canonical_json([item.model_dump(mode="json") for item in record.changed_data]),
                _canonical_json(list(record.missing_audit_elements)),
            ),
        )

    def create_candidate(
        self, record: CandidateRecord, *, idempotency_key: Optional[str] = None
    ) -> CandidateRecord:
        if record.predecessor_id is not None:
            raise StalePredecessorError("candidate creation requires no predecessor")
        operation = "create_candidate"
        fingerprint = _request_hash(record)
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (record.artifact_id,)
            )
            if replay is not None:
                return self._expect(replay[0], CandidateRecord)
            if self._candidate_head(record.candidate_id) is not None:
                raise StalePredecessorError(f"candidate {record.candidate_id} already exists")
            self._insert_artifact(record)
            self._insert_candidate_projection(record)
            self._remember_idempotency(operation, idempotency_key, fingerprint, (record,))
        return record

    def _lookup_compare_conflict(
        self, expected_predecessor_id: str
    ) -> Optional[CompareAndAppendResult]:
        if self._active_transaction_id is None:
            return None
        row = self.connection.execute(
            """
            SELECT outcome, result_json FROM ecatsl_transaction_result
            WHERE transaction_id = ?
            """,
            (self._active_transaction_id,),
        ).fetchone()
        if row is None:
            return None
        if str(row[0]) != CompareAndAppendStatus.CONFLICT.value:
            raise ImmutableArtifactError("compare-and-append result outcome is corrupted")
        try:
            result = json.loads(str(row[1]))
        except (TypeError, ValueError) as error:
            raise ImmutableArtifactError(
                "compare-and-append result is corrupted"
            ) from error
        if (
            not isinstance(result, dict)
            or result.get("expected_head_id") != expected_predecessor_id
            or (
                result.get("actual_head_id") is not None
                and not isinstance(result.get("actual_head_id"), str)
            )
        ):
            raise ImmutableArtifactError("compare-and-append result is corrupted")
        self._active_transaction_replayed = True
        return CompareAndAppendResult(
            CompareAndAppendStatus.CONFLICT,
            None,
            expected_predecessor_id,
            result.get("actual_head_id"),
            replayed=True,
        )

    def _remember_compare_conflict(
        self, expected_predecessor_id: str, actual_head_id: Optional[str]
    ) -> None:
        if self._active_transaction_id is None:
            return
        self.connection.execute(
            """
            INSERT INTO ecatsl_transaction_result
                (transaction_id, outcome, result_json, committed_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                self._active_transaction_id,
                CompareAndAppendStatus.CONFLICT.value,
                _canonical_json(
                    {
                        "expected_head_id": expected_predecessor_id,
                        "actual_head_id": actual_head_id,
                    }
                ),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def compare_and_append_candidate(
        self,
        record: CandidateRecord,
        *,
        expected_predecessor_id: str,
        idempotency_key: Optional[str] = None,
    ) -> CompareAndAppendResult:
        """Atomically compare the durable head and append or return a conflict."""

        operation = "append_candidate"
        fingerprint = _request_hash(
            {"record": record.model_dump(mode="json"), "expected": expected_predecessor_id}
        )
        with self._atomic(operation, idempotency_key, fingerprint):
            conflict_replay = self._lookup_compare_conflict(
                expected_predecessor_id
            )
            if conflict_replay is not None:
                return conflict_replay
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (record.artifact_id,)
            )
            if replay is not None:
                replayed = self._expect(replay[0], CandidateRecord)
                return CompareAndAppendResult(
                    CompareAndAppendStatus.REPLAYED,
                    replayed,
                    expected_predecessor_id,
                    replayed.artifact_id,
                    replayed=True,
                )
            head = self._candidate_head(record.candidate_id)
            if (
                record.predecessor_id != expected_predecessor_id
                or head != expected_predecessor_id
            ):
                self._remember_compare_conflict(expected_predecessor_id, head)
                return CompareAndAppendResult(
                    CompareAndAppendStatus.CONFLICT,
                    None,
                    expected_predecessor_id,
                    head,
                )
            self._insert_artifact(record)
            self._insert_candidate_projection(record)
            self._remember_idempotency(
                operation, idempotency_key, fingerprint, (record,)
            )
        return CompareAndAppendResult(
            CompareAndAppendStatus.APPENDED,
            record,
            expected_predecessor_id,
            record.artifact_id,
        )

    def append_candidate(
        self,
        record: CandidateRecord,
        *,
        expected_predecessor_id: str,
        idempotency_key: Optional[str] = None,
    ) -> CandidateRecord:
        result = self.compare_and_append_candidate(
            record,
            expected_predecessor_id=expected_predecessor_id,
            idempotency_key=idempotency_key,
        )
        if result.status is CompareAndAppendStatus.CONFLICT:
            raise CompareAndAppendConflictError(result)
        assert result.record is not None
        return result.record

    def persist_candidate(
        self,
        record: CandidateRecord,
        *,
        expected_predecessor_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> CandidateRecord:
        if record.predecessor_id is None:
            if expected_predecessor_id is not None:
                raise StalePredecessorError("candidate root cannot expect a predecessor")
            return self.create_candidate(record, idempotency_key=idempotency_key)
        return self.append_candidate(
            record,
            expected_predecessor_id=expected_predecessor_id or record.predecessor_id,
            idempotency_key=idempotency_key,
        )

    def _insert_evidence_projection(
        self, evidence: Evidence, candidate_version_id: Optional[str]
    ) -> None:
        if candidate_version_id is not None:
            self._require_candidate(candidate_version_id)
        self.connection.execute(
            """
            INSERT INTO ecatsl_evidence
                (artifact_id, candidate_version_id, evidence_kind, contradicts,
                 provenance_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                evidence.artifact_id,
                candidate_version_id,
                evidence.evidence_kind,
                evidence.contradicts if isinstance(evidence, Counterexample) else None,
                _canonical_json(evidence.provenance.model_dump(mode="json")),
            ),
        )

    def persist_evidence(
        self,
        evidence: Evidence,
        *,
        candidate_version_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Evidence:
        operation = "persist_evidence"
        fingerprint = _request_hash(
            {"evidence": evidence.model_dump(mode="json"), "candidate": candidate_version_id}
        )
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (evidence.artifact_id,)
            )
            if replay is not None:
                replayed = replay[0]
                if not isinstance(replayed, Evidence):
                    raise ArtifactRepositoryError("idempotent evidence result has wrong type")
                return replayed
            created = self._insert_artifact(evidence)
            if created:
                self._insert_evidence_projection(evidence, candidate_version_id)
            self._remember_idempotency(operation, idempotency_key, fingerprint, (evidence,))
        return evidence

    def persist_specification(
        self,
        specification: ConstrainedDeclarativeSpecification,
        *,
        idempotency_key: Optional[str] = None,
    ) -> ConstrainedDeclarativeSpecification:
        operation = "persist_specification"
        fingerprint = _request_hash(specification)
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (specification.artifact_id,)
            )
            if replay is not None:
                return self._expect(replay[0], ConstrainedDeclarativeSpecification)
            self._require_candidate(specification.candidate_record_id)
            self._insert_artifact(specification)
            self.connection.execute(
                """
                INSERT INTO ecatsl_specification
                    (artifact_id, candidate_artifact_id, role, api_signature)
                VALUES (?, ?, ?, ?)
                """,
                (
                    specification.artifact_id,
                    specification.candidate_record_id,
                    specification.role.value,
                    specification.api_signature,
                ),
            )
            self._remember_idempotency(
                operation, idempotency_key, fingerprint, (specification,)
            )
        return specification

    def persist_explanatory_support(
        self,
        support: CatalogRecord,
        *,
        idempotency_key: Optional[str] = None,
    ) -> CatalogRecord:
        operation = "persist_explanatory_support"
        fingerprint = _request_hash(support)
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (support.artifact_id,)
            )
            if replay is not None:
                replayed = replay[0]
                if not isinstance(replayed, CatalogRecord):
                    raise ArtifactRepositoryError("idempotent support result has wrong type")
                return replayed
            self._insert_artifact(support)
            self.connection.execute(
                """
                INSERT INTO ecatsl_explanatory_support
                    (artifact_id, record_type, canonical_identifier)
                VALUES (?, ?, ?)
                """,
                (support.artifact_id, support.record_type, support.canonical_identifier),
            )
            self._remember_idempotency(operation, idempotency_key, fingerprint, (support,))
        return support

    def persist_policy_outcome(
        self,
        decision: PolicyDecisionRecord,
        *,
        candidate: Optional[CandidateRecord] = None,
        expected_predecessor_id: Optional[str] = None,
        audit_failures: Sequence[AuditFailureRecord] = (),
        idempotency_key: Optional[str] = None,
    ) -> PolicyPersistenceResult:
        """Retain the authoritative outcome even when optional audit details fail."""
        operation = "persist_policy_outcome"
        fingerprint = _request_hash(
            {
                "decision": decision.model_dump(mode="json"),
                "candidate": candidate.model_dump(mode="json") if candidate else None,
                "expected": expected_predecessor_id,
                "failures": [item.model_dump(mode="json") for item in audit_failures],
            }
        )
        _reject_duplicate_failure_elements(audit_failures)
        injected_failures: Tuple[AuditFailureRecord, ...] = ()
        try:
            self._call_test_hook(
                "policy.optional_audit_metadata",
                self._transaction_id(operation, idempotency_key, fingerprint),
            )
        except OptionalMetadataPersistenceError as error:
            injected_failures = tuple(
                AuditFailureRecord(
                    version=decision.version,
                    created_at=decision.created_at,
                    provenance=decision.provenance,
                    operation="policy_audit",
                    missing_element=item,
                    failure_data=(
                        Attribute(name="error", value="optional metadata persistence failed"),
                    ),
                )
                for item in error.missing_elements
            )
        audit_failures = tuple(audit_failures) + injected_failures
        _reject_duplicate_failure_elements(audit_failures)
        missing = _unique(
            decision.missing_audit_elements
            + tuple(item.missing_element for item in audit_failures)
        )
        effective_candidate = candidate
        if candidate is not None and missing:
            effective_candidate = candidate.model_copy(
                update={
                    "missing_audit_elements": _unique(
                        candidate.missing_audit_elements + missing
                    )
                }
            )
        candidate_id = (
            effective_candidate.artifact_id
            if effective_candidate is not None
            else decision.candidate_version_id
        )
        effective_decision = decision.model_copy(
            update={
                "candidate_version_id": candidate_id,
                "missing_audit_elements": missing,
            }
        )
        supplied_failures = {item.missing_element: item for item in audit_failures}
        normalized_failures = tuple(
            (
                supplied_failures[item].model_copy(
                    update={"related_artifact_id": effective_decision.artifact_id}
                )
                if item in supplied_failures
                else AuditFailureRecord(
                    version=effective_decision.version,
                    created_at=effective_decision.created_at,
                    provenance=effective_decision.provenance,
                    related_artifact_id=effective_decision.artifact_id,
                    operation="policy_audit",
                    missing_element=item,
                    failure_data=(
                        Attribute(
                            name="error",
                            value="optional metadata persistence failed",
                        ),
                    ),
                )
            )
            for item in missing
        )
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation,
                idempotency_key,
                fingerprint,
            )
            if replay is not None:
                offset = 0
                replay_candidate: Optional[CandidateRecord] = None
                if candidate is not None:
                    replay_candidate = self._expect(replay[0], CandidateRecord)
                    offset = 1
                replay_decision = self._expect(replay[offset], PolicyDecisionRecord)
                replay_failures = tuple(
                    self._expect(item, AuditFailureRecord) for item in replay[offset + 1 :]
                )
                self._validate_policy_replay(
                    decision,
                    candidate,
                    tuple(audit_failures),
                    replay_candidate,
                    replay_decision,
                    replay_failures,
                )
                return PolicyPersistenceResult(
                    replay_candidate, replay_decision, replay_failures
                )
            if effective_candidate is not None:
                if effective_decision.candidate_version_id != effective_candidate.artifact_id:
                    raise LineageError("policy decision must reference the supplied candidate")
                head = self._candidate_head(effective_candidate.candidate_id)
                if effective_candidate.predecessor_id is None:
                    if head is not None or expected_predecessor_id is not None:
                        raise StalePredecessorError("policy candidate root is stale")
                else:
                    self._assert_candidate_head(
                        effective_candidate, expected_predecessor_id
                    )
                self._insert_artifact(effective_candidate)
                self._insert_candidate_projection(effective_candidate)
            else:
                self._require_candidate(effective_decision.candidate_version_id)
            for artifact_id in effective_decision.input_artifact_ids:
                self._require_artifact(artifact_id)
            self._insert_artifact(effective_decision)
            self.connection.execute(
                """
                INSERT INTO ecatsl_policy_decision
                    (artifact_id, candidate_version_id, policy_kind, policy_version,
                     outcome, input_artifact_ids_json, audit_metadata_json,
                     missing_audit_elements_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    effective_decision.artifact_id,
                    effective_decision.candidate_version_id,
                    effective_decision.policy_kind,
                    effective_decision.policy_version,
                    effective_decision.outcome,
                    _canonical_json(list(effective_decision.input_artifact_ids)),
                    _canonical_json(
                        [item.model_dump(mode="json") for item in effective_decision.audit_metadata]
                    ),
                    _canonical_json(list(effective_decision.missing_audit_elements)),
                ),
            )
            for failure in normalized_failures:
                self._insert_failure(failure)
            results: Tuple[Artifact, ...] = (
                ((effective_candidate,) if effective_candidate is not None else ())
                + (effective_decision,)
                + normalized_failures
            )
            self._remember_idempotency(operation, idempotency_key, fingerprint, results)
        return PolicyPersistenceResult(
            effective_candidate, effective_decision, normalized_failures
        )

    def retain_validation(
        self,
        candidate_version_id: str,
        validation: ValidationResult,
        *,
        counterexamples: Sequence[Counterexample] = (),
        idempotency_key: Optional[str] = None,
    ) -> ValidationRetentionResult:
        operation = "retain_validation"
        fingerprint = _request_hash(
            {
                "candidate": candidate_version_id,
                "validation": validation.model_dump(mode="json"),
                "counterexamples": [item.model_dump(mode="json") for item in counterexamples],
            }
        )
        expected_ids = (validation.artifact_id,) + tuple(
            item.artifact_id for item in counterexamples
        )
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, expected_ids
            )
            if replay is not None:
                return ValidationRetentionResult(
                    self._expect(replay[0], ValidationResult),
                    tuple(self._expect(item, Counterexample) for item in replay[1:]),
                )
            self._require_candidate(candidate_version_id)
            for artifact_id in validation.linked_artifact_ids:
                self._require_artifact(artifact_id)
            self._insert_artifact(validation)
            self.connection.execute(
                """
                INSERT INTO ecatsl_validation_result
                    (artifact_id, candidate_version_id, result_kind, outcome,
                     adapter_id, adapter_version)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    validation.artifact_id,
                    candidate_version_id,
                    validation.kind,
                    validation.outcome,
                    validation.adapter_id,
                    validation.adapter_version,
                ),
            )
            for counterexample in counterexamples:
                self._insert_artifact(counterexample)
                self._insert_evidence_projection(counterexample, candidate_version_id)
            results = (validation,) + tuple(counterexamples)
            self._remember_idempotency(operation, idempotency_key, fingerprint, results)
        return ValidationRetentionResult(validation, tuple(counterexamples))

    def persist_static_adapter_run(
        self,
        run: StaticAdapterRun,
        *,
        idempotency_key: Optional[str] = None,
    ) -> StaticAdapterRun:
        """Authorize and retain one configured adapter run and all of its inputs."""
        operation = "persist_static_adapter_run"
        fingerprint = _request_hash(run)
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (run.artifact_id,)
            )
            if replay is not None:
                return self._expect(replay[0], StaticAdapterRun)
            self._require_supported_adapter(run.adapter_id, run.adapter_version)
            candidates = _unique(run.candidate_record_ids)
            specifications = _unique(run.specification_ids)
            for candidate_id in candidates:
                self._require_candidate(candidate_id)
            for specification_id in specifications:
                spec_candidate = self._require_specification(specification_id)
                if spec_candidate not in candidates:
                    raise LineageError(
                        "adapter-run specification must reference a bound candidate"
                    )
            validation_candidate, validation_adapter = self._require_validation(
                run.validation_result_id
            )
            if validation_candidate not in candidates:
                raise LineageError("adapter-run validation must reference a bound candidate")
            if validation_adapter != (run.adapter_id, run.adapter_version):
                raise LineageError("adapter-run validation identity/version mismatch")
            validation = self._load_in_transaction(
                run.validation_result_id, ValidationResult
            )
            expected_links = set(candidates + specifications)
            if not expected_links.issubset(validation.linked_artifact_ids):
                raise LineageError("adapter-run validation lacks candidate/specification links")
            for artifact_id in run.input_artifact_ids:
                self._require_artifact(artifact_id)
            self._insert_artifact(run)
            self.connection.execute(
                """
                INSERT INTO ecatsl_static_adapter_run
                    (artifact_id, support_registry_version, adapter_id, adapter_version,
                     run_identity, validation_artifact_id, input_artifact_ids_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.artifact_id,
                    SUPPORTED_ADAPTER_REGISTRY_VERSION,
                    run.adapter_id,
                    run.adapter_version,
                    run.run_identity,
                    run.validation_result_id,
                    _canonical_json(list(run.input_artifact_ids)),
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO ecatsl_static_run_candidate
                    (run_artifact_id, candidate_artifact_id) VALUES (?, ?)
                """,
                [(run.artifact_id, item) for item in candidates],
            )
            self.connection.executemany(
                """
                INSERT INTO ecatsl_static_run_specification
                    (run_artifact_id, specification_artifact_id) VALUES (?, ?)
                """,
                [(run.artifact_id, item) for item in specifications],
            )
            self._remember_idempotency(operation, idempotency_key, fingerprint, (run,))
        return run

    def persist_static_path(
        self,
        path: PathEvidence,
        *,
        adapter_run_id: str,
        idempotency_key: Optional[str] = None,
    ) -> PathEvidence:
        """Retain path proof only through a configured, fully bound adapter run."""
        operation = "persist_static_path"
        fingerprint = _request_hash(
            {"path": path.model_dump(mode="json"), "run": adapter_run_id}
        )
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (path.artifact_id,)
            )
            if replay is not None:
                return self._expect(replay[0], PathEvidence)
            run = self._require_static_run(adapter_run_id)
            self._require_supported_adapter(run.adapter_id, run.adapter_version)
            if (path.adapter_id, path.adapter_version) != (
                run.adapter_id,
                run.adapter_version,
            ):
                raise LineageError("path adapter identity/version does not match its run")
            self._insert_artifact(path)
            self.connection.execute(
                """
                INSERT INTO ecatsl_path_evidence
                    (artifact_id, adapter_run_artifact_id, validation_artifact_id,
                     adapter_id, adapter_version, static_evidence_identity)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    path.artifact_id,
                    run.artifact_id,
                    run.validation_result_id,
                    path.adapter_id,
                    path.adapter_version,
                    path.static_evidence_identity,
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO ecatsl_path_candidate
                    (path_artifact_id, candidate_artifact_id) VALUES (?, ?)
                """,
                [(path.artifact_id, item) for item in _unique(run.candidate_record_ids)],
            )
            self.connection.executemany(
                """
                INSERT INTO ecatsl_path_specification
                    (path_artifact_id, specification_artifact_id) VALUES (?, ?)
                """,
                [(path.artifact_id, item) for item in _unique(run.specification_ids)],
            )
            self._remember_idempotency(operation, idempotency_key, fingerprint, (path,))
        return path

    def persist_classification(
        self,
        classification: FindingClassification,
        *,
        idempotency_key: Optional[str] = None,
    ) -> ClassificationPersistenceResult:
        """Retain a decision, all valid lineage, and one flag per unavailable element."""
        operation = "persist_classification"
        fingerprint = _request_hash(classification)
        try:
            self._call_test_hook(
                "classification.optional_audit_metadata",
                self._transaction_id(operation, idempotency_key, fingerprint),
            )
        except OptionalMetadataPersistenceError as error:
            classification = classification.model_copy(
                update={
                    "missing_metadata": _unique(
                        classification.missing_metadata + error.missing_elements
                    )
                }
            )
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(operation, idempotency_key, fingerprint)
            if replay is not None:
                replayed_classification = self._expect(
                    replay[0], FindingClassification
                )
                replayed_failures = tuple(
                    self._expect(item, AuditFailureRecord) for item in replay[1:]
                )
                self._validate_classification_replay(
                    classification, replayed_classification, replayed_failures
                )
                return ClassificationPersistenceResult(
                    replayed_classification, replayed_failures
                )

            candidates, candidate_missing = self._available_projection_ids(
                classification.candidate_record_ids,
                "ecatsl_candidate_version",
                "candidate_record",
            )
            specifications, specification_missing = self._available_projection_ids(
                classification.specification_ids,
                "ecatsl_specification",
                "specification",
            )
            validations, validation_missing = self._available_projection_ids(
                classification.validation_result_ids,
                "ecatsl_validation_result",
                "validation_result",
            )
            supports, support_missing = self._available_projection_ids(
                classification.explanatory_support_ids,
                "ecatsl_explanatory_support",
                "explanatory_support",
            )
            missing = _unique(
                classification.missing_metadata
                + candidate_missing
                + specification_missing
                + validation_missing
                + support_missing
            )

            candidate_set = set(candidates)
            for specification_id in specifications:
                if self._require_specification(specification_id) not in candidate_set:
                    raise LineageError("finding specification crosses candidate lineage")
            for validation_id in validations:
                validation_candidate, _ = self._require_validation(validation_id)
                if validation_candidate not in candidate_set:
                    raise LineageError("finding validation crosses candidate lineage")

            path_row = None
            if classification.path_evidence_id is not None:
                path_row = self.connection.execute(
                    """
                    SELECT adapter_run_artifact_id, validation_artifact_id,
                           adapter_id, adapter_version
                    FROM ecatsl_path_evidence WHERE artifact_id = ?
                    """,
                    (classification.path_evidence_id,),
                ).fetchone()
                if path_row is None:
                    if self._artifact_exists(classification.path_evidence_id):
                        raise LineageError("path artifact lacks an authorized static-path binding")
                    if classification.status is FindingStatus.CONFIRMED:
                        raise LineageError("confirmed classification requires authorized PathEvidence")
                    missing = _unique(
                        missing + (f"path_evidence:{classification.path_evidence_id}",)
                    )
            elif classification.status is FindingStatus.CONFIRMED:
                raise LineageError("confirmed classification requires PathEvidence")

            if classification.status is FindingStatus.CONFIRMED:
                assert path_row is not None
                path = self._load_in_transaction(
                    classification.path_evidence_id, PathEvidence  # type: ignore[arg-type]
                )
                adapter = (str(path_row[2]), str(path_row[3]))
                self._require_supported_adapter(*adapter)
                if adapter != (path.adapter_id, path.adapter_version):
                    raise LineageError("authorized path binding does not match path payload")
                if path.sanitizer_status not in (
                    SanitizerStatus.ABSENT,
                    SanitizerStatus.FAILED,
                ):
                    raise LineageError("blocking sanitizer cannot confirm a finding")
                path_candidates = self._related_ids(
                    "ecatsl_path_candidate", "path_artifact_id",
                    "candidate_artifact_id", path.artifact_id
                )
                path_specs = self._related_ids(
                    "ecatsl_path_specification", "path_artifact_id",
                    "specification_artifact_id", path.artifact_id
                )
                if not set(path_candidates).issubset(candidates):
                    raise LineageError("classification omits path-bound candidate lineage")
                if not set(path_specs).issubset(specifications):
                    raise LineageError("classification omits path-bound specification lineage")
                if str(path_row[1]) not in validations:
                    raise LineageError("classification omits path-bound validation lineage")

            effective = classification.model_copy(update={"missing_metadata": missing})
            self._insert_artifact(effective)
            legacy_specification = specifications[0] if specifications else None
            self.connection.execute(
                """
                INSERT INTO ecatsl_finding_lineage
                    (artifact_id, status, reason, specification_artifact_id,
                     path_evidence_artifact_id, missing_metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    effective.artifact_id,
                    effective.status.value,
                    effective.reason,
                    legacy_specification,
                    effective.path_evidence_id if path_row is not None else None,
                    _canonical_json(list(effective.missing_metadata)),
                ),
            )
            self._insert_relations(
                "ecatsl_finding_candidate", "candidate_artifact_id",
                effective.artifact_id, candidates
            )
            self._insert_relations(
                "ecatsl_finding_validation", "validation_artifact_id",
                effective.artifact_id, validations
            )
            self._insert_relations(
                "ecatsl_finding_specification", "specification_artifact_id",
                effective.artifact_id, specifications
            )
            self._insert_relations(
                "ecatsl_finding_explanatory_support",
                "explanatory_support_artifact_id", effective.artifact_id, supports
            )

            failures = tuple(
                AuditFailureRecord(
                    version=effective.version,
                    created_at=effective.created_at,
                    provenance=effective.provenance,
                    related_artifact_id=effective.artifact_id,
                    operation="finding_lineage",
                    missing_element=item,
                    failure_data=(Attribute(name="retention", value="unavailable"),),
                )
                for item in missing
            )
            for failure in failures:
                self._insert_failure(failure)
                self.connection.execute(
                    """
                    INSERT INTO ecatsl_finding_missing_metadata
                        (finding_artifact_id, missing_element, failure_artifact_id)
                    VALUES (?, ?, ?)
                    """,
                    (effective.artifact_id, failure.missing_element, failure.artifact_id),
                )
            results: Tuple[Artifact, ...] = (effective,) + failures
            self._remember_idempotency(operation, idempotency_key, fingerprint, results)
        return ClassificationPersistenceResult(effective, failures)

    def persist_scope_revision(
        self,
        scope: ScopeDefinition,
        *,
        scope_name: str = "initial",
        expected_predecessor_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> ScopeDefinition:
        operation = f"persist_scope_revision:{scope_name}"
        fingerprint = _request_hash(
            {"scope": scope.model_dump(mode="json"), "expected": expected_predecessor_id}
        )
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (scope.artifact_id,)
            )
            if replay is not None:
                return self._expect(replay[0], ScopeDefinition)
            self._assert_named_head(
                "ecatsl_scope_version", "scope_name", scope_name,
                scope.predecessor_id, expected_predecessor_id
            )
            self._insert_artifact(scope)
            self.connection.execute(
                """
                INSERT INTO ecatsl_scope_version
                    (artifact_id, scope_name, scope_version, predecessor_id,
                     language, cwe_ids_json, versioning_state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope.artifact_id, scope_name, scope.version, scope.predecessor_id,
                    scope.language, _canonical_json(list(scope.cwe_ids)),
                    "COMPLETE" if scope.versioning_complete else "INCOMPLETE",
                ),
            )
            self._remember_idempotency(operation, idempotency_key, fingerprint, (scope,))
        return scope

    def persist_reuse_revision(
        self,
        inventory: ReuseInventory,
        *,
        inventory_name: str = "default",
        expected_predecessor_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> ReuseInventory:
        operation = f"persist_reuse_revision:{inventory_name}"
        fingerprint = _request_hash(
            {"inventory": inventory.model_dump(mode="json"), "expected": expected_predecessor_id}
        )
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (inventory.artifact_id,)
            )
            if replay is not None:
                return self._expect(replay[0], ReuseInventory)
            self._assert_named_head(
                "ecatsl_reuse_inventory_version", "inventory_name", inventory_name,
                inventory.predecessor_id, expected_predecessor_id
            )
            self._insert_artifact(inventory)
            self.connection.execute(
                """
                INSERT INTO ecatsl_reuse_inventory_version
                    (artifact_id, inventory_name, inventory_version,
                     predecessor_id, entries_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    inventory.artifact_id, inventory_name, inventory.version,
                    inventory.predecessor_id,
                    _canonical_json([entry.model_dump(mode="json") for entry in inventory.entries]),
                ),
            )
            self._remember_idempotency(operation, idempotency_key, fingerprint, (inventory,))
        return inventory

    def record_failure(
        self,
        failure: AuditFailureRecord,
        *,
        idempotency_key: Optional[str] = None,
    ) -> AuditFailureRecord:
        operation = "record_failure"
        fingerprint = _request_hash(failure)
        with self._atomic(operation, idempotency_key, fingerprint):
            replay = self._lookup_idempotency(
                operation, idempotency_key, fingerprint, (failure.artifact_id,)
            )
            if replay is not None:
                return self._expect(replay[0], AuditFailureRecord)
            self._insert_failure(failure)
            self._remember_idempotency(operation, idempotency_key, fingerprint, (failure,))
        return failure

    record_creation_failure = record_failure
    record_persistence_failure = record_failure

    @staticmethod
    def _validate_policy_replay(
        requested_decision: PolicyDecisionRecord,
        requested_candidate: Optional[CandidateRecord],
        requested_failures: Sequence[AuditFailureRecord],
        replayed_candidate: Optional[CandidateRecord],
        replayed_decision: PolicyDecisionRecord,
        replayed_failures: Sequence[AuditFailureRecord],
    ) -> None:
        """Bind a replay to the exact policy request and derived audit failures."""

        if (requested_candidate is None) != (replayed_candidate is None):
            raise ImmutableArtifactError(
                "idempotent policy candidate cardinality is corrupted"
            )
        missing = replayed_decision.missing_audit_elements
        if len(missing) != len(set(missing)) or len(replayed_failures) != len(missing):
            raise ImmutableArtifactError(
                "idempotent policy failure cardinality is corrupted"
            )
        _reject_duplicate_failure_elements(requested_failures)
        explicit_by_missing = {
            item.missing_element: item for item in requested_failures
        }
        allowed_requested_missing = set(requested_decision.missing_audit_elements)
        allowed_requested_missing.update(explicit_by_missing)
        if requested_candidate is not None:
            allowed_requested_missing.update(requested_candidate.missing_audit_elements)
        if not allowed_requested_missing.issubset(missing):
            raise ImmutableArtifactError(
                "idempotent policy missing-audit elements omit requested data"
            )

        expected_candidate = requested_candidate
        candidate_id = requested_decision.candidate_version_id
        if requested_candidate is not None:
            expected_candidate = requested_candidate.model_copy(
                update={
                    "missing_audit_elements": _unique(
                        requested_candidate.missing_audit_elements + missing
                    )
                }
            )
            candidate_id = expected_candidate.artifact_id
            if replayed_candidate != expected_candidate:
                raise ImmutableArtifactError(
                    "idempotent policy candidate or lineage does not match the request"
                )

        expected_decision = requested_decision.model_copy(
            update={
                "candidate_version_id": candidate_id,
                "missing_audit_elements": missing,
            }
        )
        if replayed_decision != expected_decision:
            raise ImmutableArtifactError(
                "idempotent policy kind, version, outcome, inputs, audit data, or identity is corrupted"
            )

        expected_failures = []
        for missing_element in missing:
            explicit = explicit_by_missing.get(missing_element)
            if explicit is not None:
                expected = explicit.model_copy(
                    update={"related_artifact_id": replayed_decision.artifact_id}
                )
            else:
                expected = AuditFailureRecord(
                    version=replayed_decision.version,
                    created_at=replayed_decision.created_at,
                    provenance=replayed_decision.provenance,
                    related_artifact_id=replayed_decision.artifact_id,
                    operation="policy_audit",
                    missing_element=missing_element,
                    failure_data=(
                        Attribute(
                            name="error",
                            value="optional metadata persistence failed",
                        ),
                    ),
                )
            expected_failures.append(expected)
        if tuple(replayed_failures) != tuple(expected_failures):
            raise ImmutableArtifactError(
                "idempotent policy failure ordering or relationships are corrupted"
            )

    @staticmethod
    def _validate_classification_replay(
        requested: FindingClassification,
        replayed: FindingClassification,
        failures: Sequence[AuditFailureRecord],
    ) -> None:
        allowed_missing = set(requested.missing_metadata)
        allowed_missing.update(item.missing_element for item in failures)
        allowed_missing.update(
            f"candidate_record:{item}" for item in requested.candidate_record_ids
        )
        allowed_missing.update(
            f"specification:{item}" for item in requested.specification_ids
        )
        allowed_missing.update(
            f"validation_result:{item}" for item in requested.validation_result_ids
        )
        allowed_missing.update(
            f"explanatory_support:{item}"
            for item in requested.explanatory_support_ids
        )
        if requested.path_evidence_id is not None:
            allowed_missing.add(f"path_evidence:{requested.path_evidence_id}")
        if (
            not set(requested.missing_metadata).issubset(replayed.missing_metadata)
            or not set(replayed.missing_metadata).issubset(allowed_missing)
        ):
            raise ImmutableArtifactError(
                "idempotent classification missing-metadata list is corrupted"
            )
        expected = requested.model_copy(
            update={"missing_metadata": replayed.missing_metadata}
        )
        if replayed != expected:
            raise ImmutableArtifactError(
                "idempotent classification does not match the committed request"
            )
        expected_failures = tuple(
            AuditFailureRecord(
                version=replayed.version,
                created_at=replayed.created_at,
                provenance=replayed.provenance,
                related_artifact_id=replayed.artifact_id,
                operation="finding_lineage",
                missing_element=item,
                failure_data=(Attribute(name="retention", value="unavailable"),),
            )
            for item in replayed.missing_metadata
        )
        if tuple(failures) != expected_failures:
            raise ImmutableArtifactError(
                "idempotent classification failure relationships are corrupted"
            )

    def _insert_failure(self, failure: AuditFailureRecord) -> None:
        if failure.related_artifact_id is not None:
            self._require_artifact(failure.related_artifact_id)
        self._insert_artifact(failure)
        self.connection.execute(
            """
            INSERT INTO ecatsl_audit_failure
                (artifact_id, related_artifact_id, operation, missing_element,
                 failure_data_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                failure.artifact_id, failure.related_artifact_id,
                failure.operation, failure.missing_element,
                _canonical_json([item.model_dump(mode="json") for item in failure.failure_data]),
            ),
        )

    def _assert_candidate_head(
        self, record: CandidateRecord, expected_predecessor_id: Optional[str]
    ) -> None:
        head = self._candidate_head(record.candidate_id)
        if (
            record.predecessor_id != expected_predecessor_id
            or head != expected_predecessor_id
        ):
            raise StalePredecessorError(
                f"candidate {record.candidate_id} head is {head!r}, "
                f"not {expected_predecessor_id!r}"
            )

    def _assert_named_head(
        self,
        table: str,
        name_column: str,
        name: str,
        artifact_predecessor_id: Optional[str],
        expected_predecessor_id: Optional[str],
    ) -> None:
        row = self.connection.execute(
            f"""
            SELECT current.artifact_id
            FROM {table} AS current
            LEFT JOIN {table} AS successor
              ON successor.{name_column} = current.{name_column}
             AND successor.predecessor_id = current.artifact_id
            WHERE current.{name_column} = ? AND successor.artifact_id IS NULL
            """,
            (name,),
        ).fetchone()
        head = str(row[0]) if row is not None else None
        if artifact_predecessor_id != expected_predecessor_id or head != expected_predecessor_id:
            raise StalePredecessorError(
                f"{name} head is {head!r}, not {expected_predecessor_id!r}"
            )

    def _artifact_exists(self, artifact_id: str) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM ecatsl_artifact WHERE artifact_id = ?", (artifact_id,)
        ).fetchone() is not None

    def _require_artifact(self, artifact_id: str) -> None:
        if not self._artifact_exists(artifact_id):
            raise LineageError(f"artifact {artifact_id} does not exist")

    def _require_candidate(self, artifact_id: str) -> None:
        row = self.connection.execute(
            "SELECT 1 FROM ecatsl_candidate_version WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        if row is None:
            raise LineageError(f"candidate version {artifact_id} does not exist")

    def _require_specification(self, artifact_id: str) -> str:
        row = self.connection.execute(
            "SELECT candidate_artifact_id FROM ecatsl_specification WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise LineageError(f"specification {artifact_id} does not exist")
        self._load_in_transaction(artifact_id, ConstrainedDeclarativeSpecification)
        return str(row[0])

    def _require_validation(self, artifact_id: str) -> Tuple[str, Tuple[Optional[str], Optional[str]]]:
        row = self.connection.execute(
            """
            SELECT candidate_version_id, adapter_id, adapter_version
            FROM ecatsl_validation_result WHERE artifact_id = ?
            """,
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise LineageError(f"validation result {artifact_id} does not exist")
        self._load_in_transaction(artifact_id, ValidationResult)
        return str(row[0]), (row[1], row[2])

    def _require_static_run(self, artifact_id: str) -> StaticAdapterRun:
        row = self.connection.execute(
            "SELECT 1 FROM ecatsl_static_adapter_run WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        if row is None:
            raise LineageError(f"static adapter run {artifact_id} does not exist")
        return self._load_in_transaction(artifact_id, StaticAdapterRun)

    def _require_supported_adapter(self, adapter_id: str, adapter_version: str) -> None:
        if (adapter_id, adapter_version) not in self.supported_static_adapters:
            raise LineageError(
                f"unsupported static adapter identity/version: {adapter_id}@{adapter_version}"
            )

    def _available_projection_ids(
        self,
        artifact_ids: Sequence[str],
        table: str,
        label: str,
    ) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        available = []
        missing = []
        for artifact_id in _unique(artifact_ids):
            row = self.connection.execute(
                f"SELECT 1 FROM {table} WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
            if row is not None:
                available.append(artifact_id)
            elif self._artifact_exists(artifact_id):
                raise LineageError(f"{label} {artifact_id} has the wrong artifact kind")
            else:
                missing.append(f"{label}:{artifact_id}")
        return tuple(available), tuple(missing)

    def _related_ids(
        self, table: str, owner_column: str, value_column: str, owner_id: str
    ) -> Tuple[str, ...]:
        return tuple(
            str(row[0])
            for row in self.connection.execute(
                f"SELECT {value_column} FROM {table} WHERE {owner_column} = ? ORDER BY rowid",
                (owner_id,),
            )
        )

    def _insert_relations(
        self,
        table: str,
        value_column: str,
        finding_id: str,
        artifact_ids: Sequence[str],
    ) -> None:
        self.connection.executemany(
            f"""
            INSERT INTO {table} (finding_artifact_id, {value_column}) VALUES (?, ?)
            """,
            [(finding_id, artifact_id) for artifact_id in _unique(artifact_ids)],
        )

    @staticmethod
    def _expect(artifact: Artifact, expected: Type[ArtifactT]) -> ArtifactT:
        if type(artifact) is not expected:
            raise ArtifactRepositoryError(
                f"idempotent result is {type(artifact).__name__}, expected {expected.__name__}"
            )
        return artifact  # type: ignore[return-value]
