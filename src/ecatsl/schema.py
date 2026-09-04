"""Transactional SQLite schema installation for immutable ECATSL artifacts."""

from __future__ import annotations

import errno
import hashlib
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional, Sequence, Tuple
from uuid import uuid4


SCHEMA_VERSION = 8
_SCHEMA_VERSION_TABLE = "ecatsl_schema_version"
_PROCESS_OWNER_TOKEN = uuid4().hex
_ACTIVE_ATTEMPTS: set[str] = set()
_ACTIVE_ATTEMPTS_LOCK = threading.Lock()


def _register_attempt(attempt_id: str) -> None:
    with _ACTIVE_ATTEMPTS_LOCK:
        _ACTIVE_ATTEMPTS.add(attempt_id)


def _unregister_attempt(attempt_id: str) -> None:
    with _ACTIVE_ATTEMPTS_LOCK:
        _ACTIVE_ATTEMPTS.discard(attempt_id)


class ProcessLiveness(str, Enum):
    """Conservative process state used by crash recovery."""

    ALIVE = "ALIVE"
    DEAD = "DEAD"
    UNKNOWN = "UNKNOWN"


ProcessLivenessProbe = Callable[[int], ProcessLiveness]


def _pid_liveness(pid: int) -> ProcessLiveness:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(
            process_query_limited_information, False, pid
        )
        if not handle:
            return ProcessLiveness.UNKNOWN
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return ProcessLiveness.UNKNOWN
            return (
                ProcessLiveness.ALIVE
                if int(exit_code.value) == still_active
                else ProcessLiveness.DEAD
            )
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return ProcessLiveness.DEAD
    except PermissionError:
        return ProcessLiveness.ALIVE
    except OSError as error:
        if error.errno == errno.ESRCH:
            return ProcessLiveness.DEAD
        if error.errno == errno.EPERM:
            return ProcessLiveness.ALIVE
        return ProcessLiveness.UNKNOWN
    except ValueError:
        return ProcessLiveness.DEAD
    return ProcessLiveness.ALIVE


def _owner_liveness(
    owner_pid: int,
    owner_token: str,
    attempt_id: str,
    *,
    process_probe: ProcessLivenessProbe = _pid_liveness,
) -> ProcessLiveness:
    """Classify owner liveness, recovering only when death is provable.

    The process token distinguishes an old local process incarnation from the
    current one. For a foreign PID, a recycled PID can only delay recovery by
    appearing alive; it can never cause a live owner to be interrupted.
    """

    if owner_pid == os.getpid():
        if owner_token != _PROCESS_OWNER_TOKEN:
            return ProcessLiveness.DEAD
        with _ACTIVE_ATTEMPTS_LOCK:
            return (
                ProcessLiveness.ALIVE
                if attempt_id in _ACTIVE_ATTEMPTS
                else ProcessLiveness.DEAD
            )
    return process_probe(owner_pid)


@dataclass(frozen=True)
class SQLiteWriteConfig:
    """Bounded SQLite writer acquisition used by migrations and repositories."""

    busy_timeout_ms: int = 250
    lock_retry_attempts: int = 5
    lock_retry_initial_seconds: float = 0.01
    lock_retry_max_seconds: float = 0.2

    def __post_init__(self) -> None:
        if self.busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be non-negative")
        if self.lock_retry_attempts < 0:
            raise ValueError("lock_retry_attempts must be non-negative")
        if self.lock_retry_initial_seconds < 0 or self.lock_retry_max_seconds < 0:
            raise ValueError("lock retry delays must be non-negative")
        if self.lock_retry_initial_seconds > self.lock_retry_max_seconds:
            raise ValueError("initial lock retry delay cannot exceed the maximum")


def _is_lock_error(error: sqlite3.OperationalError) -> bool:
    message = str(error).lower()
    return "locked" in message or "busy" in message


def begin_immediate_with_retry(
    connection: sqlite3.Connection,
    config: SQLiteWriteConfig,
    *,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Acquire a writer transaction with bounded exponential lock retry."""

    delay = config.lock_retry_initial_seconds
    for attempt in range(config.lock_retry_attempts + 1):
        try:
            connection.execute("BEGIN IMMEDIATE")
            return
        except sqlite3.OperationalError as error:
            if not _is_lock_error(error) or attempt >= config.lock_retry_attempts:
                raise
            sleeper(delay)
            delay = min(config.lock_retry_max_seconds, max(delay * 2, 0.0))


@dataclass(frozen=True)
class SchemaMigration:
    """One atomic, repeatable ECATSL schema migration."""

    version: int
    name: str
    statements: Tuple[str, ...]

    @property
    def checksum(self) -> str:
        payload = "\n-- statement --\n".join(statement.strip() for statement in self.statements)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _immutable_triggers(table: str) -> Tuple[str, str]:
    return (
        f"""
        CREATE TRIGGER IF NOT EXISTS {table}_reject_update
        BEFORE UPDATE ON {table}
        BEGIN
            SELECT RAISE(ABORT, 'ECATSL records are append-only');
        END
        """,
        f"""
        CREATE TRIGGER IF NOT EXISTS {table}_reject_delete
        BEFORE DELETE ON {table}
        BEGIN
            SELECT RAISE(ABORT, 'ECATSL records are append-only');
        END
        """,
    )


_V1_TABLES = (
    "ecatsl_artifact",
    "ecatsl_candidate_version",
    "ecatsl_evidence",
    "ecatsl_policy_decision",
    "ecatsl_validation_result",
    "ecatsl_finding_lineage",
    "ecatsl_finding_candidate",
    "ecatsl_finding_validation",
    "ecatsl_scope_version",
    "ecatsl_reuse_inventory_version",
    "ecatsl_pipeline_stage",
    "ecatsl_audit_failure",
)

_V1_STATEMENTS: Tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS ecatsl_artifact (
        artifact_id TEXT PRIMARY KEY,
        artifact_type TEXT NOT NULL,
        version TEXT NOT NULL,
        content_hash TEXT NOT NULL
            CHECK(length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
        canonical_payload TEXT NOT NULL CHECK(json_valid(canonical_payload)),
        created_at TEXT NOT NULL,
        predecessor_id TEXT REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        CHECK(artifact_id = 'sha256:' || content_hash),
        CHECK(predecessor_id IS NULL OR predecessor_id <> artifact_id),
        UNIQUE(artifact_type, content_hash),
        UNIQUE(predecessor_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_candidate_version (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        candidate_id TEXT NOT NULL,
        candidate_version TEXT NOT NULL,
        candidate_type TEXT NOT NULL
            CHECK(candidate_type IN ('SOURCE', 'SINK', 'SANITIZER', 'PRECONDITION')),
        confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
        state TEXT NOT NULL
            CHECK(state IN ('PROPOSED', 'UNACCEPTED', 'ACCEPTED', 'REJECTED')),
        cwe_id TEXT NOT NULL CHECK(cwe_id GLOB 'CWE-[0-9]*'),
        predecessor_id TEXT,
        update_cause TEXT NOT NULL,
        changed_data_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(changed_data_json)),
        UNIQUE(candidate_id, candidate_version),
        UNIQUE(candidate_id, artifact_id),
        UNIQUE(candidate_id, predecessor_id),
        FOREIGN KEY(candidate_id, predecessor_id)
            REFERENCES ecatsl_candidate_version(candidate_id, artifact_id)
            ON DELETE RESTRICT,
        CHECK(predecessor_id IS NULL OR predecessor_id <> artifact_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_evidence (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        candidate_version_id TEXT
            REFERENCES ecatsl_candidate_version(artifact_id) ON DELETE RESTRICT,
        evidence_kind TEXT NOT NULL,
        contradicts TEXT,
        provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_policy_decision (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        candidate_version_id TEXT NOT NULL
            REFERENCES ecatsl_candidate_version(artifact_id) ON DELETE RESTRICT,
        policy_kind TEXT NOT NULL CHECK(policy_kind IN ('ACCEPTANCE', 'VALIDATION')),
        policy_version TEXT NOT NULL,
        outcome TEXT NOT NULL,
        input_artifact_ids_json TEXT NOT NULL CHECK(json_valid(input_artifact_ids_json)),
        UNIQUE(candidate_version_id, policy_kind, policy_version)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_validation_result (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        candidate_version_id TEXT NOT NULL
            REFERENCES ecatsl_candidate_version(artifact_id) ON DELETE RESTRICT,
        result_kind TEXT NOT NULL,
        outcome TEXT NOT NULL,
        adapter_id TEXT,
        adapter_version TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_finding_lineage (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        status TEXT NOT NULL CHECK(status IN ('CONFIRMED', 'UNCONFIRMED')),
        reason TEXT NOT NULL,
        specification_artifact_id TEXT
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        path_evidence_artifact_id TEXT
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        missing_metadata_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(missing_metadata_json))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_finding_candidate (
        finding_artifact_id TEXT NOT NULL
            REFERENCES ecatsl_finding_lineage(artifact_id) ON DELETE RESTRICT,
        candidate_artifact_id TEXT NOT NULL
            REFERENCES ecatsl_candidate_version(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(finding_artifact_id, candidate_artifact_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_finding_validation (
        finding_artifact_id TEXT NOT NULL
            REFERENCES ecatsl_finding_lineage(artifact_id) ON DELETE RESTRICT,
        validation_artifact_id TEXT NOT NULL
            REFERENCES ecatsl_validation_result(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(finding_artifact_id, validation_artifact_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_scope_version (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        scope_name TEXT NOT NULL,
        scope_version TEXT NOT NULL,
        predecessor_id TEXT,
        language TEXT NOT NULL,
        cwe_ids_json TEXT NOT NULL CHECK(json_valid(cwe_ids_json)),
        versioning_state TEXT NOT NULL,
        UNIQUE(scope_name, scope_version),
        UNIQUE(scope_name, artifact_id),
        UNIQUE(scope_name, predecessor_id),
        FOREIGN KEY(scope_name, predecessor_id)
            REFERENCES ecatsl_scope_version(scope_name, artifact_id)
            ON DELETE RESTRICT,
        CHECK(predecessor_id IS NULL OR predecessor_id <> artifact_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_reuse_inventory_version (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        inventory_name TEXT NOT NULL,
        inventory_version TEXT NOT NULL,
        predecessor_id TEXT,
        entries_json TEXT NOT NULL CHECK(json_valid(entries_json)),
        UNIQUE(inventory_name, inventory_version),
        UNIQUE(inventory_name, artifact_id),
        UNIQUE(inventory_name, predecessor_id),
        FOREIGN KEY(inventory_name, predecessor_id)
            REFERENCES ecatsl_reuse_inventory_version(inventory_name, artifact_id)
            ON DELETE RESTRICT,
        CHECK(predecessor_id IS NULL OR predecessor_id <> artifact_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_pipeline_stage (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        stage_identity TEXT NOT NULL,
        input_artifact_ids_json TEXT NOT NULL CHECK(json_valid(input_artifact_ids_json)),
        transformation_purpose TEXT NOT NULL,
        output_artifact_ids_json TEXT NOT NULL CHECK(json_valid(output_artifact_ids_json)),
        duplicate_of_artifact_id TEXT
            REFERENCES ecatsl_pipeline_stage(artifact_id) ON DELETE RESTRICT,
        consolidation_failure_artifact_id TEXT
            REFERENCES ecatsl_audit_failure(artifact_id) ON DELETE RESTRICT,
        CHECK(duplicate_of_artifact_id IS NULL OR duplicate_of_artifact_id <> artifact_id),
        CHECK(
            (duplicate_of_artifact_id IS NULL AND consolidation_failure_artifact_id IS NULL)
            OR
            (duplicate_of_artifact_id IS NOT NULL
             AND consolidation_failure_artifact_id IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ecatsl_audit_failure (
        artifact_id TEXT PRIMARY KEY
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        related_artifact_id TEXT
            REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        operation TEXT NOT NULL,
        missing_element TEXT NOT NULL,
        failure_data_json TEXT NOT NULL CHECK(json_valid(failure_data_json))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ecatsl_artifact_type ON ecatsl_artifact(artifact_type)",
    "CREATE INDEX IF NOT EXISTS idx_ecatsl_candidate_id ON ecatsl_candidate_version(candidate_id)",
    "CREATE INDEX IF NOT EXISTS idx_ecatsl_evidence_candidate ON ecatsl_evidence(candidate_version_id)",
    "CREATE INDEX IF NOT EXISTS idx_ecatsl_validation_candidate ON ecatsl_validation_result(candidate_version_id)",
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ecatsl_candidate_single_root
    ON ecatsl_candidate_version(candidate_id) WHERE predecessor_id IS NULL
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ecatsl_scope_single_root
    ON ecatsl_scope_version(scope_name) WHERE predecessor_id IS NULL
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ecatsl_reuse_single_root
    ON ecatsl_reuse_inventory_version(inventory_name) WHERE predecessor_id IS NULL
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ecatsl_pipeline_canonical_identity
    ON ecatsl_pipeline_stage(stage_identity) WHERE duplicate_of_artifact_id IS NULL
    """,
) + tuple(trigger for table in _V1_TABLES for trigger in _immutable_triggers(table)) + (
    """
    CREATE TRIGGER IF NOT EXISTS ecatsl_candidate_predecessor_matches_artifact
    BEFORE INSERT ON ecatsl_candidate_version
    WHEN (SELECT predecessor_id FROM ecatsl_artifact WHERE artifact_id = NEW.artifact_id)
         IS NOT NEW.predecessor_id
    BEGIN
        SELECT RAISE(ABORT, 'candidate predecessor must match artifact predecessor');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS ecatsl_scope_predecessor_matches_artifact
    BEFORE INSERT ON ecatsl_scope_version
    WHEN (SELECT predecessor_id FROM ecatsl_artifact WHERE artifact_id = NEW.artifact_id)
         IS NOT NEW.predecessor_id
    BEGIN
        SELECT RAISE(ABORT, 'scope predecessor must match artifact predecessor');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS ecatsl_reuse_predecessor_matches_artifact
    BEFORE INSERT ON ecatsl_reuse_inventory_version
    WHEN (SELECT predecessor_id FROM ecatsl_artifact WHERE artifact_id = NEW.artifact_id)
         IS NOT NEW.predecessor_id
    BEGIN
        SELECT RAISE(ABORT, 'reuse predecessor must match artifact predecessor');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS ecatsl_pipeline_duplicate_requires_failure
    BEFORE INSERT ON ecatsl_pipeline_stage
    WHEN NEW.duplicate_of_artifact_id IS NOT NULL
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM ecatsl_pipeline_stage AS canonical
            WHERE canonical.artifact_id = NEW.duplicate_of_artifact_id
              AND canonical.stage_identity = NEW.stage_identity
              AND canonical.duplicate_of_artifact_id IS NULL
        ) THEN RAISE(ABORT, 'duplicate stage must reference matching canonical stage') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM ecatsl_audit_failure AS failure
            WHERE failure.artifact_id = NEW.consolidation_failure_artifact_id
              AND failure.related_artifact_id = NEW.duplicate_of_artifact_id
              AND failure.operation = 'pipeline_stage_consolidation'
        ) THEN RAISE(ABORT, 'duplicate stage requires consolidation failure record') END;
    END
    """,
)

_V2_STATEMENTS: Tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS ecatsl_idempotency_key (
        operation TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_hash TEXT NOT NULL
            CHECK(length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
        result_artifact_ids_json TEXT NOT NULL CHECK(json_valid(result_artifact_ids_json)),
        committed_at TEXT NOT NULL,
        PRIMARY KEY(operation, idempotency_key)
    )
    """,
) + _immutable_triggers("ecatsl_idempotency_key")

_V3_TABLES = (
    "ecatsl_specification",
    "ecatsl_explanatory_support",
    "ecatsl_static_adapter_run",
    "ecatsl_static_run_candidate",
    "ecatsl_static_run_specification",
    "ecatsl_path_evidence",
    "ecatsl_path_candidate",
    "ecatsl_path_specification",
    "ecatsl_finding_specification",
    "ecatsl_finding_explanatory_support",
    "ecatsl_finding_missing_metadata",
)

_V3_STATEMENTS: Tuple[str, ...] = (
    "ALTER TABLE ecatsl_candidate_version ADD COLUMN missing_audit_elements_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(missing_audit_elements_json))",
    "ALTER TABLE ecatsl_policy_decision ADD COLUMN audit_metadata_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(audit_metadata_json))",
    "ALTER TABLE ecatsl_policy_decision ADD COLUMN missing_audit_elements_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(missing_audit_elements_json))",
    """
    CREATE TABLE ecatsl_specification (
        artifact_id TEXT PRIMARY KEY REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        candidate_artifact_id TEXT NOT NULL REFERENCES ecatsl_candidate_version(artifact_id) ON DELETE RESTRICT,
        role TEXT NOT NULL CHECK(role IN ('SOURCE', 'SINK', 'SANITIZER', 'PRECONDITION')),
        api_signature TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE ecatsl_explanatory_support (
        artifact_id TEXT PRIMARY KEY REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        record_type TEXT NOT NULL,
        canonical_identifier TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE ecatsl_static_adapter_run (
        artifact_id TEXT PRIMARY KEY REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        support_registry_version TEXT NOT NULL,
        adapter_id TEXT NOT NULL,
        adapter_version TEXT NOT NULL,
        run_identity TEXT NOT NULL,
        validation_artifact_id TEXT NOT NULL REFERENCES ecatsl_validation_result(artifact_id) ON DELETE RESTRICT,
        input_artifact_ids_json TEXT NOT NULL CHECK(json_valid(input_artifact_ids_json)),
        UNIQUE(adapter_id, adapter_version, run_identity)
    )
    """,
    """
    CREATE TABLE ecatsl_static_run_candidate (
        run_artifact_id TEXT NOT NULL REFERENCES ecatsl_static_adapter_run(artifact_id) ON DELETE RESTRICT,
        candidate_artifact_id TEXT NOT NULL REFERENCES ecatsl_candidate_version(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(run_artifact_id, candidate_artifact_id)
    )
    """,
    """
    CREATE TABLE ecatsl_static_run_specification (
        run_artifact_id TEXT NOT NULL REFERENCES ecatsl_static_adapter_run(artifact_id) ON DELETE RESTRICT,
        specification_artifact_id TEXT NOT NULL REFERENCES ecatsl_specification(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(run_artifact_id, specification_artifact_id)
    )
    """,
    """
    CREATE TABLE ecatsl_path_evidence (
        artifact_id TEXT PRIMARY KEY REFERENCES ecatsl_artifact(artifact_id) ON DELETE RESTRICT,
        adapter_run_artifact_id TEXT NOT NULL REFERENCES ecatsl_static_adapter_run(artifact_id) ON DELETE RESTRICT,
        validation_artifact_id TEXT NOT NULL REFERENCES ecatsl_validation_result(artifact_id) ON DELETE RESTRICT,
        adapter_id TEXT NOT NULL,
        adapter_version TEXT NOT NULL,
        static_evidence_identity TEXT NOT NULL,
        UNIQUE(adapter_run_artifact_id, static_evidence_identity)
    )
    """,
    """
    CREATE TABLE ecatsl_path_candidate (
        path_artifact_id TEXT NOT NULL REFERENCES ecatsl_path_evidence(artifact_id) ON DELETE RESTRICT,
        candidate_artifact_id TEXT NOT NULL REFERENCES ecatsl_candidate_version(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(path_artifact_id, candidate_artifact_id)
    )
    """,
    """
    CREATE TABLE ecatsl_path_specification (
        path_artifact_id TEXT NOT NULL REFERENCES ecatsl_path_evidence(artifact_id) ON DELETE RESTRICT,
        specification_artifact_id TEXT NOT NULL REFERENCES ecatsl_specification(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(path_artifact_id, specification_artifact_id)
    )
    """,
    """
    CREATE TABLE ecatsl_finding_specification (
        finding_artifact_id TEXT NOT NULL REFERENCES ecatsl_finding_lineage(artifact_id) ON DELETE RESTRICT,
        specification_artifact_id TEXT NOT NULL REFERENCES ecatsl_specification(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(finding_artifact_id, specification_artifact_id)
    )
    """,
    """
    CREATE TABLE ecatsl_finding_explanatory_support (
        finding_artifact_id TEXT NOT NULL REFERENCES ecatsl_finding_lineage(artifact_id) ON DELETE RESTRICT,
        explanatory_support_artifact_id TEXT NOT NULL REFERENCES ecatsl_explanatory_support(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(finding_artifact_id, explanatory_support_artifact_id)
    )
    """,
    """
    CREATE TABLE ecatsl_finding_missing_metadata (
        finding_artifact_id TEXT NOT NULL REFERENCES ecatsl_finding_lineage(artifact_id) ON DELETE RESTRICT,
        missing_element TEXT NOT NULL,
        failure_artifact_id TEXT NOT NULL REFERENCES ecatsl_audit_failure(artifact_id) ON DELETE RESTRICT,
        PRIMARY KEY(finding_artifact_id, missing_element)
    )
    """,
) + tuple(trigger for table in _V3_TABLES for trigger in _immutable_triggers(table))

_V4_TABLES = (
    "ecatsl_transaction",
    "ecatsl_transaction_event",
    "ecatsl_transaction_result",
)

_V4_STATEMENTS: Tuple[str, ...] = (
    """
    CREATE TABLE ecatsl_transaction (
        transaction_id TEXT PRIMARY KEY,
        operation TEXT NOT NULL,
        idempotency_key TEXT,
        request_hash TEXT NOT NULL
            CHECK(length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
        started_at TEXT NOT NULL,
        UNIQUE(operation, idempotency_key)
    )
    """,
    """
    CREATE TABLE ecatsl_transaction_event (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id TEXT NOT NULL
            REFERENCES ecatsl_transaction(transaction_id) ON DELETE RESTRICT,
        sequence INTEGER NOT NULL CHECK(sequence > 0),
        state TEXT NOT NULL
            CHECK(state IN ('STARTED', 'COMMITTED', 'FAILED', 'INTERRUPTED', 'REPLAYED')),
        occurred_at TEXT NOT NULL,
        failure_type TEXT,
        failure_message TEXT,
        UNIQUE(transaction_id, sequence)
    )
    """,
    """
    CREATE TABLE ecatsl_transaction_result (
        transaction_id TEXT PRIMARY KEY
            REFERENCES ecatsl_transaction(transaction_id) ON DELETE RESTRICT,
        outcome TEXT NOT NULL,
        result_json TEXT NOT NULL CHECK(json_valid(result_json)),
        committed_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX idx_ecatsl_transaction_event_latest
    ON ecatsl_transaction_event(transaction_id, sequence DESC)
    """,
    """
    ALTER TABLE ecatsl_idempotency_key ADD COLUMN transaction_id TEXT
        REFERENCES ecatsl_transaction(transaction_id) ON DELETE RESTRICT
    """,
) + tuple(trigger for table in _V4_TABLES for trigger in _immutable_triggers(table))

_V5_STATEMENTS: Tuple[str, ...] = (
    "ALTER TABLE ecatsl_transaction_event ADD COLUMN attempt_id TEXT",
    """
    CREATE TABLE ecatsl_transaction_attempt (
        attempt_id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL
            REFERENCES ecatsl_transaction(transaction_id) ON DELETE RESTRICT,
        owner_pid INTEGER NOT NULL CHECK(owner_pid > 0),
        owner_token TEXT NOT NULL,
        started_at TEXT NOT NULL
    )
    """,
    """
    CREATE UNIQUE INDEX idx_ecatsl_attempt_single_start
    ON ecatsl_transaction_event(attempt_id)
    WHERE attempt_id IS NOT NULL AND state = 'STARTED'
    """,
    """
    CREATE UNIQUE INDEX idx_ecatsl_attempt_single_terminal
    ON ecatsl_transaction_event(attempt_id)
    WHERE attempt_id IS NOT NULL AND state <> 'STARTED'
    """,
    """
    CREATE TRIGGER ecatsl_transaction_event_legal_transition
    BEFORE INSERT ON ecatsl_transaction_event
    WHEN NEW.attempt_id IS NOT NULL
    BEGIN
        SELECT CASE
            WHEN NEW.state = 'STARTED' AND EXISTS (
                SELECT 1 FROM ecatsl_transaction_event
                WHERE attempt_id = NEW.attempt_id
            ) THEN RAISE(ABORT, 'attempt STARTED must be its first event')
            WHEN NEW.state <> 'STARTED' AND NOT EXISTS (
                SELECT 1 FROM ecatsl_transaction_event
                WHERE attempt_id = NEW.attempt_id AND state = 'STARTED'
            ) THEN RAISE(ABORT, 'attempt terminal event requires STARTED')
            WHEN NEW.state <> 'STARTED' AND EXISTS (
                SELECT 1 FROM ecatsl_transaction_event
                WHERE attempt_id = NEW.attempt_id AND state <> 'STARTED'
            ) THEN RAISE(ABORT, 'attempt already has a terminal event')
        END;
    END
    """,
) + _immutable_triggers("ecatsl_transaction_attempt")

_V6_STATEMENTS: Tuple[str, ...] = (
    # V4 journal rows predate owned attempts. Append one deterministic terminal
    # outcome per transaction whose latest legacy attempt never completed.
    """
    INSERT INTO ecatsl_transaction_event
        (transaction_id, sequence, state, occurred_at,
         failure_type, failure_message, attempt_id)
    SELECT tx.transaction_id,
           (SELECT COALESCE(MAX(event.sequence), 0) + 1
            FROM ecatsl_transaction_event AS event
            WHERE event.transaction_id = tx.transaction_id),
           'INTERRUPTED',
           '1970-01-01T00:00:00+00:00',
           'LegacyJournalUpgrade',
           'terminal-less v4 STARTED journal converted during schema v6 upgrade',
           NULL
    FROM ecatsl_transaction AS tx
    WHERE EXISTS (
        SELECT 1 FROM ecatsl_transaction_event AS started
        WHERE started.transaction_id = tx.transaction_id
          AND started.attempt_id IS NULL
          AND started.state = 'STARTED'
    )
      AND NOT EXISTS (
        SELECT 1 FROM ecatsl_transaction_event AS terminal
        WHERE terminal.transaction_id = tx.transaction_id
          AND terminal.state <> 'STARTED'
    )
    """,
    # SQLite cannot add a composite foreign key to the historical append-only
    # event table. This insert trigger supplies the equivalent relational rule.
    """
    CREATE TRIGGER ecatsl_transaction_event_attempt_transaction_match
    BEFORE INSERT ON ecatsl_transaction_event
    WHEN NEW.attempt_id IS NOT NULL
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM ecatsl_transaction_attempt AS attempt
            WHERE attempt.attempt_id = NEW.attempt_id
              AND attempt.transaction_id = NEW.transaction_id
        ) THEN RAISE(ABORT, 'attempt must belong to event transaction') END;
    END
    """,
)

_V7_STATEMENTS: Tuple[str, ...] = (
    # V6 intentionally did not rewrite its historical predicate. A v4 retry can
    # contain STARTED -> terminal -> STARTED, so v6's "no terminal anywhere"
    # selection leaves the final legacy STARTED without a terminal. Terminalize
    # exactly those remaining transactions based on their latest legacy event.
    """
    INSERT INTO ecatsl_transaction_event
        (transaction_id, sequence, state, occurred_at,
         failure_type, failure_message, attempt_id)
    SELECT tx.transaction_id,
           (SELECT COALESCE(MAX(event.sequence), 0) + 1
            FROM ecatsl_transaction_event AS event
            WHERE event.transaction_id = tx.transaction_id),
           'INTERRUPTED',
           '1970-01-01T00:00:00+00:00',
           'LegacyJournalUpgrade',
           'terminal-less v4 retry journal converted during schema v7 upgrade',
           NULL
    FROM ecatsl_transaction AS tx
    WHERE EXISTS (
        SELECT 1
        FROM ecatsl_transaction_event AS latest
        WHERE latest.transaction_id = tx.transaction_id
          AND latest.sequence = (
              SELECT MAX(event.sequence)
              FROM ecatsl_transaction_event AS event
              WHERE event.transaction_id = tx.transaction_id
          )
          AND latest.attempt_id IS NULL
          AND latest.state = 'STARTED'
    )
    """,
)

_V8_TABLES = (
    "catalog_import_version",
    "source_record",
    "normalized_catalog_record",
    "catalog_duplicate",
    "ingestion_run",
    "ingestion_quality_report",
    "taint_template",
    "template_retrieval",
)

# Versioned local vulnerability-knowledge extension (Requirement 11.1-11.8).
# The pre-ECATSL canonical tables (cve, cwe, cvss, cve_cwe, catalog_import)
# remain the base catalog storage; this migration only adds append-only
# metadata and derived-data tables beside them. Rows are written by the
# CatalogImporter import path; source_record / normalized_catalog_record /
# catalog_duplicate / ingestion_* consumers arrive with later tasks.
_V8_STATEMENTS: Tuple[str, ...] = (
    """
    CREATE TABLE catalog_import_version (
        import_id TEXT PRIMARY KEY,
        source_kind TEXT NOT NULL,
        source_origin TEXT NOT NULL,
        source_identifier TEXT NOT NULL,
        source_revision TEXT,
        retrieved_at TEXT NOT NULL,
        retrieved_content_hash TEXT NOT NULL
            CHECK(length(retrieved_content_hash) = 64
                  AND retrieved_content_hash NOT GLOB '*[^0-9a-f]*'),
        license_metadata TEXT,
        import_tool_version TEXT NOT NULL,
        predecessor_id TEXT
            REFERENCES catalog_import_version(import_id) ON DELETE RESTRICT,
        created_at TEXT NOT NULL,
        CHECK(predecessor_id IS NULL OR predecessor_id <> import_id)
    )
    """,
    """
    CREATE INDEX idx_catalog_import_version_source_lineage
    ON catalog_import_version(source_kind, source_origin, source_identifier, created_at)
    """,
    """
    CREATE TABLE source_record (
        record_id TEXT PRIMARY KEY,
        import_id TEXT NOT NULL
            REFERENCES catalog_import_version(import_id) ON DELETE RESTRICT,
        record_type TEXT NOT NULL,
        source_identifier TEXT NOT NULL,
        source_content_hash TEXT NOT NULL
            CHECK(length(source_content_hash) = 64
                  AND source_content_hash NOT GLOB '*[^0-9a-f]*'),
        raw_reference TEXT,
        integrity_status TEXT NOT NULL DEFAULT 'UNVERIFIED'
            CHECK(integrity_status IN ('VERIFIED', 'FAILED', 'UNVERIFIED')),
        provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json))
    )
    """,
    """
    CREATE INDEX idx_source_record_import ON source_record(import_id)
    """,
    """
    CREATE TABLE normalized_catalog_record (
        normalized_id TEXT PRIMARY KEY,
        record_type TEXT NOT NULL,
        canonical_identifier TEXT NOT NULL,
        normalized_content_hash TEXT NOT NULL
            CHECK(length(normalized_content_hash) = 64
                  AND normalized_content_hash NOT GLOB '*[^0-9a-f]*'),
        normalization_profile_version TEXT NOT NULL,
        canonical_id TEXT
            REFERENCES normalized_catalog_record(normalized_id) ON DELETE RESTRICT,
        provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json)),
        CHECK(canonical_id IS NULL OR canonical_id <> normalized_id)
    )
    """,
    """
    CREATE TABLE catalog_duplicate (
        duplicate_id TEXT PRIMARY KEY,
        canonical_id TEXT NOT NULL
            REFERENCES normalized_catalog_record(normalized_id) ON DELETE RESTRICT,
        source_record_id TEXT NOT NULL
            REFERENCES source_record(record_id) ON DELETE RESTRICT,
        reason TEXT NOT NULL,
        decision_provenance_json TEXT NOT NULL CHECK(json_valid(decision_provenance_json))
    )
    """,
    """
    CREATE TABLE ingestion_run (
        run_id TEXT PRIMARY KEY,
        import_id TEXT NOT NULL
            REFERENCES catalog_import_version(import_id) ON DELETE RESTRICT,
        profile_version TEXT,
        import_tool_version TEXT NOT NULL,
        prior_run_id TEXT
            REFERENCES ingestion_run(run_id) ON DELETE RESTRICT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        content_hash TEXT NOT NULL
            CHECK(length(content_hash) = 64
                  AND content_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK(prior_run_id IS NULL OR prior_run_id <> run_id)
    )
    """,
    """
    CREATE INDEX idx_ingestion_run_import ON ingestion_run(import_id)
    """,
    """
    CREATE TABLE ingestion_quality_report (
        report_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL
            REFERENCES ingestion_run(run_id) ON DELETE RESTRICT,
        counts_json TEXT NOT NULL CHECK(json_valid(counts_json)),
        integrity_json TEXT NOT NULL CHECK(json_valid(integrity_json)),
        coverage_json TEXT NOT NULL CHECK(json_valid(coverage_json)),
        exclusions_json TEXT NOT NULL CHECK(json_valid(exclusions_json)),
        content_hash TEXT NOT NULL
            CHECK(length(content_hash) = 64
                  AND content_hash NOT GLOB '*[^0-9a-f]*')
    )
    """,
    """
    CREATE TABLE taint_template (
        template_id TEXT PRIMARY KEY,
        cwe_id TEXT NOT NULL CHECK(cwe_id GLOB 'CWE-[0-9]*'),
        role TEXT NOT NULL CHECK(role IN ('SOURCE', 'SINK', 'SANITIZER', 'PRECONDITION')),
        api_shape TEXT NOT NULL DEFAULT '',
        parameter_shape TEXT NOT NULL DEFAULT '',
        applicability_json TEXT NOT NULL CHECK(json_valid(applicability_json)),
        semantic_features_json TEXT NOT NULL CHECK(json_valid(semantic_features_json)),
        template_version TEXT NOT NULL,
        provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json))
    )
    """,
    """
    CREATE INDEX idx_taint_template_cwe_role ON taint_template(cwe_id, role)
    """,
    """
    CREATE TABLE template_retrieval (
        retrieval_id TEXT PRIMARY KEY,
        cwe_id TEXT NOT NULL CHECK(cwe_id GLOB 'CWE-[0-9]*'),
        query_identity TEXT NOT NULL,
        ranking_profile_version TEXT NOT NULL,
        result_template_ids_json TEXT NOT NULL CHECK(json_valid(result_template_ids_json)),
        scores_json TEXT NOT NULL CHECK(json_valid(scores_json)),
        provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json))
    )
    """,
) + tuple(trigger for table in _V8_TABLES for trigger in _immutable_triggers(table))

MIGRATIONS: Tuple[SchemaMigration, ...] = (
    SchemaMigration(version=1, name="append_only_artifact_foundation", statements=_V1_STATEMENTS),
    SchemaMigration(version=2, name="durable_idempotency_keys", statements=_V2_STATEMENTS),
    SchemaMigration(version=3, name="typed_lineage_and_static_path_binding", statements=_V3_STATEMENTS),
    SchemaMigration(version=4, name="durable_transaction_journal", statements=_V4_STATEMENTS),
    SchemaMigration(version=5, name="independent_transaction_attempts", statements=_V5_STATEMENTS),
    SchemaMigration(
        version=6,
        name="legacy_journal_and_attempt_transaction_integrity",
        statements=_V6_STATEMENTS,
    ),
    SchemaMigration(
        version=7,
        name="legacy_retry_terminalization",
        statements=_V7_STATEMENTS,
    ),
    SchemaMigration(
        version=8,
        name="versioned_catalog_import_foundation",
        statements=_V8_STATEMENTS,
    ),
)


def _create_version_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS ecatsl_schema_version (
            version INTEGER PRIMARY KEY CHECK(version > 0),
            migration_name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL
                CHECK(length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*'),
            installed_at TEXT NOT NULL
        )
        """
    )
    for trigger in _immutable_triggers(_SCHEMA_VERSION_TABLE):
        connection.execute(trigger)


def _validate_applied_migrations(
    applied_rows: Sequence[Tuple[int, str, str]],
    selected: Sequence[SchemaMigration],
) -> int:
    """Require installed migration history to be an untampered exact prefix."""

    applied_versions = tuple(row[0] for row in applied_rows)
    expected_versions = tuple(range(1, len(applied_rows) + 1))
    if applied_versions != expected_versions:
        raise sqlite3.DatabaseError(
            "ECATSL migration history is out of order or contains a gap"
        )
    if len(applied_rows) > len(selected):
        raise sqlite3.DatabaseError("database uses a newer ECATSL schema version")
    for version, recorded_name, recorded_checksum in applied_rows:
        migration = selected[version - 1]
        if (recorded_name, recorded_checksum) != (migration.name, migration.checksum):
            raise sqlite3.DatabaseError(
                f"ECATSL migration {version} name or checksum mismatch"
            )
    return len(applied_rows)


def _append_transaction_event(
    connection: sqlite3.Connection,
    transaction_id: str,
    state: str,
    *,
    attempt_id: Optional[str] = None,
    failure: Optional[BaseException] = None,
) -> None:
    row = connection.execute(
        "SELECT COALESCE(MAX(sequence), 0) FROM ecatsl_transaction_event "
        "WHERE transaction_id = ?",
        (transaction_id,),
    ).fetchone()
    sequence = int(row[0]) + 1
    connection.execute(
        """
        INSERT INTO ecatsl_transaction_event
            (transaction_id, sequence, state, occurred_at, failure_type,
             failure_message, attempt_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            transaction_id,
            sequence,
            state,
            datetime.now(timezone.utc).isoformat(),
            type(failure).__name__ if failure is not None else None,
            str(failure) if failure is not None else None,
            attempt_id,
        ),
    )


def _recover_dead_migration_attempts(
    connection: sqlite3.Connection,
    transaction_id: str,
    *,
    process_probe: ProcessLivenessProbe = _pid_liveness,
) -> None:
    rows = connection.execute(
        """
        SELECT attempt.attempt_id, attempt.owner_pid, attempt.owner_token
        FROM ecatsl_transaction_attempt AS attempt
        JOIN ecatsl_transaction_event AS started
          ON started.attempt_id = attempt.attempt_id AND started.state = 'STARTED'
        LEFT JOIN ecatsl_transaction_event AS terminal
          ON terminal.attempt_id = attempt.attempt_id AND terminal.state <> 'STARTED'
        WHERE attempt.transaction_id = ? AND terminal.event_id IS NULL
        """,
        (transaction_id,),
    ).fetchall()
    for attempt_id, owner_pid, owner_token in rows:
        if _owner_liveness(
            int(owner_pid),
            str(owner_token),
            str(attempt_id),
            process_probe=process_probe,
        ) is ProcessLiveness.DEAD:
            _append_transaction_event(
                connection,
                transaction_id,
                "INTERRUPTED",
                attempt_id=str(attempt_id),
            )


def _prepare_migration_journal(
    connection: sqlite3.Connection,
    migration: SchemaMigration,
    config: SQLiteWriteConfig,
    *,
    process_probe: ProcessLivenessProbe = _pid_liveness,
) -> Tuple[str, str]:
    request_hash = migration.checksum
    key = f"{migration.version}:{migration.name}:{migration.checksum}"
    transaction_id = "tx:" + hashlib.sha256(
        f"schema_migration\0{key}\0{request_hash}".encode("utf-8")
    ).hexdigest()
    attempt_id = "attempt:" + uuid4().hex
    _register_attempt(attempt_id)
    begin_immediate_with_retry(connection, config)
    try:
        row = connection.execute(
            """
            SELECT transaction_id, request_hash FROM ecatsl_transaction
            WHERE operation = 'schema_migration' AND idempotency_key = ?
            """,
            (key,),
        ).fetchone()
        if row is None:
            connection.execute(
                """
                INSERT INTO ecatsl_transaction
                    (transaction_id, operation, idempotency_key, request_hash, started_at)
                VALUES (?, 'schema_migration', ?, ?, ?)
                """,
                (
                    transaction_id,
                    key,
                    request_hash,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        elif (str(row[0]), str(row[1])) != (transaction_id, request_hash):
            raise sqlite3.DatabaseError(
                f"migration {migration.version} retry identity does not match prior attempt"
            )
        _recover_dead_migration_attempts(
            connection, transaction_id, process_probe=process_probe
        )
        connection.execute(
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
        _append_transaction_event(
            connection, transaction_id, "STARTED", attempt_id=attempt_id
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        _unregister_attempt(attempt_id)
        raise
    return transaction_id, attempt_id


def _install_ecatsl_schema(
    connection: sqlite3.Connection,
    *,
    migrations: Optional[Sequence[SchemaMigration]],
    write_config: Optional[SQLiteWriteConfig],
    failure_hook: Optional[Callable[[str], None]],
    process_probe: ProcessLivenessProbe,
) -> int:
    selected = tuple(MIGRATIONS if migrations is None else migrations)
    if not selected:
        return 0
    versions = tuple(migration.version for migration in selected)
    if versions != tuple(range(1, len(selected) + 1)):
        raise ValueError("ECATSL migrations must be contiguous and start at version 1")
    if connection.in_transaction:
        raise sqlite3.OperationalError("ECATSL schema installation requires an idle connection")

    config = write_config or SQLiteWriteConfig()
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {config.busy_timeout_ms}")

    begin_immediate_with_retry(connection, config)
    try:
        _create_version_table(connection)
        applied_rows = tuple(
            (int(row[0]), str(row[1]), str(row[2]))
            for row in connection.execute(
                """
                SELECT version, migration_name, checksum
                FROM ecatsl_schema_version
                ORDER BY version
                """
            )
        )
        applied_count = _validate_applied_migrations(applied_rows, selected)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise

    for migration in selected[applied_count:]:
        transaction_id: Optional[str] = None
        attempt_id: Optional[str] = None
        # Built-in migrations are each a single SQLite transaction: an interrupted
        # installation rolls back both DDL and its version row, so they do not need a
        # permanent retry journal. Extension migrations use durable independent
        # attempts once the v5 journal tables are available; this preserves recovery
        # telemetry without creating baseline no-key journal rows on every new DB.
        journal_available = migration.version > SCHEMA_VERSION and connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'ecatsl_transaction_attempt'"
        ).fetchone() is not None
        if journal_available:
            transaction_id, attempt_id = _prepare_migration_journal(
                connection, migration, config, process_probe=process_probe
            )
        try:
            if failure_hook is not None:
                failure_hook(f"migration:{migration.version}:after_started")
            begin_immediate_with_retry(connection, config)
            if failure_hook is not None:
                failure_hook(f"migration:{migration.version}:after_writer_acquired")

            # Applicability must be checked while holding the writer lock. Another
            # installer may have committed this migration after our initial read.
            installed = connection.execute(
                """
                SELECT migration_name, checksum FROM ecatsl_schema_version
                WHERE version = ?
                """,
                (migration.version,),
            ).fetchone()
            if installed is not None:
                if (str(installed[0]), str(installed[1])) != (
                    migration.name,
                    migration.checksum,
                ):
                    raise sqlite3.DatabaseError(
                        f"ECATSL migration {migration.version} name or checksum mismatch"
                    )
                if transaction_id is not None:
                    _append_transaction_event(
                        connection,
                        transaction_id,
                        "REPLAYED",
                        attempt_id=attempt_id,
                    )
                connection.commit()
                continue

            for statement in migration.statements:
                connection.execute(statement)
            connection.execute(
                """
                INSERT INTO ecatsl_schema_version
                    (version, migration_name, checksum, installed_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    migration.version,
                    migration.name,
                    migration.checksum,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            if transaction_id is not None:
                _append_transaction_event(
                    connection,
                    transaction_id,
                    "COMMITTED",
                    attempt_id=attempt_id,
                )
            connection.commit()
        except BaseException as error:
            # Roll back every in-flight writer, including cancellation/process-style
            # BaseException paths. Only ordinary operation failures are finalized.
            connection.rollback()
            if transaction_id is not None and isinstance(error, Exception):
                begin_immediate_with_retry(connection, config)
                try:
                    _append_transaction_event(
                        connection,
                        transaction_id,
                        "FAILED",
                        attempt_id=attempt_id,
                        failure=error,
                    )
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
            raise
        finally:
            if attempt_id is not None:
                _unregister_attempt(attempt_id)

    row = connection.execute("SELECT MAX(version) FROM ecatsl_schema_version").fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def install_ecatsl_schema(
    connection: sqlite3.Connection,
    *,
    migrations: Optional[Sequence[SchemaMigration]] = None,
    write_config: Optional[SQLiteWriteConfig] = None,
) -> int:
    """Install pending migrations with bounded writer acquisition and atomic versions."""

    return _install_ecatsl_schema(
        connection,
        migrations=migrations,
        write_config=write_config,
        failure_hook=None,
        process_probe=_pid_liveness,
    )


def install_ecatsl_schema_for_testing(
    connection: sqlite3.Connection,
    *,
    migrations: Optional[Sequence[SchemaMigration]] = None,
    write_config: Optional[SQLiteWriteConfig] = None,
    failure_hook: Callable[[str], None],
    process_probe: ProcessLivenessProbe = _pid_liveness,
) -> int:
    """Explicit test-only boundary for deterministic migration interruption."""

    return _install_ecatsl_schema(
        connection,
        migrations=migrations,
        write_config=write_config,
        failure_hook=failure_hook,
        process_probe=process_probe,
    )
