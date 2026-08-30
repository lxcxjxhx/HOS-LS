"""Focused tests for the transactional ECATSL SQLite schema."""

import hashlib
import sqlite3
import threading

import pytest

from src.ecatsl.schema import (
    MIGRATIONS,
    SCHEMA_VERSION,
    SchemaMigration,
    install_ecatsl_schema,
    install_ecatsl_schema_for_testing,
)
from src.nvd.catalog_import import CatalogImporter


ECATSL_TABLES = {
    "ecatsl_artifact",
    "ecatsl_audit_failure",
    "ecatsl_candidate_version",
    "ecatsl_evidence",
    "ecatsl_explanatory_support",
    "ecatsl_finding_candidate",
    "ecatsl_finding_explanatory_support",
    "ecatsl_finding_lineage",
    "ecatsl_finding_missing_metadata",
    "ecatsl_finding_specification",
    "ecatsl_finding_validation",
    "ecatsl_idempotency_key",
    "ecatsl_path_candidate",
    "ecatsl_path_evidence",
    "ecatsl_path_specification",
    "ecatsl_pipeline_stage",
    "ecatsl_policy_decision",
    "ecatsl_reuse_inventory_version",
    "ecatsl_schema_version",
    "ecatsl_scope_version",
    "ecatsl_specification",
    "ecatsl_static_adapter_run",
    "ecatsl_static_run_candidate",
    "ecatsl_static_run_specification",
    "ecatsl_transaction",
    "ecatsl_transaction_attempt",
    "ecatsl_transaction_event",
    "ecatsl_transaction_result",
    "ecatsl_validation_result",
}

ORIGINAL_V1_CHECKSUM = "7fc0ac809f919eceed1f0d294ca14de959bda88a07ecd815af59007fadf6e1ae"


def _artifact_id(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _insert_artifact(
    connection: sqlite3.Connection,
    label: str,
    *,
    artifact_type: str = "test",
    predecessor_id=None,
) -> str:
    content_hash = hashlib.sha256(label.encode("utf-8")).hexdigest()
    artifact_id = "sha256:" + content_hash
    connection.execute(
        """
        INSERT INTO ecatsl_artifact
            (artifact_id, artifact_type, version, content_hash, canonical_payload,
             created_at, predecessor_id)
        VALUES (?, ?, '1', ?, '{}', '2026-01-01T00:00:00+00:00', ?)
        """,
        (artifact_id, artifact_type, content_hash, predecessor_id),
    )
    return artifact_id


def _create_populated_legacy_catalog(database) -> None:
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            CREATE TABLE cwe (
                cwe_id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                weakness_abstraction TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE cve (
                cve_id TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                published_date TEXT,
                last_modified TEXT
            );
            CREATE TABLE cvss (
                cve_id TEXT PRIMARY KEY REFERENCES cve(cve_id) ON DELETE CASCADE,
                score REAL,
                severity TEXT,
                vector TEXT,
                version TEXT
            );
            CREATE TABLE cve_cwe (
                cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
                cwe_id TEXT NOT NULL REFERENCES cwe(cwe_id) ON DELETE CASCADE,
                is_primary INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (cve_id, cwe_id)
            );
            CREATE TABLE catalog_import (
                source_kind TEXT NOT NULL,
                source_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                PRIMARY KEY (source_kind, source_path, sha256)
            );
            INSERT INTO cwe VALUES
                ('CWE-89', 'SQL Injection', 'Base', 'Stable', 'Legacy weakness');
            INSERT INTO cve VALUES
                ('CVE-2026-0001', 'Legacy vulnerability', '2026-01-01', '2026-01-02');
            INSERT INTO cvss VALUES
                ('CVE-2026-0001', 9.1, 'CRITICAL', 'CVSS:3.1/AV:N', '31');
            INSERT INTO cve_cwe VALUES ('CVE-2026-0001', 'CWE-89', 1);
            INSERT INTO catalog_import VALUES
                ('nvd', 'legacy.json', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                 '2026-01-03T00:00:00+00:00', 1);
            """
        )
        connection.commit()
    finally:
        connection.close()


def _create_version_ledger(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE ecatsl_schema_version (
            version INTEGER PRIMARY KEY CHECK(version > 0),
            migration_name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL,
            installed_at TEXT NOT NULL
        )
        """
    )


def test_populated_legacy_catalog_migrates_idempotently_without_data_loss(tmp_path):
    database = tmp_path / "catalog.db"
    _create_populated_legacy_catalog(database)

    with CatalogImporter(database) as importer:
        importer._create_schema()
        tables = {
            row[0]
            for row in importer.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert ECATSL_TABLES <= tables
        assert {"cve", "cwe", "cvss", "cve_cwe", "catalog_import"} <= tables
        assert importer.connection.execute("SELECT * FROM cwe").fetchall() == [
            ("CWE-89", "SQL Injection", "Base", "Stable", "Legacy weakness")
        ]
        assert importer.connection.execute("SELECT * FROM cve").fetchall() == [
            ("CVE-2026-0001", "Legacy vulnerability", "2026-01-01", "2026-01-02")
        ]
        assert importer.connection.execute("SELECT score, severity FROM cvss").fetchall() == [
            (9.1, "CRITICAL")
        ]
        assert importer.connection.execute("SELECT * FROM cve_cwe").fetchall() == [
            ("CVE-2026-0001", "CWE-89", 1)
        ]
        assert importer.connection.execute(
            "SELECT version FROM ecatsl_schema_version ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, SCHEMA_VERSION + 1)]


def test_historical_populated_v1_database_upgrades_in_place(tmp_path):
    """Freeze the shipped v1 checksum and preserve populated ECATSL v1 rows."""
    assert MIGRATIONS[0].checksum == ORIGINAL_V1_CHECKSUM
    database = tmp_path / "historical-v1.db"
    connection = sqlite3.connect(database)
    try:
        assert install_ecatsl_schema(connection, migrations=(MIGRATIONS[0],)) == 1
        candidate_id = _insert_artifact(
            connection, "historical-candidate", artifact_type="historical:CandidateRecord"
        )
        _insert_candidate(connection, candidate_id, "historical-candidate", "1")
        evidence_id = _insert_artifact(
            connection, "historical-evidence", artifact_type="historical:Evidence"
        )
        connection.execute(
            """
            INSERT INTO ecatsl_evidence
                (artifact_id, candidate_version_id, evidence_kind, provenance_json)
            VALUES (?, ?, 'REPOSITORY', '{}')
            """,
            (evidence_id, candidate_id),
        )
        decision_id = _insert_artifact(
            connection, "historical-decision", artifact_type="historical:PolicyDecision"
        )
        connection.execute(
            """
            INSERT INTO ecatsl_policy_decision
                (artifact_id, candidate_version_id, policy_kind, policy_version,
                 outcome, input_artifact_ids_json)
            VALUES (?, ?, 'ACCEPTANCE', 'v1', 'UNACCEPTED', '[]')
            """,
            (decision_id, candidate_id),
        )
        connection.commit()
        before = connection.execute(
            "SELECT artifact_id, artifact_type, canonical_payload FROM ecatsl_artifact ORDER BY rowid"
        ).fetchall()

        assert install_ecatsl_schema(connection) == SCHEMA_VERSION

        assert connection.execute(
            "SELECT artifact_id, artifact_type, canonical_payload FROM ecatsl_artifact ORDER BY rowid"
        ).fetchall() == before
        assert connection.execute(
            "SELECT candidate_id, candidate_version, missing_audit_elements_json "
            "FROM ecatsl_candidate_version"
        ).fetchall() == [("historical-candidate", "1", "[]")]
        assert connection.execute(
            "SELECT evidence_kind FROM ecatsl_evidence"
        ).fetchall() == [("REPOSITORY",)]
        assert connection.execute(
            "SELECT policy_version, audit_metadata_json, missing_audit_elements_json "
            "FROM ecatsl_policy_decision"
        ).fetchall() == [("v1", "[]", "[]")]
        assert connection.execute(
            "SELECT version, checksum FROM ecatsl_schema_version ORDER BY version"
        ).fetchall()[0] == (1, ORIGINAL_V1_CHECKSUM)
        assert connection.execute(
            "SELECT version FROM ecatsl_schema_version ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, SCHEMA_VERSION + 1)]
    finally:
        connection.close()


def test_failed_ddl_rolls_back_and_corrected_migration_can_retry(tmp_path):
    connection = sqlite3.connect(tmp_path / "rollback.db")
    try:
        assert install_ecatsl_schema(connection) == SCHEMA_VERSION
        failing = SchemaMigration(
            version=SCHEMA_VERSION + 1,
            name="retryable_migration",
            statements=(
                "CREATE TABLE ecatsl_should_rollback (id INTEGER PRIMARY KEY)",
                "CREATE TABL invalid_sql (id INTEGER)",
            ),
        )
        with pytest.raises(sqlite3.DatabaseError):
            install_ecatsl_schema(connection, migrations=MIGRATIONS + (failing,))

        assert connection.execute(
            "SELECT MAX(version) FROM ecatsl_schema_version"
        ).fetchone() == (SCHEMA_VERSION,)
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_should_rollback'"
        ).fetchone() is None

        corrected = SchemaMigration(
            version=SCHEMA_VERSION + 1,
            name="retryable_migration",
            statements=("CREATE TABLE ecatsl_retry_succeeded (id INTEGER PRIMARY KEY)",),
        )
        assert install_ecatsl_schema(
            connection, migrations=MIGRATIONS + (corrected,)
        ) == SCHEMA_VERSION + 1
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_retry_succeeded'"
        ).fetchone() == ("ecatsl_retry_succeeded",)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("recorded_name", "recorded_checksum"),
    [
        ("tampered_name", MIGRATIONS[0].checksum),
        (MIGRATIONS[0].name, "0" * 64),
    ],
)
def test_migration_name_or_checksum_mismatch_is_rejected(
    tmp_path, recorded_name, recorded_checksum
):
    connection = sqlite3.connect(tmp_path / f"mismatch-{recorded_name}.db")
    try:
        _create_version_ledger(connection)
        connection.execute(
            "INSERT INTO ecatsl_schema_version VALUES (1, ?, ?, '2026-01-01')",
            (recorded_name, recorded_checksum),
        )
        connection.commit()
        with pytest.raises(sqlite3.DatabaseError, match="name or checksum mismatch"):
            install_ecatsl_schema(connection)
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_artifact'"
        ).fetchone() is None
    finally:
        connection.close()


def test_gapped_or_out_of_order_migration_ledger_is_rejected(tmp_path):
    connection = sqlite3.connect(tmp_path / "gapped.db")
    out_of_order = SchemaMigration(
        version=SCHEMA_VERSION + 1,
        name="out_of_order",
        statements=("CREATE TABLE ecatsl_out_of_order (id INTEGER)",),
    )
    try:
        _create_version_ledger(connection)
        connection.execute(
            "INSERT INTO ecatsl_schema_version VALUES (?, ?, ?, '2026-01-02')",
            (out_of_order.version, out_of_order.name, out_of_order.checksum),
        )
        connection.commit()
        with pytest.raises(sqlite3.DatabaseError, match="out of order or contains a gap"):
            install_ecatsl_schema(connection, migrations=MIGRATIONS + (out_of_order,))
        assert connection.execute(
            "SELECT version FROM ecatsl_schema_version"
        ).fetchall() == [(SCHEMA_VERSION + 1,)]
    finally:
        connection.close()


def test_migration_history_is_append_only(tmp_path):
    connection = sqlite3.connect(tmp_path / "ledger.db")
    try:
        install_ecatsl_schema(connection)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE ecatsl_schema_version SET migration_name = 'tampered' WHERE version = 1"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM ecatsl_schema_version WHERE version = 1")
    finally:
        connection.close()


def test_artifact_identity_predecessors_and_append_only_constraints(tmp_path):
    connection = sqlite3.connect(tmp_path / "constraints.db")
    try:
        install_ecatsl_schema(connection)
        root = _insert_artifact(connection, "root")
        _insert_artifact(connection, "successor", predecessor_id=root)

        with pytest.raises(sqlite3.IntegrityError):
            _insert_artifact(connection, "duplicate-successor", predecessor_id=root)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO ecatsl_artifact
                    (artifact_id, artifact_type, version, content_hash,
                     canonical_payload, created_at)
                VALUES ('sha256:wrong', 'test', '1', ?, '{}', '2026-01-01')
                """,
                ("a" * 64,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE ecatsl_artifact SET version = '2' WHERE artifact_id = ?", (root,)
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM ecatsl_artifact WHERE artifact_id = ?", (root,))
    finally:
        connection.close()


def _insert_candidate(
    connection: sqlite3.Connection,
    artifact_id: str,
    candidate_id: str,
    version: str,
    predecessor_id=None,
) -> None:
    connection.execute(
        """
        INSERT INTO ecatsl_candidate_version
            (artifact_id, candidate_id, candidate_version, candidate_type,
             confidence, state, cwe_id, predecessor_id, update_cause)
        VALUES (?, ?, ?, 'SOURCE', 0.5, 'PROPOSED', 'CWE-89', ?, 'test')
        """,
        (artifact_id, candidate_id, version, predecessor_id),
    )


def test_candidate_lineage_is_single_root_single_successor_and_entity_scoped(tmp_path):
    connection = sqlite3.connect(tmp_path / "candidate-lineage.db")
    try:
        install_ecatsl_schema(connection)
        a1 = _insert_artifact(connection, "candidate-a-v1", artifact_type="candidate")
        b1 = _insert_artifact(connection, "candidate-b-v1", artifact_type="candidate")
        _insert_candidate(connection, a1, "candidate-a", "1")
        _insert_candidate(connection, b1, "candidate-b", "1")

        second_a_root = _insert_artifact(connection, "candidate-a-root-2", artifact_type="candidate")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_candidate(connection, second_a_root, "candidate-a", "root-2")

        a2 = _insert_artifact(
            connection, "candidate-a-v2", artifact_type="candidate", predecessor_id=a1
        )
        _insert_candidate(connection, a2, "candidate-a", "2", predecessor_id=a1)
        b2 = _insert_artifact(
            connection, "candidate-b-v2", artifact_type="candidate", predecessor_id=b1
        )
        _insert_candidate(connection, b2, "candidate-b", "2", predecessor_id=b1)

        split = _insert_artifact(
            connection, "candidate-split", artifact_type="candidate", predecessor_id=second_a_root
        )
        with pytest.raises(sqlite3.IntegrityError, match="predecessor must match"):
            _insert_candidate(connection, split, "candidate-a", "split", predecessor_id=a1)
    finally:
        connection.close()


def test_scope_and_reuse_lineages_reject_multiple_roots_and_split_predecessors(tmp_path):
    connection = sqlite3.connect(tmp_path / "other-lineages.db")
    try:
        install_ecatsl_schema(connection)
        scope_root = _insert_artifact(connection, "scope-v1", artifact_type="scope")
        connection.execute(
            """
            INSERT INTO ecatsl_scope_version
                (artifact_id, scope_name, scope_version, predecessor_id, language,
                 cwe_ids_json, versioning_state)
            VALUES (?, 'initial', '1', NULL, 'python', '["CWE-89"]', 'COMPLETE')
            """,
            (scope_root,),
        )
        extra_scope_root = _insert_artifact(connection, "scope-root-2", artifact_type="scope")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO ecatsl_scope_version
                    (artifact_id, scope_name, scope_version, predecessor_id, language,
                     cwe_ids_json, versioning_state)
                VALUES (?, 'initial', '2', NULL, 'python', '["CWE-89"]', 'COMPLETE')
                """,
                (extra_scope_root,),
            )

        reuse_root = _insert_artifact(connection, "reuse-v1", artifact_type="reuse")
        connection.execute(
            """
            INSERT INTO ecatsl_reuse_inventory_version
                (artifact_id, inventory_name, inventory_version, predecessor_id, entries_json)
            VALUES (?, 'default', '1', NULL, '[]')
            """,
            (reuse_root,),
        )
        extra_reuse_root = _insert_artifact(connection, "reuse-root-2", artifact_type="reuse")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO ecatsl_reuse_inventory_version
                    (artifact_id, inventory_name, inventory_version, predecessor_id, entries_json)
                VALUES (?, 'default', '2', NULL, '[]')
                """,
                (extra_reuse_root,),
            )

        scope_successor = _insert_artifact(
            connection, "scope-split", artifact_type="scope", predecessor_id=extra_scope_root
        )
        with pytest.raises(sqlite3.IntegrityError, match="scope predecessor must match"):
            connection.execute(
                """
                INSERT INTO ecatsl_scope_version
                    (artifact_id, scope_name, scope_version, predecessor_id, language,
                     cwe_ids_json, versioning_state)
                VALUES (?, 'initial', '3', ?, 'python', '["CWE-89"]', 'COMPLETE')
                """,
                (scope_successor, scope_root),
            )

        reuse_successor = _insert_artifact(
            connection, "reuse-split", artifact_type="reuse", predecessor_id=extra_reuse_root
        )
        with pytest.raises(sqlite3.IntegrityError, match="reuse predecessor must match"):
            connection.execute(
                """
                INSERT INTO ecatsl_reuse_inventory_version
                    (artifact_id, inventory_name, inventory_version, predecessor_id, entries_json)
                VALUES (?, 'default', '3', ?, '[]')
                """,
                (reuse_successor, reuse_root),
            )
    finally:
        connection.close()


def _insert_stage(
    connection: sqlite3.Connection,
    artifact_id: str,
    identity: str,
    duplicate_of=None,
    failure_id=None,
) -> None:
    connection.execute(
        """
        INSERT INTO ecatsl_pipeline_stage
            (artifact_id, stage_identity, input_artifact_ids_json,
             transformation_purpose, output_artifact_ids_json,
             duplicate_of_artifact_id, consolidation_failure_artifact_id)
        VALUES (?, ?, '[]', 'normalize', '[]', ?, ?)
        """,
        (artifact_id, identity, duplicate_of, failure_id),
    )


def test_duplicate_stage_identity_requires_documented_consolidation_failure(tmp_path):
    connection = sqlite3.connect(tmp_path / "stages.db")
    try:
        install_ecatsl_schema(connection)
        canonical = _insert_artifact(connection, "stage-canonical", artifact_type="pipeline_stage")
        _insert_stage(connection, canonical, "same-stage")

        other_canonical = _insert_artifact(
            connection, "stage-other-canonical", artifact_type="pipeline_stage"
        )
        with pytest.raises(sqlite3.IntegrityError):
            _insert_stage(connection, other_canonical, "same-stage")

        failure_id = _insert_artifact(connection, "stage-failure", artifact_type="audit_failure")
        connection.execute(
            """
            INSERT INTO ecatsl_audit_failure
                (artifact_id, related_artifact_id, operation, missing_element, failure_data_json)
            VALUES (?, ?, 'pipeline_stage_consolidation', 'duplicate_decision', '{}')
            """,
            (failure_id, canonical),
        )
        retained_duplicate = _insert_artifact(
            connection, "stage-retained-duplicate", artifact_type="pipeline_stage"
        )
        _insert_stage(
            connection,
            retained_duplicate,
            "same-stage",
            duplicate_of=canonical,
            failure_id=failure_id,
        )
        assert connection.execute(
            "SELECT artifact_id FROM ecatsl_pipeline_stage WHERE stage_identity = 'same-stage'"
        ).fetchall() == [(canonical,), (retained_duplicate,)]

        unrelated_failure = _insert_artifact(
            connection, "unrelated-failure", artifact_type="audit_failure"
        )
        connection.execute(
            """
            INSERT INTO ecatsl_audit_failure
                (artifact_id, related_artifact_id, operation, missing_element, failure_data_json)
            VALUES (?, ?, 'other_operation', 'x', '{}')
            """,
            (unrelated_failure, canonical),
        )
        invalid_duplicate = _insert_artifact(
            connection, "invalid-stage-duplicate", artifact_type="pipeline_stage"
        )
        with pytest.raises(sqlite3.IntegrityError, match="requires consolidation failure"):
            _insert_stage(
                connection,
                invalid_duplicate,
                "same-stage",
                duplicate_of=canonical,
                failure_id=unrelated_failure,
            )
    finally:
        connection.close()


class _MigrationInterruption(BaseException):
    pass


def test_interrupted_journaled_migration_recovers_without_partial_schema(tmp_path):
    database = tmp_path / "migration-interruption.db"
    migration = SchemaMigration(
        version=SCHEMA_VERSION + 1,
        name="restart_safe_migration",
        statements=(
            "CREATE TABLE ecatsl_restart_safe (id INTEGER PRIMARY KEY)",
        ),
    )
    selected = MIGRATIONS + (migration,)
    connection = sqlite3.connect(database)
    try:
        assert install_ecatsl_schema(connection) == SCHEMA_VERSION

        def interrupt(point):
            if point == f"migration:{migration.version}:after_started":
                raise _MigrationInterruption("simulated process loss")

        with pytest.raises(_MigrationInterruption):
            install_ecatsl_schema_for_testing(
                connection,
                migrations=selected,
                failure_hook=interrupt,
            )
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_restart_safe'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT state FROM ecatsl_transaction_event ORDER BY event_id"
        ).fetchall()[-1] == ("STARTED",)
    finally:
        connection.close()

    connection = sqlite3.connect(database)
    try:
        assert install_ecatsl_schema(connection, migrations=selected) == migration.version
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_restart_safe'"
        ).fetchone() == ("ecatsl_restart_safe",)
        assert connection.execute(
            "SELECT state FROM ecatsl_transaction_event WHERE transaction_id = ("
            "SELECT transaction_id FROM ecatsl_transaction "
            "WHERE operation = 'schema_migration' AND idempotency_key LIKE ?"
            ") ORDER BY sequence",
            (f"{migration.version}:%",),
        ).fetchall() == [
            ("STARTED",), ("INTERRUPTED",), ("STARTED",), ("COMMITTED",)
        ]
    finally:
        connection.close()


def test_migration_base_exception_after_writer_acquisition_rolls_back_lock(tmp_path):
    database = tmp_path / "migration-base-exception.db"
    migration = SchemaMigration(
        version=SCHEMA_VERSION + 1,
        name="inflight_interruption",
        statements=("CREATE TABLE ecatsl_inflight_ddl (id INTEGER PRIMARY KEY)",),
    )
    selected = MIGRATIONS + (migration,)
    connection = sqlite3.connect(database, timeout=0)
    try:
        install_ecatsl_schema(connection)

        def interrupt(point):
            if point == f"migration:{migration.version}:after_writer_acquired":
                raise _MigrationInterruption("after writer acquisition")

        with pytest.raises(_MigrationInterruption):
            install_ecatsl_schema_for_testing(
                connection, migrations=selected, failure_hook=interrupt
            )
        assert not connection.in_transaction
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_inflight_ddl'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT state FROM ecatsl_transaction_event ORDER BY event_id DESC LIMIT 1"
        ).fetchone() == ("STARTED",)

        independent = sqlite3.connect(database, timeout=0)
        try:
            independent.execute("BEGIN IMMEDIATE")
            independent.rollback()
        finally:
            independent.close()

        assert install_ecatsl_schema(connection, migrations=selected) == migration.version
        assert connection.execute(
            "SELECT state FROM ecatsl_transaction_event WHERE transaction_id = ("
            "SELECT transaction_id FROM ecatsl_transaction "
            "WHERE operation = 'schema_migration' AND idempotency_key LIKE ?"
            ") ORDER BY sequence",
            (f"{migration.version}:%",),
        ).fetchall() == [
            ("STARTED",),
            ("INTERRUPTED",),
            ("STARTED",),
            ("COMMITTED",),
        ]
    finally:
        connection.close()


def test_concurrent_migration_installers_recheck_under_writer_lock(tmp_path):
    database = tmp_path / "concurrent-installers.db"
    bootstrap = sqlite3.connect(database)
    try:
        install_ecatsl_schema(bootstrap)
    finally:
        bootstrap.close()

    migration = SchemaMigration(
        version=SCHEMA_VERSION + 1,
        name="single_execution",
        statements=("CREATE TABLE ecatsl_single_execution (id INTEGER PRIMARY KEY)",),
    )
    selected = MIGRATIONS + (migration,)
    barrier = threading.Barrier(2)
    results = []
    errors = []
    result_lock = threading.Lock()

    def synchronize(point):
        if point == f"migration:{migration.version}:after_started":
            barrier.wait(timeout=10)

    def install():
        connection = sqlite3.connect(database, timeout=0)
        try:
            version = install_ecatsl_schema_for_testing(
                connection,
                migrations=selected,
                failure_hook=synchronize,
            )
            with result_lock:
                results.append(version)
        except BaseException as error:
            with result_lock:
                errors.append(error)
        finally:
            connection.close()

    threads = [threading.Thread(target=install) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert results == [migration.version, migration.version]
    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM ecatsl_schema_version WHERE version = ?",
            (migration.version,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT state FROM ecatsl_transaction_event WHERE transaction_id = ("
            "SELECT transaction_id FROM ecatsl_transaction "
            "WHERE operation = 'schema_migration' AND idempotency_key LIKE ?"
            ") ORDER BY sequence",
            (f"{migration.version}:%",),
        ).fetchall() == [
            ("STARTED",),
            ("STARTED",),
            ("COMMITTED",),
            ("REPLAYED",),
        ]
    finally:
        connection.close()


def test_v4_terminal_less_started_row_upgrades_to_interrupted_outcome(tmp_path):
    database = tmp_path / "legacy-v4-started.db"
    connection = sqlite3.connect(database)
    try:
        assert install_ecatsl_schema(connection, migrations=MIGRATIONS[:4]) == 4
        request_hash = "a" * 64
        connection.execute(
            """
            INSERT INTO ecatsl_transaction
                (transaction_id, operation, idempotency_key, request_hash, started_at)
            VALUES ('tx:legacy-started', 'legacy_operation', 'legacy-key', ?,
                    '2026-01-01T00:00:00+00:00')
            """,
            (request_hash,),
        )
        connection.execute(
            """
            INSERT INTO ecatsl_transaction_event
                (transaction_id, sequence, state, occurred_at)
            VALUES ('tx:legacy-started', 1, 'STARTED',
                    '2026-01-01T00:00:00+00:00')
            """
        )
        connection.commit()

        assert install_ecatsl_schema(connection) == SCHEMA_VERSION
        assert connection.execute(
            """
            SELECT state, attempt_id, failure_type
            FROM ecatsl_transaction_event
            WHERE transaction_id = 'tx:legacy-started'
            ORDER BY sequence
            """
        ).fetchall() == [
            ("STARTED", None, None),
            ("INTERRUPTED", None, "LegacyJournalUpgrade"),
        ]
        assert connection.execute(
            "SELECT COUNT(*) FROM ecatsl_transaction_attempt"
        ).fetchone() == (0,)

        # Re-running installation cannot append a second legacy terminal.
        assert install_ecatsl_schema(connection) == SCHEMA_VERSION
        assert connection.execute(
            "SELECT COUNT(*) FROM ecatsl_transaction_event "
            "WHERE transaction_id = 'tx:legacy-started'"
        ).fetchone() == (2,)
    finally:
        connection.close()


def test_attempt_terminal_event_must_use_attempt_owner_transaction(tmp_path):
    connection = sqlite3.connect(tmp_path / "attempt-transaction.db")
    try:
        install_ecatsl_schema(connection)
        for suffix in ("a", "b"):
            connection.execute(
                """
                INSERT INTO ecatsl_transaction
                    (transaction_id, operation, idempotency_key, request_hash, started_at)
                VALUES (?, ?, ?, ?, '2026-01-01T00:00:00+00:00')
                """,
                (f"tx:{suffix}", f"operation-{suffix}", f"key-{suffix}", suffix * 64),
            )
        connection.execute(
            """
            INSERT INTO ecatsl_transaction_attempt
                (attempt_id, transaction_id, owner_pid, owner_token, started_at)
            VALUES ('attempt:a', 'tx:a', 123, 'owner-a',
                    '2026-01-01T00:00:00+00:00')
            """
        )
        connection.execute(
            """
            INSERT INTO ecatsl_transaction_event
                (transaction_id, sequence, state, occurred_at, attempt_id)
            VALUES ('tx:a', 1, 'STARTED', '2026-01-01T00:00:00+00:00',
                    'attempt:a')
            """
        )

        with pytest.raises(sqlite3.IntegrityError, match="attempt must belong"):
            connection.execute(
                """
                INSERT INTO ecatsl_transaction_event
                    (transaction_id, sequence, state, occurred_at, attempt_id)
                VALUES ('tx:b', 1, 'COMMITTED',
                        '2026-01-01T00:00:01+00:00', 'attempt:a')
                """
            )
        connection.execute(
            """
            INSERT INTO ecatsl_transaction_event
                (transaction_id, sequence, state, occurred_at, attempt_id)
            VALUES ('tx:a', 2, 'COMMITTED', '2026-01-01T00:00:01+00:00',
                    'attempt:a')
            """
        )
        assert connection.execute(
            "SELECT state FROM ecatsl_transaction_event "
            "WHERE transaction_id = 'tx:a' ORDER BY sequence"
        ).fetchall() == [("STARTED",), ("COMMITTED",)]
    finally:
        connection.close()


def test_v4_failed_retry_with_terminal_less_start_is_terminalized_by_v7(tmp_path):
    database = tmp_path / "legacy-v4-retry-started.db"
    connection = sqlite3.connect(database)
    try:
        assert install_ecatsl_schema(connection, migrations=MIGRATIONS[:4]) == 4
        connection.execute(
            """
            INSERT INTO ecatsl_transaction
                (transaction_id, operation, idempotency_key, request_hash, started_at)
            VALUES ('tx:legacy-retry', 'legacy_operation', 'legacy-retry-key', ?,
                    '2026-01-01T00:00:00+00:00')
            """,
            ("b" * 64,),
        )
        connection.executemany(
            """
            INSERT INTO ecatsl_transaction_event
                (transaction_id, sequence, state, occurred_at, failure_type)
            VALUES ('tx:legacy-retry', ?, ?, ?, ?)
            """,
            (
                (1, "STARTED", "2026-01-01T00:00:00+00:00", None),
                (2, "FAILED", "2026-01-01T00:00:01+00:00", "LegacyFailure"),
                (3, "STARTED", "2026-01-01T00:00:02+00:00", None),
            ),
        )
        connection.commit()

        assert install_ecatsl_schema(connection) == SCHEMA_VERSION
        assert connection.execute(
            """
            SELECT state, attempt_id, failure_type
            FROM ecatsl_transaction_event
            WHERE transaction_id = 'tx:legacy-retry'
            ORDER BY sequence
            """
        ).fetchall() == [
            ("STARTED", None, None),
            ("FAILED", None, "LegacyFailure"),
            ("STARTED", None, None),
            ("INTERRUPTED", None, "LegacyJournalUpgrade"),
        ]

        assert install_ecatsl_schema(connection) == SCHEMA_VERSION
        assert connection.execute(
            "SELECT COUNT(*) FROM ecatsl_transaction_event "
            "WHERE transaction_id = 'tx:legacy-retry'"
        ).fetchone() == (4,)
    finally:
        connection.close()
