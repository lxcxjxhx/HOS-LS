"""End-to-end SQLite migration/recovery compatibility over a populated NVD/CWE catalog."""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3

import pytest

from src.ecatsl.artifact_repository import ArtifactRepository
from src.ecatsl.models import AcceptancePolicy, Provenance
from src.ecatsl.schema import (
    MIGRATIONS,
    SCHEMA_VERSION,
    SchemaMigration,
    install_ecatsl_schema,
    install_ecatsl_schema_for_testing,
)
from src.nvd.catalog_import import CatalogImporter, ImportSummary
from src.nvd.nvd_query_adapter import NVDQueryAdapter


FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "baseline"
NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


class SimulatedProcessLoss(BaseException):
    """Deliberately bypass normal exception finalization in migration recovery tests."""


def _assert_catalog_queries(database: Path) -> None:
    adapter = NVDQueryAdapter(str(database), use_cache=False)
    try:
        assert adapter.is_available() is True
        assert adapter.get_all_cwe_ids() == ["CWE-89"]
        assert adapter.get_cwe_by_id("CWE-89")["cwe_name"] == (
            "Improper Neutralization of Special Elements used in an SQL Command"
        )
        assert adapter.search_vulnerabilities("CWE-89", "HIGH", 1) == [
            {
                "cve_id": "CVE-2025-0001",
                "description": "A minimal SQL injection catalog fixture.",
                "cvss_score": 8.8,
                "severity": "HIGH",
            }
        ]
    finally:
        adapter._disconnect()


def _populated_catalog(tmp_path) -> Path:
    database = tmp_path / "catalog.db"
    with CatalogImporter(database, batch_size=2) as importer:
        assert importer.import_cwe_xml(FIXTURES / "mitre_cwe.xml") == ImportSummary(cwes=1)
        assert importer.import_nvd(FIXTURES / "nvd_cve.json") == ImportSummary(cves=1)
    return database


def _policy() -> AcceptancePolicy:
    return AcceptancePolicy(
        version="migration-recovery-policy-v1",
        created_at=NOW,
        provenance=Provenance(
            origin="repository",
            retrieved_at=NOW,
            source_identifier="tests/integration/ecatsl",
            source_revision="v1",
            content_identity="migration-recovery-policy",
        ),
        conditions=("independent_evidence",),
    )


def test_populated_catalog_survives_failed_extension_migration_and_restart_replay(tmp_path):
    database = _populated_catalog(tmp_path)
    _assert_catalog_queries(database)

    # Repository restart plus the same idempotency key must return the existing
    # artifact without changing the populated catalog schema or catalog contents.
    policy = _policy()
    with ArtifactRepository(database) as repository:
        assert repository.persist_artifact(policy, idempotency_key="catalog-policy") == policy
    with ArtifactRepository(database) as repository:
        assert repository.persist_artifact(policy, idempotency_key="catalog-policy") == policy
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM ecatsl_artifact WHERE artifact_id = ?",
            (policy.artifact_id,),
        ).fetchone() == (1,)
    _assert_catalog_queries(database)

    failed = SchemaMigration(
        version=SCHEMA_VERSION + 1,
        name="populated_catalog_failed_extension",
        statements=(
            "CREATE TABLE ecatsl_catalog_rollback_probe (id INTEGER PRIMARY KEY)",
            "CREATE TABL invalid_catalog_ddl (id INTEGER)",
        ),
    )
    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            install_ecatsl_schema(connection, migrations=MIGRATIONS + (failed,))
        assert connection.execute(
            "SELECT MAX(version) FROM ecatsl_schema_version"
        ).fetchone() == (SCHEMA_VERSION,)
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_catalog_rollback_probe'"
        ).fetchone() is None
    finally:
        connection.close()

    recovery = SchemaMigration(
        version=SCHEMA_VERSION + 1,
        name="populated_catalog_restart_safe_extension",
        statements=("CREATE TABLE ecatsl_catalog_recovery_probe (id INTEGER PRIMARY KEY)",),
    )
    selected = MIGRATIONS + (recovery,)
    connection = sqlite3.connect(database)
    try:
        def interrupt(point: str) -> None:
            if point == f"migration:{recovery.version}:after_started":
                raise SimulatedProcessLoss("simulated migration process loss")

        with pytest.raises(SimulatedProcessLoss):
            install_ecatsl_schema_for_testing(
                connection, migrations=selected, failure_hook=interrupt
            )
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_catalog_recovery_probe'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT state FROM ecatsl_transaction_event ORDER BY event_id DESC LIMIT 1"
        ).fetchone() == ("STARTED",)
    finally:
        connection.close()

    connection = sqlite3.connect(database)
    try:
        assert install_ecatsl_schema(connection, migrations=selected) == recovery.version
        assert install_ecatsl_schema(connection, migrations=selected) == recovery.version
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'ecatsl_catalog_recovery_probe'"
        ).fetchone() == ("ecatsl_catalog_recovery_probe",)
        assert connection.execute(
            "SELECT COUNT(*) FROM ecatsl_schema_version WHERE version = ?",
            (recovery.version,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT state FROM ecatsl_transaction_event WHERE transaction_id = ("
            "SELECT transaction_id FROM ecatsl_transaction "
            "WHERE operation = 'schema_migration' AND idempotency_key LIKE ?"
            ") ORDER BY sequence",
            (f"{recovery.version}:{recovery.name}:%",),
        ).fetchall() == [
            ("STARTED",),
            ("INTERRUPTED",),
            ("STARTED",),
            ("COMMITTED",),
        ]
    finally:
        connection.close()

    _assert_catalog_queries(database)
