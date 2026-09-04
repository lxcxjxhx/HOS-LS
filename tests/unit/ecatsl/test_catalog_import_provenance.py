"""Versioned Catalog_Import provenance and v8 migration coverage (Task 6.1).

Covers the versioned catalog-import, source-record, normalized-record,
canonical/duplicate, ingestion-run, quality-report, taint-template, and
retrieval-provenance tables introduced by the v8 migration, the CatalogImporter
provenance records (origin/revision/retrieval hash/time/license/tool version/
predecessor), and the preservation of the pre-ECATSL canonical tables.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.ecatsl.schema import (
    MIGRATIONS,
    SCHEMA_VERSION,
    install_ecatsl_schema,
)
from src.nvd.catalog_import import (
    CATALOG_IMPORTER_TOOL_VERSION,
    DEFAULT_SOURCE_ORIGINS,
    CatalogImporter,
    ImportSummary,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "baseline"

V8_TABLES = {
    "catalog_import_version",
    "source_record",
    "normalized_catalog_record",
    "catalog_duplicate",
    "ingestion_run",
    "ingestion_quality_report",
    "taint_template",
    "template_retrieval",
}

LEGACY_TABLES = {"cwe", "cve", "cvss", "cve_cwe", "catalog_import"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _import_rows(connection: sqlite3.Connection) -> list[tuple]:
    return connection.execute(
        "SELECT import_id, source_kind, source_origin, source_identifier, "
        "source_revision, retrieved_content_hash, license_metadata, "
        "import_tool_version, predecessor_id FROM catalog_import_version "
        "ORDER BY created_at, import_id"
    ).fetchall()


def _table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def test_v8_migration_installs_catalog_tables_and_preserves_legacy_tables(tmp_path):
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        tables = _table_names(importer.connection)
        assert V8_TABLES <= tables
        assert LEGACY_TABLES <= tables
        assert importer.connection.execute(
            "SELECT version FROM ecatsl_schema_version ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, SCHEMA_VERSION + 1)]
        # Every v8 table is append-only.
        now = datetime.now(timezone.utc).isoformat()
        importer.connection.execute(
            """
            INSERT INTO catalog_import_version
                (import_id, source_kind, source_origin, source_identifier,
                 retrieved_at, retrieved_content_hash, import_tool_version,
                 created_at)
            VALUES ('catalog-import:test', 'nvd', 'nvd:api-2.0', '/x.json',
                    ?, ?, 'tool', ?)
            """,
            (now, "a" * 64, now),
        )
        importer.connection.commit()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            importer.connection.execute(
                "DELETE FROM catalog_import_version WHERE import_id = 'catalog-import:test'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            importer.connection.execute(
                "UPDATE catalog_import_version SET source_revision = 'tampered' "
                "WHERE import_id = 'catalog-import:test'"
            )


def test_v7_database_upgrades_to_v8_and_replays_idempotently(tmp_path):
    database = tmp_path / "catalog-v7.db"
    connection = sqlite3.connect(database)
    try:
        assert install_ecatsl_schema(connection, migrations=MIGRATIONS[:7]) == 7
        assert connection.execute(
            "SELECT MAX(version) FROM ecatsl_schema_version"
        ).fetchone() == (7,)
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'catalog_import_version'"
        ).fetchone() is None

        assert install_ecatsl_schema(connection) == SCHEMA_VERSION
        assert install_ecatsl_schema(connection) == SCHEMA_VERSION
        assert connection.execute(
            "SELECT version FROM ecatsl_schema_version ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, SCHEMA_VERSION + 1)]
        assert _table_names(connection) >= V8_TABLES
    finally:
        connection.close()


def test_cwe_import_records_versioned_catalog_import_provenance(tmp_path):
    database = tmp_path / "catalog.db"
    source = FIXTURES / "mitre_cwe.xml"
    with CatalogImporter(database) as importer:
        assert importer.import_cwe_xml(source) == ImportSummary(cwes=1)
        rows = _import_rows(importer.connection)
        assert len(rows) == 1
        import_id, kind, origin, identifier, revision, content_hash, license_, tool, pred = rows[0]
        assert kind == "cwe"
        assert origin == DEFAULT_SOURCE_ORIGINS["cwe"]
        assert identifier == str(source.resolve())
        assert revision is None
        assert content_hash == _sha256(source)
        assert license_ is None
        assert tool == CATALOG_IMPORTER_TOOL_VERSION
        assert pred is None
        assert import_id.startswith("catalog-import:")
        # Canonical cwe data plus the legacy catalog_import row remain intact.
        assert importer.connection.execute(
            "SELECT cwe_id, name FROM cwe"
        ).fetchall() == [("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command")]
        assert importer.connection.execute("SELECT COUNT(*) FROM catalog_import").fetchone() == (1,)


def test_nvd_import_records_versioned_catalog_import_provenance(tmp_path):
    database = tmp_path / "catalog.db"
    source = FIXTURES / "nvd_cve.json"
    with CatalogImporter(database) as importer:
        assert importer.import_nvd(source) == ImportSummary(cves=1)
        rows = _import_rows(importer.connection)
        assert len(rows) == 1
        _, kind, origin, identifier, revision, content_hash, license_, tool, pred = rows[0]
        assert kind == "nvd"
        assert origin == DEFAULT_SOURCE_ORIGINS["nvd"]
        assert identifier == str(source.resolve())
        assert content_hash == _sha256(source)
        assert tool == CATALOG_IMPORTER_TOOL_VERSION
        assert pred is None
        assert importer.connection.execute(
            "SELECT cve_id, description FROM cve"
        ).fetchall() == [("CVE-2025-0001", "A minimal SQL injection catalog fixture.")]


def test_provenance_overrides_are_recorded(tmp_path):
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        assert importer.import_cwe_xml(
            FIXTURES / "mitre_cwe.xml",
            source_origin="example:mirror",
            source_revision="rev-42",
            license_metadata='{"license": "CC0", "spdx": "CC0-1.0"}',
        ) == ImportSummary(cwes=1)
        rows = _import_rows(importer.connection)
        assert rows[0][2] == "example:mirror"
        assert rows[0][4] == "rev-42"
        assert rows[0][6] == '{"license": "CC0", "spdx": "CC0-1.0"}'


def test_repeated_and_changed_imports_append_predecessor_lineage(tmp_path):
    database = tmp_path / "catalog.db"
    # Copy the fixture into a writable path so the same source identifier can
    # later carry changed content (same origin/identifier, new content hash).
    source = tmp_path / "nvd_cve.json"
    source.write_bytes((FIXTURES / "nvd_cve.json").read_bytes())
    with CatalogImporter(database) as importer:
        assert importer.import_nvd(source) == ImportSummary(cves=1)
        assert importer.import_nvd(source) == ImportSummary(cves=1)
        rows = _import_rows(importer.connection)
        assert len(rows) == 2
        assert rows[0][8] is None
        assert rows[1][8] == rows[0][0]
        assert rows[0][5] == rows[1][5] == _sha256(source)
        # The legacy catalog_import row is replaced in place, not duplicated.
        assert importer.connection.execute("SELECT COUNT(*) FROM catalog_import").fetchone() == (1,)
        assert importer.connection.execute(
            "SELECT COUNT(*) FROM cve"
        ).fetchone() == (1,)

        source.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2025-0001",
                                "published": "2025-01-02T00:00:00.000Z",
                                "lastModified": "2025-02-01T00:00:00.000Z",
                                "descriptions": [
                                    {"lang": "en", "value": "Changed minimal fixture."}
                                ],
                                "weaknesses": [
                                    {"description": [{"lang": "en", "value": "CWE-89"}]}
                                ],
                            }
                        }
                    ]
                }
            )
        )
        assert importer.import_nvd(source) == ImportSummary(cves=1)
        rows = _import_rows(importer.connection)
        assert len(rows) == 3
        assert rows[2][8] == rows[1][0]
        assert rows[2][5] == _sha256(source)
        assert rows[2][4] is None
        assert importer.connection.execute(
            "SELECT description FROM cve"
        ).fetchone() == ("Changed minimal fixture.",)


def test_empty_nvd_file_is_skipped_without_versioned_row(tmp_path):
    database = tmp_path / "catalog.db"
    empty = tmp_path / "empty.json"
    empty.write_text('{"vulnerabilities": []}')
    with CatalogImporter(database) as importer:
        assert importer.import_nvd(empty) == ImportSummary(cves=0, skipped=1)
        assert _import_rows(importer.connection) == []
        assert importer.connection.execute("SELECT COUNT(*) FROM catalog_import").fetchone() == (0,)


def test_empty_cwe_catalog_records_legacy_row_but_no_versioned_import(tmp_path):
    database = tmp_path / "catalog.db"
    empty_xml = tmp_path / "empty_cwe.xml"
    empty_xml.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Weakness_Catalog Name="empty"><Weaknesses/></Weakness_Catalog>'
    )
    with CatalogImporter(database) as importer:
        assert importer.import_cwe_xml(empty_xml) == ImportSummary(cwes=0)
        assert _import_rows(importer.connection) == []
        assert importer.connection.execute(
            "SELECT record_count FROM catalog_import"
        ).fetchone() == (0,)


def test_multi_weakness_catalog_streams_in_bounded_batches(tmp_path):
    database = tmp_path / "catalog.db"
    catalog = tmp_path / "multi_cwe.xml"
    weaknesses = "\n".join(
        (
            f'    <Weakness ID="{identifier}" Name="Weakness {identifier}" '
            f'Abstraction="Base" Status="Stable">\n'
            f"      <Description>Description text for {identifier}.</Description>\n"
            "    </Weakness>"
        )
        for identifier in (89, 78, 918, 79, 22)
    )
    catalog.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Weakness_Catalog Name="multi">\n'
        f"  <Weaknesses>\n{weaknesses}\n  </Weaknesses>\n"
        "</Weakness_Catalog>\n"
    )
    with CatalogImporter(database, batch_size=2) as importer:
        assert importer.import_cwe_xml(catalog) == ImportSummary(cwes=5)
        assert importer.connection.execute(
            "SELECT cwe_id, description FROM cwe ORDER BY cwe_id"
        ).fetchall() == [
            ("CWE-22", "Description text for 22."),
            ("CWE-78", "Description text for 78."),
            ("CWE-79", "Description text for 79."),
            ("CWE-89", "Description text for 89."),
            ("CWE-918", "Description text for 918."),
        ]
        # One streamed source produced exactly one versioned import row.
        rows = _import_rows(importer.connection)
        assert len(rows) == 1
        assert rows[0][1] == "cwe"
        assert rows[0][5] == _sha256(catalog)


def test_directory_import_streams_files_and_records_each_import(tmp_path):
    database = tmp_path / "catalog.db"
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()
    first = nvd_dir / "a.json"
    second = nvd_dir / "b.json"
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-0001",
                    "published": "2025-01-02T00:00:00.000Z",
                    "lastModified": "2025-01-03T00:00:00.000Z",
                    "descriptions": [{"lang": "en", "value": "Minimal fixture."}],
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
                }
            }
        ]
    }
    first.write_text(json.dumps(payload))
    second.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2025-0002",
                            "published": "2025-02-01T00:00:00.000Z",
                            "lastModified": "2025-02-02T00:00:00.000Z",
                            "descriptions": [{"lang": "en", "value": "Second fixture."}],
                            "weaknesses": [
                                {"description": [{"lang": "en", "value": "CWE-78"}]}
                            ],
                        }
                    }
                ]
            }
        )
    )
    with CatalogImporter(database, batch_size=2) as importer:
        assert importer.import_nvd(nvd_dir) == ImportSummary(cves=2)
        rows = _import_rows(importer.connection)
        assert len(rows) == 2
        assert {row[1] for row in rows} == {"nvd"}
        assert {row[5] for row in rows} == {_sha256(first), _sha256(second)}
        assert all(row[8] is None for row in rows)
        assert importer.connection.execute(
            "SELECT COUNT(*) FROM cve"
        ).fetchone() == (2,)


def test_catalog_import_version_rows_are_append_only(tmp_path):
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        importer.import_nvd(FIXTURES / "nvd_cve.json")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            importer.connection.execute(
                "UPDATE catalog_import_version SET source_revision = 'tampered' "
                "WHERE import_id = (SELECT import_id FROM catalog_import_version LIMIT 1)"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            importer.connection.execute("DELETE FROM catalog_import_version")


def test_timestamp_fields_are_utc_isoformat(tmp_path):
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        importer.import_nvd(FIXTURES / "nvd_cve.json")
        (retrieved_at, created_at) = importer.connection.execute(
            "SELECT retrieved_at, created_at FROM catalog_import_version"
        ).fetchone()
        for value in (retrieved_at, created_at):
            parsed = datetime.fromisoformat(value)
            assert parsed.tzinfo is not None
            assert parsed.utcoffset().total_seconds() == 0
