"""Deterministic normalization, deduplication, incremental import and quality
telemetry for CatalogImporter (Task 6.2).

Covers Requirements 9.4-9.7 and 11.2-11.7: stable normalized identities,
canonicalization with retained duplicate sources and decisions, zero-new replay,
new/changed-only incremental runs, integrity outcomes, and complete per-run
counts/reasons/coverage/import-identity telemetry.
"""

import json
import sqlite3
from pathlib import Path

from src.nvd.catalog_import import (
    DEFAULT_NORMALIZATION_PROFILE,
    CatalogImporter,
    IngestionService,
    IngestionReport,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "baseline"


def _rows(connection: sqlite3.Connection, sql: str, params=()) -> list[tuple]:
    return connection.execute(sql, params).fetchall()


def _quality_report(connection: sqlite3.Connection, report: IngestionReport) -> dict:
    row = connection.execute(
        "SELECT counts_json, integrity_json, coverage_json, exclusions_json, "
        "content_hash FROM ingestion_quality_report WHERE report_id = ?",
        (report.report_id,),
    ).fetchone()
    assert row is not None
    return {
        "counts": json.loads(row[0]),
        "integrity": json.loads(row[1]),
        "coverage": json.loads(row[2]),
        "exclusions": json.loads(row[3]),
        "content_hash": row[4],
    }


def test_cwe_ingestion_writes_versioned_rows_and_quality_report(tmp_path):
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        service = IngestionService(importer)
        report = service.ingest_cwe_xml(FIXTURES / "mitre_cwe.xml")
        assert report.source_kind == "cwe"
        assert report.profile_version == DEFAULT_NORMALIZATION_PROFILE
        assert report.counts["retrieved"] == 1
        assert report.counts["imported"] == 1
        assert report.counts["normalized"] == 1
        assert report.counts["new_canonical"] == 1
        assert report.counts["duplicate"] == 0
        assert report.counts["unchanged"] == 0
        assert report.integrity == {"checked": 1, "verified": 1, "failed": 0}

        stored = _quality_report(importer.connection, report)
        assert stored["counts"] == report.counts
        assert stored["content_hash"] == report.content_hash
        assert stored["coverage"]["source_kind"] == "cwe"
        assert stored["coverage"]["canonical_identifiers"] == 1

        # Canonical base data plus every versioned row are present.
        assert _rows(importer.connection, "SELECT cwe_id FROM cwe") == [("CWE-89",)]
        import_rows = _rows(
            importer.connection,
            "SELECT source_kind, source_origin FROM catalog_import_version",
        )
        assert import_rows == [("cwe", "mitre:cwec_xml")]
        source_rows = _rows(
            importer.connection,
            "SELECT record_type, source_identifier FROM source_record",
        )
        assert source_rows == [("CWE", "CWE-89")]
        normalized_rows = _rows(
            importer.connection,
            "SELECT record_type, canonical_identifier, canonical_id "
            "FROM normalized_catalog_record",
        )
        assert normalized_rows == [("CWE", "CWE-89", None)]
        run_rows = _rows(
            importer.connection,
            "SELECT import_id, profile_version, prior_run_id FROM ingestion_run",
        )
        assert run_rows[0][1] == DEFAULT_NORMALIZATION_PROFILE
        assert run_rows[0][2] is None
        assert report.run_id.startswith("ingestion-run:")


def test_identical_replay_reports_zero_new_canonical(tmp_path):
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        service = IngestionService(importer)
        first = service.ingest_cwe_xml(FIXTURES / "mitre_cwe.xml")
        second = service.ingest_cwe_xml(FIXTURES / "mitre_cwe.xml")
        assert second.counts["unchanged"] == 1
        assert second.counts["new_canonical"] == 0
        assert second.counts["normalized"] == 0
        assert second.counts["duplicate"] == 0
        assert _rows(
            importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record"
        ) == [(1,)]
        assert _rows(importer.connection, "SELECT COUNT(*) FROM source_record") == [(1,)]
        # A new versioned run links its prior run (Requirement 11.7).
        assert _rows(
            importer.connection, "SELECT COUNT(*) FROM ingestion_run"
        ) == [(2,)]
        assert _rows(
            importer.connection,
            "SELECT prior_run_id FROM ingestion_run ORDER BY completed_at",
        )[1][0] == first.run_id


def test_changed_records_append_canonical_version_and_skip_unchanged(tmp_path):
    database = tmp_path / "catalog.db"
    catalog = tmp_path / "cwe.xml"
    catalog.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Weakness_Catalog Name="two">\n'
        "  <Weaknesses>\n"
        '    <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">\n'
        "      <Description>Original 89 description.</Description>\n"
        "    </Weakness>\n"
        '    <Weakness ID="78" Name="OS Command Injection" Abstraction="Base" Status="Stable">\n'
        "      <Description>Original 78 description.</Description>\n"
        "    </Weakness>\n"
        "  </Weaknesses>\n"
        "</Weakness_Catalog>\n"
    )
    with CatalogImporter(database) as importer:
        service = IngestionService(importer)
        first = service.ingest_cwe_xml(catalog)
        assert first.counts["new_canonical"] == 2

        catalog.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Weakness_Catalog Name="two">\n'
            "  <Weaknesses>\n"
            '    <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">\n'
            "      <Description>Updated 89 description.</Description>\n"
            "    </Weakness>\n"
            '    <Weakness ID="78" Name="OS Command Injection" Abstraction="Base" Status="Stable">\n'
            "      <Description>Original 78 description.</Description>\n"
            "    </Weakness>\n"
            "  </Weaknesses>\n"
            "</Weakness_Catalog>\n"
        )
        second = service.ingest_cwe_xml(catalog)
        assert second.counts["retrieved"] == 2
        assert second.counts["unchanged"] == 1  # CWE-78 unchanged
        assert second.counts["new_canonical"] == 1  # CWE-89 changed
        assert second.counts["imported"] == 1
        # Append-only version history: two canonical versions of CWE-89 exist.
        assert _rows(
            importer.connection,
            "SELECT COUNT(*) FROM normalized_catalog_record "
            "WHERE canonical_identifier = 'CWE-89' AND canonical_id IS NULL",
        ) == [(2,)]
        assert _rows(
            importer.connection,
            "SELECT description FROM cwe WHERE cwe_id = 'CWE-89'",
        ) == [("Updated 89 description.",)]


def test_same_normalized_content_is_duplicate_decision(tmp_path):
    database = tmp_path / "catalog.db"
    nvd_file = tmp_path / "nvd.json"

    def write_document(references: list[str]) -> None:
        nvd_file.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2025-0001",
                                "published": "2025-01-02T00:00:00.000Z",
                                "lastModified": "2025-01-03T00:00:00.000Z",
                                "descriptions": [
                                    {"lang": "en", "value": "Stable payload."}
                                ],
                                "weaknesses": [
                                    {"description": [{"lang": "en", "value": "CWE-89"}]}
                                ],
                                "references": [
                                    {"url": ref} for ref in references
                                ],
                            }
                        }
                    ]
                }
            )
        )

    with CatalogImporter(database) as importer:
        service = IngestionService(importer)
        write_document(["https://example.test/a"])
        first = service.ingest_nvd(nvd_file)[0]
        assert first.counts["new_canonical"] == 1

        # Changed raw references leave the normalized payload identical, so the
        # second source record is a duplicate of the canonical record.
        write_document(["https://example.test/a", "https://example.test/b"])
        second = service.ingest_nvd(nvd_file)[0]
        assert second.counts["duplicate"] == 1
        assert second.counts["new_canonical"] == 0
        assert second.counts["imported"] == 1
        assert _rows(
            importer.connection,
            "SELECT COUNT(*) FROM source_record WHERE source_identifier = 'CVE-2025-0001'",
        ) == [(2,)]
        assert _rows(
            importer.connection,
            "SELECT reason FROM catalog_duplicate",
        ) == [("duplicate_canonical_identifier",)]
        # Canonical normalized record is unchanged.
        assert _rows(
            importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record"
        ) == [(1,)]


def test_content_hash_integrity_outcomes_are_recorded(tmp_path):
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        service = IngestionService(importer)
        report = service.ingest_nvd(
            FIXTURES / "nvd_cve.json", expected_content_hash="0" * 64
        )[0]
        assert report.counts["integrity_failed"] == 1
        assert report.integrity == {"checked": 1, "verified": 0, "failed": 1}
        assert report.counts["imported"] == 1  # records are retained and audited
        assert _rows(
            importer.connection,
            "SELECT integrity_status FROM source_record",
        ) == [("FAILED",)]

        verified = service.ingest_nvd(FIXTURES / "nvd_cve.json")[0]
        assert verified.counts["integrity_failed"] == 0
        assert verified.integrity == {"checked": 1, "verified": 1, "failed": 0}


def test_invalid_and_incomplete_records_are_excluded_or_counted(tmp_path):
    database = tmp_path / "catalog.db"
    nvd_file = tmp_path / "mixed.json"
    nvd_file.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2025-0001", "published": "2025-01-02"}},
                    {"cve": {"id": "not-a-cve", "published": "2025-01-02"}},
                ]
            }
        )
    )
    with CatalogImporter(database) as importer:
        service = IngestionService(importer)
        report = service.ingest_nvd(nvd_file)[0]
        # No description on CVE-2025-0001 -> missing field, still imported.
        assert report.counts["retrieved"] == 1
        assert report.counts["imported"] == 1
        assert report.counts["missing_required_field"] == 1
        # The malformed identifier is excluded with its reason retained.
        assert report.counts["excluded"] == 1
        assert report.exclusions == [
            {"reason": "invalid_source_record", "identifiers": [""]}
        ]
        stored = _quality_report(importer.connection, report)
        assert stored["exclusions"] == report.exclusions


def test_bounded_batch_commits_track_peak_batch_size(tmp_path):
    database = tmp_path / "catalog.db"
    catalog = tmp_path / "cwe.xml"
    weaknesses = "\n".join(
        (
            f'    <Weakness ID="{i}" Name="W{i}" Abstraction="Base" Status="Stable">\n'
            f"      <Description>Description {i}.</Description>\n"
            "    </Weakness>"
        )
        for i in range(1, 6)
    )
    catalog.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Weakness_Catalog Name="batch">\n'
        f"  <Weaknesses>\n{weaknesses}\n  </Weaknesses>\n"
        "</Weakness_Catalog>\n"
    )
    with CatalogImporter(database, batch_size=2) as importer:
        service = IngestionService(importer)
        report = service.ingest_cwe_xml(catalog)
        assert report.counts["new_canonical"] == 5
        assert report.peak_batch_size == 2
        assert _rows(
            importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record"
        ) == [(5,)]
        assert _rows(importer.connection, "SELECT COUNT(*) FROM ingestion_run") == [(1,)]


def test_directory_nvd_ingest_returns_one_report_per_file(tmp_path):
    database = tmp_path / "catalog.db"
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()
    for index in (1, 2):
        (nvd_dir / f"{index}.json").write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": f"CVE-2025-000{index}",
                                "published": "2025-01-02T00:00:00.000Z",
                                "lastModified": "2025-01-03T00:00:00.000Z",
                                "descriptions": [
                                    {"lang": "en", "value": f"Fixture {index}."}
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
    with CatalogImporter(database) as importer:
        service = IngestionService(importer)
        reports = service.ingest_nvd(nvd_dir)
        assert len(reports) == 2
        assert [report.counts["new_canonical"] for report in reports] == [1, 1]
        assert _rows(
            importer.connection, "SELECT COUNT(*) FROM ingestion_run"
        ) == [(2,)]


def test_normalization_identity_is_deterministic_and_profile_scoped(tmp_path):
    payload = {"id": "CWE-89", "name": "SQL Injection", "description": "Text."}
    first = IngestionService._normalized_content_hash("catalog-normalize/v1", payload)
    second = IngestionService._normalized_content_hash("catalog-normalize/v1", payload)
    assert first == second
    assert len(first) == 64
    # A changed profile version or payload changes the normalized identity.
    assert IngestionService._normalized_content_hash(
        "catalog-normalize/v2", payload
    ) != first
    changed = dict(payload, description="Other text.")
    assert IngestionService._normalized_content_hash(
        "catalog-normalize/v1", changed
    ) != first
    # Records imported by the service carry that deterministic identity.
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        service = IngestionService(importer)
        report = service.ingest_nvd(FIXTURES / "nvd_cve.json")[0]
        stored = _quality_report(importer.connection, report)
        assert stored["content_hash"] == report.content_hash
        (normalized_hash,) = _rows(
            importer.connection,
            "SELECT normalized_content_hash FROM normalized_catalog_record "
            "WHERE canonical_identifier = 'CVE-2025-0001'",
        )[0]
        payload = {
            "id": "CVE-2025-0001",
            "description": "A minimal SQL injection catalog fixture.",
            "published": "2025-01-02T00:00:00.000Z",
            "last_modified": "2025-01-03T00:00:00.000Z",
            "cwes": ["CWE-89"],
            "cvss": {
                "score": 8.8,
                "severity": "HIGH",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "version": "31",
            },
        }
        assert normalized_hash == IngestionService._normalized_content_hash(
            DEFAULT_NORMALIZATION_PROFILE, payload
        )
