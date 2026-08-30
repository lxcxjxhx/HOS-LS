"""Executable characterization tests for the pre-ECATSL reusable baseline."""

import inspect
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.analyzers.input_tracer import ControllabilityResult, InputTracer
from src.analyzers.sast_prefilter import SastPrefilter
from src.analyzers.verification_adapter import VerificationAdapter, VerificationStats
from src.ecatsl.models import PathEvidence
from src.nvd.catalog_import import CatalogImporter, ImportSummary
from src.nvd.db.sqlite_connection import SQLiteConnection
from src.nvd.etl_batch_import import BatchImportManager, ETLProgress
from src.nvd.nvd_query_adapter import NVDQueryAdapter


BASELINE_FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "baseline"
CATALOG_TABLES = {
    "catalog_import": ("source_kind", "source_path", "sha256", "imported_at", "record_count"),
    "cve": ("cve_id", "description", "published_date", "last_modified"),
    "cve_cwe": ("cve_id", "cwe_id", "is_primary"),
    "cvss": ("cve_id", "score", "severity", "vector", "version"),
    "cwe": ("cwe_id", "name", "weakness_abstraction", "status", "description"),
}


def _parameter_names(callable_object):
    return tuple(inspect.signature(callable_object).parameters)


def _assert_not_path_evidence(raw_output):
    assert not isinstance(raw_output, PathEvidence)
    assert isinstance(raw_output, dict)
    assert "supported_adapter" not in raw_output
    assert "static_evidence_identity" not in raw_output
    assert "sanitizer_status" not in raw_output
    with pytest.raises(ValidationError):
        PathEvidence.model_validate(raw_output)


@pytest.fixture
def populated_catalog(tmp_path):
    database = tmp_path / "catalog.db"
    with CatalogImporter(database, batch_size=2) as importer:
        cwe_summary = importer.import_cwe_xml(BASELINE_FIXTURES / "mitre_cwe.xml")
        nvd_summary = importer.import_nvd(BASELINE_FIXTURES / "nvd_cve.json")
    return database, cwe_summary, nvd_summary


def test_public_constructor_and_method_signatures_are_characterized():
    assert _parameter_names(CatalogImporter) == ("database_path", "batch_size")
    assert _parameter_names(CatalogImporter.import_cwe_xml) == ("self", "source")
    assert _parameter_names(CatalogImporter.import_nvd) == ("self", "source")

    assert _parameter_names(BatchImportManager) == ("base_path",)
    assert _parameter_names(BatchImportManager.init_database) == ("self",)
    assert _parameter_names(BatchImportManager.get_progress) == ("self", "etl_name")
    assert _parameter_names(BatchImportManager.run_etl) == (
        "self",
        "etl_name",
        "data_path",
        "continue_mode",
    )

    assert _parameter_names(NVDQueryAdapter) == ("db_path", "use_cache")
    assert _parameter_names(NVDQueryAdapter.get_cwe_by_id) == ("self", "cwe_id")
    assert _parameter_names(NVDQueryAdapter.match_cwe) == ("self", "keywords", "limit")
    assert _parameter_names(NVDQueryAdapter.search_vulnerabilities) == (
        "self",
        "cwe_id",
        "severity",
        "limit",
    )

    assert _parameter_names(InputTracer) == ("project_root",)
    assert _parameter_names(InputTracer.trace_controllability) == (
        "self",
        "file_path",
        "line_number",
        "code_snippet",
    )
    assert _parameter_names(InputTracer.verify_sql_injection_prerequisites) == (
        "self",
        "file_path",
        "line_number",
        "code_snippet",
    )

    assert _parameter_names(SastPrefilter) == ("config",)
    assert _parameter_names(SastPrefilter.codeql_hard_analyze) == ("self", "source_root")
    assert _parameter_names(SastPrefilter.cascade) == ("self", "source_root", "files")

    assert _parameter_names(VerificationAdapter) == ("project_root", "nvd_db_path")
    assert _parameter_names(VerificationAdapter.adapt_finding) == (
        "self",
        "finding",
        "project_root",
    )
    assert _parameter_names(VerificationAdapter.verify_scanner_results) == (
        "self",
        "findings",
        "scanner_name",
        "project_root",
        "filter_hallucinations",
        "hallucination_threshold",
        "scanner_threshold",
    )


def test_catalog_import_schema_and_existing_queries_remain_usable(populated_catalog):
    database, cwe_summary, nvd_summary = populated_catalog
    assert cwe_summary == ImportSummary(cwes=1)
    assert nvd_summary == ImportSummary(cves=1)

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert set(CATALOG_TABLES) <= tables
        for table, expected_columns in CATALOG_TABLES.items():
            actual_columns = tuple(
                row[1] for row in connection.execute(f"PRAGMA table_info({table})")
            )
            assert actual_columns == expected_columns

    adapter = NVDQueryAdapter(str(database), use_cache=False)
    try:
        assert adapter.is_available() is True
        assert adapter.get_all_cwe_ids() == ["CWE-89"]
        assert adapter.get_cwe_by_id("CWE-89") == {
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "cwe_description": "User-controlled input is used to construct an SQL command.",
            "confidence": 1.0,
        }
        assert adapter.match_cwe(["SQL"], limit=1)[0]["cwe_id"] == "CWE-89"
        assert adapter.search_vulnerabilities(cwe_id="CWE-89", severity="HIGH", limit=1) == [
            {
                "cve_id": "CVE-2025-0001",
                "description": "A minimal SQL injection catalog fixture.",
                "cvss_score": 8.8,
                "severity": "HIGH",
            }
        ]
        stats = adapter.get_cwe_with_cvss_stats("CWE-89")
        assert stats["cve_count"] == 1
        assert stats["avg_cvss"] == 8.8
    finally:
        adapter._disconnect()


def test_batch_import_manager_extends_temp_database_and_exposes_progress(monkeypatch, tmp_path):
    database = tmp_path / "batch.db"
    sqlite3.connect(database).close()
    connection = SQLiteConnection(str(database))
    monkeypatch.setattr(
        SQLiteConnection,
        "get_instance",
        classmethod(lambda cls, db_path=None: connection),
    )

    manager = BatchImportManager(str(tmp_path))
    try:
        manager.init_database()
        assert manager.get_progress("nvd") is None
        assert manager.get_all_progress() == {}
        assert manager.run_etl("not-a-real-etl", str(tmp_path)) is False

        manager._save_checkpoint(
            "nvd",
            last_file="fixture.json",
            last_index=2,
            processed=3,
            inserted=2,
            skipped=1,
            status="running",
        )
        progress = manager.get_progress("nvd")
        assert isinstance(progress, ETLProgress)
        assert progress.etl_name == "nvd"
        assert progress.last_file == "fixture.json"
        assert progress.last_index == 2
        assert progress.processed_count == 3
        assert progress.inserted_count == 2
        assert progress.skipped_count == 1
        assert progress.status == "running"

        with sqlite3.connect(database) as raw_connection:
            tables = {
                row[0]
                for row in raw_connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        assert {"cve", "cwe", "cvss", "cve_cwe", "etl_records", "etl_progress"} <= tables
    finally:
        connection.close()


def test_input_tracer_actual_output_matches_recorded_shape_and_is_not_path_evidence():
    sample = BASELINE_FIXTURES / "input_tracer_sample.py"
    expected_shape = json.loads(
        (BASELINE_FIXTURES / "input_tracer_output_shape.json").read_text(encoding="utf-8")
    )
    code_snippet = sample.read_text(encoding="utf-8").splitlines()[4]

    result = InputTracer(str(BASELINE_FIXTURES)).verify_sql_injection_prerequisites(
        str(sample), 5, code_snippet
    )
    assert isinstance(result, ControllabilityResult)
    raw_output = result.to_dict()
    assert sorted(raw_output) == expected_shape["top_level_keys"]
    assert sorted(raw_output["trace_path"][0]) == expected_shape["trace_node_keys"]
    for key, value in expected_shape["representative_values"].items():
        assert raw_output[key] == value
    assert expected_shape["path_evidence"] is False
    _assert_not_path_evidence(raw_output)


def test_sast_prefilter_actual_sarif_hit_shape_is_not_path_evidence(monkeypatch, tmp_path):
    source_root = tmp_path / "repository"
    source_root.mkdir()
    (source_root / ".codeql-db").mkdir()
    (source_root / ".codeql-db" / "codeql-database.yml").write_text(
        "name: baseline\n", encoding="utf-8"
    )
    shutil.copyfile(
        BASELINE_FIXTURES / "codeql_result.sarif",
        source_root / ".codeql-results.sarif",
    )
    monkeypatch.setattr(SastPrefilter, "_envs_bin", staticmethod(lambda name: "codeql.exe"))
    monkeypatch.setattr(
        SastPrefilter,
        "_run",
        staticmethod(
            lambda cmd, timeout=3600: subprocess.CompletedProcess(cmd, 0, "", "")
        ),
    )

    raw_output = SastPrefilter({"backends": ["codeql"]}).codeql_hard_analyze(
        str(source_root)
    )
    assert raw_output == {
        "available": True,
        "hits": [
            {
                "file": "app.py",
                "line": 6,
                "rule": "py/sql-injection",
                "cwe": "CWE-089",
                "severity": "error",
                "message": "Query is built from user-controlled sources.",
                "backend": "codeql",
            }
        ],
        "note": "codeql 命中 1 条",
    }
    assert "codeFlows" not in raw_output["hits"][0]
    _assert_not_path_evidence(raw_output)
    _assert_not_path_evidence(raw_output["hits"][0])


def test_verification_adapter_normalization_shape_is_usable_but_not_path_evidence(
    populated_catalog, tmp_path
):
    database, _, _ = populated_catalog
    adapter = VerificationAdapter(project_root=str(tmp_path), nvd_db_path=str(database))
    raw_output = adapter.adapt_finding(
        {
            "rule_id": "py/sql-injection",
            "severity": "high",
            "description": "Potential SQL injection",
            "file_path": "app.py",
            "line": 6,
            "code_snippet": "cursor.execute(query)",
        }
    )

    assert raw_output == {
        "id": "dict_app.py_6",
        "rule_id": "py/sql-injection",
        "rule_name": "py/sql-injection",
        "severity": "high",
        "description": "Potential SQL injection",
        "file_path": "app.py",
        "location": {"file": "app.py", "line": 6},
        "code_snippet": "cursor.execute(query)",
        "fix_suggestion": "",
        "confidence": 0.5,
        "metadata": {},
    }
    _assert_not_path_evidence(raw_output)

    stats = adapter.get_verification_stats(
        [
            {
                "metadata": {
                    "verification_level": "single_verified",
                    "confidence_score": 0.75,
                }
            }
        ]
    )
    assert isinstance(stats, VerificationStats)
    assert stats.to_dict() == {
        "total_findings": 1,
        "triple_verified": 0,
        "double_verified": 0,
        "single_verified": 1,
        "needs_review": 0,
        "potential_hallucination": 0,
        "unknown": 0,
        "hallucinations_filtered": 0,
        "average_confidence": 0.75,
    }
