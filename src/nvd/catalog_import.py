"""Versioned, offline-first importer for NVD CVE and MITRE CWE catalogs.

The importer deliberately does not encode framework routes or vulnerability patterns.
It normalizes authoritative catalog data into the SQLite schema consumed by
:class:`src.nvd.nvd_query_adapter.NVDQueryAdapter`.  Scanners can then retrieve
CWE/CVE evidence without updating data or making network requests during a scan.

Supported NVD inputs are NVD API 2.0 response documents (``vulnerabilities``),
individual NVD CVE documents (``id``), and directories containing either format.
CWE input is the official MITRE CWE XML catalog (``cwec_latest.xml``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional


IGNORED_CWE_IDS = {"NVD-CWE-noinfo", "NVD-CWE-Other", ""}
CVSS_METRIC_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@dataclass(frozen=True)
class ImportSummary:
    """Counts produced by one import operation."""

    cwes: int = 0
    cves: int = 0
    skipped: int = 0


class CatalogImporter:
    """Import official vulnerability catalogs into an idempotent SQLite database."""

    def __init__(self, database_path: str | Path, batch_size: int = 500) -> None:
        self.database_path = Path(database_path).expanduser()
        self.batch_size = max(1, batch_size)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.database_path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "CatalogImporter":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cwe (
                cwe_id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                weakness_abstraction TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS cve (
                cve_id TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                published_date TEXT,
                last_modified TEXT
            );
            CREATE TABLE IF NOT EXISTS cvss (
                cve_id TEXT PRIMARY KEY REFERENCES cve(cve_id) ON DELETE CASCADE,
                score REAL,
                severity TEXT,
                vector TEXT,
                version TEXT
            );
            CREATE TABLE IF NOT EXISTS cve_cwe (
                cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
                cwe_id TEXT NOT NULL REFERENCES cwe(cwe_id) ON DELETE CASCADE,
                is_primary INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (cve_id, cwe_id)
            );
            CREATE TABLE IF NOT EXISTS catalog_import (
                source_kind TEXT NOT NULL,
                source_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                PRIMARY KEY (source_kind, source_path, sha256)
            );
            CREATE TABLE IF NOT EXISTS catalog_import_version (
                import_id TEXT PRIMARY KEY, source_kind TEXT NOT NULL,
                source_origin TEXT NOT NULL, source_identifier TEXT NOT NULL,
                source_revision TEXT, retrieved_at TEXT NOT NULL,
                retrieved_content_hash TEXT NOT NULL, license_metadata TEXT,
                import_tool_version TEXT NOT NULL, predecessor_id TEXT
            );
            CREATE TABLE IF NOT EXISTS source_record (
                record_id TEXT PRIMARY KEY, import_id TEXT NOT NULL,
                record_type TEXT NOT NULL, source_identifier TEXT NOT NULL,
                source_content_hash TEXT NOT NULL, integrity_status TEXT NOT NULL,
                provenance_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS normalized_catalog_record (
                normalized_id TEXT PRIMARY KEY, record_type TEXT NOT NULL,
                canonical_identifier TEXT NOT NULL, normalized_content_hash TEXT NOT NULL,
                normalization_profile_version TEXT NOT NULL, canonical_id TEXT,
                provenance_json TEXT NOT NULL,
                UNIQUE(record_type, canonical_identifier)
            );
            CREATE TABLE IF NOT EXISTS catalog_duplicate (
                duplicate_id TEXT PRIMARY KEY, canonical_id TEXT NOT NULL,
                source_record_id TEXT NOT NULL, reason TEXT NOT NULL,
                decision_provenance_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ingestion_run (
                run_id TEXT PRIMARY KEY, import_id TEXT NOT NULL, profile_version TEXT NOT NULL,
                import_tool_version TEXT NOT NULL, prior_run_id TEXT, started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL, content_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ingestion_quality_report (
                report_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, counts_json TEXT NOT NULL,
                integrity_json TEXT NOT NULL, coverage_json TEXT NOT NULL,
                exclusions_json TEXT NOT NULL, content_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS taint_template (
                template_id TEXT PRIMARY KEY, cwe_id TEXT NOT NULL, role TEXT NOT NULL,
                api_shape TEXT NOT NULL, parameter_shape TEXT NOT NULL,
                applicability_json TEXT NOT NULL, semantic_features_json TEXT NOT NULL,
                template_version TEXT NOT NULL, provenance_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS template_retrieval (
                retrieval_id TEXT PRIMARY KEY, cwe_id TEXT NOT NULL,
                query_identity TEXT NOT NULL, ranking_profile_version TEXT NOT NULL,
                result_template_ids_json TEXT NOT NULL, scores_json TEXT NOT NULL,
                provenance_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id ON cve_cwe(cwe_id);
            CREATE INDEX IF NOT EXISTS idx_cvss_severity ON cvss(severity);
            CREATE INDEX IF NOT EXISTS idx_taint_template_cwe ON taint_template(cwe_id);
            """
        )
        self.connection.commit()

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _text(element: Optional[ET.Element]) -> str:
        if element is None:
            return ""
        return " ".join(part.strip() for part in element.itertext() if part.strip())

    @staticmethod
    def _local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def import_cwe_xml(self, source: str | Path) -> ImportSummary:
        """Import the official MITRE CWE XML catalog using idempotent upserts."""
        path = Path(source)
        root = ET.parse(path).getroot()
        rows: list[tuple[str, str, str, str, str]] = []
        for element in root.iter():
            if self._local_name(element.tag) != "Weakness":
                continue
            identifier = element.get("ID")
            if not identifier:
                continue
            description = next(
                (self._text(child) for child in element if self._local_name(child.tag) == "Description"),
                "",
            )
            rows.append(
                (
                    f"CWE-{identifier}",
                    element.get("Name", ""),
                    element.get("Abstraction", ""),
                    element.get("Status", ""),
                    description,
                )
            )

        with self.connection:
            self.connection.executemany(
                """
                INSERT INTO cwe (cwe_id, name, weakness_abstraction, status, description)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cwe_id) DO UPDATE SET
                    name=excluded.name,
                    weakness_abstraction=excluded.weakness_abstraction,
                    status=excluded.status,
                    description=excluded.description
                """,
                rows,
            )
            self._record_import("cwe", path, len(rows))
        return ImportSummary(cwes=len(rows))

    def import_nvd(self, source: str | Path) -> ImportSummary:
        """Import NVD API 2.0 JSON files or a directory of exported response files."""
        path = Path(source)
        paths = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        imported = 0
        skipped = 0
        for json_path in paths:
            try:
                with json_path.open(encoding="utf-8") as stream:
                    document = json.load(stream)
                records = list(self._iter_nvd_records(document))
                if not records:
                    skipped += 1
                    continue
                with self.connection:
                    for record in records:
                        self._upsert_nvd_record(record)
                    self._record_import("nvd", json_path, len(records))
                imported += len(records)
            except (OSError, ValueError, TypeError, sqlite3.DatabaseError):
                skipped += 1
        return ImportSummary(cves=imported, skipped=skipped)

    @staticmethod
    def _iter_nvd_records(document: Any) -> Iterator[dict[str, Any]]:
        if not isinstance(document, dict):
            return
        if isinstance(document.get("vulnerabilities"), list):
            for entry in document["vulnerabilities"]:
                if isinstance(entry, dict) and isinstance(entry.get("cve"), dict):
                    yield entry["cve"]
            return
        if isinstance(document.get("cve"), dict):
            yield document["cve"]
            return
        if document.get("id", "").startswith("CVE-"):
            yield document

    @staticmethod
    def _description(record: dict[str, Any]) -> str:
        descriptions = record.get("descriptions", [])
        if not isinstance(descriptions, list):
            return ""
        english = next(
            (
                item.get("value", "")
                for item in descriptions
                if isinstance(item, dict) and item.get("lang") == "en"
            ),
            "",
        )
        return english or next(
            (item.get("value", "") for item in descriptions if isinstance(item, dict)),
            "",
        )

    @staticmethod
    def _cwe_ids(record: dict[str, Any]) -> list[str]:
        result: list[str] = []
        for weakness in record.get("weaknesses", []) or []:
            for description in weakness.get("description", []) if isinstance(weakness, dict) else []:
                candidate = description.get("value", "") if isinstance(description, dict) else ""
                if candidate and candidate not in IGNORED_CWE_IDS and candidate not in result:
                    result.append(candidate)
        return result

    @staticmethod
    def _cvss(record: dict[str, Any]) -> Optional[tuple[float, str, str, str]]:
        metrics = record.get("metrics", {})
        if not isinstance(metrics, dict):
            return None
        for metric_name in CVSS_METRIC_ORDER:
            values = metrics.get(metric_name, [])
            if not isinstance(values, list) or not values:
                continue
            metric = values[0] if isinstance(values[0], dict) else {}
            data = metric.get("cvssData", {}) if isinstance(metric.get("cvssData"), dict) else {}
            score = data.get("baseScore")
            if score is None:
                continue
            severity = data.get("baseSeverity") or metric.get("baseSeverity") or ""
            vector = data.get("vectorString", "")
            return float(score), str(severity).upper(), str(vector), metric_name.removeprefix("cvssMetricV")
        return None

    def _upsert_nvd_record(self, record: dict[str, Any]) -> None:
        cve_id = record.get("id", "")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            raise ValueError("NVD record does not contain a valid CVE identifier")
        self.connection.execute(
            """
            INSERT INTO cve (cve_id, description, published_date, last_modified)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                published_date=excluded.published_date,
                last_modified=excluded.last_modified
            """,
            (cve_id, self._description(record), record.get("published"), record.get("lastModified")),
        )
        cvss = self._cvss(record)
        if cvss:
            self.connection.execute(
                """
                INSERT INTO cvss (cve_id, score, severity, vector, version)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    score=excluded.score, severity=excluded.severity,
                    vector=excluded.vector, version=excluded.version
                """,
                (cve_id, *cvss),
            )
        self.connection.execute("DELETE FROM cve_cwe WHERE cve_id = ?", (cve_id,))
        for index, cwe_id in enumerate(self._cwe_ids(record)):
            self.connection.execute(
                "INSERT OR IGNORE INTO cwe (cwe_id) VALUES (?)", (cwe_id,)
            )
            self.connection.execute(
                "INSERT INTO cve_cwe (cve_id, cwe_id, is_primary) VALUES (?, ?, ?)",
                (cve_id, cwe_id, int(index == 0)),
            )

    @staticmethod
    def normalize_record(record: dict[str, Any], profile_version: str) -> tuple[str, str]:
        """Return deterministic normalized JSON and identity for a profile."""
        normalized = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        identity = hashlib.sha256(
            (profile_version + "\0" + normalized).encode("utf-8")
        ).hexdigest()
        return normalized, identity

    def ingest_ecatsl_records(
        self,
        *,
        source_kind: str,
        source_identifier: str,
        records: list[dict[str, Any]],
        profile_version: str = "1",
        import_tool_version: str = "1",
        source_origin: str = "local",
        source_revision: Optional[str] = None,
        license_metadata: Optional[str] = None,
    ) -> dict[str, Any]:
        """Incrementally normalize compatible records in the existing SQLite store."""
        retrieved_at = datetime.now(timezone.utc).isoformat()
        source_payload = json.dumps(records, sort_keys=True, separators=(",", ":"))
        source_hash = hashlib.sha256(source_payload.encode()).hexdigest()
        import_id = hashlib.sha256(
            f"{source_kind}\0{source_identifier}\0{source_hash}\0{import_tool_version}".encode()
        ).hexdigest()
        prior = self.connection.execute(
            "SELECT run_id FROM ingestion_run WHERE import_id=? AND profile_version=? "
            "AND import_tool_version=? ORDER BY completed_at DESC LIMIT 1",
            (import_id, profile_version, import_tool_version),
        ).fetchone()
        created = duplicates = excluded = missing = 0
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO catalog_import_version VALUES(?,?,?,?,?,?,?,?,?,NULL)",
                (import_id, source_kind, source_origin, source_identifier, source_revision,
                 retrieved_at, source_hash, license_metadata, import_tool_version),
            )
            for index, record in enumerate(records):
                canonical = str(record.get("canonical_identifier", ""))
                record_type = str(record.get("record_type", ""))
                if not canonical or not record_type:
                    missing += 1; excluded += 1; continue
                normalized, normalized_hash = self.normalize_record(record, profile_version)
                source_record_id = hashlib.sha256(
                    f"{import_id}\0{index}\0{normalized_hash}".encode()
                ).hexdigest()
                self.connection.execute(
                    "INSERT OR IGNORE INTO source_record VALUES(?,?,?,?,?,?,?)",
                    (source_record_id, import_id, record_type, canonical, normalized_hash,
                     "VERIFIED", json.dumps({"origin": source_origin})),
                )
                existing = self.connection.execute(
                    "SELECT normalized_id FROM normalized_catalog_record WHERE "
                    "record_type=? AND (canonical_identifier=? OR normalized_content_hash=?)",
                    (record_type, canonical, normalized_hash),
                ).fetchone()
                if existing:
                    duplicates += 1
                    duplicate_id = hashlib.sha256(
                        f"{existing[0]}\0{source_record_id}".encode()
                    ).hexdigest()
                    self.connection.execute(
                        "INSERT OR IGNORE INTO catalog_duplicate VALUES(?,?,?,?,?)",
                        (duplicate_id, existing[0], source_record_id, "canonical-or-content-match", "{}"),
                    )
                else:
                    created += 1
                    self.connection.execute(
                        "INSERT INTO normalized_catalog_record VALUES(?,?,?,?,?,?,?)",
                        (normalized_hash, record_type, canonical, normalized_hash,
                         profile_version, normalized_hash, normalized),
                    )
            counts = {"retrieved": len(records), "imported": len(records)-excluded,
                      "normalized": len(records)-excluded, "canonical": created,
                      "new_canonical_record_count": created, "duplicate": duplicates,
                      "missing_required_field": missing, "excluded": excluded}
            run_hash = hashlib.sha256(json.dumps(counts, sort_keys=True).encode()).hexdigest()
            run_id = hashlib.sha256(f"{import_id}\0{profile_version}\0{run_hash}".encode()).hexdigest()
            self.connection.execute(
                "INSERT OR REPLACE INTO ingestion_run VALUES(?,?,?,?,?,?,?,?)",
                (run_id, import_id, profile_version, import_tool_version,
                 prior[0] if prior else None, retrieved_at, retrieved_at, run_hash),
            )
            self.connection.execute(
                "INSERT OR REPLACE INTO ingestion_quality_report VALUES(?,?,?,?,?,?,?)",
                (run_id+":quality", run_id, json.dumps(counts),
                 json.dumps({"VERIFIED": len(records)-excluded}),
                 json.dumps({"source_kind": source_kind}),
                 json.dumps({"missing_required_fields": excluded}), run_hash),
            )
        return {"run_id": run_id, "import_id": import_id, "counts": counts}

    def _record_import(self, source_kind: str, path: Path, record_count: int) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO catalog_import
                (source_kind, source_path, sha256, imported_at, record_count)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                source_kind,
                str(path.resolve()),
                self._sha256(path),
                datetime.now(timezone.utc).isoformat(),
                record_count,
            ),
        )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Import official NVD CVE and MITRE CWE catalogs into SQLite")
    parser.add_argument("--database", required=True, help="Target SQLite database path")
    parser.add_argument("--cwe", help="Official MITRE CWE XML catalog path")
    parser.add_argument("--nvd", action="append", default=[], help="NVD API 2.0 JSON file or export directory; repeatable")
    parser.add_argument("--batch-size", type=int, default=500, help="Reserved import batch size for compatible callers")
    args = parser.parse_args(argv)
    if not args.cwe and not args.nvd:
        parser.error("provide at least one of --cwe or --nvd")

    with CatalogImporter(args.database, args.batch_size) as importer:
        if args.cwe:
            summary = importer.import_cwe_xml(args.cwe)
            print(f"CWE imported: {summary.cwes}")
        for nvd_source in args.nvd:
            summary = importer.import_nvd(nvd_source)
            print(f"NVD imported: {summary.cves}; skipped files: {summary.skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
