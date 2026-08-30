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

from src.ecatsl.schema import install_ecatsl_schema


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
            CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id ON cve_cwe(cwe_id);
            CREATE INDEX IF NOT EXISTS idx_cvss_severity ON cvss(severity);
            """
        )
        self.connection.commit()
        install_ecatsl_schema(self.connection)

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
