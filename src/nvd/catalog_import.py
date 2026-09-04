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
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional
from uuid import uuid4

from src.ecatsl.schema import install_ecatsl_schema


IGNORED_CWE_IDS = {"NVD-CWE-noinfo", "NVD-CWE-Other", ""}
CVSS_METRIC_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

# Versioned Catalog_Import provenance defaults (Requirement 11.1). The origin
# identifies the authoritative source format and the tool version identifies the
# importer release that produced the normalized local records.
DEFAULT_SOURCE_ORIGINS = {"cwe": "mitre:cwec_xml", "nvd": "nvd:api-2.0"}
CATALOG_IMPORTER_TOOL_VERSION = "catalog-importer/1"

# Versioned deterministic source-to-normalized mapping used by IngestionService
# (Requirement 11.2-11.3): equal source content plus this profile version always
# produces equal normalized content identities.
DEFAULT_NORMALIZATION_PROFILE = "catalog-normalize/v1"


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
        self.import_tool_version = CATALOG_IMPORTER_TOOL_VERSION
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

    @staticmethod
    def _iter_cwe_weaknesses(path: Path) -> Iterator[dict[str, str]]:
        """Stream MITRE CWE ``Weakness`` records without materializing the tree.

        Yields one normalized ``{"id": "CWE-89", ...}`` dict per weakness with
        an identifier.  The parsed subtree is cleared after extraction so a full
        catalog release is never held in memory.
        """
        context = ET.iterparse(path, events=("end",))
        for _, element in context:
            # Descendant end events must not clear their elements: the
            # Description text is still needed when the enclosing Weakness
            # end event fires. Only the Weakness subtree is released, once
            # its fields have been extracted.
            if CatalogImporter._local_name(element.tag) != "Weakness":
                continue
            identifier = element.get("ID")
            record: Optional[dict[str, str]] = None
            if identifier:
                description = next(
                    (
                        CatalogImporter._text(child)
                        for child in element
                        if CatalogImporter._local_name(child.tag) == "Description"
                    ),
                    "",
                )
                record = {
                    "id": f"CWE-{identifier}",
                    "name": element.get("Name", ""),
                    "abstraction": element.get("Abstraction", ""),
                    "status": element.get("Status", ""),
                    "description": description,
                }
            element.clear()
            if record is not None:
                yield record

    def import_cwe_xml(
        self,
        source: str | Path,
        *,
        source_origin: Optional[str] = None,
        source_revision: Optional[str] = None,
        license_metadata: Optional[str] = None,
    ) -> ImportSummary:
        """Import the official MITRE CWE XML catalog using idempotent upserts.

        Records are streamed with :func:`xml.etree.ElementTree.iterparse` and
        written in bounded batches instead of holding the whole catalog in
        memory.  ``source_origin`` / ``source_revision`` / ``license_metadata``
        override the recorded versioned Catalog_Import provenance.
        """
        path = Path(source)
        origin = source_origin or DEFAULT_SOURCE_ORIGINS["cwe"]
        upsert = """
            INSERT INTO cwe (cwe_id, name, weakness_abstraction, status, description)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cwe_id) DO UPDATE SET
                name=excluded.name,
                weakness_abstraction=excluded.weakness_abstraction,
                status=excluded.status,
                description=excluded.description
        """
        count = 0
        batch: list[tuple[str, str, str, str, str]] = []
        with self.connection:
            for record in self._iter_cwe_weaknesses(path):
                batch.append(
                    (
                        record["id"],
                        record["name"],
                        record["abstraction"],
                        record["status"],
                        record["description"],
                    )
                )
                if len(batch) >= self.batch_size:
                    self.connection.executemany(upsert, batch)
                    count += len(batch)
                    batch.clear()
            if batch:
                self.connection.executemany(upsert, batch)
                count += len(batch)
            # The legacy catalog_import row is preserved unconditionally for
            # existing callers; the versioned row records real ingestions only.
            self._record_import("cwe", path, count)
            if count:
                self._record_import_version(
                    "cwe",
                    path,
                    source_origin=origin,
                    source_revision=source_revision,
                    license_metadata=license_metadata,
                )
        return ImportSummary(cwes=count)

    def import_nvd(
        self,
        source: str | Path,
        *,
        source_origin: Optional[str] = None,
        source_revision: Optional[str] = None,
        license_metadata: Optional[str] = None,
    ) -> ImportSummary:
        """Import NVD API 2.0 JSON files or a directory of exported response files.

        Directory imports stream one bounded response file at a time; records
        are upserted lazily instead of being materialized as a list.  Optional
        ``source_origin`` / ``source_revision`` / ``license_metadata`` override
        the recorded versioned Catalog_Import provenance for every file.
        """
        path = Path(source)
        origin = source_origin or DEFAULT_SOURCE_ORIGINS["nvd"]
        paths = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        imported = 0
        skipped = 0
        for json_path in paths:
            try:
                with json_path.open(encoding="utf-8") as stream:
                    document = json.load(stream)
                with self.connection:
                    file_count = 0
                    for record in self._iter_nvd_records(document):
                        self._upsert_nvd_record(record)
                        file_count += 1
                    if not file_count:
                        skipped += 1
                        continue
                    self._record_import("nvd", json_path, file_count)
                    self._record_import_version(
                        "nvd",
                        json_path,
                        source_origin=origin,
                        source_revision=source_revision,
                        license_metadata=license_metadata,
                    )
                imported += file_count
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

    def _record_import_version(
        self,
        source_kind: str,
        path: Path,
        *,
        source_origin: str,
        source_revision: Optional[str],
        license_metadata: Optional[str],
    ) -> str:
        """Append one versioned Catalog_Import row for a completed ingestion.

        The previous ingestion of the same source origin and identifier becomes
        the predecessor, forming an immutable import lineage (Requirement 11.1).
        The retrieved-content identity is the source file sha256 so later
        integrity verification can compare it against the recorded hash.
        """
        now = datetime.now(timezone.utc).isoformat()
        identifier = str(path.resolve())
        predecessor = self.connection.execute(
            """
            SELECT import_id FROM catalog_import_version
            WHERE source_kind = ? AND source_origin = ? AND source_identifier = ?
            ORDER BY created_at DESC, import_id DESC
            LIMIT 1
            """,
            (source_kind, source_origin, identifier),
        ).fetchone()
        import_id = "catalog-import:" + uuid4().hex
        self.connection.execute(
            """
            INSERT INTO catalog_import_version
                (import_id, source_kind, source_origin, source_identifier,
                 source_revision, retrieved_at, retrieved_content_hash,
                 license_metadata, import_tool_version, predecessor_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                import_id,
                source_kind,
                source_origin,
                identifier,
                source_revision,
                now,
                self._sha256(path),
                license_metadata,
                self.import_tool_version,
                predecessor[0] if predecessor is not None else None,
                now,
            ),
        )
        return import_id


@dataclass(frozen=True)
class IngestionReport:
    """Versioned data-quality report for one completed ingestion run."""

    source_kind: str
    profile_version: str
    import_id: str
    run_id: str
    report_id: str
    content_hash: str
    latency_ms: int
    peak_batch_size: int
    counts: dict[str, int]
    integrity: dict[str, int]
    coverage: dict[str, Any]
    exclusions: list[dict[str, Any]] = field(default_factory=list)


_CWE_UPSERT_SQL = """
    INSERT INTO cwe (cwe_id, name, weakness_abstraction, status, description)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(cwe_id) DO UPDATE SET
        name=excluded.name,
        weakness_abstraction=excluded.weakness_abstraction,
        status=excluded.status,
        description=excluded.description
"""


class IngestionService:
    """Deterministic normalization, deduplication and data-quality telemetry.

    Runs against the SQLite connection of a :class:`CatalogImporter`; source
    parsing and the canonical catalog upserts are delegated to that importer
    (reuse-first).  The service appends the versioned source-record,
    normalized-record, canonical/duplicate, ingestion-run, and quality-report
    rows and reports (Requirements 9.4-9.7, 11.2-11.7).

    Identity and decision rules
    ---------------------------
    * ``source_record.record_id`` is content-addressed over (record type, source
      identifier, source content hash): re-ingesting an unchanged record never
      creates a new row (Requirement 11.6).
    * ``normalized_catalog_record.normalized_id`` is content-addressed over
      (profile version, record type, canonical identifier, normalized content
      hash): equal source content plus the same profile yields one normalized
      record with one normalized content identity (Requirement 11.3).
    * Duplicate source records (equal canonical identifier/type or equal
      normalized content identity/type) are retained as ``catalog_duplicate``
      decisions against the canonical normalized record (Requirement 11.4).
      Content-changed records for an existing identifier append a new canonical
      normalized version instead.
    * Records commit in bounded batches; an interrupted run resumes by replay,
      because every row identity is deterministic and a run is only terminal
      once its ``ingestion_run`` row is written.
    """

    def __init__(
        self,
        importer: CatalogImporter,
        *,
        profile_version: str = DEFAULT_NORMALIZATION_PROFILE,
        batch_size: Optional[int] = None,
    ) -> None:
        self.importer = importer
        self.connection = importer.connection
        self.profile_version = profile_version
        self.batch_size = max(1, batch_size or importer.batch_size)

    # ------------------------------------------------------------------ public

    def ingest_cwe_xml(
        self,
        source: str | Path,
        *,
        expected_content_hash: Optional[str] = None,
        source_origin: Optional[str] = None,
        source_revision: Optional[str] = None,
        license_metadata: Optional[str] = None,
    ) -> IngestionReport:
        """Run the deterministic ingestion pipeline over one MITRE CWE XML file."""
        path = Path(source)
        return self._ingest_source(
            source_kind="cwe",
            path=path,
            source_origin=source_origin or DEFAULT_SOURCE_ORIGINS["cwe"],
            source_revision=source_revision,
            license_metadata=license_metadata,
            expected_content_hash=expected_content_hash,
            raw_records=self.importer._iter_cwe_weaknesses(path),
            extract=self._extract_cwe_record,
            persist_base=self._persist_cwe_base,
        )

    def ingest_nvd(
        self,
        source: str | Path,
        *,
        expected_content_hash: Optional[str] = None,
        source_origin: Optional[str] = None,
        source_revision: Optional[str] = None,
        license_metadata: Optional[str] = None,
    ) -> list[IngestionReport]:
        """Run the deterministic ingestion pipeline over NVD JSON input.

        A directory is ingested one bounded response file at a time and one
        report is returned per file.
        """
        path = Path(source)
        paths = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        reports: list[IngestionReport] = []
        for json_path in paths:
            try:
                with json_path.open(encoding="utf-8") as stream:
                    document = json.load(stream)
            except (OSError, ValueError):
                continue
            reports.append(
                self._ingest_source(
                    source_kind="nvd",
                    path=json_path,
                    source_origin=source_origin or DEFAULT_SOURCE_ORIGINS["nvd"],
                    source_revision=source_revision,
                    license_metadata=license_metadata,
                    expected_content_hash=expected_content_hash,
                    raw_records=self.importer._iter_nvd_records(document),
                    extract=self._extract_nvd_record,
                    persist_base=self._persist_nvd_base,
                )
            )
        return reports

    # --------------------------------------------------------------- internals

    @staticmethod
    def _sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def _normalized_content_hash(
        cls, profile_version: str, payload: dict[str, Any]
    ) -> str:
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return cls._sha256_text(profile_version + "\n" + canonical)

    @staticmethod
    def _cwe_normalized_payload(record: dict[str, str]) -> dict[str, Any]:
        return {
            key: record[key]
            for key in ("id", "name", "abstraction", "status", "description")
        }

    @staticmethod
    def _nvd_normalized_payload(record: dict[str, Any]) -> dict[str, Any]:
        cvss = CatalogImporter._cvss(record)
        return {
            "id": record.get("id"),
            "description": CatalogImporter._description(record),
            "published": record.get("published"),
            "last_modified": record.get("lastModified"),
            "cwes": CatalogImporter._cwe_ids(record),
            "cvss": (
                {
                    "score": cvss[0],
                    "severity": cvss[1],
                    "vector": cvss[2],
                    "version": cvss[3],
                }
                if cvss is not None
                else None
            ),
        }

    @staticmethod
    def _extract_cwe_record(
        raw: dict[str, str],
    ) -> Optional[tuple[str, str, str, str, dict[str, Any]]]:
        payload = IngestionService._cwe_normalized_payload(raw)
        identifier = payload["id"]
        raw_text = json.dumps(
            raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return ("CWE", identifier, identifier, raw_text, payload)

    @staticmethod
    def _extract_nvd_record(
        raw: dict[str, Any],
    ) -> Optional[tuple[str, str, str, str, dict[str, Any]]]:
        cve_id = raw.get("id") if isinstance(raw, dict) else None
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            return None
        payload = IngestionService._nvd_normalized_payload(raw)
        raw_text = json.dumps(
            raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return ("CVE", cve_id, cve_id, raw_text, payload)

    @staticmethod
    def _persist_cwe_base(
        connection: sqlite3.Connection,
        raw: dict[str, str],
        payload: dict[str, Any],
    ) -> None:
        connection.execute(
            _CWE_UPSERT_SQL,
            (
                payload["id"],
                payload["name"],
                payload["abstraction"],
                payload["status"],
                payload["description"],
            ),
        )

    @staticmethod
    def _persist_nvd_base(
        connection: sqlite3.Connection,
        raw: dict[str, Any],
        payload: dict[str, Any],
    ) -> None:
        # Base upserts write raw catalog rows; the normalized payload identifies
        # the record but the raw document carries the authoritative fields.
        connection.execute(
            """
            INSERT INTO cve (cve_id, description, published_date, last_modified)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                published_date=excluded.published_date,
                last_modified=excluded.last_modified
            """,
            (
                payload["id"],
                payload["description"],
                payload["published"],
                payload["last_modified"],
            ),
        )
        cvss = payload["cvss"]
        if cvss is not None:
            connection.execute(
                """
                INSERT INTO cvss (cve_id, score, severity, vector, version)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    score=excluded.score, severity=excluded.severity,
                    vector=excluded.vector, version=excluded.version
                """,
                (
                    payload["id"],
                    cvss["score"],
                    cvss["severity"],
                    cvss["vector"],
                    cvss["version"],
                ),
            )
        connection.execute("DELETE FROM cve_cwe WHERE cve_id = ?", (payload["id"],))
        for index, cwe_id in enumerate(payload["cwes"]):
            connection.execute("INSERT OR IGNORE INTO cwe (cwe_id) VALUES (?)", (cwe_id,))
            connection.execute(
                "INSERT INTO cve_cwe (cve_id, cwe_id, is_primary) VALUES (?, ?, ?)",
                (payload["id"], cwe_id, int(index == 0)),
            )

    @staticmethod
    def _append_exclusion(
        exclusions: list[dict[str, Any]], reason: str, identifier: str
    ) -> None:
        for item in exclusions:
            if item["reason"] == reason:
                item["identifiers"].append(identifier)
                return
        exclusions.append({"reason": reason, "identifiers": [identifier]})

    def _ingest_source(
        self,
        source_kind: str,
        path: Path,
        *,
        source_origin: str,
        source_revision: Optional[str],
        license_metadata: Optional[str],
        expected_content_hash: Optional[str],
        raw_records: Iterator[dict[str, Any]],
        extract: Callable[[dict[str, Any]], Optional[tuple[str, str, str, str, dict[str, Any]]]],
        persist_base: Callable[[sqlite3.Connection, dict[str, Any], dict[str, Any]], None],
    ) -> IngestionReport:
        started = time.perf_counter()
        conn = self.connection
        file_hash = self.importer._sha256(path)
        integrity_ok = expected_content_hash is None or expected_content_hash == file_hash
        integrity_status = "VERIFIED" if integrity_ok else "FAILED"
        counts = {
            "retrieved": 0,
            "imported": 0,
            "normalized": 0,
            "new_canonical": 0,
            "duplicate": 0,
            "unchanged": 0,
            "missing_required_field": 0,
            "integrity_failed": 0,
            "excluded": 0,
        }
        integrity = {
            "checked": 1,
            "verified": int(integrity_ok),
            "failed": int(not integrity_ok),
        }
        if not integrity_ok:
            counts["integrity_failed"] = 1
        exclusions: list[dict[str, Any]] = []
        canonical_identifiers: set[str] = set()

        import_id = self.importer._record_import_version(
            source_kind,
            path,
            source_origin=source_origin,
            source_revision=source_revision,
            license_metadata=license_metadata,
        )
        conn.commit()

        pending = 0
        peak_batch = 0
        for raw in raw_records:
            parsed = extract(raw)
            if parsed is None:
                counts["excluded"] += 1
                self._append_exclusion(exclusions, "invalid_source_record", "")
                continue
            record_type, source_identifier, canonical_identifier, raw_text, payload = parsed
            counts["retrieved"] += 1
            if not payload.get("description"):
                # Present but incomplete records are counted and still imported;
                # only unparseable records are excluded.
                counts["missing_required_field"] += 1
            content_hash = self._sha256_text(raw_text)
            # Incremental selection: records already ingested with the same
            # source identifier and content are skipped (Requirement 11.6-11.7).
            existing = conn.execute(
                """
                SELECT record_id FROM source_record
                WHERE record_type = ? AND source_identifier = ? AND source_content_hash = ?
                """,
                (record_type, source_identifier, content_hash),
            ).fetchone()
            if existing is not None:
                counts["unchanged"] += 1
                continue

            normalized_hash = self._normalized_content_hash(self.profile_version, payload)
            normalized_id = "normalized:" + self._sha256_text(
                "\0".join(
                    (self.profile_version, record_type, canonical_identifier, normalized_hash)
                )
            )
            source_record_id = "source:" + self._sha256_text(
                "\0".join((record_type, source_identifier, content_hash))
            )
            current_canonical = conn.execute(
                """
                SELECT normalized_id, normalized_content_hash
                FROM normalized_catalog_record
                WHERE record_type = ? AND canonical_identifier = ?
                  AND canonical_id IS NULL
                ORDER BY rowid DESC LIMIT 1
                """,
                (record_type, canonical_identifier),
            ).fetchone()
            same_content_canonical = conn.execute(
                """
                SELECT normalized_id FROM normalized_catalog_record
                WHERE record_type = ? AND normalized_content_hash = ?
                  AND canonical_id IS NULL
                ORDER BY rowid DESC LIMIT 1
                """,
                (record_type, normalized_hash),
            ).fetchone()
            conn.execute(
                """
                INSERT OR IGNORE INTO source_record
                    (record_id, import_id, record_type, source_identifier,
                     source_content_hash, raw_reference, integrity_status,
                     provenance_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_record_id,
                    import_id,
                    record_type,
                    source_identifier,
                    content_hash,
                    str(path.resolve()),
                    integrity_status,
                    json.dumps(
                        {
                            "canonical_identifier": canonical_identifier,
                            "profile_version": self.profile_version,
                            "import_id": import_id,
                            "source_origin": source_origin,
                            "source_revision": source_revision,
                        },
                        sort_keys=True,
                    ),
                ),
            )
            if current_canonical is not None and str(current_canonical[1]) == normalized_hash:
                reason = "duplicate_canonical_identifier"
                canonical_id: Optional[str] = str(current_canonical[0])
            elif same_content_canonical is not None:
                reason = "duplicate_normalized_content"
                canonical_id = str(same_content_canonical[0])
            else:
                reason = ""
                canonical_id = None
            if canonical_id is None:
                # New canonical normalized version for this canonical identifier.
                conn.execute(
                    """
                    INSERT OR IGNORE INTO normalized_catalog_record
                        (normalized_id, record_type, canonical_identifier,
                         normalized_content_hash, normalization_profile_version,
                         canonical_id, provenance_json)
                    VALUES (?, ?, ?, ?, ?, NULL, ?)
                    """,
                    (
                        normalized_id,
                        record_type,
                        canonical_identifier,
                        normalized_hash,
                        self.profile_version,
                        json.dumps(
                            {
                                "source_record_id": source_record_id,
                                "import_id": import_id,
                                "profile_version": self.profile_version,
                            },
                            sort_keys=True,
                        ),
                    ),
                )
                counts["normalized"] += 1
                counts["new_canonical"] += 1
            else:
                conn.execute(
                    """
                    INSERT INTO catalog_duplicate
                        (duplicate_id, canonical_id, source_record_id, reason,
                         decision_provenance_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "catalog-duplicate:" + uuid4().hex,
                        canonical_id,
                        source_record_id,
                        reason,
                        json.dumps(
                            {
                                "record_type": record_type,
                                "canonical_identifier": canonical_identifier,
                                "normalized_content_hash": normalized_hash,
                                "profile_version": self.profile_version,
                                "import_id": import_id,
                            },
                            sort_keys=True,
                        ),
                    ),
                )
                counts["duplicate"] += 1
            persist_base(conn, raw, payload)
            counts["imported"] += 1
            canonical_identifiers.add(canonical_identifier)
            pending += 1
            if pending >= self.batch_size:
                conn.commit()
                peak_batch = max(peak_batch, pending)
                pending = 0
        if pending:
            conn.commit()
            peak_batch = max(peak_batch, pending)

        coverage = {
            "source_kind": source_kind,
            "source_origin": source_origin,
            "source_identifier": str(path.resolve()),
            "source_content_hash": file_hash,
            "records": counts["retrieved"],
            "canonical_identifiers": len(canonical_identifiers),
        }
        report_payload = {
            "counts": counts,
            "integrity": integrity,
            "coverage": coverage,
            "exclusions": exclusions,
        }
        report_hash = self._sha256_text(
            json.dumps(report_payload, sort_keys=True, separators=(",", ":"))
        )
        run_id = "ingestion-run:" + uuid4().hex
        report_id = "quality-report:" + uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        prior_run = conn.execute(
            """
            SELECT run.run_id FROM ingestion_run AS run
            JOIN catalog_import_version AS import
              ON import.import_id = run.import_id
            WHERE import.source_kind = ? AND import.source_origin = ?
              AND import.source_identifier = ?
            ORDER BY run.completed_at DESC, run.run_id DESC LIMIT 1
            """,
            (source_kind, source_origin, str(path.resolve())),
        ).fetchone()
        conn.execute(
            """
            INSERT INTO ingestion_run
                (run_id, import_id, profile_version, import_tool_version,
                 prior_run_id, started_at, completed_at, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                import_id,
                self.profile_version,
                self.importer.import_tool_version,
                prior_run[0] if prior_run is not None else None,
                datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
                now,
                file_hash,
            ),
        )
        conn.execute(
            """
            INSERT INTO ingestion_quality_report
                (report_id, run_id, counts_json, integrity_json,
                 coverage_json, exclusions_json, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                run_id,
                json.dumps(counts, sort_keys=True),
                json.dumps(integrity, sort_keys=True),
                json.dumps(coverage, sort_keys=True),
                json.dumps(exclusions, sort_keys=True),
                report_hash,
            ),
        )
        conn.commit()
        latency_ms = int((time.perf_counter() - started) * 1000)
        return IngestionReport(
            source_kind=source_kind,
            profile_version=self.profile_version,
            import_id=import_id,
            run_id=run_id,
            report_id=report_id,
            content_hash=report_hash,
            latency_ms=latency_ms,
            peak_batch_size=peak_batch,
            counts=counts,
            integrity=integrity,
            coverage=coverage,
            exclusions=exclusions,
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
