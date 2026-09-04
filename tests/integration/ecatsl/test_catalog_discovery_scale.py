"""Realistic-scale catalog ingestion and generic discovery integration (Task 6.6).

Exercises populated-schema migration, repeated and changed-only imports,
duplicate canonicalization, interrupted batch resume, stable ranking, cache
compatibility, bounded batch behavior, and complete quality telemetry over a
generated multi-thousand-record catalog; then generic code/config/import-graph
discovery across multiple repository shapes without route configuration, with
literal user-maintained route enumeration rejected and every hypothesis
unconfirmed without a static path.

_Requirements: 9.3-9.7, 11.1-11.13_
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.ecatsl.confirmation import FindingConfirmationService
from src.ecatsl.discovery import DiscoveryPolicy, RepositoryDiscovery
from src.ecatsl.models import DiscoveryStrategy, FindingStatus, Provenance
from src.nvd.catalog_import import CatalogImporter, IngestionService
from src.nvd.nvd_query_adapter import NVDQueryAdapter, TaintTemplateRepository

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)
SEED = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "catalog" / "catalog_seed.json"
WEAKNESS_CYCLE = ("CWE-89", "CWE-78", "CWE-918")
TOTAL_RECORDS = 1500
PER_FILE = 500


def _prov(label: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=label,
        source_revision="scale-v1",
        content_identity=label,
    )


def _record(index: int, changed: bool = False) -> dict:
    cve_id = f"CVE-2025-{index:05d}"
    weakness = WEAKNESS_CYCLE[index % len(WEAKNESS_CYCLE)]
    description = f"Scale record {index} exercising {weakness} patterns."
    if changed:
        description += " Changed revision."
    return {
        "cve": {
            "id": cve_id,
            "published": "2025-06-01T00:00:00.000Z",
            "lastModified": "2025-06-02T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": description}],
            "weaknesses": [{"description": [{"lang": "en", "value": weakness}]}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 5.0 + (index % 50) / 10,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ]
            },
        }
    }


def _write_release(directory: Path, *, change_from: int | None = None) -> None:
    for file_index in range(TOTAL_RECORDS // PER_FILE):
        document = {"vulnerabilities": []}
        for offset in range(PER_FILE):
            index = file_index * PER_FILE + offset
            changed = change_from is not None and index >= change_from
            document["vulnerabilities"].append(_record(index, changed=changed))
        path = directory / f"release-{file_index}.json"
        path.write_text(json.dumps(document))


def _count(connection: sqlite3.Connection, sql: str, params=()) -> int:
    return connection.execute(sql, params).fetchone()[0]


def _interrupted_service(importer: CatalogImporter, interrupt_after: int) -> IngestionService:
    """Wrap IngestionService so record persistence fails after N records."""
    service = IngestionService(importer)
    state = {"processed": 0}

    def persist_base(connection, raw, payload):
        state["processed"] += 1
        if state["processed"] > interrupt_after:
            raise KeyboardInterrupt("simulated mid-batch interruption")
        IngestionService._persist_nvd_base(connection, raw, payload)

    service._persist_nvd_base = persist_base  # type: ignore[method-assign]
    return service


def test_scale_seed_fixture_shape_is_valid(tmp_path):
    """The committed fixture documents the generated record shape."""
    document = json.loads(SEED.read_text())
    assert document["description"].startswith("Seed catalog records")
    assert len(document["vulnerabilities"]) == 2
    with CatalogImporter(tmp_path / "catalog.db") as importer:
        summary = importer.import_nvd(SEED)
        assert summary.cves == 2


def test_scale_ingestion_reports_telemetry_and_supports_replay_and_change_only(
    tmp_path,
):
    release = tmp_path / "release"
    release.mkdir()
    _write_release(release)

    with CatalogImporter(tmp_path / "catalog.db", batch_size=250) as importer:
        for path in sorted(release.glob("release-*.json")):
            summary = importer.import_nvd(path)
            assert summary.cves == PER_FILE
        # Cache compatibility: the pre-ECATSL query path stays intact at scale.
        adapter = NVDQueryAdapter(str(tmp_path / "catalog.db"), use_cache=False)
        try:
            assert adapter.get_all_cwe_ids() == ["CWE-78", "CWE-89", "CWE-918"]
            assert len(adapter.search_vulnerabilities("CWE-89", None, 5)) == 5
        finally:
            adapter._disconnect()

        service = IngestionService(importer, batch_size=250)
        reports = service.ingest_nvd(release)
        assert len(reports) == 3
        assert sum(report.counts["retrieved"] for report in reports) == TOTAL_RECORDS
        assert sum(report.counts["new_canonical"] for report in reports) == TOTAL_RECORDS
        # Bounded batches: every report commits at the configured batch size.
        assert all(report.peak_batch_size == 250 for report in reports)
        for report in reports:
            stored = importer.connection.execute(
                "SELECT counts_json, coverage_json FROM ingestion_quality_report "
                "WHERE report_id = ?",
                (report.report_id,),
            ).fetchone()
            assert stored is not None
            assert json.loads(stored[0])["imported"] == report.counts["imported"]
            assert json.loads(stored[1])["records"] == PER_FILE

        # Identical replay is zero-new across the whole release.
        replay = service.ingest_nvd(release)
        assert sum(item.counts["new_canonical"] for item in replay) == 0
        assert sum(item.counts["unchanged"] for item in replay) == TOTAL_RECORDS

        # Changed-only selection: only records at or after the change point are
        # re-ingested; everything before stays unchanged.
        _write_release(release, change_from=1200)
        incremental = service.ingest_nvd(release)
        assert sum(item.counts["new_canonical"] for item in incremental) == 300
        assert sum(item.counts["unchanged"] for item in incremental) == 1200

        # Duplicate canonicalization: equal payload under a distinct raw body is
        # retained as a duplicate source, not a second canonical record.
        duplicate = release / "duplicate.json"
        duplicate.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": dict(
                                _record(0)["cve"],
                                references=[{"url": "https://scale.test/ref"}],
                            )
                        }
                    ]
                }
            )
        )
        duplicate_report = service.ingest_nvd(duplicate)[0]
        assert duplicate_report.counts["duplicate"] == 1
        assert duplicate_report.counts["new_canonical"] == 0
        # Append-only version history: 1500 originals + 300 changed revisions.
        assert _count(
            importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record"
        ) == TOTAL_RECORDS + 300
        assert _count(importer.connection, "SELECT COUNT(*) FROM catalog_duplicate") == 1

        # Stable ranking over the populated catalog.
        importer.connection.execute(
            """
            INSERT INTO taint_template
                (template_id, cwe_id, role, api_shape, parameter_shape,
                 applicability_json, semantic_features_json, template_version,
                 provenance_json)
            VALUES
                ('scale-89-a', 'CWE-89', 'SOURCE', 'cursor.execute(q)', '[0]',
                 '{"language": "python"}', '["sql"]', 'v1', '{}'),
                ('scale-89-b', 'CWE-89', 'SINK', 'conn.commit()', '[]',
                 '{"language": "python"}', '["sql"]', 'v1', '{}'),
                ('scale-78', 'CWE-78', 'SOURCE', 'os.system(c)', '[0]',
                 '{"language": "python"}', '["command"]', 'v1', '{}')
            """
        )
        importer.connection.commit()
        repository = TaintTemplateRepository(str(tmp_path / "catalog.db"))
        try:
            first = repository.retrieve("CWE-89")
            second = repository.retrieve("CWE-89")
            assert first.template_ids == second.template_ids
            assert set(first.template_ids) == {"scale-89-a", "scale-89-b", "scale-78"}
            assert first.template_ids[0].startswith("scale-89-")
        finally:
            repository.close()


def test_scale_interrupted_batch_resume_is_idempotent(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    _write_release(release)

    with CatalogImporter(tmp_path / "catalog.db", batch_size=120) as importer:
        service = IngestionService(importer, batch_size=120)
        broken = _interrupted_service(importer, interrupt_after=200)
        with pytest.raises(KeyboardInterrupt):
            broken.ingest_nvd(release / "release-0.json")
        # A partially committed run left durable rows but no ingestion_run.
        partial_canonical = _count(
            importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record"
        )
        assert 0 < partial_canonical < PER_FILE
        assert _count(importer.connection, "SELECT COUNT(*) FROM ingestion_run") == 0

        # Resume by replaying the same source: previously committed records are
        # skipped as unchanged and the remainder completes the run.
        resumed = service.ingest_nvd(release / "release-0.json")[0]
        assert resumed.counts["new_canonical"] == PER_FILE - partial_canonical
        assert resumed.counts["unchanged"] == partial_canonical
        assert _count(
            importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record"
        ) == PER_FILE
        assert _count(importer.connection, "SELECT COUNT(*) FROM ingestion_run") == 1

        # The remaining release files complete normally.
        rest = service.ingest_nvd(release)
        assert sum(item.counts["new_canonical"] for item in rest) == 1000
        assert _count(
            importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record"
        ) == TOTAL_RECORDS


def _shape_flat(tmp_path: Path) -> Path:
    root = tmp_path / "flat"
    root.mkdir()
    (root / "server.py").write_text(
        "import json\n"
        "\n"
        "@app.route('/items')\n"
        "def list_items(request):\n"
        "    return json.dumps([])\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    list_items(None)\n"
    )
    return root


def _shape_package(tmp_path: Path) -> Path:
    root = tmp_path / "packaged"
    (root / "pkg" / "sub").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("FLAG = 1\n")
    (root / "pkg" / "sub" / "api.py").write_text(
        "from .. import FLAG\n"
        "\n"
        "def create_item(payload):\n"
        "    return FLAG and payload\n"
    )
    (root / "config.json").write_text(
        json.dumps({"api_path": "/api/v2", "database": "x"})
    )
    return root


def _shape_config_only(tmp_path: Path) -> Path:
    root = tmp_path / "config-only"
    root.mkdir()
    (root / "settings.ini").write_text("url_prefix = https://scale.test\n")
    (root / "deploy.env").write_text("entrypoint=worker.main\n")
    return root


def test_scale_discovery_across_repository_shapes_without_route_configuration(
    tmp_path,
):
    discovery = RepositoryDiscovery()
    shapes = [
        _shape_flat(tmp_path),
        _shape_package(tmp_path),
        _shape_config_only(tmp_path),
    ]
    service = FindingConfirmationService()
    for shape in shapes:
        observations = discovery.discover(str(shape), _prov(shape.name))
        assert observations, f"shape {shape.name} must yield observations"
        telemetry = discovery.last_telemetry
        assert telemetry is not None
        assert telemetry.parsed > 0
        assert telemetry.invalid == 0
        assert telemetry.failed == 0
        for observation in observations:
            assert observation.confirmatory is False
        hypotheses = discovery.rank(observations, (), _prov("ranking"))
        assert hypotheses == ()  # no templates -> no hypotheses, still safe
        # Without a static path nothing from discovery can be confirmed.
        classification = service.classify(
            provenance=_prov("finding"),
            path=None,
            candidate_record_ids=(f"candidate:{shape.name}",),
        )
        assert classification.status is FindingStatus.UNCONFIRMED

    # The config-only shape still surfaces endpoint keys, not a route list.
    config_observations = discovery.discover(str(shapes[2]), _prov("config-only"))
    values = {
        attribute.value
        for observation in config_observations
        for attribute in observation.context
        if attribute.name == "values"
    }
    joined = ",".join(values)
    assert "https://scale.test" in joined
    assert "worker.main" in joined


def test_scale_rejects_literal_user_maintained_route_enumeration():
    policy = DiscoveryPolicy()
    strategy = DiscoveryStrategy(
        version="1",
        created_at=NOW,
        provenance=_prov("strategy"),
        strategy_kind="route-list",
        evidence_inputs=("/login", "/logout", "/items"),
        enumerates_individual_routes=True,
        hard_coded=True,
        generalizes_across_evidence=False,
        requires_user_route_maintenance=True,
    )
    allowed, reason = policy.validate(strategy)
    assert allowed is False
    assert "per-route" in reason
