"""Concrete provider wiring for the ECATSL service (Task 6.5).

Covers Requirements 1.5-1.7, 4.3, 6.1-6.3 and 11.8-11.13: the local SQLite
catalog feeds the service template-provider port in deterministic ranking
order, generic repository discovery feeds the discovery port, failures stay
isolated and audited, and catalog/discovery-assisted hypotheses never become
proof or confirm findings without a supported static path.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.ecatsl.discovery import RepositoryDiscovery
from src.ecatsl.models import Provenance
from src.ecatsl.scope import INITIAL_CWES, initial_scope
from src.ecatsl.service import (
    AnalysisRequest,
    ECATSLService,
    build_sqlite_template_provider,
)
from src.ecatsl.artifact_repository import ArtifactRepository
from src.ecatsl.candidate_ledger import CandidateLedger
from src.ecatsl.models import (
    AcceptancePolicy,
    Attribute,
    ValidationPolicy,
)
from src.nvd.catalog_import import CatalogImporter

NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)
FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "baseline"


def _prov(label: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=label,
        source_revision="v1",
        content_identity=label,
    )


@pytest.fixture
def catalog_database(tmp_path) -> Path:
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        importer.import_cwe_xml(FIXTURES / "mitre_cwe.xml")
        importer.import_nvd(FIXTURES / "nvd_cve.json")
        importer.connection.execute(
            """
            INSERT INTO taint_template
                (template_id, cwe_id, role, api_shape, parameter_shape,
                 applicability_json, semantic_features_json, template_version,
                 provenance_json)
            VALUES
                ('t-89-first', 'CWE-89', 'SOURCE', 'cursor.execute(query)', '[0]',
                 '{"language": "python"}', '["sql", "query"]', 'v1', '{}'),
                ('t-89-second', 'CWE-89', 'SINK', 'conn.commit()', '[]',
                 '{"language": "python"}', '["sql"]', 'v1', '{}'),
                ('t-78', 'CWE-78', 'SOURCE', 'os.system(cmd)', '[0]',
                 '{"language": "java"}', '["command"]', 'v1', '{}')
            """
        )
        importer.connection.commit()
    return database


def _repository(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import helpers\n"
        "\n"
        "@app.route('/login')\n"
        "def login(request):\n"
        "    return helpers.query(request)\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    login(None)\n"
    )
    (tmp_path / "helpers.py").write_text("def query(request):\n    return request\n")
    return tmp_path


def _service(tmp_path: Path, *, discovery, template_provider) -> ECATSLService:
    database = tmp_path / "service-artifacts.db"
    repository = ArtifactRepository(database)
    ledger = CandidateLedger(repository)
    return ECATSLService(
        scope=initial_scope(created_at=NOW, provenance=_prov("scope")),
        provenance=_prov("service"),
        repository=repository,
        ledger=ledger,
        acceptance_policy=AcceptancePolicy(
            version="1",
            created_at=NOW,
            provenance=_prov("acceptance"),
            conditions=("independent_evidence",),
        ),
        validation_policy=ValidationPolicy(
            version="1",
            created_at=NOW,
            provenance=_prov("validation"),
            result_mappings=(
                Attribute(name="COMPLETE_PATH", value="PRESERVE"),
                Attribute(name="NO_PATH", value="UNACCEPT"),
                Attribute(name="*", value="UNACCEPT"),
            ),
        ),
        discovery=discovery,
        template_provider=template_provider,
    )


def test_sqlite_template_provider_preserves_ranking_order_and_scope(
    catalog_database,
):
    provider = build_sqlite_template_provider(
        str(catalog_database), scope_cwe_ids=INITIAL_CWES
    )
    templates = provider(("CWE-89",))
    # Exact-weakness templates rank first (relevance 1.0); semantically related
    # in-scope templates follow in deterministic order.
    assert [template.cwe_id for template in templates][:2] == ["CWE-89", "CWE-89"]
    assert templates[0].api_shape == "cursor.execute(query)"
    assert templates[-1].api_shape == "os.system(cmd)"
    # The java-language CWE-78 template is in scope but is only requested for
    # its own weakness identifier, where it ranks first.
    templates_78 = provider(("CWE-78",))
    assert templates_78[0].api_shape == "os.system(cmd)"
    # Out-of-scope requests never reach the catalog.
    assert provider(("CWE-22",)) == ()

    for template in (*templates, *templates_78):
        assert template.confirmatory is False
        assert template.provenance.origin == "local-sqlite-catalog"

    with sqlite3.connect(catalog_database) as connection:
        rows = connection.execute(
            "SELECT COUNT(*) FROM template_retrieval WHERE cwe_id = 'CWE-89'"
        ).fetchone()
    assert rows[0] == 1  # repeated identical queries are idempotent
    provider(("CWE-89",))
    with sqlite3.connect(catalog_database) as connection:
        rows = connection.execute(
            "SELECT COUNT(*) FROM template_retrieval WHERE cwe_id = 'CWE-89'"
        ).fetchone()
    assert rows[0] == 1


def test_wired_providers_produce_nonconfirmatory_hypotheses_without_confirming(
    tmp_path, catalog_database
):
    repo = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    provider = build_sqlite_template_provider(
        str(catalog_database), scope_cwe_ids=INITIAL_CWES
    )
    service = _service(tmp_path, discovery=discovery, template_provider=provider)
    result = service.analyze(
        AnalysisRequest(repository_ref=str(repo), language="python", cwe_ids=("CWE-89",))
    )

    assert result.status == "COMPLETE"
    assert result.audit_failures == ()
    assert result.hypotheses, "wired providers must produce hypotheses"
    assert all(item.confirmatory is False for item in result.hypotheses)
    assert all(item.ranking_score > 0.0 for item in result.hypotheses)
    # Every hypothesis retains both a discovery and a catalog input identity.
    assert all(len(item.evidence_ids) == 2 for item in result.hypotheses)
    # No static adapter is configured: nothing may be confirmed.
    assert result.findings
    assert all(finding.status == "UNCONFIRMED" for finding in result.findings)
    # Discovery telemetry from the wired concrete provider is available.
    assert discovery.last_telemetry is not None
    assert discovery.last_telemetry.parsed == 2


def test_template_provider_failure_is_isolated_and_audited(tmp_path, catalog_database):
    repo = _repository(tmp_path)
    calls = {"count": 0}

    def failing_provider(cwe_ids):
        calls["count"] += 1
        raise RuntimeError("catalog outage")

    service = _service(
        tmp_path, discovery=RepositoryDiscovery(), template_provider=failing_provider
    )
    result = service.analyze(
        AnalysisRequest(repository_ref=str(repo), language="python", cwe_ids=("CWE-89",))
    )
    assert calls["count"] == 1
    assert result.status == "COMPLETE"
    assert any(
        failure.operation == "template_retrieval"
        for failure in result.audit_failures
    )
    # Discovery observations still persist and hypotheses stay empty but safe.
    assert result.hypotheses == ()
    assert all(finding.status == "UNCONFIRMED" for finding in result.findings)


def test_out_of_scope_request_short_circuits_before_providers(tmp_path, catalog_database):
    calls = {"templates": 0, "discover": 0}

    class CountingDiscovery(RepositoryDiscovery):
        def discover(self, root, provenance):
            calls["discover"] += 1
            return super().discover(root, provenance)

    def counting_provider(cwe_ids):
        calls["templates"] += 1
        return ()

    service = _service(
        tmp_path,
        discovery=CountingDiscovery(),
        template_provider=counting_provider,
    )
    result = service.analyze(
        AnalysisRequest(repository_ref=str(tmp_path), language="python", cwe_ids=("CWE-22",))
    )
    assert result.status == "OUT_OF_SCOPE"
    assert calls["templates"] == 0
    assert calls["discover"] == 0
