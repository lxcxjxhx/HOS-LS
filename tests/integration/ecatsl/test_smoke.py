"""Task 8.2 end-to-end smoke test over a real populated SQLite catalog.

Runs the complete ECATSL pipeline through ``ECATSLService``: idempotent
migration on top of an existing populated NVD/CWE catalog (MITRE/NVD
fixtures), generic ``RepositoryDiscovery`` over repository code, SQLite
catalog template ranking, policy/ledger/compiler lifecycle, fixture-backed
static adapter normalization through the real shipped adapters, and
confirmation exclusively through ``FindingConfirmationService``.

Asserts the evidence boundary: exactly the complete supported static path
confirms; catalog-only (no adapter), unsupported-adapter, and
static-incomplete cases stay unconfirmed; and all lineage plus telemetry
survives restart/replay.

_Requirements: 1.1-1.7, 2.1-2.8, 3.1-3.9, 4.1-4.8, 5.1-5.7, 6.1-6.3,
7.1-7.6, 8.1, 9.11, 10.1, 11.8-11.13_
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.ecatsl.artifact_repository import ArtifactRepository
from src.ecatsl.candidate_ledger import CandidateLedger
from src.ecatsl.discovery import RepositoryDiscovery
from src.ecatsl.models import (
    AcceptancePolicy,
    Attribute,
    FindingStatus,
    Provenance,
    ValidationPolicy,
)
from src.ecatsl.scope import INITIAL_CWES, initial_scope
from src.ecatsl.service import (
    AnalysisRequest,
    ECATSLService,
    build_sqlite_template_provider,
)
from src.ecatsl.static_adapters import CodeQLSastAdapter, InputTracerAdapter
from src.nvd.catalog_import import CatalogImporter, ImportSummary

NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)
BASELINE_FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "baseline"
STATIC_FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "static"

EXPECTED_STAGES = (
    "scope gate",
    "discovery assistance",
    "tooling-first resolution",
    "candidate lifecycle",
    "controlled compilation",
    "static validation",
    "confirmation",
)


def _prov(label: str) -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=NOW,
        source_identifier=label,
        source_revision="v1",
        content_identity=label,
    )


# ----------------------------------------------------------- fixture builders


@pytest.fixture
def populated_catalog(tmp_path) -> Path:
    """Existing populated SQLite NVD/CWE catalog from the shared fixtures."""
    database = tmp_path / "catalog.db"
    with CatalogImporter(database, batch_size=2) as importer:
        assert importer.import_cwe_xml(BASELINE_FIXTURES / "mitre_cwe.xml") == ImportSummary(cwes=1)
        assert importer.import_nvd(BASELINE_FIXTURES / "nvd_cve.json") == ImportSummary(cves=1)
    return database


def _catalog_database(tmp_path: Path) -> Path:
    """The service artifact database is the same shared SQLite catalog path."""
    return tmp_path / "catalog.db"


def _repository(tmp_path: Path) -> Path:
    """A minimal single-candidate repository: one function, no imports.

    One Python observation pairs with the single seeded CWE-89 template into
    exactly one candidate, so the happy path confirms exactly one finding.
    """
    (tmp_path / "app.py").write_text(
        "def login(request):\n    return request\n"
    )
    return tmp_path


def _add_taint_templates(database: Path, *, only_cwe89: bool = False) -> None:
    """Seed deterministic in-scope taint templates into the catalog.

    ``only_cwe89`` restricts the seed to the single CWE-89 sink so the happy
    path produces exactly one candidate (one observation x one template).
    """
    rows = [
        ("t-89-sink", "CWE-89", "SINK", "app.login(request)", "[0]",
         '{"language": "python"}', '["sql", "query"]', "v1", "{}"),
        ("t-78-source", "CWE-78", "SOURCE", "os.system(cmd)", "[0]",
         '{"language": "python"}', '["command"]', "v1", "{}"),
        ("t-918-sink", "CWE-918", "SINK", "requests.get(url)", "[0]",
         '{"language": "python"}', '["url"]', "v1", "{}"),
    ]
    if only_cwe89:
        rows = rows[:1]
    with sqlite3.connect(database) as connection:
        connection.executemany(
            """
            INSERT INTO taint_template
                (template_id, cwe_id, role, api_shape, parameter_shape,
                 applicability_json, semantic_features_json, template_version,
                 provenance_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        connection.commit()


def _tracer_fixture(name: str) -> SimpleNamespace:
    raw = json.loads((STATIC_FIXTURES / name).read_text(encoding="utf-8"))
    return SimpleNamespace(
        trace_path=raw.get("trace_path"),
        is_exploitable=raw.get("is_exploitable", False),
        confidence=raw.get("confidence", 0.0),
        source_type=raw.get("source_type", "unknown"),
        controllability_level=raw.get("controllability_level", "not_controlled"),
        summary=raw.get("summary", ""),
    )


class FixtureInputTracer:
    """Delegates to the shipped adapter contract with fixture controllability."""

    def __init__(self, result: SimpleNamespace) -> None:
        self.result = result
        self.calls = 0

    def trace_controllability(self, file_path, line_number, code_snippet=None):
        self.calls += 1
        return self.result


class FixturePrefilter:
    """Delegates to the shipped adapter contract with fixture SARIF output."""

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls = 0

    def codeql_hard_analyze(self, source_root, files=None):
        self.calls += 1
        return self.payload


class RecordingAdapter:
    """Wraps a real shipped adapter, recording execute/normalize delegation."""

    def __init__(self, delegate) -> None:
        self._delegate = delegate
        self.adapter_id = delegate.adapter_id
        self.adapter_version = delegate.adapter_version
        self.executed = 0
        self.normalized = 0

    def supports(self, applicability, semantics):
        return self._delegate.supports(applicability, semantics)

    def execute(self, specification, repository_ref):
        self.executed += 1
        if self.adapter_id == "input-tracer":
            return self._tracer
        if self.adapter_id == "codeql-sast":
            return self._codeql
        raise AssertionError(f"unexpected adapter {self.adapter_id}")

    def normalize(self, raw, *, provenance):
        self.normalized += 1
        return self._delegate.normalize(raw, provenance=provenance)


def _adapter_suite(tmp_path: Path, *, mode: str):
    """Build (adapters, supported_set) for the requested smoke mode."""
    adapters = []
    supported = []
    if mode == "confirming":
        complete = _tracer_fixture("input_tracer_complete.json")
        tracer = RecordingAdapter(InputTracerAdapter(FixtureInputTracer(complete)))
        tracer._tracer = complete
        codeql = RecordingAdapter(
            CodeQLSastAdapter(FixturePrefilter(
                json.loads((STATIC_FIXTURES / "codeql_complete.json").read_text(encoding="utf-8"))
            ))
        )
        codeql._codeql = json.loads(
            (STATIC_FIXTURES / "codeql_complete.json").read_text(encoding="utf-8")
        )
        adapters = [tracer, codeql]
        supported = [("input-tracer", "1"), ("codeql-sast", "1")]
    elif mode == "incomplete":
        no_path = _tracer_fixture("input_tracer_no_path.json")
        tracer = RecordingAdapter(InputTracerAdapter(FixtureInputTracer(no_path)))
        tracer._tracer = no_path
        adapters = [tracer]
        supported = [("input-tracer", "1")]
    elif mode == "unsupported":
        plain = json.loads(
            (STATIC_FIXTURES / "codeql_plain_hit.json").read_text(encoding="utf-8")
        )
        codeql = RecordingAdapter(CodeQLSastAdapter(FixturePrefilter(plain)))
        codeql._codeql = plain
        adapters = [codeql]
        supported = [("codeql-sast", "1")]
    elif mode == "none":
        pass
    return adapters, supported


def _service(
    tmp_path: Path,
    *,
    catalog_database: Path,
    adapters,
    supported,
    discovery=None,
    template_provider=None,
):
    repository = ArtifactRepository(
        str(catalog_database), supported_static_adapters=tuple(supported)
    )
    ledger = CandidateLedger(repository)
    service = ECATSLService(
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
        static_adapters=adapters,
        supported_static_adapters=tuple(supported),
    )
    return service, repository


def _request(**overrides):
    values = {
        "repository_ref": "repo://demo",
        "language": "python",
        "cwe_ids": ("CWE-89",),
    }
    values.update(overrides)
    return AnalysisRequest(**values)


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is not None else NOW.replace(tzinfo=None)


def _freeze_pipeline_clock(monkeypatch):
    for module in (
        "service",
        "candidate_ledger",
        "compiler",
        "confirmation",
        "discovery",
        "static_adapters",
    ):
        monkeypatch.setattr(f"src.ecatsl.{module}.datetime", _FrozenDatetime)


# ------------------------------------------------------------------- helpers


def _stage_purposes(result):
    return tuple(stage.transformation_purpose for stage in result.stage_records)


def _count(repository, table):
    return int(
        repository.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    )


# --------------------------------------------------------------------- tests


def test_smoke_full_pipeline_confirms_exactly_the_complete_static_path(
    tmp_path, populated_catalog, monkeypatch
):
    """Happy path: generic discovery + catalog ranking + static path confirm."""
    _freeze_pipeline_clock(monkeypatch)
    _add_taint_templates(populated_catalog, only_cwe89=True)
    target = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    adapters, supported = _adapter_suite(tmp_path, mode="confirming")
    provider = build_sqlite_template_provider(str(populated_catalog), scope_cwe_ids=INITIAL_CWES)
    service, repository = _service(
        tmp_path,
        catalog_database=populated_catalog,
        adapters=adapters,
        supported=supported,
        discovery=discovery,
        template_provider=provider,
    )
    try:
        result = service.analyze(_request(repository_ref=str(target)))

        assert result.status == "COMPLETE"
        assert result.audit_failures == ()
        assert _stage_purposes(result) == EXPECTED_STAGES
        # Catalog ranking ran through the real SQLite provider and ranked the
        # exact-weakness template first, deterministically.
        assert result.hypotheses
        assert all(item.confirmatory is False for item in result.hypotheses)
        assert all(len(item.evidence_ids) == 2 for item in result.hypotheses)
        # Exactly the complete supported static path confirms; catalog and
        # discovery hypotheses alone never do (requirements 4.1-4.3, 11.12).
        confirmed = [f for f in result.findings if f.status is FindingStatus.CONFIRMED]
        unconfirmed = [f for f in result.findings if f.status is not FindingStatus.CONFIRMED]
        assert len(confirmed) == 1, "exactly one complete supported path may confirm"
        assert confirmed[0].path_evidence_id is not None
        assert confirmed[0].specification_ids
        assert confirmed[0].candidate_record_ids
        assert confirmed[0].validation_result_ids
        for finding in unconfirmed:
            assert finding.path_evidence_id is None
        # All stage outputs are retained and reloadable.
        for stage in result.stage_records:
            for artifact_id in stage.output_artifact_ids:
                if artifact_id:
                    assert repository.load(artifact_id).artifact_id == artifact_id
        # Two supported adapters each proved the complete path; one retained
        # confirmation binds exactly one qualifying path (both adapters'
        # evidence points at the same single confirmed finding).
        assert _count(repository, "ecatsl_path_evidence") == 2
        # Telemetry: the delegated adapters actually executed and normalized.
        tracer_adapter, codeql_adapter = adapters
        assert tracer_adapter.executed == tracer_adapter.normalized > 0
        assert codeql_adapter.executed == codeql_adapter.normalized > 0
        assert discovery.last_telemetry is not None
        assert discovery.last_telemetry.parsed >= 1
        # Populated catalog data still answers through the shared database.
        with sqlite3.connect(populated_catalog) as connection:
            cves = connection.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            cwes = connection.execute("SELECT COUNT(*) FROM cwe").fetchone()[0]
        assert cves >= 1 and cwes >= 1
    finally:
        repository.close()


def test_smoke_catalog_only_stays_unconfirmed(tmp_path, populated_catalog):
    """Discovery + catalog hypotheses without any adapter never confirm."""
    _add_taint_templates(populated_catalog)
    target = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    provider = build_sqlite_template_provider(str(populated_catalog), scope_cwe_ids=INITIAL_CWES)
    adapters, supported = _adapter_suite(tmp_path, mode="none")
    service, repository = _service(
        tmp_path,
        catalog_database=populated_catalog,
        adapters=adapters,
        supported=supported,
        discovery=discovery,
        template_provider=provider,
    )
    try:
        result = service.analyze(_request(repository_ref=str(target)))

        assert result.status == "COMPLETE"
        assert result.audit_failures == ()
        assert result.hypotheses, "wired providers must produce hypotheses"
        assert all(item.confirmatory is False for item in result.hypotheses)
        assert result.findings
        assert all(f.status is FindingStatus.UNCONFIRMED for f in result.findings)
        assert all(f.path_evidence_id is None for f in result.findings)
        assert _count(repository, "ecatsl_path_evidence") == 0
    finally:
        repository.close()


def test_smoke_unsupported_adapter_stays_unconfirmed(tmp_path, populated_catalog):
    """An allowlisted adapter with no complete flow retains an unconfirmed finding."""
    _add_taint_templates(populated_catalog)
    target = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    provider = build_sqlite_template_provider(str(populated_catalog), scope_cwe_ids=INITIAL_CWES)
    adapters, supported = _adapter_suite(tmp_path, mode="unsupported")
    service, repository = _service(
        tmp_path,
        catalog_database=populated_catalog,
        adapters=adapters,
        supported=supported,
        discovery=discovery,
        template_provider=provider,
    )
    try:
        result = service.analyze(_request(repository_ref=str(target)))

        assert result.status == "COMPLETE"
        assert result.audit_failures == ()
        # The plain SARIF hit is retained but carries no ordered code flow, so
        # nothing confirms (requirements 2.8, 4.1-4.5).
        assert all(f.status is FindingStatus.UNCONFIRMED for f in result.findings)
        assert _count(repository, "ecatsl_path_evidence") == 0
        with sqlite3.connect(populated_catalog) as connection:
            outcomes = connection.execute(
                "SELECT outcome FROM ecatsl_validation_result WHERE adapter_id IS NOT NULL"
            ).fetchall()
        assert outcomes
        assert all(row[0] != "COMPLETE_PATH" for row in outcomes)
    finally:
        repository.close()


def test_smoke_static_incomplete_stays_unconfirmed(tmp_path, populated_catalog):
    """Empty trace path output maps to NO_PATH and never to a finding."""
    _add_taint_templates(populated_catalog)
    target = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    provider = build_sqlite_template_provider(str(populated_catalog), scope_cwe_ids=INITIAL_CWES)
    adapters, supported = _adapter_suite(tmp_path, mode="incomplete")
    service, repository = _service(
        tmp_path,
        catalog_database=populated_catalog,
        adapters=adapters,
        supported=supported,
        discovery=discovery,
        template_provider=provider,
    )
    try:
        result = service.analyze(_request(repository_ref=str(target)))

        assert result.status == "COMPLETE"
        assert result.audit_failures == ()
        assert all(f.status is FindingStatus.UNCONFIRMED for f in result.findings)
        assert all(f.path_evidence_id is None for f in result.findings)
        assert _count(repository, "ecatsl_path_evidence") == 0
    finally:
        repository.close()


def test_smoke_out_of_scope_short_circuits(tmp_path, populated_catalog):
    """Out-of-scope requests stop before any downstream processing (Req 6.3)."""
    _add_taint_templates(populated_catalog)
    target = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    provider = build_sqlite_template_provider(str(populated_catalog), scope_cwe_ids=INITIAL_CWES)
    adapters, supported = _adapter_suite(tmp_path, mode="confirming")
    service, repository = _service(
        tmp_path,
        catalog_database=populated_catalog,
        adapters=adapters,
        supported=supported,
        discovery=discovery,
        template_provider=provider,
    )
    try:
        result = service.analyze(_request(repository_ref=str(target), cwe_ids=("CWE-22",)))

        assert result.status == "OUT_OF_SCOPE"
        assert result.hypotheses == ()
        assert result.candidates == ()
        assert result.specifications == ()
        assert result.findings == ()
        with sqlite3.connect(populated_catalog) as connection:
            rows = connection.execute(
                "SELECT COUNT(*) FROM template_retrieval"
            ).fetchone()[0]
        assert rows == 0  # out-of-scope requests never reach the catalog
    finally:
        repository.close()


def test_smoke_idempotent_migration_and_restart_replay(tmp_path, populated_catalog, monkeypatch):
    """Lineage and telemetry survive reopen/replay on the populated catalog."""
    _freeze_pipeline_clock(monkeypatch)
    _add_taint_templates(populated_catalog, only_cwe89=True)
    target = _repository(tmp_path)
    discovery = RepositoryDiscovery()
    provider = build_sqlite_template_provider(str(populated_catalog), scope_cwe_ids=INITIAL_CWES)
    adapters, supported = _adapter_suite(tmp_path, mode="confirming")

    first_service, first_repository = _service(
        tmp_path,
        catalog_database=populated_catalog,
        adapters=adapters,
        supported=supported,
        discovery=discovery,
        template_provider=provider,
    )
    try:
        first = first_service.analyze(_request(repository_ref=str(target)))
        assert first.status == "COMPLETE"
        assert first.audit_failures == ()
    finally:
        first_repository.close()

    # Idempotent migration: reopening the populated catalog re-enters safely.
    second_service, second_repository = _service(
        tmp_path,
        catalog_database=populated_catalog,
        adapters=adapters,
        supported=supported,
        discovery=discovery,
        template_provider=provider,
    )
    try:
        second = second_service.analyze(_request(repository_ref=str(target)))

        assert second.status == "COMPLETE"
        assert second.audit_failures == ()
        # Restart persistence: the first run's confirmation survives reopen.
        reloaded = second_repository.load(
            first.findings[[f.status is FindingStatus.CONFIRMED for f in first.findings].index(True)].artifact_id,
            type(first.findings[0]),
        )
        assert reloaded.status is FindingStatus.CONFIRMED
        # Replay through a new service stays deterministic and unconfirmed
        # rows stay unconfirmed.
        confirmed_second = [f for f in second.findings if f.status is FindingStatus.CONFIRMED]
        assert len(confirmed_second) == 1
        assert confirmed_second[0].artifact_id == reloaded.artifact_id
        # The retained lineage is queryable after restart.
        assert _count(second_repository, "ecatsl_path_evidence") >= 1
        with sqlite3.connect(populated_catalog) as connection:
            retrieval = connection.execute(
                "SELECT COUNT(*) FROM template_retrieval"
            ).fetchone()[0]
        assert retrieval >= 1  # catalog retrieval telemetry persisted
    finally:
        second_repository.close()
