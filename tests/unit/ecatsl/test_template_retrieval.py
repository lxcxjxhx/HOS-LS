"""Deterministic semantic template retrieval (Task 6.3).

Covers Requirements 4.3-4.4, 6.1-6.3, 11.8-11.9 and 11.12-11.13: in-scope-only
retrieval, versioned deterministic ranking with stable tie-breaking, persisted
retrieval provenance, preserved catalog queries, and the absence of any
confirmation/controllability surface.
"""

import json
import sqlite3
from dataclasses import fields
from pathlib import Path

import pytest

from src.nvd.catalog_import import CatalogImporter
from src.nvd.nvd_query_adapter import (
    CATALOG_EVIDENCE_SCALE,
    TEMPLATE_RANKING_PROFILE,
    TEMPLATE_RANKING_WEIGHTS,
    RankedTemplate,
    TaintTemplateRepository,
    TemplateRetrievalResult,
    applicability_score,
    evidence_score,
    relevance_score,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "baseline"

INITIAL_CWES = ("CWE-89", "CWE-78", "CWE-918")


def _insert_template(
    connection: sqlite3.Connection,
    template_id: str,
    cwe_id: str,
    role: str,
    applicability: dict,
    features: list[str],
    *,
    api_shape: str = "api()",
    parameter_shape: list[int] | None = None,
    version: str = "v1",
) -> None:
    connection.execute(
        """
        INSERT INTO taint_template
            (template_id, cwe_id, role, api_shape, parameter_shape,
             applicability_json, semantic_features_json, template_version,
             provenance_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            template_id,
            cwe_id,
            role,
            api_shape,
            json.dumps(parameter_shape if parameter_shape is not None else []),
            json.dumps(applicability, sort_keys=True),
            json.dumps(features),
            version,
            json.dumps({"origin": "test", "supplier": "tests"}),
        ),
    )


@pytest.fixture
def populated_database(tmp_path) -> Path:
    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        importer.import_cwe_xml(FIXTURES / "mitre_cwe.xml")  # CWE-89 named record
        importer.import_nvd(FIXTURES / "nvd_cve.json")  # CVE-2025-0001 -> CWE-89
    return database


def _retrieval_rows(connection: sqlite3.Connection) -> list[tuple]:
    return connection.execute(
        "SELECT retrieval_id, cwe_id, query_identity, ranking_profile_version, "
        "result_template_ids_json, scores_json, provenance_json "
        "FROM template_retrieval ORDER BY retrieval_id"
    ).fetchall()


def test_pure_score_functions_are_deterministic():
    assert relevance_score("CWE-89", "CWE-89", ("sql",), frozenset()) == 1.0
    terms = frozenset({"sql", "injection", "query", "command"})
    jaccard = relevance_score("CWE-89", "CWE-78", ("sql", "injection"), terms)
    assert jaccard == 2 / 4
    assert relevance_score("CWE-89", "CWE-918", ("os",), terms) == 0.0

    assert applicability_score({"language": "python"}, {"language": "python"}) == 1.0
    assert applicability_score({}, {"language": "python"}) == 0.5
    assert applicability_score({}, None) == 0.5
    assert applicability_score({"language": "python"}, None) == 0.5
    assert applicability_score({"language": "python"}, {"language": "java"}) == 0.0
    assert applicability_score(
        {"language": "python"}, {"framework": "django"}
    ) == 0.5

    assert evidence_score(0) == 0.0
    assert evidence_score(CATALOG_EVIDENCE_SCALE) == 1.0
    assert evidence_score(10 * CATALOG_EVIDENCE_SCALE) == 1.0


def test_retrieve_returns_only_in_scope_templates(populated_database):
    with sqlite3.connect(populated_database) as connection:
        _insert_template(connection, "t-sql-89", "CWE-89", "SOURCE",
                         {"language": "python"}, ["sql", "injection"])
        _insert_template(connection, "t-os-78", "CWE-78", "SINK",
                         {"language": "python"}, ["os", "command"])
        _insert_template(connection, "t-ssrf-918", "CWE-918", "SINK",
                         {"language": "python"}, ["server", "side", "request"])
        connection.commit()

    repository = TaintTemplateRepository(
        str(populated_database), scope_cwe_ids=("CWE-89",)
    )
    try:
        result = repository.retrieve("CWE-89")
        assert set(result.template_ids) == {"t-sql-89"}
    finally:
        repository.close()

    repository = TaintTemplateRepository(
        str(populated_database), scope_cwe_ids=INITIAL_CWES
    )
    try:
        result = repository.retrieve("CWE-89")
        assert set(result.template_ids) == {"t-sql-89", "t-os-78", "t-ssrf-918"}
    finally:
        repository.close()


def test_exact_weakness_relevance_ranks_first_with_stable_ties(populated_database):
    with sqlite3.connect(populated_database) as connection:
        _insert_template(connection, "t-a-89", "CWE-89", "SOURCE",
                         {"language": "python"}, ["sql", "injection"])
        _insert_template(connection, "t-b-89", "CWE-89", "SOURCE",
                         {"language": "python"}, ["sql", "injection", "query"])
        _insert_template(connection, "t-78", "CWE-78", "SINK",
                         {"language": "python"}, ["os", "command"])
        connection.commit()

    repository = TaintTemplateRepository(str(populated_database))
    try:
        result = repository.retrieve("CWE-89")
        ids = result.template_ids
        # Exact CWE-89 matches have relevance 1.0 and outrank the CWE-78 template.
        assert ids[0] == "t-a-89"  # tie with t-b-89 broken by template id
        assert ids[1] == "t-b-89"
        assert ids[2] == "t-78"
        # Deterministic: repeated retrieval returns the identical ordering.
        assert repository.retrieve("CWE-89").template_ids == ids
        for item in result.ranked:
            expected = (
                TEMPLATE_RANKING_WEIGHTS["relevance"] * item.relevance
                + TEMPLATE_RANKING_WEIGHTS["applicability"]
                * item.applicability_score
                + TEMPLATE_RANKING_WEIGHTS["catalog_evidence"]
                * item.catalog_evidence
            )
            assert item.final_score == expected
        by_id = {item.template_id: item for item in result.ranked}
        assert by_id["t-a-89"].relevance == 1.0
        assert by_id["t-78"].relevance < 1.0
    finally:
        repository.close()


def test_applicability_conflict_scores_zero(populated_database):
    with sqlite3.connect(populated_database) as connection:
        _insert_template(connection, "t-py-89", "CWE-89", "SOURCE",
                         {"language": "python"}, ["sql", "injection"])
        _insert_template(connection, "t-java-89", "CWE-89", "SOURCE",
                         {"language": "java"}, ["sql", "injection"])
        connection.commit()

    repository = TaintTemplateRepository(str(populated_database))
    try:
        result = repository.retrieve("CWE-89", applicability={"language": "java"})
        ranked = {item.template_id: item for item in result.ranked}
        assert ranked["t-py-89"].applicability_score == 0.0
        assert ranked["t-java-89"].applicability_score == 1.0
        assert result.template_ids[0] == "t-java-89"
        assert result.template_ids[1] == "t-py-89"
    finally:
        repository.close()


def test_catalog_evidence_reflects_linked_cve_records(populated_database):
    with sqlite3.connect(populated_database) as connection:
        _insert_template(connection, "t-89", "CWE-89", "SOURCE",
                         {}, ["sql", "injection"])
        _insert_template(connection, "t-918", "CWE-918", "SINK",
                         {}, ["ssrf"])
        connection.commit()

    repository = TaintTemplateRepository(str(populated_database))
    try:
        # Catalog evidence is query-level: the CWE-89 query is backed by one
        # linked CVE in the fixture, so every retrieved template shares it.
        result = repository.retrieve("CWE-89")
        for item in result.ranked:
            assert item.catalog_evidence == 1 / CATALOG_EVIDENCE_SCALE
        assert result.ranked[0].catalog_evidence == 1 / CATALOG_EVIDENCE_SCALE
        # A query without linked catalog records receives zero evidence.
        no_evidence = repository.retrieve("CWE-918")
        for item in no_evidence.ranked:
            assert item.catalog_evidence == 0.0
    finally:
        repository.close()


def test_retrieval_provenance_is_persisted_idempotently(populated_database):
    with sqlite3.connect(populated_database) as connection:
        _insert_template(connection, "t-89", "CWE-89", "SOURCE",
                         {"language": "python"}, ["sql", "injection"])
        connection.commit()

    repository = TaintTemplateRepository(str(populated_database))
    try:
        first = repository.retrieve("CWE-89", applicability={"language": "python"},
                                    context={"framework": "django"})
        second = repository.retrieve("CWE-89", applicability={"language": "python"},
                                     context={"framework": "django"})
        assert first.retrieval_id == second.retrieval_id

        with sqlite3.connect(populated_database) as connection:
            rows = _retrieval_rows(connection)
            assert len(rows) == 1  # idempotent, identical query does not duplicate
            _, cwe_id, identity, profile, ids_json, scores_json, provenance_json = rows[0]
            assert cwe_id == "CWE-89"
            assert identity == first.query_identity
            assert profile == TEMPLATE_RANKING_PROFILE
            assert json.loads(ids_json) == ["t-89"]
            assert len(json.loads(scores_json)) == 1
            provenance = json.loads(provenance_json)
            assert provenance["cwe_id"] == "CWE-89"
            assert provenance["applicability"] == {"language": "python"}
            assert provenance["context"] == {"framework": "django"}
            assert provenance["ranking_profile_version"] == TEMPLATE_RANKING_PROFILE

        # A different query input gets its own provenance row.
        third = repository.retrieve("CWE-89")
        assert third.retrieval_id != first.retrieval_id
        with sqlite3.connect(populated_database) as connection:
            assert len(_retrieval_rows(connection)) == 2
    finally:
        repository.close()


def test_retrieval_exposes_no_confirmation_or_controllability_surface(
    populated_database,
):
    with sqlite3.connect(populated_database) as connection:
        _insert_template(connection, "t-89", "CWE-89", "SOURCE",
                         {}, ["sql", "injection"])
        connection.commit()

    repository = TaintTemplateRepository(str(populated_database))
    try:
        result = repository.retrieve("CWE-89")
        assert isinstance(result, TemplateRetrievalResult)
        assert isinstance(result.ranked[0], RankedTemplate)
        attribute_names = {item.name for item in fields(RankedTemplate)}
        assert not (attribute_names & {"confirmatory", "controllability",
                                       "path_evidence", "confirmed"})
        assert not hasattr(result, "confirmatory")
        assert not hasattr(result.ranked[0], "path_evidence")
    finally:
        repository.close()


def test_legacy_database_without_template_tables_returns_empty(tmp_path):
    database = tmp_path / "plain.db"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE cwe (cwe_id TEXT PRIMARY KEY, name TEXT, description TEXT)"
    )
    connection.commit()
    connection.close()

    repository = TaintTemplateRepository(str(database))
    try:
        result = repository.retrieve("CWE-89")
        assert isinstance(result, TemplateRetrievalResult)
        assert result.template_ids == ()
        assert result.scores == ()
    finally:
        repository.close()


def test_existing_catalog_queries_stay_usable_after_retrieval(populated_database):
    from src.nvd.nvd_query_adapter import NVDQueryAdapter

    with sqlite3.connect(populated_database) as connection:
        _insert_template(connection, "t-89", "CWE-89", "SOURCE",
                         {}, ["sql", "injection"])
        connection.commit()

    repository = TaintTemplateRepository(str(populated_database))
    adapter = NVDQueryAdapter(str(populated_database), use_cache=False)
    try:
        repository.retrieve("CWE-89")
        assert adapter.get_all_cwe_ids() == ["CWE-89"]
        assert adapter.get_cwe_by_id("CWE-89")["cwe_name"].startswith(
            "Improper Neutralization"
        )
    finally:
        repository.close()
        adapter._disconnect()
