"""Feature: evidence-constrained-taint-spec-learning, Property 17 tests.

Property 17: Template retrieval is relevance-ranked and provenance-linked.
Generate templates, applicability, catalog evidence, and ties and assert
deterministic ordering (score desc, then template id), the versioned weight
formula, and complete retrieval provenance.

Validates: Requirements 11.8-11.9
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from src.nvd.nvd_query_adapter import (  # noqa: E402
    TEMPLATE_RANKING_WEIGHTS,
    RankedTemplate,
    TaintTemplateRepository,
    applicability_score,
    evidence_score,
    rank_templates,
)

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

_SCORES = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)


@settings(max_examples=100, deadline=None)
@given(
    templates=st.lists(
        st.tuples(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=6),
            st.sampled_from(("CWE-89", "CWE-78", "CWE-918")),
            st.tuples(_SCORES, _SCORES, _SCORES),
        ),
        min_size=1,
        max_size=6,
        unique_by=lambda item: item[0],
    ),
)
def test_property_17_ranking_order_is_deterministic_and_score_exact(templates):
    """Feature: evidence-constrained-taint-spec-learning, Property 17: retrieval ordering is deterministic (score desc, template id tie-break) and every final score equals the versioned weight formula."""
    scored = []
    for template_id, cwe_id, (relevance, app_score, evidence) in templates:
        final = (
            TEMPLATE_RANKING_WEIGHTS["relevance"] * relevance
            + TEMPLATE_RANKING_WEIGHTS["applicability"] * app_score
            + TEMPLATE_RANKING_WEIGHTS["catalog_evidence"] * evidence
        )
        scored.append(
            (
                template_id,
                cwe_id,
                "SOURCE",
                "api()",
                (),
                {},
                "v1",
                final,
                relevance,
                app_score,
                evidence,
            )
        )
    first_ranking = rank_templates(scored)
    second_ranking = rank_templates(scored)
    assert [item.template_id for item in first_ranking] == [
        item.template_id for item in second_ranking
    ]
    assert len(first_ranking) == len(scored)
    for position in range(len(first_ranking) - 1):
        current, following = first_ranking[position], first_ranking[position + 1]
        if current.final_score == following.final_score:
            assert current.template_id < following.template_id
        else:
            assert current.final_score > following.final_score
    for item in first_ranking:
        expected = (
            TEMPLATE_RANKING_WEIGHTS["relevance"] * item.relevance
            + TEMPLATE_RANKING_WEIGHTS["applicability"] * item.applicability_score
            + TEMPLATE_RANKING_WEIGHTS["catalog_evidence"] * item.catalog_evidence
        )
        assert item.final_score == expected
        assert isinstance(item, RankedTemplate)


@settings(max_examples=100, deadline=None)
@given(
    template_language=st.sampled_from(("python", "java", "go", None)),
    query_language=st.sampled_from(("python", "java", None)),
    query_framework=st.sampled_from(("django", "flask", None)),
)
def test_property_17_applicability_score_is_total_and_deterministic(
    template_language, query_language, query_framework
):
    """Feature: evidence-constrained-taint-spec-learning, Property 17: the documented applicability component is a total deterministic function returning exactly {0.0, 0.5, 1.0}."""
    template_applicability = (
        {"language": template_language} if template_language else {}
    )
    query = {}
    if query_language:
        query["language"] = query_language
    if query_framework:
        query["framework"] = query_framework
    first = applicability_score(template_applicability, query)
    assert first in (0.0, 0.5, 1.0)
    assert applicability_score(template_applicability, query) == first
    if not template_applicability:
        assert first == 0.5
    elif template_language and query_language and template_language != query_language:
        assert first == 0.0
    elif template_language and query_language:
        assert first == 1.0


@settings(max_examples=100, deadline=None)
@given(cve_count=st.integers(min_value=0, max_value=500))
def test_property_17_catalog_evidence_is_normalized_and_stable(cve_count: int):
    """Feature: evidence-constrained-taint-spec-learning, Property 17: the catalog evidence component is monotone, capped at 1.0, and stable."""
    score = evidence_score(cve_count)
    assert 0.0 <= score <= 1.0
    assert evidence_score(cve_count) == score
    assert evidence_score(cve_count + 1) >= score
    if cve_count == 0:
        assert score == 0.0


def test_property_17_retrieval_provenance_is_complete_and_replay_stable(tmp_path):
    """Feature: evidence-constrained-taint-spec-learning, Property 17: every persisted retrieval links query identity, profile, result ids, scores, and inputs, and identical queries never duplicate provenance."""
    from src.nvd.catalog_import import CatalogImporter

    database = tmp_path / "catalog.db"
    with CatalogImporter(database) as importer:
        baseline = Path(__file__).parents[3] / "fixtures" / "ecatsl" / "baseline"
        importer.import_cwe_xml(baseline / "mitre_cwe.xml")
        importer.import_nvd(baseline / "nvd_cve.json")
        importer.connection.execute(
            """
            INSERT INTO taint_template
                (template_id, cwe_id, role, api_shape, parameter_shape,
                 applicability_json, semantic_features_json, template_version,
                 provenance_json)
            VALUES
                ('t-exact', 'CWE-89', 'SOURCE', 'cursor.execute(q)', '[0]',
                 '{"language": "python"}', '["sql", "injection"]', 'v1', '{}'),
                ('t-related', 'CWE-78', 'SOURCE', 'os.system(c)', '[0]',
                 '{}', '["sql"]', 'v1', '{}')
            """
        )
        importer.connection.commit()

    repository = TaintTemplateRepository(str(database))
    try:
        first = repository.retrieve(
            "CWE-89", applicability={"language": "python"}
        )
        second = repository.retrieve(
            "CWE-89", applicability={"language": "python"}
        )
        assert first.retrieval_id == second.retrieval_id
        assert first.template_ids == second.template_ids
        assert first.scores == second.scores
        # Exact weakness relevance outranks the semantically related template.
        assert first.template_ids[0] == "t-exact"
        assert first.ranked[0].relevance == 1.0
        assert first.ranked[1].relevance > 0.0

        connection = sqlite3.connect(database)
        try:
            rows = connection.execute(
                "SELECT retrieval_id, cwe_id, query_identity, "
                "ranking_profile_version, result_template_ids_json, scores_json, "
                "provenance_json FROM template_retrieval"
            ).fetchall()
        finally:
            connection.close()
        assert len(rows) == 1
        _, cwe_id, identity, profile, ids_json, scores_json, provenance_json = rows[0]
        assert cwe_id == "CWE-89"
        assert identity == first.query_identity
        assert profile == first.ranking_profile_version
        assert json.loads(ids_json) == list(first.template_ids)
        assert json.loads(scores_json) == list(first.scores)
        provenance = json.loads(provenance_json)
        assert provenance["cwe_id"] == "CWE-89"
        assert provenance["applicability"] == {"language": "python"}
        assert provenance["ranking_profile_version"] == profile
    finally:
        repository.close()
