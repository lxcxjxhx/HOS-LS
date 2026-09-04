"""Feature: evidence-constrained-taint-spec-learning, Property 16 tests.

Property 16: Catalog normalization, canonicalization, and ingestion are stable.
Generate source identities, content, normalization profiles, and import tool
versions and assert stable content hashes, one canonical record per canonical
key with all duplicate source identities retained, zero-new replay, and
new/changed-only incremental selection.

Validates: Requirements 11.2-11.4, 11.6-11.7
"""

import json
from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from src.nvd.catalog_import import CatalogImporter, IngestionService  # noqa: E402

NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)

_CWE_IDS = ("89", "78", "918", "79", "22")


def _description_strategy() -> st.SearchStrategy[str]:
    return st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz ",
        min_size=5,
        max_size=40,
    ).filter(lambda value: value.strip())


def _nvd_document(
    identifier: str, description: str, references: tuple[str, ...]
) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": identifier,
                    "published": "2026-01-02T00:00:00.000Z",
                    "lastModified": "2026-01-03T00:00:00.000Z",
                    "descriptions": [{"lang": "en", "value": description}],
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-89"}]}
                    ],
                    "references": [{"url": ref} for ref in references],
                }
            }
        ]
    }


def _count(connection, sql: str, params=()) -> int:
    return connection.execute(sql, params).fetchone()[0]


@settings(max_examples=100, deadline=None)
@given(
    description=_description_strategy(),
    profile_version=st.sampled_from(("catalog-normalize/v1", "catalog-normalize/v2")),
    trailing_variation=st.booleans(),
)
def test_property_16_normalized_identity_is_stable_for_equal_source_content(
    tmp_path_factory, description: str, profile_version: str, trailing_variation: bool
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 16: equal source content identity plus profile version always yields equal normalized content identity."""
    # Pure-function level: the normalized identity depends only on the payload
    # and the profile version, never on run time, tool identity, or ordering.
    payload = {"id": "CWE-89", "name": "SQL Injection", "description": description}
    first = IngestionService._normalized_content_hash(profile_version, payload)
    assert (
        IngestionService._normalized_content_hash(profile_version, payload) == first
    )
    other_profile = "catalog-normalize/v1"
    if profile_version == other_profile:
        other_profile = "catalog-normalize/v2"
    assert (
        IngestionService._normalized_content_hash(other_profile, payload) != first
    )
    changed = dict(payload, description=description + ("!" if trailing_variation else "."))
    assert (
        IngestionService._normalized_content_hash(profile_version, changed) != first
    )

    # Service level: ingesting the identical source twice records one
    # normalized row whose stored hash equals the recomputed identity.
    work = tmp_path_factory.mktemp("property16")
    source = work / "nvd.json"
    source.write_text(json.dumps(_nvd_document("CVE-2026-0001", description, ("a",))))
    with CatalogImporter(work / "catalog.db") as importer:
        service = IngestionService(importer, profile_version=profile_version)
        first_run = service.ingest_nvd(source)[0]
        second_run = service.ingest_nvd(source)[0]
        assert first_run.counts["new_canonical"] == 1
        assert second_run.counts["new_canonical"] == 0
        assert second_run.counts["unchanged"] == 1
        assert _count(importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record") == 1


@settings(max_examples=100, deadline=None)
@given(
    identifier=st.sampled_from(_CWE_IDS),
    description=_description_strategy(),
    references_a=st.lists(
        st.text(alphabet="abcdefgh/", min_size=4, max_size=12),
        min_size=1,
        max_size=2,
    ),
    references_b=st.lists(
        st.text(alphabet="wxyz/", min_size=4, max_size=12),
        min_size=1,
        max_size=2,
    ),
)
def test_property_16_one_canonical_record_retains_all_duplicate_sources(
    tmp_path_factory,
    identifier: str,
    description: str,
    references_a: list[str],
    references_b: list[str],
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 16: records sharing a canonical key retain one canonical record and every duplicate source identity."""
    hypothesis.assume(sorted(references_a) != sorted(references_b))
    work = tmp_path_factory.mktemp("property16-dup")
    source_a = work / "a.json"
    source_b = work / "b.json"
    cve_id = f"CVE-2026-{identifier}-0001"
    source_a.write_text(
        json.dumps(_nvd_document(cve_id, description, tuple(references_a)))
    )
    source_b.write_text(
        json.dumps(_nvd_document(cve_id, description, tuple(references_b)))
    )
    with CatalogImporter(work / "catalog.db") as importer:
        service = IngestionService(importer)
        first = service.ingest_nvd(source_a)[0]
        second = service.ingest_nvd(source_b)[0]
        assert first.counts["new_canonical"] == 1
        # Same identifier and equal normalized payload: a duplicate decision.
        assert second.counts["duplicate"] == 1
        assert second.counts["new_canonical"] == 0
        assert _count(importer.connection, "SELECT COUNT(*) FROM normalized_catalog_record") == 1
        assert _count(importer.connection, "SELECT COUNT(*) FROM source_record") == 2
        assert _count(importer.connection, "SELECT COUNT(*) FROM catalog_duplicate") == 1


@settings(max_examples=100, deadline=None)
@given(
    records=st.lists(
        st.tuples(st.sampled_from(_CWE_IDS), _description_strategy()),
        min_size=2,
        max_size=4,
        unique_by=lambda item: item[0],
    ),
    change_index=st.integers(min_value=0, max_value=3),
)
def test_property_16_replay_is_zero_new_and_selection_is_changed_only(
    tmp_path_factory, records: list[tuple[str, str]], change_index: int
) -> None:
    """Feature: evidence-constrained-taint-spec-learning, Property 16: identical replay creates zero new canonical records and an incremental run ingests only the changed record."""
    work = tmp_path_factory.mktemp("property16-incremental")
    source = work / "nvd.json"
    ids = [f"CVE-2026-{identifier}-0002" for identifier, _ in records]

    def write(descriptions: list[str]) -> None:
        document = {"vulnerabilities": []}
        for cve_id, description in zip(ids, descriptions):
            document["vulnerabilities"].append(
                _nvd_document(cve_id, description, ("base",))["vulnerabilities"][0]
            )
        source.write_text(json.dumps(document))

    write([description for _, description in records])
    with CatalogImporter(work / "catalog.db") as importer:
        service = IngestionService(importer)
        first = service.ingest_nvd(source)[0]
        assert first.counts["new_canonical"] == len(records)
        replay = service.ingest_nvd(source)[0]
        assert replay.counts["new_canonical"] == 0
        assert replay.counts["unchanged"] == len(records)

        changed_index = change_index % len(records)
        changed_descriptions = [
            description + " changed" if position == changed_index else description
            for position, (_, description) in enumerate(records)
        ]
        write(changed_descriptions)
        incremental = service.ingest_nvd(source)[0]
        assert incremental.counts["new_canonical"] == 1
        assert incremental.counts["unchanged"] == len(records) - 1
        changed_id = ids[changed_index]
        assert _count(
            importer.connection,
            "SELECT COUNT(*) FROM normalized_catalog_record "
            "WHERE canonical_identifier = ?",
            (changed_id,),
        ) == 2
