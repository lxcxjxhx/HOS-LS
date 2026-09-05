"""Feature: evidence-constrained-taint-spec-learning, Property 12.

Property 12: Dataset canonicalization and transforms are reproducible.
Generate records, supplied hashes, duplicates, and transform versions and
assert integrity outcomes, one canonical record, retained identities, and
stable output hashes.

Validates: Requirements 9.4-9.6.
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from src.ecatsl.dataset_release import (  # noqa: E402
    REQUIRED_FIELDS,
    build_release,
    canonicalize,
    deterministic_transform,
)
from src.ecatsl.models import Attribute, Provenance  # noqa: E402

_OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))

_CONTENT = st.binary(max_size=48)


def _hash(content: bytes) -> str:
    return sha256(content).hexdigest()


def _provenance(tag="dataset-release") -> Provenance:
    return Provenance(
        origin="local-fixture",
        retrieved_at=_OFFSET_TIME,
        source_identifier="bench/datasets/VulnGym",
        source_revision="v0.1.4",
        content_identity=f"dataset:{tag}",
    )


def _records(contents):
    rows = []
    for i, content in enumerate(contents):
        rows.append(
            {
                "id": f"s{i}",
                "content": content,
                "content_hash": _hash(content),
                "classification": "vulnerable" if i % 2 else "fixed",
                "project_id": f"proj{i % 3}",
                "project_time_group": f"proj{i % 3}:g{i % 4}",
            }
        )
    return rows


def _count(completeness, name):
    return int(next(a.value for a in completeness if a.name == name))


def _attrs(attrs):
    return tuple(sorted((a.name, a.value) for a in attrs))


@settings(max_examples=100)
@given(st.lists(_CONTENT, min_size=1, max_size=12), st.data())
def test_integrity_canonicalization_and_retained_identities(contents, data):
    """Req 9.4-9.5: verified hashes, one canonical record, identities kept."""
    duplicate_at = data.draw(st.integers(min_value=0, max_value=len(contents) - 1))
    rows = _records(contents)
    rows.append(dict(rows[duplicate_at], id="dup"))

    manifest, quality = build_release(
        rows,
        version="v1",
        created_at=_OFFSET_TIME,
        provenance=_provenance(),
        data_type="benchmark_sample",
    )

    # Req 9.4: every supplied hash that matches retrieved content is VERIFIED.
    assert _attrs(quality.integrity_results) == _attrs(
        Attribute(name=f"integrity:{rec['id']}", value="VERIFIED") for rec in rows
    )
    # One canonical record per distinct (content_hash, data_type) pair.
    distinct = len(set(contents))
    assert _count(quality.completeness, "record_count") == len(contents) + 1
    assert _count(quality.completeness, "retained_count") == len(contents) + 1
    assert _count(quality.completeness, "canonical_count") == distinct
    assert quality.duplicate_count == len(contents) + 1 - distinct
    assert quality.excluded_count == 0
    assert quality.exclusion_reasons == ()

    # Duplicate identities are retained: no sample row is dropped from the
    # release even though only one canonical record remains per content.
    sample_ids = {s.sample_id for s in manifest.samples}
    assert sample_ids == {f"s{i}" for i in range(len(contents))} | {"dup"}

    # Direct contract: first occurrence is canonical, later equal identities
    # are listed under the canonical record id (first-match deterministic).
    h1, h2 = sha256(b"alpha").hexdigest(), sha256(b"beta").hexdigest()
    canonical, duplicates = canonicalize(
        (
            {"id": "a", "content_hash": h1, "data_type": "t"},
            {"id": "b", "content_hash": h1, "data_type": "t"},
            {"id": "c", "content_hash": h2, "data_type": "t"},
        )
    )
    assert [rec["id"] for rec in canonical] == ["a", "c"]
    assert duplicates == {"a": ["b"]}


@settings(max_examples=100)
@given(_CONTENT, st.data())
def test_tampered_supplied_hash_is_excluded(content, data):
    """Req 9.4: FAILED integrity rows are excluded with a reason."""
    other = data.draw(_CONTENT)
    assume(other != content)
    row = _records([content])[0]
    row["content_hash"] = _hash(other)
    row["id"] = "t1"

    manifest, quality = build_release(
        [row],
        version="v1",
        created_at=_OFFSET_TIME,
        provenance=_provenance(),
        data_type="benchmark_sample",
    )

    assert _attrs(quality.integrity_results) == (("integrity:t1", "FAILED"),)
    assert quality.excluded_count == 1
    assert quality.exclusion_reasons == ("integrity_failed:t1",)
    assert manifest.samples == ()


@settings(max_examples=100)
@given(_CONTENT, st.data())
def test_transforms_are_stable_and_version_defining(content, data):
    """Req 9.6: same input + version is stable; a new version is a new output."""
    v1 = data.draw(st.text(min_size=1, max_size=8))
    v2 = data.draw(st.text(min_size=1, max_size=8))
    assume(v1 != v2)

    # Pure contract: repeated invocation reproduces the same output hash and
    # different versions yield different output hashes for the same input.
    digest = _hash(content)
    assert deterministic_transform(digest.encode(), v1) == deterministic_transform(
        digest.encode(), v1
    )
    assert deterministic_transform(digest.encode(), v1) != deterministic_transform(
        digest.encode(), v2
    )

    def release(version):
        return build_release(
            _records([content]),
            version="v1",
            created_at=_OFFSET_TIME,
            provenance=_provenance(version),
            data_type="benchmark_sample",
            transform=(version, lambda row: row),
        )

    manifest_a, _ = release(v1)
    manifest_b, _ = release(v1)
    manifest_c, _ = release(v2)

    expected = deterministic_transform(digest.encode(), v1)
    assert _attrs(manifest_a.sample_attributes) == _attrs(manifest_b.sample_attributes)
    transform_values = {
        a.value for a in manifest_a.sample_attributes if a.name.startswith("transform:")
    }
    assert transform_values == {expected}
    # A changed transform version is a tracked input change: new manifest id.
    assert manifest_a.model_dump_json() == manifest_b.model_dump_json()
    assert manifest_a.model_dump_json() != manifest_c.model_dump_json()

    # REQUIRED_FIELDS is the release-wide validity contract (constant surface).
    assert REQUIRED_FIELDS == ("id", "content_hash", "classification")
