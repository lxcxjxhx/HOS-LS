"""Feature: evidence-constrained-taint-spec-learning, Property 13.

Property 13: Benchmark split and version lineage are stable.
Generate project-time groups, pairs, and tracked changes and assert no
group/pair leakage, immutable successor manifests, and retained evaluation
lineage.

Validates: Requirements 9.8-9.11.
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from src.ecatsl.dataset_release import (  # noqa: E402
    SPLITS,
    assign_split,
    build_release,
)
from src.ecatsl.models import Provenance  # noqa: E402

_OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))

_GROUPS = st.tuples(
    st.sampled_from(["alpha", "beta", "gamma"]),
    st.integers(min_value=0, max_value=5),
).map(lambda t: f"{t[0]}:2024Q{t[1]}")

_VERSIONS = st.sampled_from(("v1", "v2", "transform:dedup@1"))


def _provenance(tag="split-lineage") -> Provenance:
    return Provenance(
        origin="local-fixture",
        retrieved_at=_OFFSET_TIME,
        source_identifier="bench/datasets/VulnGym",
        source_revision="v0.1.4",
        content_identity=f"dataset:{tag}",
    )


def _rows(groups, pairs):
    """Rows grouped by Project_Time_Group; ``pairs`` maps row index -> pair_id."""
    rows = []
    for i, group in enumerate(groups):
        content = f"content-{i}".encode()
        rows.append(
            {
                "id": f"s{i}",
                "content": content,
                "content_hash": sha256(content).hexdigest(),
                "classification": "vulnerable" if i % 2 == 0 else "fixed",
                "project_id": group.split(":")[0],
                "project_time_group": group,
                "pair_id": pairs.get(i),
            }
        )
    return rows


def _build(rows, *, version="v1", tracked=None, predecessor_id=None):
    return build_release(
        rows,
        version=version,
        created_at=_OFFSET_TIME,
        provenance=_provenance(),
        data_type="benchmark_sample",
        tracked=tracked,
        predecessor_id=predecessor_id,
    )


def _split_of(manifest, sample_id):
    return next(
        a.value for a in manifest.split_assignments if a.name == f"split:{sample_id}"
    )


@settings(max_examples=100)
@given(st.lists(_GROUPS, min_size=1, max_size=10, unique=True), st.data())
def test_no_group_or_pair_leakage_across_splits(groups, data):
    """Req 9.8-9.9: one split per Project_Time_Group; pairs never span splits."""
    # Every row in a group shares one pair_id (pairs are group-internal).
    pairs = {i: f"pair-{g}" for i, g in enumerate(groups)}
    rows = _rows(groups, pairs)
    manifest, _ = _build(rows)

    for group in groups:
        members = [rec["id"] for rec in rows if rec["project_time_group"] == group]
        splits = {_split_of(manifest, sid) for sid in members}
        assert len(splits) == 1
        assert splits == {assign_split(group)}
        assert splits.pop() in SPLITS
        # Pair members share the group split: no cross-split pair leak.
        pair_split = {_split_of(manifest, f"s{i}") for i, g in enumerate(groups) if g == group}
        assert len(pair_split) == 1

    # Every retained row has exactly one split assignment.
    assert len(manifest.split_assignments) == len(rows)

    # A paired relationship landing in two splits is rejected outright.
    # Deterministically pick a second group whose split differs from the first.
    first_group = "alpha:2024Q1"
    first_split = assign_split(first_group)
    second_group = next(
        (g for g in (f"g{i}:2024Q2" for i in range(64)) if assign_split(g) != first_split),
        None,
    )
    assert second_group is not None
    leaked = [
        {"id": "a", "content": b"a", "content_hash": sha256(b"a").hexdigest(),
         "classification": "vulnerable",
         "project_id": "p1", "project_time_group": first_group, "pair_id": "px"},
        {"id": "b", "content": b"b", "content_hash": sha256(b"b").hexdigest(),
         "classification": "fixed",
         "project_id": "p2", "project_time_group": second_group, "pair_id": "px"},
    ]
    try:
        _build(leaked)
    except ValueError as exc:
        assert "paired samples leaked across splits" in str(exc)
    else:
        raise AssertionError("cross-split pair was not rejected")


@settings(max_examples=100)
@given(st.lists(_GROUPS, min_size=1, max_size=8, unique=True), _VERSIONS, _VERSIONS)
def test_tracked_changes_create_immutable_successors(groups, version_a, version_b):
    """Req 9.10-9.11: identical inputs replay identically; tracked changes and
    new versions produce new immutable manifest identities with lineage."""
    rows = _rows(groups, {i: f"pair-{g}" for i, g in enumerate(groups)})

    base, base_quality = _build(rows, version=version_a)
    replay, _ = _build(rows, version=version_a)
    # Same inputs: identical immutable release (stable evaluation lineage).
    assert base.model_dump_json() == replay.model_dump_json()
    assert base_quality.model_dump_json() == _build(rows, version=version_a)[1].model_dump_json()

    # Version bump alone re-issues a distinct manifest identity (Req 9.10).
    successor, _ = _build(rows, version=f"{version_a}+1")
    assert successor.model_dump_json() != base.model_dump_json()

    # A tracked configuration change is version-defining too.
    tracked_a, _ = _build(rows, version=version_a, tracked={"transform": "t1"})
    tracked_b, _ = _build(rows, version=version_a, tracked={"transform": "t2"})
    assert tracked_a.model_dump_json() != tracked_b.model_dump_json()
    # Same tracked inputs replay identically.
    assert tracked_a.model_dump_json() == _build(
        rows, version=version_a, tracked={"transform": "t1"}
    )[0].model_dump_json()

    # Successor manifests retain the lineage pointer (Req 9.11).
    linked, _ = _build(rows, version=version_a, predecessor_id=base.artifact_id)
    assert linked.artifact_id != base.artifact_id
    assert linked.predecessor_id == base.artifact_id
    # Evaluated lineage is retained: same samples, splits, and provenance.
    assert linked.samples == base.samples
    assert linked.split_assignments == base.split_assignments
    assert linked.provenance == base.provenance
