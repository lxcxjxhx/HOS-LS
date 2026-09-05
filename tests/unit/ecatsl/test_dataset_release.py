"""Task 7.1: immutable dataset releases and leakage-safe splits (Req 9.1-9.11)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from src.ecatsl.dataset_release import (
    assign_split,
    build_release,
    canonicalize,
    deterministic_transform,
    integrity,
    load_vulngym_entries,
)
from src.ecatsl.models import Provenance

OFFSET_TIME = datetime(2026, 2, 3, 12, 30, tzinfo=timezone(timedelta(hours=5)))


def provenance(identity: str = "dataset:v1") -> Provenance:
    return Provenance(
        origin="repository",
        retrieved_at=OFFSET_TIME,
        source_identifier="bench/datasets/VulnGym",
        source_revision="v0.1.4",
        content_identity=identity,
        transformation_history=("release:v1",),
    )


def row(rid, *, project="proj-a", group=None, content=b"vuln-code", **extra):
    fields = {
        "id": rid,
        "content": content,
        "content_hash": __import__("hashlib").sha256(content).hexdigest(),
        "classification": "vulnerable",
        "project_id": project,
        "project_time_group": group or f"{project}:t1",
        "pair_id": f"pair-{rid}",
    }
    fields.update(extra)
    return fields


def build(rows, **kw):
    kw.setdefault("version", "1")
    kw.setdefault("created_at", OFFSET_TIME)
    kw.setdefault("provenance", provenance())
    kw.setdefault("data_type", "vulngym_entry")
    return build_release(rows, **kw)


def test_integrity_outcomes():
    assert integrity(b"content", "hash") == "FAILED"
    assert integrity(b"content", __import__("hashlib").sha256(b"content").hexdigest()) == "VERIFIED"


def test_deterministic_transform_stable():
    assert deterministic_transform(b"a", "v1") == deterministic_transform(b"a", "v1")
    assert deterministic_transform(b"a", "v1") != deterministic_transform(b"a", "v2")
    assert deterministic_transform(b"a", "v1") != deterministic_transform(b"b", "v1")


def test_canonicalize_first_wins_and_keeps_duplicates():
    a = {"id": "a@h:t", "content_hash": "h", "data_type": "x"}
    b = {"id": "b@h:t", "content_hash": "h", "data_type": "x"}
    c = {"id": "c@i:t", "content_hash": "i", "data_type": "x"}
    canonical, duplicates = canonicalize([a, b, c])
    assert [rec["id"] for rec in canonical] == ["a@h:t", "c@i:t"]
    assert duplicates == {"a@h:t": ["b@h:t"]}


def test_same_group_same_split():
    assert assign_split("g") == assign_split("g")


def test_release_verifies_hashes_and_reports_quality():
    good = row("s1")
    rows = [good, row("s2", content=b"other"), row("bad", content=b"x", content_hash="deadbeef")]
    manifest, report = build(rows)
    assert len(manifest.samples) == 2
    assert report.excluded_count == 1
    assert report.exclusion_reasons == ("integrity_failed:bad",)
    outcomes = {a.name: a.value for a in report.integrity_results}
    assert outcomes == {"integrity:s1": "VERIFIED", "integrity:s2": "VERIFIED", "integrity:bad": "FAILED"}


def test_release_missing_fields_excluded():
    manifest, report = build([row("ok"), {"id": "no-hash", "classification": "vulnerable"}])
    assert len(manifest.samples) == 1
    assert report.excluded_count == 1
    assert report.exclusion_reasons == ("missing_fields:no-hash",)


def test_duplicate_content_canonicalized_with_identity_retained():
    manifest, report = build([row("s1"), row("s1"), row("s1")])
    assert len(manifest.samples) == 3
    assert report.duplicate_count == 2
    assert any(a.name == "canonical_count" and a.value == "1" for a in report.completeness)


def test_group_and_pair_stay_in_one_split():
    rows = [
        row("s1", project="p1", group="p1:old"),
        row("s2", project="p1", group="p1:old"),
        row("s3", project="p2", group="p2:new"),
    ]
    manifest, _ = build(rows)
    split_of = {a.name: a.value for a in manifest.split_assignments}
    assert split_of["split:s1"] == split_of["split:s2"]
    assert split_of["split:s1"] in {"train", "validation", "evaluation"}


def test_paired_samples_cannot_leak_across_splits():
    rows = [
        row("s1", content=b"before", project="p1", group="p1:old"),
        row("s2", content=b"after", project="p1", group="p1:old"),
    ]
    rows[0]["pair_id"] = rows[1]["pair_id"] = "pair-x"
    rows[0]["project_time_group"] = "p1:old"
    rows[1]["project_time_group"] = "p2:new"
    # The guard rejects any pair whose members land in different splits.
    with pytest.raises(ValueError, match="leaked across splits"):
        build(rows)


def test_tracked_change_creates_new_manifest_version():
    kwargs = dict(version="1", created_at=OFFSET_TIME, provenance=provenance(), data_type="t")
    rows = [row("s1")]
    base, base_report = build_release(rows, **kwargs)
    changed, changed_report = build_release(rows, tracked={"tooling": "hos-ls 0.3.5"}, **kwargs)
    assert base.artifact_id != changed.artifact_id
    assert changed_report.completeness[-1].name == "tracked:tooling"


def test_sample_attributes_carry_provenance_and_metadata():
    manifest, _ = build([row("s1", source_metadata="http://advisory")])
    names = {a.name for a in manifest.sample_attributes}
    assert "provenance" in names
    assert "source_metadata:s1" in names
    assert "project_id:s1" in names
    assert "classification:s1" in names


def test_manifest_is_immutable_release_pair():
    manifest, report = build([row("s1")])
    with pytest.raises(Exception):
        manifest.samples = ()
    assert report.version == "1"


def test_load_vulngym_entries_smoke(tmp_path):
    entry = {
        "entry_id": "entry-00001",
        "project": "open-webui",
        "commit": "9942de8011d4b5a141ac507c974c061c0cdad59a",
        "report_id": "GHSA-X",
        "source_link": "http://advisory",
    }
    path = tmp_path / "entries.jsonl"
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    rows = load_vulngym_entries(path, collected_at="2026-09-04")
    assert rows[0]["id"] == "entry-00001"
    assert rows[0]["project_time_group"] == "open-webui:9942de8011d4"
    manifest, report = build(rows)
    assert len(manifest.samples) == 1
    assert report.excluded_count == 0
