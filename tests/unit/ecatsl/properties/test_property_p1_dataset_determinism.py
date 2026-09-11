"""Feature: ecatsl-operationalization-and-bench-integration, Property P1 tests.

Property P1 (dataset build determinism): row-order shuffles and duplicate
rows of manifest inputs never change the emitted release for retained
samples, corrupt rows are always excluded with the precise
``integrity_failed:<sample_id>`` reason, and below the 60-sample minimum
the quality report truthfully records ``insufficient_samples`` with the
actual count (never inflated).

Validates: Requirements 4.1-4.4 (tasks.md 4.3, label
``Feature: ecatsl-operationalization-and-bench-integration, Property P1``).
"""

from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from src.ecatsl.eval_dataset import (
    MINIMUM_PAIRED_SAMPLES,
    EvalManifest,
    EvalSampleEntry,
    build_manifest,
    emit_release,
)

FIXED = datetime(2025, 1, 1, tzinfo=timezone.utc)


def _fixed_clock():
    return FIXED


NON_PYTHON_SUFFIXES = (".ts", ".svelte", ".go", ".md", "")


def make_entry(idx, python=True):
    """VulnGym-shaped row; suffix choice drives the Python-ecosystem filter."""
    suffix = ".py" if python else NON_PYTHON_SUFFIXES[idx % len(NON_PYTHON_SUFFIXES)]
    return {
        "entry_id": f"entry-{idx:04d}",
        "project": "proj",
        "repo_url": "https://github.com/example/proj",
        "commit": f"c{idx:012d}",
        "vuln_ids": [f"CVE-2025-{idx:04d}"],
        "report_id": f"GHSA-test-{idx:04d}",
        "entry_point": {"file": f"src/app{idx}{suffix}"},
        "critical_operation": {"file": f"src/lib{idx}{suffix}"},
        "trace": [{"file": f"src/hop{idx}{suffix}"}],
    }


def _write_and_emit(tmp_path, manifest, name="manifest.json"):
    path = tmp_path / name
    path.write_text(manifest.to_json(), encoding="utf-8")
    return emit_release(path, clock=_fixed_clock)


def _attr_value(quality, name):
    for attribute in quality.completeness:
        if attribute.name == name:
            return attribute.value
    return None


@settings(max_examples=100, deadline=None)
@given(data=st.data())
def test_p1_row_order_and_duplicates_are_order_independent(tmp_path_factory, data):
    """Req 4.1/4.3: shuffled and duplicated inputs emit identical releases."""
    n = data.draw(st.integers(min_value=1, max_value=8))
    base = [make_entry(i) for i in range(n)]
    order = data.draw(st.permutations(base))
    duplicates = data.draw(st.integers(min_value=0, max_value=3))
    perturbed = list(order) + [dict(row) for row in order[:duplicates]]

    first = build_manifest(base, clock=_fixed_clock, build_command="p1")
    second = build_manifest(perturbed, clock=_fixed_clock, build_command="p1")
    # Retained rows are order-independent; diagnostic counters honestly
    # disclose perturbation artifacts (duplicates are counted, never merged
    # silently), so equality is asserted per scope (Req 4.1/4.3).
    assert first.to_dict()["entries"] == second.to_dict()["entries"]
    # Duplicate rows appended = min(duplicates, n) because the perturbation
    # draws copies from the shuffled order itself (len(order) = n).
    assert second.duplicate_entry_ids == min(duplicates, n)
    assert [e.sample_id for e in second.entries] == sorted(
        e.sample_id for e in second.entries
    )

    tmp_path = tmp_path_factory.mktemp("p1_order")
    manifest_a, quality_a = _write_and_emit(tmp_path, first, "a.json")
    manifest_b, quality_b = _write_and_emit(tmp_path, first, "b.json")
    # Same manifest content from a different path must replay byte-identical:
    # the release identity is content-derived, path-independent (Req 4.3).
    assert manifest_a.model_dump_json() == manifest_b.model_dump_json()
    assert quality_a.model_dump_json() == quality_b.model_dump_json()
    # Duplicated shuffled input yields the same sample set & split decisions;
    # only honest diagnostic counters (duplicate_count etc.) may differ.
    manifest_c, _ = _write_and_emit(tmp_path, second, "c.json")
    assert [s.sample_id for s in manifest_a.samples] == [
        s.sample_id for s in manifest_c.samples
    ]
    assert [s.content_hash for s in manifest_a.samples] == [
        s.content_hash for s in manifest_c.samples
    ]
    assert [a.name + "=" + a.value for a in manifest_a.split_assignments] == [
        a.name + "=" + a.value for a in manifest_c.split_assignments
    ]


@settings(max_examples=100, deadline=None)
@given(data=st.data())
def test_p1_corrupt_hash_rows_are_excluded_precisely(tmp_path_factory, data):
    """Req 4.3: corrupt rows never enter the release; reasons name them."""
    n = data.draw(st.integers(min_value=2, max_value=8))
    manifest = build_manifest(
        [make_entry(i) for i in range(n)], clock=_fixed_clock, build_command="p1"
    )
    corrupt_count = data.draw(st.integers(min_value=1, max_value=n - 1))
    corrupt_ids = data.draw(
        st.sets(st.sampled_from([e.sample_id for e in manifest.entries]),
                min_size=corrupt_count, max_size=corrupt_count)
    )
    tampered_entries = tuple(
        e if e.sample_id not in corrupt_ids else
        EvalSampleEntry(
            sample_id=e.sample_id, source=e.source, repo_url=e.repo_url,
            vuln_ids=e.vuln_ids, label=e.label, cwe_map=e.cwe_map,
            workdir=e.workdir, hash="0" * 64,
            project_time_group=e.project_time_group, pair_id=e.pair_id,
            filter_evidence=e.filter_evidence,
        )
        for e in manifest.entries
    )
    broken = EvalManifest(
        entries=tampered_entries, source_release=manifest.source_release,
        build_command=manifest.build_command, built_at=manifest.built_at,
        filter_rules=manifest.filter_rules,
        unmapped_cwe_count=manifest.unmapped_cwe_count,
        duplicate_entry_ids=manifest.duplicate_entry_ids,
        excluded_non_python=manifest.excluded_non_python,
        invalid_entries=manifest.invalid_entries,
    )
    tmp_path = tmp_path_factory.mktemp("p1_corrupt")
    _, quality = _write_and_emit(tmp_path, broken)
    assert quality.excluded_count == corrupt_count
    for sample_id in corrupt_ids:
        assert f"integrity_failed:{sample_id}" in quality.exclusion_reasons
    retained = int(_attr_value(quality, "retained_count"))
    assert retained == n - corrupt_count


@settings(max_examples=100, deadline=None)
@given(n=st.integers(min_value=1, max_value=59), data=st.data())
def test_p1_insufficient_samples_recorded_truthfully(tmp_path_factory, n, data):
    """Req 4.4: below 60 retained samples the report says so, with counts."""
    python_count = data.draw(st.integers(min_value=max(n, 1), max_value=n))
    rows = [make_entry(i, python=(i < python_count)) for i in range(n)]
    manifest = build_manifest(rows, clock=_fixed_clock, build_command="p1")
    assert len(manifest.entries) == python_count
    assert manifest.excluded_non_python == n - python_count

    tmp_path = tmp_path_factory.mktemp("p1_insufficient")
    _, quality = _write_and_emit(tmp_path, manifest)
    retained = int(_attr_value(quality, "retained_count"))
    assert retained == python_count
    if retained < MINIMUM_PAIRED_SAMPLES:
        assert _attr_value(quality, "insufficient_samples") == "true"
        assert int(_attr_value(quality, "sample_minimum")) == MINIMUM_PAIRED_SAMPLES
        assert int(_attr_value(quality, "unmapped_cwe_count")) == retained


def test_p1_sufficient_dataset_has_no_insufficient_flag(tmp_path_factory):
    """Req 4.4 boundary: exactly 60 retained samples is sufficient."""
    manifest = build_manifest(
        [make_entry(i) for i in range(MINIMUM_PAIRED_SAMPLES)],
        clock=_fixed_clock, build_command="p1",
    )
    tmp_path = tmp_path_factory.mktemp("p1_sufficient")
    _, quality = _write_and_emit(tmp_path, manifest)
    assert int(_attr_value(quality, "retained_count")) == MINIMUM_PAIRED_SAMPLES
    assert _attr_value(quality, "insufficient_samples") is None
