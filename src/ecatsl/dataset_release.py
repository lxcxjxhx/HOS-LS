"""Immutable dataset releases and leakage-safe splits (Task 7.1, Req 9.1-9.11).

Pure decision layer on top of the existing ecatsl artifact models. Every
release function takes fully-typed rows (one dict per benchmark sample) so
callers can feed VulnGym entries (``bench/datasets/VulnGym/data/entries.jsonl``)
or synthetic fixtures without I/O coupling. Content identities are derived by
the Artifact base model itself, so any tracked change to samples, splits, or
metadata produces a new immutable manifest id (Req 9.10).
"""
import json
from hashlib import sha256

from .models import (
    Attribute,
    BenchmarkManifest,
    BenchmarkSample,
    DataQualityReport,
)

SPLITS = ("train", "validation", "evaluation")
REQUIRED_FIELDS = ("id", "content_hash", "classification")


def integrity(content, expected):
    """Req 9.4: verify recorded hash against retrieved content."""
    return "VERIFIED" if sha256(content).hexdigest() == expected else "FAILED"


def deterministic_transform(content, version):
    """Req 9.6: same input hash + version always yields the same output hash."""
    return sha256(version.encode() + b"\0" + content).hexdigest()


def canonicalize(records):
    """Req 9.5: one canonical record per (content_hash, data_type); identities kept."""
    canonical: dict[tuple[str, str], dict] = {}
    duplicates: dict[tuple[str, str], list] = {}
    for record in records:
        key = (record["content_hash"], record["data_type"])
        if key in canonical:
            duplicates.setdefault(canonical[key]["id"], []).append(record["id"])
        else:
            canonical[key] = record
    return tuple(canonical.values()), duplicates


def assign_split(project_time_group):
    """Deterministic split keyed on Project_Time_Group (Req 9.8)."""
    return SPLITS[int(sha256(project_time_group.encode()).hexdigest(), 16) % 3]


def _attr(name, value):
    return Attribute(name=name, value=str(value))


def build_samples(records):
    """Req 9.2: typed Paired_Sample rows with pair links and Project_Time_Group."""
    return tuple(
        BenchmarkSample(
            sample_id=rec["id"],
            classification=rec["classification"],
            project_id=rec["project_id"],
            project_time_group=rec["project_time_group"],
            content_hash=rec["content_hash"],
            pair_id=rec.get("pair_id"),
        )
        for rec in records
    )


def build_release(
    records,
    *,
    version,
    created_at,
    provenance,
    data_type,
    catalog_record_ids=(),
    tracked=None,
    required_fields=REQUIRED_FIELDS,
    transform=None,
    predecessor_id=None,
):
    """One immutable release: verify, canonicalize, transform, split, report.

    Row keys: ``id``, ``content_hash``, ``classification``, ``project_id``,
    ``project_time_group``; optional ``content`` (bytes; omit to trust the
    supplied hash), ``pair_id``, ``collected_at``, ``source_metadata``.
    ``tracked``: version-defining inputs (Req 9.10) recorded in the report.
    Returns ``(manifest, quality)``.
    """
    integrity_results = []
    validity = []
    valid_rows = []
    excluded = []
    for rec in records:
        if "content" in rec:
            outcome = integrity(rec["content"], rec["content_hash"])
            integrity_results.append(_attr(f"integrity:{rec['id']}", outcome))
            if outcome == "FAILED":
                excluded.append(f"integrity_failed:{rec['id']}")
                continue
        missing = [f for f in required_fields if not rec.get(f)]
        if missing:
            validity.append(_attr(f"invalid:{rec['id']}", f"missing:{','.join(missing)}"))
            excluded.append(f"missing_fields:{rec['id']}")
            continue
        validity.append(_attr(f"valid:{rec['id']}", "fields_ok"))
        valid_rows.append(rec)

    canonical, duplicates = canonicalize(
        [
            {
                "id": f"{rec['id']}@{rec['content_hash'][:12]}:{data_type}",
                "content_hash": rec["content_hash"],
                "data_type": data_type,
            }
            for rec in valid_rows
        ]
    )
    duplicate_count = sum(len(ids) for ids in duplicates.values())

    # Req 9.9: one split decision per Project_Time_Group, shared atomically by
    # every sample (and every pair member) in that group.
    group_split: dict[str, str] = {}
    id_split = {}
    split_assignments = []
    for rec in valid_rows:
        split = group_split.setdefault(rec["project_time_group"], assign_split(rec["project_time_group"]))
        id_split[rec["id"]] = split
        split_assignments.append(_attr(f"split:{rec['id']}", split))

    # A paired vulnerable/fixed-or-clean relationship may not leak across splits.
    pair_splits: dict[str, str] = {}
    for rec in valid_rows:
        pair_id = rec.get("pair_id")
        if pair_id and pair_splits.setdefault(pair_id, id_split[rec["id"]]) != id_split[rec["id"]]:
            raise ValueError(f"paired samples leaked across splits: {pair_id}")

    transform_version = transform[0] if transform else None

    completeness = (
        _attr("record_count", len(records)),
        _attr("retained_count", len(valid_rows)),
        _attr("canonical_count", len(canonical)),
    )
    if tracked:
        completeness += tuple(_attr(f"tracked:{k}", v) for k, v in sorted(tracked.items()))

    report = DataQualityReport(
        version=version,
        created_at=created_at,
        provenance=provenance,
        completeness=completeness,
        validity=tuple(validity),
        integrity_results=tuple(integrity_results),
        duplicate_count=duplicate_count,
        excluded_count=len(excluded),
        exclusion_reasons=tuple(sorted(excluded)),
    )

    provenance_json = provenance.model_dump_json()
    sample_attributes = []
    for rec in valid_rows:
        for key in ("project_id", "classification", "collected_at", "source_metadata"):
            if rec.get(key) is not None:
                sample_attributes.append(_attr(f"{key}:{rec['id']}", rec[key]))
        if transform_version is not None:
            sample_attributes.append(
                _attr(f"transform:{rec['id']}",
                      deterministic_transform(rec["content_hash"].encode(), transform_version))
            )
        sample_attributes.append(_attr("provenance", provenance_json))
    if tracked:
        # Req 9.10: tracked changes redefine the manifest identity.
        sample_attributes.extend(
            _attr(f"tracked:{k}", v) for k, v in sorted(tracked.items())
        )

    manifest = BenchmarkManifest(
        version=version,
        created_at=created_at,
        provenance=provenance,
        predecessor_id=predecessor_id,
        samples=build_samples(valid_rows),
        catalog_record_ids=tuple(catalog_record_ids),
        split_assignments=tuple(split_assignments),
        sample_attributes=tuple(sample_attributes),
    )
    return manifest, report


def load_vulngym_entries(path, collected_at=None):
    """Build release-ready rows from ``bench/datasets/VulnGym/data/entries.jsonl``."""
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            content = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
            rows.append({
                "id": entry["entry_id"],
                "content": content,
                "content_hash": sha256(content).hexdigest(),
                "classification": "vulnerable",
                "project_id": entry["project"],
                "project_time_group": f"{entry['project']}:{entry['commit'][:12]}",
                "collected_at": collected_at,
                "source_metadata": entry.get("source_link", ""),
                "pair_id": entry.get("report_id"),
            })
    return rows
