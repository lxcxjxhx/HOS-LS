"""Operational evaluation dataset builder (Task 4.1, Req 4.1-4.5).

Deterministic, replayable selection of a Python-ecosystem subset from
VulnGym-style entry rows into an auditable manifest, plus release emission
that reuses ``dataset_release.build_release`` full semantics (content-hash
verification, canonicalization, duplicate-identity preservation, and
project-time-group leakage-safe splits, Req 9.1-9.11).

The clock is injected so byte-identical replays are possible (Req 4.1/4.3).
Selection rules are data, written into the manifest for audit (Req 4.1);
CWE is never guessed (Req 4.2); the VulnGym submodule is never written to
(Req 4.5) -- all derivatives live wherever the caller persists the manifest.
"""
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Tuple

from .dataset_release import build_release
from .models import Attribute, BenchmarkManifest, DataQualityReport, Provenance

#: Req 4.4: below this many retained paired samples the quality report must
#: say ``insufficient_samples`` and report the actual count -- never inflate.
MINIMUM_PAIRED_SAMPLES = 60

#: Req 4.2 provenance tag for samples selected straight from VulnGym rows.
SOURCE_VULNGYM = "vulngym"

#: Python-ecosystem code file suffixes (matched case-insensitively, R1).
PYTHON_CODE_SUFFIXES = frozenset({".py", ".pyi"})

#: Fixed, auditable fallback project-name hints (R2). Substring-matched in
#: lowercase against the ``project`` field and ``repo_url``. File-suffix
#: evidence (R1) always wins; the list ships inside ``FILTER_RULES`` so any
#: borderline call stays auditable in the manifest itself.
PYTHON_PROJECT_HINTS = frozenset(
    {
        "adk-python",
        "airflow",
        "autogpt",
        "langchain-core",
        "langflow",
        "litellm",
        "mlflow",
        "nltk",
        "onnx",
        "fastmcp",
    }
)

#: The full selection policy, persisted into every manifest (Req 4.1 audit).
FILTER_RULES: Tuple[str, ...] = (
    "R1 file_suffix_python: an entry is Python-ecosystem when any code file "
    "(entry_point.file, critical_operation.file, trace[].file) ends with a "
    "Python suffix (.py, .pyi; case-insensitive)",
    "R2 project_hint_python: fallback lowercase substring match of the "
    "project field and repo_url against the fixed hint list "
    f"({', '.join(sorted(PYTHON_PROJECT_HINTS))})",
    "R3 evidence_recording: every retained entry records the matched "
    "rule(s) in filter_evidence; non-matching entries are counted in "
    "excluded_non_python",
    "R4 identity: sample_id = entry_id; duplicate entry_ids keep the first "
    "occurrence in input order and are counted in duplicate_entry_ids",
    "R5 label: VulnGym rows are verified vulnerable findings; the label is "
    "'vulnerable' and is never inferred from vulnerability titles",
    "R6 cwe_policy: no CWE guessing; cwe_map stays null when the source row "
    "carries no CWE and unmapped rows are counted in unmapped_cwe_count",
    "R7 pairing: pair_id = report_id (one advisory, many trace paths)",
    "R8 determinism: retained entries are sorted by sample_id so the "
    "manifest is independent of input row order",
)

Clock = Callable[[], datetime]


def _real_clock() -> datetime:
    """Production default: real UTC clock (injected clocks win, Req 4.1)."""
    return datetime.now(timezone.utc)


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Stable byte form of one manifest row; basis of its content hash."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _entry_payload(entry: "EvalSampleEntry") -> dict:
    """Canonical dict of one row EXCLUDING ``hash`` -- the single hashing
    authority shared by ``build_manifest`` and ``emit_release`` so hash
    verification stays closed and self-reference-free (Req 4.3)."""
    return {
        "sample_id": entry.sample_id,
        "source": entry.source,
        "repo_url": entry.repo_url,
        "vuln_ids": list(entry.vuln_ids),
        "label": entry.label,
        "cwe_map": None if entry.cwe_map is None else list(entry.cwe_map),
        "workdir": entry.workdir,
        "project_time_group": entry.project_time_group,
        "pair_id": entry.pair_id,
        "filter_evidence": list(entry.filter_evidence),
    }


def _repo_name(repo_url: str) -> str:
    stripped = repo_url.strip().rstrip("/")
    return stripped.rsplit("/", 1)[-1] if stripped else ""


def _python_ecosystem_evidence(entry: Mapping[str, Any]) -> Tuple[bool, Tuple[str, ...]]:
    """Apply R1 then R2; return the decision plus its audit evidence."""
    evidence = []
    files = [
        str((entry.get("entry_point") or {}).get("file", "")),
        str((entry.get("critical_operation") or {}).get("file", "")),
    ]
    for hop in entry.get("trace") or ():
        if isinstance(hop, Mapping):
            files.append(str(hop.get("file", "")))
    for path in files:
        suffix = f".{path.rsplit('.', 1)[-1].lower()}" if "." in path else ""
        if suffix in PYTHON_CODE_SUFFIXES:
            evidence.append(f"file_suffix:{path}")
    if evidence:
        return True, tuple(evidence)
    project = str(entry.get("project", "")).lower()
    repo = str(entry.get("repo_url", "")).lower()
    for hint in sorted(PYTHON_PROJECT_HINTS):
        if hint in project or f"/{hint}" in repo:
            evidence.append(f"project_hint:{hint}")
    return bool(evidence), tuple(evidence)


@dataclass(frozen=True)
class EvalSampleEntry:
    """One manifest row (design 4.1): a Python-ecosystem sample to release."""

    sample_id: str
    source: str
    repo_url: str
    vuln_ids: Tuple[str, ...]
    label: str
    cwe_map: Optional[Tuple[str, ...]]  # null = unmapped, never guessed (R6)
    workdir: str
    hash: str  # sha256 of the canonical payload (all fields but hash itself)
    project_time_group: str
    pair_id: Optional[str]
    filter_evidence: Tuple[str, ...]


@dataclass(frozen=True)
class EvalManifest:
    """Selection manifest: auditable filter rules + deterministic rows."""

    entries: Tuple[EvalSampleEntry, ...]
    source_release: str
    build_command: str
    built_at: datetime
    filter_rules: Tuple[str, ...]
    unmapped_cwe_count: int = 0
    duplicate_entry_ids: int = 0
    excluded_non_python: int = 0
    invalid_entries: int = 0

    def to_dict(self) -> dict:
        rows = []
        for entry in self.entries:
            rows.append({**_entry_payload(entry), "hash": entry.hash})
        return {
            "source_release": self.source_release,
            "build_command": self.build_command,
            "built_at": self.built_at.isoformat(),
            "filter_rules": list(self.filter_rules),
            "unmapped_cwe_count": self.unmapped_cwe_count,
            "duplicate_entry_ids": self.duplicate_entry_ids,
            "excluded_non_python": self.excluded_non_python,
            "invalid_entries": self.invalid_entries,
            "entries": rows,
        }

    def to_json(self) -> str:
        """Byte-stable serialization for idempotent replays (Req 4.1)."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvalManifest":
        try:
            entries = tuple(
                EvalSampleEntry(
                    sample_id=str(raw["sample_id"]),
                    source=str(raw["source"]),
                    repo_url=str(raw["repo_url"]),
                    vuln_ids=tuple(str(v) for v in raw["vuln_ids"]),
                    label=str(raw["label"]),
                    cwe_map=None
                    if raw["cwe_map"] is None
                    else tuple(str(c) for c in raw["cwe_map"]),
                    workdir=str(raw["workdir"]),
                    hash=str(raw["hash"]),
                    project_time_group=str(raw["project_time_group"]),
                    pair_id=None if raw["pair_id"] is None else str(raw["pair_id"]),
                    filter_evidence=tuple(str(e) for e in raw["filter_evidence"]),
                )
                for raw in data["entries"]
            )
            return cls(
                entries=entries,
                source_release=str(data["source_release"]),
                build_command=str(data["build_command"]),
                built_at=datetime.fromisoformat(str(data["built_at"])),
                filter_rules=tuple(str(rule) for rule in data["filter_rules"]),
                unmapped_cwe_count=int(data["unmapped_cwe_count"]),
                duplicate_entry_ids=int(data["duplicate_entry_ids"]),
                excluded_non_python=int(data["excluded_non_python"]),
                invalid_entries=int(data["invalid_entries"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"malformed eval manifest: {error}") from error

    @classmethod
    def from_path(cls, path) -> "EvalManifest":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def build_manifest(
    entries: Iterable[Mapping[str, Any]],
    *,
    source: str = SOURCE_VULNGYM,
    clock: Optional[Clock] = None,
    build_command: str = "",
    source_release: str = "",
) -> EvalManifest:
    """Deterministically select the Python-ecosystem subset (Req 4.1/4.2).

    Row-order independent (R8: output sorted by sample_id); duplicates keep
    their first occurrence (R4); CVE/GHSA ids keep their source values and
    CWE stays null when unmapped (R6). The clock is injected so replays
    with the same fixed clock are byte-identical.
    """
    now = (clock or _real_clock)()
    seen = set()
    picked = []
    duplicates = 0
    non_python = 0
    invalid = 0
    unmapped = 0
    for entry in entries:
        entry_id = str(entry.get("entry_id", "") or "").strip()
        if not entry_id:
            invalid += 1
            continue
        if entry_id in seen:
            duplicates += 1
            continue
        seen.add(entry_id)
        is_python, evidence = _python_ecosystem_evidence(entry)
        if not is_python:
            non_python += 1
            continue
        cwe = entry.get("cwe")
        if cwe is None:
            unmapped += 1
        draft = EvalSampleEntry(
            sample_id=entry_id,
            source=source,
            repo_url=str(entry.get("repo_url", "") or ""),
            vuln_ids=tuple(str(v) for v in entry.get("vuln_ids") or ()),
            label="vulnerable",
            cwe_map=None if cwe is None else tuple(str(c) for c in cwe),
            workdir=str(entry.get("workdir", "") or ""),
            hash="",
            project_time_group=(
                f"{entry.get('project', '') or ''}:{str(entry.get('commit', '') or '')[:12]}"
            ),
            pair_id=str(entry.get("report_id", "") or "") or None,
            filter_evidence=evidence,
        )
        digest = sha256(_canonical_bytes(_entry_payload(draft))).hexdigest()
        picked.append(replace(draft, hash=digest))
    # R8: sort by sample_id so the manifest is input-row-order independent.
    picked.sort(key=lambda item: item.sample_id)
    return EvalManifest(
        entries=tuple(picked),
        source_release=source_release,
        build_command=build_command,
        built_at=now,
        filter_rules=FILTER_RULES,
        unmapped_cwe_count=unmapped,
        duplicate_entry_ids=duplicates,
        excluded_non_python=non_python,
        invalid_entries=invalid,
    )


def emit_release(
    manifest_path,
    *,
    version: str = "1",
    clock: Optional[Clock] = None,
    data_type: str = "ecatsl_eval",
) -> Tuple[BenchmarkManifest, DataQualityReport]:
    """Emit the immutable release from a manifest file (Req 4.3/4.4/4.5).

    Reuses ``build_release`` full semantics: every row's canonical payload
    is re-verified against the recorded hash (FAILED rows are excluded with
    a precise reason), duplicates keep their identities, and splits are
    assigned per project-time group without pair leakage. The clock is
    injected; replays with the same fixed clock are byte-identical. Below
    MINIMUM_PAIRED_SAMPLES retained rows, the quality report records
    ``insufficient_samples`` plus the actual count (never inflated).
    """
    manifest = EvalManifest.from_path(manifest_path)
    now = (clock or _real_clock)()
    manifest_bytes = Path(manifest_path).read_bytes()
    rows = []
    for entry in manifest.entries:
        rows.append(
            {
                "id": entry.sample_id,
                "content": _canonical_bytes(_entry_payload(entry)),
                "content_hash": entry.hash,
                "classification": entry.label,
                "project_id": _repo_name(entry.repo_url) or entry.sample_id,
                "project_time_group": entry.project_time_group,
                "pair_id": entry.pair_id,
                "collected_at": manifest.built_at,
                "source_metadata": entry.source,
            }
        )
    provenance = Provenance(
        origin="ecatsl-eval-manifest",
        retrieved_at=now,
        # Path-free identity: the manifest's own content hash keeps replays
        # byte-identical across locations (Req 4.3 idempotency).
        source_identifier="sha256:" + sha256(manifest_bytes).hexdigest(),
        source_revision=manifest.source_release or None,
        content_identity=sha256(manifest_bytes).hexdigest(),
        transformation_history=("build_manifest:python_ecosystem_filter",),
    )
    bench_manifest, quality = build_release(
        tuple(rows),
        version=version,
        created_at=now,
        provenance=provenance,
        data_type=data_type,
    )
    return bench_manifest, _annotate_quality(quality, manifest)


def _annotate_quality(
    quality: DataQualityReport, manifest: EvalManifest
) -> DataQualityReport:
    """Append dataset-level annotations as a fresh immutable report.

    The DataQualityReport is content-addressed, so annotations must live in
    the artifact itself; rebuilding from the same fields keeps replay
    byte-identical (Req 4.3) while recording unmapped-CWE counts (Req 4.2)
    and the insufficient-samples verdict (Req 4.4).
    """
    extra = [
        Attribute(name="unmapped_cwe_count", value=str(manifest.unmapped_cwe_count))
    ]
    retained = _completeness_int(quality, "retained_count")
    if retained is not None and retained < MINIMUM_PAIRED_SAMPLES:
        extra.append(Attribute(name="insufficient_samples", value="true"))
        extra.append(Attribute(name="sample_minimum", value=str(MINIMUM_PAIRED_SAMPLES)))
    return DataQualityReport(
        version=quality.version,
        created_at=quality.created_at,
        provenance=quality.provenance,
        completeness=tuple(quality.completeness) + tuple(extra),
        validity=quality.validity,
        integrity_results=quality.integrity_results,
        duplicate_count=quality.duplicate_count,
        excluded_count=quality.excluded_count,
        exclusion_reasons=quality.exclusion_reasons,
    )


def _completeness_int(quality: DataQualityReport, name: str) -> Optional[int]:
    for attribute in quality.completeness:
        if attribute.name == name:
            try:
                return int(attribute.value)
            except (TypeError, ValueError):
                return None
    return None
