"""Framework-neutral, hypothesis-only repository discovery (Task 6.4).

The concrete :class:`RepositoryDiscovery` assistance derives non-confirmatory
``DiscoveryObservation`` hypotheses from repository code, repository-contained
configuration, and available import/call-graph evidence.  It never reads a
user-authored route list: every strategy is generic structural discovery
(Requirement 11.10).  :class:`DiscoveryPolicy` rejects a strategy only when it
simultaneously enumerates individual routes, is hard-coded, does not generalize
across supported evidence, and requires user route maintenance (Requirement
11.11).

All observations are provenance-linked, carry file/content identities, and are
non-confirmatory: no endpoint/entrypoint/API observation can become a
Confirmed_Finding or produce Path_Evidence (Requirements 4.2-4.3, 11.12-11.13).
Per-run data-quality telemetry counts parsed, skipped, invalid, and failed
files and observation totals (Requirement 11.9).

_Requirements: 1.4, 4.2-4.3, 7.1-7.3, 11.9-11.13_
"""

import ast
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from typing import Any, Mapping, Optional, Sequence, Tuple

from .models import (
    Attribute,
    CandidateHypothesis,
    DiscoveryObservation,
    Provenance,
    TaintTemplate,
)

# Discovery producers and derivation kinds (versioned identities).
DISCOVERY_PRODUCER = "ecatsl-repository-discovery"
DISCOVERY_PRODUCER_VERSION = "1"
DERIVATION_KINDS = (
    "repository_code",
    "repository_config",
    "repository_import_graph",
)
RANKING_PROFILE_VERSION = "discovery-rank/v2"

# Versioned deterministic weights combining the catalog rank position of the
# ordered templates, the documented applicability/scope match, and the
# repository observation kind (Task 6.5, Requirement 1.5-1.7).
RANKING_WEIGHTS = {
    "catalog_rank": 0.4,
    "applicability": 0.3,
    "observation": 0.3,
}

# Observation-kind weights: entrypoints weigh more than plain functions.
OBSERVATION_WEIGHTS = {
    "entrypoint": 1.0,
    "configuration": 0.9,
    "function": 0.5,
    "import_graph": 0.25,
}

# Generic, data-driven configuration keys that name repository entrypoints.
# These are template keys, not user-maintained per-route enumerations.
_CONFIG_ENDPOINT_KEYS = frozenset(
    {
        "endpoint",
        "entrypoint",
        "api_path",
        "api_prefix",
        "url_prefix",
        "route_prefix",
    }
)
_CONFIG_COMMENT_PREFIXES = ("#", "//", ";")


@dataclass(frozen=True)
class DiscoveryTelemetry:
    """Data-quality telemetry for one discovery run."""

    files_scanned: int
    parsed: int
    skipped: int
    invalid: int
    failed: int
    observations: int
    latency_ms: int

    @property
    def total_files(self) -> int:
        return self.parsed + self.skipped + self.invalid + self.failed


class DiscoveryPolicy:
    """Strategy validation: reject only brittle per-route enumeration.

    A strategy may be rejected only when every prohibited trait holds at once
    (Requirement 11.11): it enumerates individual routes/patterns, is hard-coded
    rather than evidence/data-driven, does not generalize across supported
    evidence, and requires the user to maintain route entries.
    """

    @staticmethod
    def _traits(strategy: Any) -> Mapping[str, Any]:
        if isinstance(strategy, Mapping):
            return strategy
        traits = {
            name: getattr(strategy, name)
            for name in (
                "strategy_kind",
                "enumerates_individual_routes",
                "hard_coded",
                "generalizes_across_evidence",
                "requires_user_route_maintenance",
            )
            if hasattr(strategy, name)
        }
        return traits

    def validate(self, strategy: Any) -> Tuple[bool, str]:
        traits = self._traits(strategy)
        rejected = (
            bool(traits.get("enumerates_individual_routes", False))
            and bool(traits.get("hard_coded", False))
            and not bool(traits.get("generalizes_across_evidence", True))
            and bool(traits.get("requires_user_route_maintenance", False))
        )
        if rejected:
            return (
                False,
                "rejected brittle user-maintained per-route enumeration",
            )
        return True, "allowed generic discovery"


DISCOVERY_POLICY = DiscoveryPolicy()


def _file_sha256(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _is_config_file(path: Path) -> bool:
    """Reuse the existing ConfigScanner extension classification."""
    try:
        from src.analyzers.config_scanner import ConfigScanner

        extensions = ConfigScanner.CONFIG_EXTENSIONS
    except Exception:
        extensions = {
            ".yml", ".yaml", ".properties", ".xml", ".json", ".env",
            ".toml", ".ini", ".conf",
        }
    return path.suffix.lower() in extensions


def _parse_config_content(path: Path, text: str) -> Tuple[Optional[dict], bool]:
    """Best-effort generic config parse; returns (mapping, valid_flag)."""
    try:
        if path.suffix.lower() == ".json":
            value = json.loads(text)
            if isinstance(value, dict):
                return value, True
            return None, True
        mapping: dict[str, Any] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(_CONFIG_COMMENT_PREFIXES):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
            elif ":" in line:
                key, _, value = line.partition(":")
            else:
                continue
            key = key.strip().strip("\"'")
            value = value.strip().strip("\"'")
            if key:
                mapping[key] = value
        return mapping, True
    except (ValueError, TypeError):
        return None, False


def _collect_strings(value: Any, out: list[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if (
                str(key).lower() in _CONFIG_ENDPOINT_KEYS
                and isinstance(item, str)
                and item.strip()
            ):
                out.append((str(key), item.strip()))
            else:
                _collect_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _collect_strings(item, out)


class RepositoryDiscovery:
    """Generic repository-driven discovery of entrypoints and API candidates.

    ``discover`` scans repository code (Python AST), repository-contained
    configuration, and local import edges without any route configuration.
    ``rank`` pairs observations with in-scope non-confirmatory templates into
    ``CandidateHypothesis`` records deterministically.
    """

    def __init__(
        self,
        *,
        policy: Optional[DiscoveryPolicy] = None,
        producer: str = DISCOVERY_PRODUCER,
        producer_version: str = DISCOVERY_PRODUCER_VERSION,
        language: str = "python",
    ) -> None:
        self.policy = policy or DISCOVERY_POLICY
        self.producer = producer
        self.producer_version = producer_version
        self.language = language
        self.last_telemetry: Optional[DiscoveryTelemetry] = None

    # ---------------------------------------------------------------- discover

    def discover(
        self, root: str, provenance: Provenance
    ) -> Sequence[DiscoveryObservation]:
        started = perf_counter()
        root_path = Path(root)
        files = (
            [root_path]
            if root_path.is_file()
            else sorted(
                (path for path in root_path.rglob("*") if path.is_file())
            )
        )
        observations: list[DiscoveryObservation] = []
        parsed = 0
        skipped = 0
        invalid = 0
        failed = 0
        for path in files:
            suffix = path.suffix.lower()
            is_config = _is_config_file(path)
            if suffix != ".py" and not is_config:
                skipped += 1
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                if suffix == ".py":
                    observed = self._observe_python(path, text, provenance)
                    if observed is None:
                        invalid += 1
                        continue
                    parsed += 1
                    observations.extend(observed)
                else:
                    mapping, valid = _parse_config_content(path, text)
                    if not valid:
                        invalid += 1
                        continue
                    parsed += 1
                    collected: list[tuple[str, str]] = []
                    _collect_strings(mapping, collected)
                    if collected:
                        observations.append(
                            self._observation(
                                provenance=provenance,
                                derivation_kind="repository_config",
                                path=path,
                                line=1,
                                name="configuration entrypoints",
                                extra=(
                                    Attribute(name="config_file", value=str(path)),
                                    Attribute(
                                        name="keys",
                                        value=",".join(
                                            sorted({key for key, _ in collected})
                                        ),
                                    ),
                                    Attribute(
                                        name="values",
                                        value=",".join(
                                            value for _, value in collected
                                        ),
                                    ),
                                ),
                            )
                        )
            except Exception:
                failed += 1
        latency_ms = int((perf_counter() - started) * 1000)
        self.last_telemetry = DiscoveryTelemetry(
            files_scanned=len(files),
            parsed=parsed,
            skipped=skipped,
            invalid=invalid,
            failed=failed,
            observations=len(observations),
            latency_ms=latency_ms,
        )
        return tuple(observations)

    def _observe_python(
        self, path: Path, text: str, provenance: Provenance
    ) -> Optional[Sequence[DiscoveryObservation]]:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return None
        observations: list[DiscoveryObservation] = []
        content_identity = _file_sha256(text)
        has_entrypoint = False
        imports: list[str] = []
        functions: list[tuple[str, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append((node.name, node.lineno))
                for decorator in getattr(node, "decorator_list", ()):
                    if self._is_entrypoint_decorator(decorator):
                        observations.append(
                            self._observation(
                                provenance=provenance,
                                derivation_kind="repository_code",
                                path=path,
                                line=node.lineno,
                                name=node.name,
                                extra=(
                                    Attribute(name="kind", value="entrypoint"),
                                    Attribute(name="decorator", value="http-handler"),
                                ),
                                content_identity=content_identity,
                            )
                        )
            if isinstance(node, ast.If):
                test = node.test
                if (
                    isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                ):
                    has_entrypoint = True
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name.split(".")[0])
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imports.append(module.split(".")[0])
        if has_entrypoint:
            observations.append(
                self._observation(
                    provenance=provenance,
                    derivation_kind="repository_code",
                    path=path,
                    line=1,
                    name="__main__ entrypoint",
                    extra=(
                        Attribute(name="kind", value="entrypoint"),
                        Attribute(name="guard", value="__main__"),
                    ),
                    content_identity=content_identity,
                )
            )
        for name, lineno in functions:
            observations.append(
                self._observation(
                    provenance=provenance,
                    derivation_kind="repository_code",
                    path=path,
                    line=lineno,
                    name=name,
                    extra=(Attribute(name="kind", value="function"),),
                    content_identity=content_identity,
                )
            )
        local_imports = sorted(
            {name for name in imports if name not in {"os", "sys", "re", "json"}}
        )
        if local_imports:
            observations.append(
                self._observation(
                    provenance=provenance,
                    derivation_kind="repository_import_graph",
                    path=path,
                    line=1,
                    name="module imports",
                    extra=(
                        Attribute(name="imports", value=",".join(local_imports)),
                        Attribute(name="kind", value="import_graph"),
                    ),
                    content_identity=content_identity,
                )
            )
        return observations

    @staticmethod
    def _is_entrypoint_decorator(decorator: Any) -> bool:
        """Data-driven HTTP-handler decorator shape (framework-agnostic)."""
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
            return decorator.func.attr.lower() in {
                "route", "get", "post", "put", "delete", "patch", "add_route",
            }
        return False

    def _observation(
        self,
        *,
        provenance: Provenance,
        derivation_kind: str,
        path: Path,
        line: int,
        name: str,
        extra: Tuple[Attribute, ...],
        content_identity: Optional[str] = None,
    ) -> DiscoveryObservation:
        now = datetime.now(timezone.utc)
        return DiscoveryObservation(
            version="1",
            created_at=now,
            provenance=provenance,
            derivation_kind=derivation_kind,
            locations=(f"{path}:{line}",),
            source_content_identities=(
                content_identity or _file_sha256(path.read_text(errors="replace")),
            ),
            producer=self.producer,
            producer_version=self.producer_version,
            context=(Attribute(name="name", value=name),) + extra,
        )

    # ------------------------------------------------------------------- rank

    def rank(
        self,
        observations: Sequence[DiscoveryObservation],
        templates: Sequence[TaintTemplate],
        provenance: Provenance,
    ) -> Sequence[CandidateHypothesis]:
        """Combine observations with ranked templates (versioned scores).

        ``templates`` arrive in catalog-ranking order (Task 6.3 provider), so
        the hypothesis score deterministically combines the catalog rank
        position, the documented applicability/scope decision, and the
        observation kind weight.  Every hypothesis retains both the discovery
        and the catalog input identities and stays non-confirmatory
        (Requirement 1.5-1.7, 11.9, 11.13).
        """
        ranked: list[CandidateHypothesis] = []
        template_count = len(templates)
        for position, template in enumerate(templates):
            catalog_rank = (template_count - position) / template_count
            applicability_match = (
                1.0
                if template.applicability.language == self.language
                else 0.0
            )
            for observation in observations:
                if observation.derivation_kind not in DERIVATION_KINDS:
                    continue
                observation_score = self._observation_weight(observation)
                score = (
                    RANKING_WEIGHTS["catalog_rank"] * catalog_rank
                    + RANKING_WEIGHTS["applicability"] * applicability_match
                    + RANKING_WEIGHTS["observation"] * observation_score
                )
                ranked.append(
                    CandidateHypothesis(
                        version="1",
                        created_at=datetime.now(timezone.utc),
                        provenance=provenance,
                        candidate_type=template.role,
                        api_signature=template.api_shape,
                        applicability=template.applicability,
                        cwe_id=template.cwe_id,
                        evidence_ids=(
                            observation.artifact_id,
                            template.artifact_id,
                        ),
                        ranking_score=score,
                        ranking_profile_version=RANKING_PROFILE_VERSION,
                    )
                )
        ranked.sort(
            key=lambda item: (
                -item.ranking_score,
                item.cwe_id,
                item.api_signature,
                item.evidence_ids,
            )
        )
        return tuple(ranked)

    def _observation_weight(self, observation: DiscoveryObservation) -> float:
        """Data-driven observation kind weight for hypothesis ranking."""
        if observation.derivation_kind == "repository_config":
            return OBSERVATION_WEIGHTS["configuration"]
        kind = next(
            (
                attribute.value
                for attribute in observation.context
                if attribute.name == "kind"
            ),
            "function",
        )
        return OBSERVATION_WEIGHTS.get(kind, OBSERVATION_WEIGHTS["function"])
