"""ECATSL CLI command group (theme C-1, tasks 3.1; Requirements 3.1-3.5).

Exposes the existing ``src/ecatsl`` decision layers as ``hos-ls ecatsl``
subcommands — ``analyze``, ``dataset``, ``evaluate``, ``report`` — without
adding a scanner, importer, or bypass evaluation path.

``analyze`` wires ``ECATSLService`` exactly as designed (scope gate →
discovery/catalog providers → tooling-first resolution → candidate lifecycle
→ declarative compilation → supported static validation → static-path-gated
confirmation), persists all artifacts into the shared append-only SQLite
store, and prints a structured summary. Single-file discovery/adapter
failures stay isolated by the service itself (audited as ``AuditFailureRecord``
rows with terminal ``FAILED`` semantics); the CLI counts them, verifies their
persistence, and keeps the run alive (Requirement 3.5).

``dataset`` builds an immutable release through ``build_release`` from a
JSONL sample source (zero network). ``evaluate`` builds a verified
``EvaluationReport`` from a release manifest plus per-sample finding
classifications supplied explicitly (the per-sample orchestration that
bridges analyze findings to sample ids is task 5.1's ``eval_runner``).
``report`` emits the ``Cost_Report`` and the paired baseline comparison.

Exit codes (Requirement 3.5): ``0`` complete (any finding count), ``1``
artifact persistence failed, ``2`` usage/configuration error. Every option
value is funneled through ``ECATSLConfig`` validation (``extra="forbid"``
semantics preserved): invalid values exit 2 before any repository state is
written (Requirement 3.2). The clock is injected as a parameter (production
default: real UTC clock) so batch runs stay idempotent under replay. The
confirmation boundary is unchanged (Requirement 3.4): no CLI option can
upgrade catalog/RAG/LLM/discovery output into a confirmation — only a fully
supported static path confirms, as the help text states.
"""

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
import types
from typing import Any, Callable, Optional, Sequence, Tuple, Union, get_args, get_origin

import click

from src.ecatsl.config import ECATSLConfig
from src.ecatsl.evaluation import build_evaluation_report
from src.ecatsl.models import (
    Attribute,
    BenchmarkManifest,
    DataQualityReport,
    DiscoveryObservation,
    EvaluationReport,
    EvaluationTelemetry,
    FindingStatus,
    OperationalComplexity,
    Provenance,
)
from src.ecatsl.reporting import build_cost_report, build_optimization_report

#: Exit-code contract (Requirement 3.5).
EXIT_OK = 0
EXIT_PERSISTENCE_FAILURE = 1
EXIT_USAGE_ERROR = 2

#: Terminal record identities for isolated failures (Requirement 3.5).
TERMINAL_FAILED = "FAILED"
TERMINAL_UNAVAILABLE = "UNAVAILABLE"

#: Artifact types referenced by the CLI summaries/terminal records.
SUMMARY_RECORD_KIND = "cli_analyze_summary"
TERMINAL_RECORD_KIND = "cli_terminal_failure"
CLI_PRODUCER = "hos-ls-ecatsl-cli"
CLI_PRODUCER_VERSION = "1"

CONFIRMATION_BOUNDARY_TEXT = (
    "Confirmation boundary: only a fully supported static path can confirm a "
    "finding. Catalog, RAG, LLM, and discovery outputs are non-confirmatory "
    "explanatory support; no CLI option can upgrade them into a confirmation."
)

CLOCK_METAVAR = "ISO8601_UTC"


# ---------------------------------------------------------------------------
# Clock injection (Requirement 3.1: batch runs replay idempotently)
# ---------------------------------------------------------------------------

def _real_clock() -> datetime:
    """Production default: real UTC clock."""
    return datetime.now(timezone.utc)


def _parse_clock_option(value: Optional[str]) -> Optional[Callable[[], datetime]]:
    """Build a fixed injected clock from ``--clock`` for replayable runs."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise click.BadParameter(
            f"invalid ISO-8601 timestamp: {value!r}", param_hint="--clock"
        )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    fixed = parsed.astimezone(timezone.utc)

    def _fixed_clock() -> datetime:
        return fixed

    return _fixed_clock


def _require_aware(clock: Callable[[], datetime]) -> datetime:
    """Normalize an injected clock reading to timezone-aware UTC."""
    value = clock()
    if value.tzinfo is None:
        raise click.BadParameter(
            "injected clock must produce a timezone-aware datetime",
            param_hint="--clock",
        )
    return value.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Configuration gate (Requirement 3.2: every value passes ECATSLConfig)
# ---------------------------------------------------------------------------

def _parse_inline_json(value: str, option_name: str) -> Any:

    try:
        return json.loads(value)
    except ValueError as error:
        raise click.BadParameter(
            f"{option_name} is not valid JSON: {error}", param_hint=option_name
        )


def _split_override(item: str) -> Tuple[str, str]:
    """Split one ``key=value`` override into a strict 2-tuple.

    A bare ``key`` (no ``=``) defaults to boolean ``true`` so single-flag
    overrides keep working in the terse CLI form.
    """
    if "=" in item:
        key, value = item.split("=", 1)
        return key, value
    return item, "true"


def _read_config_document(path: str) -> Any:
    """Read an ECATSLConfig document as JSON, or TOML via a stdlib fallback."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError as error:
            raise click.BadParameter(
                f"config file {path!r} is TOML but no TOML parser is installed",
                param_hint="--config",
            ) from error
    try:
        return tomllib.loads(text)
    except Exception as error:
        raise click.BadParameter(
            f"config file {path!r} could not be parsed: {error}",
            param_hint="--config",
        ) from error


def _split_inline_key(raw_key: str) -> Tuple[str, ...]:
    segments = tuple(segment.strip() for segment in raw_key.split("."))
    if not all(segments):
        raise click.BadParameter(
            f"empty segment in --set key {raw_key!r}", param_hint="--set"
        )
    return segments


def _annotation_is_sequence(annotation: Any) -> bool:
    origin = get_origin(annotation)
    if origin in (tuple, list, set, frozenset):
        return True
    if origin is Union or origin is types.UnionType:
        return any(_annotation_is_sequence(arg) for arg in get_args(annotation))
    return False


def _key_is_sequence_typed(raw_key: str) -> bool:
    """Whether a ``--set`` key targets a sequence-typed ``ECATSLConfig`` field."""
    root = raw_key.split(".", 1)[0].strip()
    field = ECATSLConfig.model_fields.get(root)
    return field is not None and _annotation_is_sequence(field.annotation)


def _assign_dotted(document: dict, segments: Tuple[str, ...], value: Any) -> None:
    node: Any = document
    for segment in segments[:-1]:
        child = node.get(segment)
        if not isinstance(child, dict):
            child = {}
            node[segment] = child
        node = child
    node[segments[-1]] = value


def _coerce_override_value(raw_value: str, *, sequence: bool = False) -> Any:
    lowered = raw_value.strip().lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if raw_value.startswith(("[", "{")):
        return _parse_inline_json(raw_value, "--set")
    if sequence:
        # Human-friendly comma list for sequence-typed fields: passing the
        # bare string would fail pydantic's tuple/list type check before the
        # field's own value validation could name the violated field
        # (Requirement 3.2's rejection-message contract).
        return tuple(item.strip() for item in raw_value.split(",") if item.strip())
    return raw_value


def _build_config_document(
    *,
    config: Optional[str],
    inline_json: Optional[str],
    inline_set: Tuple[Tuple[str, str], ...],
) -> dict:
    if inline_json and inline_set:
        raise click.BadParameter(
            "--config-json and --set are mutually exclusive",
            param_hint="--config-json",
        )
    document: Any = {}
    if config:
        document = _read_config_document(config)
    if inline_json:
        document = _parse_inline_json(inline_json, "--config-json")
    if not isinstance(document, dict):
        raise click.BadParameter(
            "configuration must be a JSON/TOML object", param_hint="--config"
        )
    for raw_key, raw_value in inline_set:
        sequence = _key_is_sequence_typed(raw_key)
        _assign_dotted(
            document,
            _split_inline_key(raw_key),
            _coerce_override_value(raw_value, sequence=sequence),
        )
    return document


def _load_config(
    *,
    config: Optional[str] = None,
    inline_json: Optional[str] = None,
    inline_set: Tuple[Tuple[str, str], ...] = (),
    database: Optional[str] = None,
    language: Optional[str] = None,
    cwe_ids: Tuple[str, ...] = (),
) -> ECATSLConfig:
    """Validate every CLI value through ``ECATSLConfig`` (Requirement 3.2).

    Invalid values (out-of-scope CWE/language, non-allowlisted adapter,
    misassigned confirmatory provider, brittle routes, unknown fields) exit
    with code 2 and never write repository state.
    """
    document = _build_config_document(
        config=config, inline_json=inline_json, inline_set=inline_set
    )
    if database:
        document["database_path"] = database
    if language:
        document["language"] = language
    if cwe_ids:
        document["cwe_ids"] = list(cwe_ids)
    try:
        return ECATSLConfig.model_validate(document)
    except Exception as error:
        raise click.BadParameter(str(error), param_hint="--config") from error


# ---------------------------------------------------------------------------
# Wiring (reuses existing src/ecatsl decision layers; no new scanner)
# ---------------------------------------------------------------------------

def _provider_provenance(stage: str, *, created_at: datetime) -> Provenance:
    return Provenance(
        origin="ecatsl:cli",
        retrieved_at=created_at,
        source_identifier=f"cli:{stage}",
        source_revision="cli:v1",
        content_identity=f"cli:{stage}",
        transformation_history=(f"ecatsl-cli:{stage}:v1",),
    )


def _open_repository(config: ECATSLConfig):
    """Open the shared append-only SQLite ECATSL store (no new store)."""
    from src.ecatsl.artifact_repository import ArtifactRepository

    return ArtifactRepository(
        config.database_path,
        supported_static_adapters=tuple(config.supported_static_adapters),
    )


def _wired_service(
    config: ECATSLConfig,
    *,
    repository_ref: str,
    clock: Callable[[], datetime],
):
    """Assemble ``ECATSLService`` from existing ``src/ecatsl`` components.

    Reuses the shipped scope definition, the SQLite catalog template provider,
    repository discovery, the delegated ``InputTracer``/``SastPrefilter``
    static adapters, and the shared artifact repository. Nothing here
    instantiates a second scanner, importer, or bypass confirmation path.
    """
    from src.analyzers.input_tracer import InputTracer
    from src.analyzers.sast_prefilter import SastPrefilter
    from src.ecatsl.candidate_ledger import CandidateLedger
    from src.ecatsl.discovery import RepositoryDiscovery
    from src.ecatsl.models import AcceptancePolicy, ValidationPolicy
    from src.ecatsl.scope import initial_scope
    from src.ecatsl.service import ECATSLService, build_sqlite_template_provider
    from src.ecatsl.static_adapters import CodeQLSastAdapter, InputTracerAdapter

    created_at = _require_aware(clock)
    provenance = _provider_provenance("wiring", created_at=created_at)
    repository = _open_repository(config)
    try:
        ledger = CandidateLedger(repository)
        acceptance = AcceptancePolicy(
            version=config.acceptance_policy_version,
            created_at=created_at,
            provenance=_provider_provenance("acceptance-policy", created_at=created_at),
            conditions=("independent_evidence",),
        )
        validation = ValidationPolicy(
            version=config.validation_policy_version,
            created_at=created_at,
            provenance=_provider_provenance("validation-policy", created_at=created_at),
            result_mappings=(
                Attribute(name="COMPLETE_PATH", value="PRESERVE"),
                Attribute(name="NO_PATH", value="UNACCEPT"),
                Attribute(name="*", value="UNACCEPT"),
            ),
        )
        adapters: Tuple[Any, ...] = (
            InputTracerAdapter(InputTracer(repository_ref)),
            CodeQLSastAdapter(SastPrefilter()),
        )
        service = ECATSLService(
            scope=initial_scope(created_at=created_at, provenance=provenance),
            provenance=provenance,
            repository=repository,
            ledger=ledger,
            acceptance_policy=acceptance,
            validation_policy=validation,
            discovery=RepositoryDiscovery(),
            template_provider=build_sqlite_template_provider(
                config.database_path, scope_cwe_ids=tuple(config.cwe_ids)
            ),
            static_adapters=adapters,
            supported_static_adapters=tuple(config.supported_static_adapters),
            compiler_version=config.compiler_version,
        )
    except BaseException:
        repository.close()
        raise
    return service, repository


# ---------------------------------------------------------------------------
# Analyze summary and failure isolation (Requirement 3.3, 3.5)
# ---------------------------------------------------------------------------

def _collect_analyze_summary(result: Any) -> dict:
    """Aggregate one ``AnalysisResult`` into the structured summary fields."""
    findings = tuple(result.findings or ())
    confirmed = tuple(
        item for item in findings if item.status is FindingStatus.CONFIRMED
    )
    unconfirmed = tuple(
        item for item in findings if item.status is FindingStatus.UNCONFIRMED
    )
    audit_failures = tuple(result.audit_failures or ())
    failure_counts: dict[str, int] = {}
    for failure in audit_failures:
        failure_counts[failure.operation] = (
            failure_counts.get(failure.operation, 0) + 1
        )
    complexity = result.complexity
    return {
        "status": result.status,
        "scope_status": (
            result.scope_result.status.value if result.scope_result else None
        ),
        "confirmed": len(confirmed),
        "unconfirmed": len(unconfirmed),
        "finding_ids": tuple(
            dict.fromkeys(item.artifact_id for item in findings if item.artifact_id)
        ),
        "artifact_count": len(tuple(result.stage_records or ())),
        "audit_failure_count": len(audit_failures),
        "audit_failures": failure_counts,
        "telemetry": {
            "configured_adapters": complexity.configured_adapters,
            "pipeline_stages": complexity.pipeline_stages,
            "external_service_dependencies": (
                complexity.external_service_dependencies
            ),
            "manual_execution_steps": complexity.manual_execution_steps,
        }
        if complexity is not None
        else {},
        "limitations": tuple(result.limitations or ()),
    }


def _persist_observation(
    repository: Any,
    *,
    derivation_kind: str,
    locations: Sequence[str],
    identities: Sequence[str],
    context: Sequence[Attribute],
    clock: Callable[[], datetime],
) -> bool:
    """Persist one non-confirmatory CLI observation; False on failure."""
    created_at = _require_aware(clock)
    try:
        repository.persist_artifact(
            DiscoveryObservation(
                version="1",
                created_at=created_at,
                provenance=_provider_provenance(derivation_kind, created_at=created_at),
                derivation_kind=derivation_kind,
                locations=tuple(locations),
                source_content_identities=tuple(identities),
                producer=CLI_PRODUCER,
                producer_version=CLI_PRODUCER_VERSION,
                context=tuple(context),
            )
        )
    except Exception as error:
        print(
            f"WARNING: {derivation_kind} record could not be persisted: {error}",
            file=sys.stderr,
        )
        return False
    return True


def _persist_analyze_summary(
    repository: Any, summary: dict, *, clock: Callable[[], datetime]
) -> bool:
    context = tuple(
        Attribute(name=key, value=_summary_value(summary[key])) for key in sorted(summary)
    )
    return _persist_observation(
        repository,
        derivation_kind=SUMMARY_RECORD_KIND,
        locations=(),
        identities=tuple(str(item) for item in summary["finding_ids"]),
        context=context,
        clock=clock,
    )


def _persist_terminal_record(
    repository: Any,
    *,
    status: str,
    detail: str,
    clock: Callable[[], datetime],
) -> bool:
    """Record one terminal ``FAILED``/``UNAVAILABLE`` observation."""
    return _persist_observation(
        repository,
        derivation_kind=TERMINAL_RECORD_KIND,
        locations=(detail,),
        identities=(status,),
        context=(Attribute(name="terminal_status", value=status),),
        clock=clock,
    )


def _count_unpersisted_failures(
    repository: Any, audit_failures: Sequence[Any]
) -> int:
    """Count audited failures whose terminal record never reached the store.

    The service already records every isolated failure through the dedicated
    audit API; this check verifies each terminal record actually persisted
    (Requirement 3.5: exit 1 only for real persistence failures).
    """
    ids = tuple(
        dict.fromkeys(
            failure.artifact_id
            for failure in audit_failures
            if getattr(failure, "artifact_id", "")
        )
    )
    if not ids:
        return 0
    try:
        placeholders = ",".join("?" for _ in ids)
        rows = repository.connection.execute(
            f"SELECT artifact_id FROM ecatsl_artifact WHERE artifact_id IN ({placeholders})",
            ids,
        ).fetchall()
    except sqlite3.Error:
        return len(ids)
    persisted = {str(row[0]) for row in rows}
    return sum(1 for artifact_id in ids if artifact_id not in persisted)


def _summary_value(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _print_table(title: str, rows: Sequence[Sequence[str]]) -> None:
    """Dependency-free aligned text table (human-readable mode)."""
    columns = len(rows[0]) if rows else 0
    widths = [
        max(len(str(row[column])) for row in rows) if rows else 0
        for column in range(columns)
    ]
    print(title)
    for row in rows:
        print(
            "  "
            + "  ".join(
                str(cell).ljust(widths[column])
                for column, cell in enumerate(row)
            )
        )


def _emit_summary(
    command: str, payload: dict, *, as_json: bool, exit_code: int
) -> None:
    if as_json:
        print(_json_output({**payload, "command": command, "exit_code": exit_code}))
    else:
        _print_table(
            f"ECATSL {command}",
            tuple(
                (key, _summary_value(value))
                for key, value in sorted(payload.items())
            ),
        )


def _json_output(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


# ---------------------------------------------------------------------------
# Artifact file loading helpers (JSONL; one artifact per line)
# ---------------------------------------------------------------------------

def _load_latest_artifact(
    path: str, model_type: Any, option_hint: str
) -> Any:
    artifact: Optional[Any] = None
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            try:
                candidate = model_type.model_validate(payload)
            except Exception:
                continue
            if artifact is None or candidate.created_at > artifact.created_at:
                artifact = candidate
    if artifact is None:
        raise click.BadParameter(
            f"file {path!r} contains no {model_type.__name__} artifact",
            param_hint=option_hint,
        )
    return artifact


def _rebuild_quality(manifest: BenchmarkManifest) -> DataQualityReport:
    """Rebuild the minimal quality report bound to a loaded manifest.

    The evaluation contract requires the quality-report identity; the CLI
    recomputes the deterministic canonical count from the manifest's own
    retained samples and records the reconstruction as a limitation.
    """
    unique_hashes = {sample.content_hash for sample in manifest.samples}
    return DataQualityReport(
        version="1",
        created_at=manifest.created_at,
        provenance=manifest.provenance,
        completeness=(
            Attribute(name="record_count", value=str(len(manifest.samples))),
            Attribute(name="retained_count", value=str(len(manifest.samples))),
            Attribute(name="canonical_count", value=str(len(unique_hashes))),
        ),
        validity=(),
        integrity_results=(),
        duplicate_count=max(len(manifest.samples) - len(unique_hashes), 0),
        excluded_count=0,
        exclusion_reasons=(),
    )


def _parse_classification_overrides(
    classifications: Tuple[str, ...]
) -> dict[str, FindingStatus]:
    """Parse ``--classification sample_id=STATUS`` pairs into a mapping."""
    overrides: dict[str, FindingStatus] = {}
    for item in classifications:
        sample_id, separator, raw_status = item.partition("=")
        if not separator or not sample_id.strip() or not raw_status.strip():
            raise click.BadParameter(
                f"--classification expects sample_id=STATUS, got {item!r}",
                param_hint="--classification",
            )
        try:
            overrides[sample_id.strip()] = FindingStatus(raw_status.strip().upper())
        except ValueError:
            raise click.BadParameter(
                f"invalid finding status {raw_status!r} "
                "(expected CONFIRMED/UNCONFIRMED)",
                param_hint="--classification",
            )
    return overrides


def _load_classification_file(path: str) -> dict[str, FindingStatus]:
    """Load ``sample_id -> status`` mappings from a JSON file."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise click.BadParameter(
            f"classification file {path!r} must be a JSON object",
            param_hint="--classifications-json",
        )
    statuses: dict[str, FindingStatus] = {}
    for sample_id, raw_status in payload.items():
        if not isinstance(raw_status, str):
            raise click.BadParameter(
                f"classification for {sample_id!r} must be a string",
                param_hint="--classifications-json",
            )
        try:
            statuses[str(sample_id)] = FindingStatus(raw_status.upper())
        except ValueError:
            raise click.BadParameter(
                f"invalid finding status {raw_status!r} for {sample_id!r} "
                "(expected CONFIRMED/UNCONFIRMED)",
                param_hint="--classifications-json",
            )
    return statuses


# ---------------------------------------------------------------------------
# Command group
# ---------------------------------------------------------------------------

@click.group(name="ecatsl")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="ECATSLConfig source: JSON/TOML file validated before any command runs.",
)
@click.option("--config-json", default=None, help="Inline ECATSLConfig JSON object.")
@click.option(
    "--set",
    "config_overrides",
    multiple=True,
    help="Inline override key=value (dotted key path into the config object).",
)
@click.option(
    "--database",
    "database_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Shared SQLite ECATSL store path (overrides config.database_path).",
)
@click.option(
    "--clock",
    "clock_value",
    default=None,
    metavar=CLOCK_METAVAR,
    help="Fixed UTC ISO-8601 clock for idempotent batch replay (default: real clock).",
)
@click.pass_context
def ecatsl(
    ctx: click.Context,
    config_path: Optional[str],
    config_json: Optional[str],
    config_overrides: Tuple[str, str],
    database_path: Optional[str],
    clock_value: Optional[str],
) -> None:
    """Evidence-Constrained Automated Taint Specification Learning (ECATSL).

    Run the ECATSL decision layers over a repository and persist artifacts
    into the shared append-only SQLite ECATSL store. Configuration passes
    ECATSLConfig validation: invalid values exit 2 and write no repository
    state. The clock is injected (default: real clock) so batch runs replay
    idempotently.
    """
    ctx.ensure_object(dict)
    # The group callback only assembles the raw config document; full
    # ECATSLConfig validation runs at subcommand execution (Requirement 3.2)
    # so `--help` stays short-circuited (Requirement 3.1) and no state is
    # written before validation.
    document = _build_config_document(
        config=config_path,
        inline_json=config_json,
        inline_set=tuple(
            _split_override(item) for item in config_overrides
        ),
    )
    if database_path:
        document["database_path"] = database_path
    ctx.obj["ecatsl_document"] = document
    ctx.obj["ecatsl_clock"] = _parse_clock_option(clock_value) or _real_clock


def _validated_config(
    ctx: click.Context,
    *,
    language: Optional[str] = None,
    cwe_ids: Tuple[str, ...] = (),
) -> ECATSLConfig:
    """Validate the command's effective configuration through ECATSLConfig.

    Subcommand-level ``--language``/``--cwe`` options override the document;
    any invalid value exits with code 2 before repository state is written
    (Requirement 3.2).
    """
    document = dict(ctx.obj["ecatsl_document"])
    if language:
        document["language"] = language
    if cwe_ids:
        document["cwe_ids"] = list(cwe_ids)
    try:
        return ECATSLConfig.model_validate(document)
    except Exception as error:
        raise click.BadParameter(str(error), param_hint="--config") from error


@ecatsl.command()
@click.argument("repository", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--language",
    default=None,
    help="Analysis language (default: config language; validated by ECATSLConfig).",
)
@click.option(
    "--cwe",
    "cwe_ids",
    multiple=True,
    help="Requested CWE mappings (repeatable; validated by ECATSLConfig).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the structured JSON summary.")
@click.pass_context
def analyze(
    ctx: click.Context,
    repository: str,
    language: Optional[str],
    cwe_ids: Tuple[str, ...],
    as_json: bool,
) -> None:
    """Analyze a repository through the single ECATSL pipeline.

    Runs scope gate → discovery/catalog providers → tooling-first resolution
    → candidate lifecycle → declarative compilation → supported static
    validation → static-path-gated confirmation, then persists every artifact
    into the shared SQLite ECATSL store.

    Single-file discovery/adapter failures are isolated: the service audits
    them as terminal FAILED records in the store and the CLI counts them in
    the summary; the run still completes. Exit codes: 0 = complete (any
    finding count), 1 = an artifact persistence failed, 2 = usage or
    configuration error.
    """
    config = _validated_config(ctx, language=language, cwe_ids=cwe_ids)
    clock: Callable[[], datetime] = ctx.obj["ecatsl_clock"]
    from src.ecatsl.service import AnalysisRequest

    repo = None
    try:
        service, repo = _wired_service(
            config, repository_ref=repository, clock=clock
        )
        result = service.analyze(
            AnalysisRequest(
                repository_ref=repository,
                language=config.language,
                cwe_ids=tuple(config.cwe_ids),
            )
        )
    except click.BadParameter:
        if repo is not None:
            repo.close()
        raise
    except Exception as error:
        # Whole-run failure: record UNAVAILABLE terminal semantics and exit 1.
        if repo is not None:
            repo.close()
        try:
            failed_repo = _open_repository(config)
        except Exception:
            failed_repo = None
        if failed_repo is not None:
            try:
                _persist_terminal_record(
                    failed_repo,
                    status=TERMINAL_UNAVAILABLE,
                    detail=f"analyze run failed: {error}",
                    clock=clock,
                )
            finally:
                failed_repo.close()
        failure_payload: dict[str, Any] = {
            "status": "RUN_FAILED",
            "error": str(error),
        }
        _emit_summary("analyze", failure_payload, as_json=as_json, exit_code=EXIT_PERSISTENCE_FAILURE)
        ctx.exit(EXIT_PERSISTENCE_FAILURE)

    summary = _collect_analyze_summary(result)
    summary_ok = _persist_analyze_summary(repo, summary, clock=clock)
    unpersisted_failures = _count_unpersisted_failures(
        repo, tuple(result.audit_failures or ())
    )
    repo.close()
    exit_code = EXIT_OK if summary_ok and not unpersisted_failures else EXIT_PERSISTENCE_FAILURE
    payload: dict[str, Any] = {**summary, "exit_code": exit_code}
    if as_json:
        print(_json_output({"command": "analyze", **payload}))
    else:
        rows = [
            ("status", summary["status"]),
            ("confirmed", str(summary["confirmed"])),
            ("unconfirmed", str(summary["unconfirmed"])),
            ("finding_ids", ", ".join(summary["finding_ids"]) or "-"),
            ("artifact_count", str(summary["artifact_count"])),
            ("audit_failure_count", str(summary["audit_failure_count"])),
            ("unpersisted_failures", str(unpersisted_failures)),
        ]
        rows.extend(
            (f"audit_failure:{operation}", str(count))
            for operation, count in sorted(summary["audit_failures"].items())
        )
        telemetry = summary["telemetry"]
        if telemetry:
            rows.extend(
                (f"telemetry:{key}", str(value)) for key, value in sorted(telemetry.items())
            )
        rows.extend(
            (f"limitation:{index}", limitation)
            for index, limitation in enumerate(summary["limitations"], start=1)
        )
        _print_table("ECATSL analyze summary", rows)
    if exit_code:
        ctx.exit(EXIT_PERSISTENCE_FAILURE)
    ctx.exit(EXIT_OK)


@ecatsl.command()
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Dataset source JSONL (one benchmark sample row per line).",
)
@click.option(
    "--data-type",
    default="ecatsl_eval",
    show_default=True,
    help="Release data_type identity (canonicalization key).",
)
@click.option("--release-version", default="1", show_default=True, help="Release version string.")
@click.option(
    "--catalog-ids",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Optional catalog record ids (JSONL/text, one id per line).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the structured JSON summary.")
@click.pass_context
def dataset(
    ctx: click.Context,
    input_path: str,
    data_type: str,
    release_version: str,
    catalog_ids: Optional[str],
    as_json: bool,
) -> None:
    """Build an immutable ECATSL dataset release (zero network access).

    Feeds the sample source through ``build_release``'s full semantics:
    content-hash integrity verification, field validation, canonicalization,
    deterministic split assignment, and leakage-safe pair handling. The
    manifest and quality report are persisted into the shared SQLite store.
    """
    config: ECATSLConfig = _validated_config(ctx)
    clock: Callable[[], datetime] = ctx.obj["ecatsl_clock"]
    created_at = _require_aware(clock)
    from src.ecatsl.dataset_release import build_release

    rows: list[dict] = []
    with open(input_path, encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    catalog_record_ids: Tuple[str, ...] = ()
    if catalog_ids:
        with open(catalog_ids, encoding="utf-8") as handle:
            catalog_record_ids = tuple(
                stripped for stripped in (line.strip() for line in handle) if stripped
            )
    try:
        manifest, quality = build_release(
            tuple(rows),
            version=release_version,
            created_at=created_at,
            provenance=_provider_provenance("dataset", created_at=created_at),
            data_type=data_type,
            catalog_record_ids=catalog_record_ids,
        )
    except Exception as error:
        raise click.BadParameter(
            f"release build failed: {error}", param_hint="--input"
        ) from error
    persisted = True
    with _open_repository(config) as repo:
        try:
            for artifact in (manifest, quality):
                repo.persist_artifact(artifact)
        except Exception as error:
            persisted = _persist_terminal_record(
                repo,
                status=TERMINAL_FAILED,
                detail=f"dataset persistence failed: {error}",
                clock=clock,
            )
    payload: dict[str, Any] = {
        "manifest_id": manifest.artifact_id,
        "manifest_version": manifest.version,
        "quality_report_id": quality.artifact_id,
        "quality_report_version": quality.version,
        "record_count": len(rows),
        "retained_count": len(manifest.samples),
        "excluded_count": quality.excluded_count,
        "duplicate_count": quality.duplicate_count,
    }
    exit_code = EXIT_OK if persisted else EXIT_PERSISTENCE_FAILURE
    _emit_summary("dataset", payload, as_json=as_json, exit_code=exit_code)
    if exit_code:
        ctx.exit(EXIT_PERSISTENCE_FAILURE)
    ctx.exit(EXIT_OK)


@ecatsl.command()
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Benchmark manifest artifact JSONL (from `ecatsl dataset`).",
)
@click.option(
    "--classification",
    "classifications",
    multiple=True,
    help="Verified classification override: sample_id=CONFIRMED|UNCONFIRMED (repeatable).",
)
@click.option(
    "--classifications-json",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="JSON file mapping sample_id to CONFIRMED/UNCONFIRMED.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the structured JSON summary.")
@click.option(
    "--no-persist",
    is_flag=True,
    help="Do not persist the evaluation into the shared store.",
)
@click.pass_context
def evaluate(
    ctx: click.Context,
    manifest: str,
    classifications: Tuple[str, ...],
    classifications_json: Optional[str],
    as_json: bool,
    no_persist: bool,
) -> None:
    """Evaluate a dataset release against verified sample classifications.

    Classifications come from ``--classification`` overrides plus an optional
    ``--classifications-json`` file; samples without an entry count as
    not-predicted (UNCONFIRMED). Metrics, strata, and telemetry are computed
    through ``build_evaluation_report`` — no new evaluation logic. Bridging
    analyze findings to benchmark sample ids happens in the eval_runner
    (task 5.1), not here.
    """
    config: ECATSLConfig = _validated_config(ctx)
    clock: Callable[[], datetime] = ctx.obj["ecatsl_clock"]
    created_at = _require_aware(clock)
    loaded_manifest = _load_latest_artifact(manifest, BenchmarkManifest, "--manifest")
    quality = _rebuild_quality(loaded_manifest)
    overrides = _parse_classification_overrides(classifications)
    file_statuses = (
        _load_classification_file(classifications_json) if classifications_json else {}
    )
    merged: dict[str, FindingStatus] = {**file_statuses, **overrides}
    report = build_evaluation_report(
        loaded_manifest,
        quality,
        merged,
        version="1",
        created_at=created_at,
        provenance=_provider_provenance("evaluate", created_at=created_at),
        telemetry=EvaluationTelemetry(
            latency_seconds=0.0,
            llm_tokens=0,
            llm_monetary_cost=0.0,
            complexity=OperationalComplexity(
                configured_adapters=0,
                pipeline_stages=0,
                external_service_dependencies=0,
                manual_execution_steps=0,
            ),
        ),
        evidence_limitations=(
            "classifications supplied via CLI overrides/files only; "
            "quality report rebuilt from the manifest; bridge analyze "
            "findings to sample ids via eval_runner (task 5.1)",
        ),
    )
    persistence_ok = True
    if not no_persist:
        with _open_repository(config) as repo:
            try:
                repo.persist_artifact(report)
            except Exception as error:
                persistence_ok = _persist_terminal_record(
                    repo,
                    status=TERMINAL_FAILED,
                    detail=f"evaluation persistence failed: {error}",
                    clock=clock,
                )
    metrics: dict[str, str] = {
        attr.name: str(attr.value) for attr in report.verified_metrics
    }
    payload: dict[str, Any] = {
        "evaluation_report_id": report.artifact_id,
        "benchmark_manifest_id": report.benchmark_manifest_id,
        "classified_samples": len(merged),
        "sample_count": len(loaded_manifest.samples),
        "metrics": metrics,
    }
    exit_code = EXIT_OK if persistence_ok else EXIT_PERSISTENCE_FAILURE
    if as_json:
        print(_json_output({"command": "evaluate", **payload, "exit_code": exit_code}))
    else:
        _print_table(
            "ECATSL evaluation",
            tuple((key, _summary_value(value)) for key, value in payload["metrics"].items())
            + (
                ("evaluation_report_id", report.artifact_id),
                ("classified_samples", str(len(merged))),
            ),
        )
    if exit_code:
        ctx.exit(EXIT_PERSISTENCE_FAILURE)
    ctx.exit(EXIT_OK)


@ecatsl.command()
@click.option(
    "--evaluation",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Evaluation report artifact JSONL (from `ecatsl evaluate`).",
)
@click.option(
    "--baseline-evaluation",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Baseline Evaluation_Report JSONL for the paired comparison report.",
)
@click.option(
    "--comparison-baseline",
    default=None,
    help="Comparison baseline identity for the paired comparison report.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the structured JSON summary.")
@click.pass_context
def report(
    ctx: click.Context,
    evaluation: str,
    baseline_evaluation: Optional[str],
    comparison_baseline: Optional[str],
    as_json: bool,
) -> None:
    """Produce the Cost_Report / optimization report from persisted evaluations.

    Builds the ``Cost_Report`` through ``build_cost_report`` and — when a
    baseline evaluation is supplied — the paired ``BaselineComparison``
    through ``build_optimization_report``. Claims stay evidence-gated: without
    completed-experiment linkage and stated limitations, measured differences
    are reported without superiority language (Req 8.4-8.6).
    """
    config: ECATSLConfig = _validated_config(ctx)
    clock: Callable[[], datetime] = ctx.obj["ecatsl_clock"]
    created_at = _require_aware(clock)
    changed_report = _load_latest_artifact(evaluation, EvaluationReport, "--evaluation")
    cost_report = build_cost_report(
        changed_report,
        version="1",
        created_at=created_at,
        provenance=_provider_provenance("report", created_at=created_at),
    )
    comparison_payload: dict[str, Any] = {}
    if baseline_evaluation:
        baseline_report = _load_latest_artifact(
            baseline_evaluation, EvaluationReport, "--baseline-evaluation"
        )
        from src.ecatsl.evaluation import DEFAULT_BASELINE

        comparison = build_optimization_report(
            baseline_report,
            changed_report,
            comparison_baseline=(
                Attribute(name="comparison_baseline", value=comparison_baseline)
                if comparison_baseline
                else DEFAULT_BASELINE
            ),
        )
        comparison_payload = {
            "measured_differences": {
                attr.name: attr.value for attr in comparison.measured_differences
            },
            "claims": [
                {
                    "metric": claim.metric,
                    "measured_difference": claim.measured_difference,
                    "direction": claim.direction,
                    "claim": claim.claim,
                    "missing_evidence": list(claim.missing_evidence),
                }
                for claim in comparison.claims
            ],
            "missing_experiment_link": list(comparison.missing_experiment_link),
        }
    with _open_repository(config) as repo:
        try:
            repo.persist_artifact(cost_report)
            persisted = True
        except Exception as error:
            persisted = _persist_terminal_record(
                repo,
                status=TERMINAL_FAILED,
                detail=f"cost report persistence failed: {error}",
                clock=clock,
            )
    payload: dict[str, Any] = {
        "cost_report_id": cost_report.artifact_id,
        "evaluation_report_id": cost_report.evaluation_report_id,
        "benchmark_manifest_id": cost_report.benchmark_manifest_id,
        "missing_cost_data": cost_report.missing_cost_data,
    }
    if comparison_payload:
        payload["baseline_comparison"] = comparison_payload
    exit_code = EXIT_OK if persisted else EXIT_PERSISTENCE_FAILURE
    if as_json:
        print(_json_output({"command": "report", **payload, "exit_code": exit_code}))
    else:
        _print_table(
            "ECATSL cost report",
            tuple(
                (key, _summary_value(value))
                for key, value in payload.items()
                if key != "baseline_comparison"
            ),
        )
        for stratum in cost_report.strata:
            _print_table(
                f"stratum {stratum.key}",
                (
                    ("definition", stratum.key),
                    ("sample_count", str(stratum.sample_count)),
                    ("precision", str(stratum.precision)),
                    ("recall", str(stratum.recall)),
                    ("f1", str(stratum.f1)),
                    ("analysis_latency_seconds", str(stratum.analysis_latency_seconds)),
                    ("llm_tokens", str(stratum.llm_tokens)),
                    ("llm_cost", str(stratum.llm_cost)),
                    ("audit_cost", str(stratum.audit_cost)),
                    ("missing_cost_data", str(stratum.missing_cost_data)),
                ),
            )
    if exit_code:
        ctx.exit(EXIT_PERSISTENCE_FAILURE)
    ctx.exit(EXIT_OK)
