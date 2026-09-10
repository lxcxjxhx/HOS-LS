"""Task 3.2: unit tests for the ``ecatsl`` CLI command group (Req 3.1-3.6).

Covers the configuration-gate rejection matrix (invalid values exit 2 with
zero repository writes and a message naming the violated field), the
exit-code contract, ``--json`` summary structures, failure isolation, clock
injection, and command-group registration in ``src.cli.main``.
"""
import json
import sqlite3
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from src.cli.commands.ecatsl_cmd import ecatsl

runner = CliRunner()
DB_NAME = "ecatsl.db"
CLOCK = "2026-09-08T00:00:00Z"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

def _sample_row(sample_id="S1", digest="a" * 64):
    return {
        "id": sample_id,
        "content_hash": digest,
        "classification": "vulnerable",
        "project_id": "proj",
        "project_time_group": "proj:g1",
    }


@pytest.fixture
def gate_env(tmp_path):
    """Valid analyze target and dataset input so rejection reaches the
    ``ECATSLConfig`` gate (not click's own ``exists`` checks)."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
    input_file = tmp_path / "samples.jsonl"
    input_file.write_text(
        json.dumps(_sample_row()) + "\n", encoding="utf-8"
    )
    return SimpleNamespace(
        tmp_path=tmp_path,
        repo=str(repo_dir),
        input=str(input_file),
        db=tmp_path / DB_NAME,
    )


def _invoke(db, args, clock=CLOCK):
    """Invoke with group-level ``--database``/``--clock`` before the subcommand."""
    return runner.invoke(ecatsl, ["--database", str(db), "--clock", clock, *args])


def _canonical_payloads(db, artifact_id):
    """Fetch persisted canonical payloads for one artifact id."""
    conn = sqlite3.connect(str(db))
    try:
        rows = conn.execute(
            "SELECT canonical_payload FROM ecatsl_artifact WHERE artifact_id=?",
            (artifact_id,),
        ).fetchall()
    finally:
        conn.close()
    return [row[0] for row in rows]


def _dataset_run(env, as_json=True):
    args = ["dataset", "--input", env.input]
    if as_json:
        args.append("--json")
    return _invoke(env.db, args)


# ---------------------------------------------------------------------------
# Registration and help surfaces (Requirement 3.1)
# ---------------------------------------------------------------------------

def test_ecatsl_group_registered_in_main_cli():
    main = pytest.importorskip("src.cli.main")
    assert "ecatsl" in main.cli.commands


def test_group_help_lists_all_four_subcommands():
    result = runner.invoke(ecatsl, ["--help"])
    assert result.exit_code == 0
    for subcommand in ("analyze", "dataset", "evaluate", "report"):
        assert subcommand in result.output


def test_analyze_help_declares_exit_codes_and_terminal_semantics():
    result = runner.invoke(ecatsl, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "0 = complete" in result.output
    assert "FAILED" in result.output


# ---------------------------------------------------------------------------
# Configuration gate rejection matrix (Requirement 3.2): exit 2, zero writes
# ---------------------------------------------------------------------------

REJECTION_CASES = [
    # Group-level --set/--database overrides precede the subcommand; the full
    # argv is built per case so the option hierarchy is explicit.
    (
        "out-of-scope-cwe",
        lambda env: ["--database", str(env.db), "analyze", env.repo, "--cwe", "CWE-79"],
        "initial scope",
    ),
    (
        "out-of-scope-language",
        lambda env: ["--database", str(env.db), "analyze", env.repo, "--language", "java"],
        "initial scope",
    ),
    (
        "non-allowlisted-adapter",
        lambda env: [
            "--database", str(env.db),
            "--set", 'supported_static_adapters=[["bogus-adapter","1"]]',
            "dataset", "--input", env.input,
        ],
        "unsupported static adapter",
    ),
    (
        "brittle-per-route-enumeration",
        lambda env: [
            "--database", str(env.db),
            "--set", 'discovery_strategies=[{"strategy":"generic","routes":["/a"]}]',
            "dataset", "--input", env.input,
        ],
        "per-route",
    ),
    (
        "confirmatory-provider-misconfig",
        lambda env: [
            "--database", str(env.db),
            "--set", "confirmation_provider=llm",
            "dataset", "--input", env.input,
        ],
        "only static adapters may confirm",
    ),
    (
        "unknown-extra-field",
        lambda env: [
            "--database", str(env.db),
            "--set", "bogus_option=1",
            "dataset", "--input", env.input,
        ],
        "bogus_option",
    ),
    (
        # No group-level --database: the blank override must reach
        # ECATSLConfig (a valid group --database would win the merge order).
        "blank-database-path",
        lambda env: [
            "--set", "database_path=",
            "dataset", "--input", env.input,
        ],
        "database_path",
    ),
    (
        "unsupported-ranking-profile",
        lambda env: [
            "--database", str(env.db),
            "--set", "ranking_profiles=custom/v1",
            "dataset", "--input", env.input,
        ],
        "ranking profile",
    ),
]


@pytest.mark.parametrize("name,argv_of,fragment", REJECTION_CASES, ids=[c[0] for c in REJECTION_CASES])
def test_config_gate_rejects_with_exit_2_zero_writes(gate_env, name, argv_of, fragment):
    env = gate_env
    result = runner.invoke(ecatsl, argv_of(env))
    assert result.exit_code == 2, result.output[-300:]
    assert fragment in result.output, result.output[-300:]
    assert not env.db.exists(), "rejected configuration wrote repository state"


def test_invalid_clock_is_rejected_before_any_work(gate_env):
    result = _invoke(gate_env.db, ["dataset", "--input", gate_env.input], clock="not-a-timestamp")
    assert result.exit_code == 2
    assert "--clock" in result.output
    assert not gate_env.db.exists()


# ---------------------------------------------------------------------------
# dataset → evaluate → report chain with injected clock (Req 3.1, 3.5)
# ---------------------------------------------------------------------------

def test_dataset_json_summary_structure(gate_env):
    result = _dataset_run(gate_env)
    assert result.exit_code == 0, result.output[-300:]
    payload = json.loads(result.output)
    assert payload["command"] == "dataset"
    assert payload["exit_code"] == 0
    assert payload["manifest_id"]
    assert payload["quality_report_id"]
    assert payload["record_count"] == 1
    assert payload["retained_count"] == 1
    assert payload["excluded_count"] == 0
    assert payload["duplicate_count"] == 0


def test_dataset_replay_is_idempotent_under_injected_clock(gate_env):
    first = json.loads(_dataset_run(gate_env).output)
    replay = json.loads(_dataset_run(gate_env).output)
    assert replay["manifest_id"] == first["manifest_id"]
    assert replay["quality_report_id"] == first["quality_report_id"]


def test_dataset_human_table_mode(gate_env):
    result = _dataset_run(gate_env, as_json=False)
    assert result.exit_code == 0, result.output[-300:]
    assert "ECATSL dataset" in result.output


def _persist_manifest_to_file(env, manifest_id, target):
    target.write_text(
        "\n".join(_canonical_payloads(env.db, manifest_id)), encoding="utf-8"
    )


def test_evaluate_json_summary_and_metrics(gate_env):
    dataset = json.loads(_dataset_run(gate_env).output)
    manifest_file = gate_env.tmp_path / "manifest.jsonl"
    _persist_manifest_to_file(gate_env, dataset["manifest_id"], manifest_file)
    classifications = gate_env.tmp_path / "cls.json"
    classifications.write_text(
        json.dumps({"S1": "CONFIRMED"}), encoding="utf-8"
    )
    result = _invoke(
        gate_env.db,
        [
            "evaluate",
            "--manifest", str(manifest_file),
            "--classifications-json", str(classifications),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output[-300:]
    payload = json.loads(result.output)
    assert payload["command"] == "evaluate"
    assert payload["evaluation_report_id"]
    assert payload["metrics"]["tp"] == "1"
    assert payload["metrics"]["confirmed"] == "1"


def test_report_json_summary_from_evaluation(gate_env):
    dataset = json.loads(_dataset_run(gate_env).output)
    manifest_file = gate_env.tmp_path / "manifest.jsonl"
    _persist_manifest_to_file(gate_env, dataset["manifest_id"], manifest_file)
    classifications = gate_env.tmp_path / "cls.json"
    classifications.write_text(json.dumps({"S1": "CONFIRMED"}), encoding="utf-8")
    evaluation = json.loads(_invoke(
        gate_env.db,
        [
            "evaluate",
            "--manifest", str(manifest_file),
            "--classifications-json", str(classifications),
            "--json",
        ],
    ).output)
    eval_file = gate_env.tmp_path / "eval.jsonl"
    eval_file.write_text(
        "\n".join(_canonical_payloads(gate_env.db, evaluation["evaluation_report_id"])),
        encoding="utf-8",
    )
    result = _invoke(
        gate_env.db, ["report", "--evaluation", str(eval_file), "--json"]
    )
    assert result.exit_code == 0, result.output[-300:]
    payload = json.loads(result.output)
    assert payload["command"] == "report"
    assert payload["cost_report_id"]


def test_report_paired_baseline_makes_no_evidence_free_claims(gate_env):
    dataset = json.loads(_dataset_run(gate_env).output)
    manifest_file = gate_env.tmp_path / "manifest.jsonl"
    _persist_manifest_to_file(gate_env, dataset["manifest_id"], manifest_file)
    classifications = gate_env.tmp_path / "cls.json"
    classifications.write_text(json.dumps({"S1": "CONFIRMED"}), encoding="utf-8")
    evaluation = json.loads(_invoke(
        gate_env.db,
        [
            "evaluate",
            "--manifest", str(manifest_file),
            "--classifications-json", str(classifications),
            "--json",
        ],
    ).output)
    eval_file = gate_env.tmp_path / "eval.jsonl"
    eval_file.write_text(
        "\n".join(_canonical_payloads(gate_env.db, evaluation["evaluation_report_id"])),
        encoding="utf-8",
    )
    result = _invoke(
        gate_env.db,
        [
            "report",
            "--evaluation", str(eval_file),
            "--baseline-evaluation", str(eval_file),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output[-300:]
    payload = json.loads(result.output)
    comparison = payload["baseline_comparison"]
    assert "claims" in comparison
    assert all(not claim["claim"] for claim in comparison["claims"])


# ---------------------------------------------------------------------------
# analyze: summary structure, failure isolation, exit-code contract (Req 3.3)
# ---------------------------------------------------------------------------

def test_analyze_completes_with_zero_findings_and_structured_summary(gate_env):
    result = _invoke(gate_env.db, ["analyze", gate_env.repo, "--json"])
    assert result.exit_code == 0, result.output[-400:]
    payload = json.loads(result.output)
    assert payload["command"] == "analyze"
    assert payload["exit_code"] == 0
    assert payload["status"]
    assert payload["confirmed"] == 0
    assert payload["unconfirmed"] == 0
    assert payload["finding_ids"] == []
    assert "audit_failure_count" in payload
    assert "telemetry" in payload
    assert "limitations" in payload


def test_analyze_human_table_mode(gate_env):
    result = _invoke(gate_env.db, ["analyze", gate_env.repo])
    assert result.exit_code == 0, result.output[-400:]
    assert "ECATSL analyze" in result.output
