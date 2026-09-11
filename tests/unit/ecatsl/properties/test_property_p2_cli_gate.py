"""Feature: ecatsl-operationalization-and-bench-integration, Property P2 tests.

Property P2 (CLI configuration-gate closure): any generated illegal CLI
configuration — out-of-scope language/CWE, non-allowlisted static adapter,
confirmatory provider misassignment, brittle per-route discovery strategies,
unsupported ranking profile, blank database path, or unknown extra field —
exits with code 2, writes zero repository state, and its error message names
the violated field or violation category.

Validates: Requirements 3.2, 3.4 (tasks.md 3.3, label
``Feature: ecatsl-operationalization-and-bench-integration, Property P2``).
"""

import json
import os
import shutil
import tempfile

import pytest

hypothesis = pytest.importorskip("hypothesis")
from click.testing import CliRunner
from hypothesis import given, settings, strategies as st

from src.cli.commands.ecatsl_cmd import ecatsl

runner = CliRunner()
CLOCK = "2026-09-08T00:00:00Z"

SAMPLE_ROW = {
    "id": "S1",
    "content_hash": "a" * 64,
    "classification": "vulnerable",
    "project_id": "proj",
    "project_time_group": "proj:g1",
}

#: Illegal value pools per violation dimension. Every entry is rejected by
#: ``ECATSLConfig`` value validation (not merely type parsing), so the CLI
#: rejection message is the config gate's own diagnostic (Requirement 3.2).
_LANGUAGE_POOL = ("java", "javascript", "go", "ruby", "Python ")
_CWE_POOL = ("CWE-22", "CWE-79", "CWE-352", "CWE-89,CWE-22")
_RANKING_POOL = ("custom/v1", "bogus/v1", "template/v2", "discovery/v9")
_ADAPTER_POOL = (
    '[["bogus-adapter","1"]]',
    '[["input-tracer","1"],["nope","9"]]',
    '[["phantom-sast","1"]]',
)
_PROVIDER_POOL = ("llm", "rag", "catalog", "template", "discovery", "magic")
_ROUTES_POOL = (
    '[{"strategy":"generic","routes":["/admin"]}]',
    '[{"strategy":"config","routes":["/x","/y"]}]',
)
_EXTRA_KEY_POOL = ("bogus_option", "phantom_flag", "mystery_switch")

_DIMENSIONS = (
    "out-of-scope-language",
    "out-of-scope-cwe",
    "non-allowlisted-adapter",
    "confirmatory-provider-misconfig",
    "brittle-per-route-enumeration",
    "unsupported-ranking-profile",
    "blank-database-path",
    "unknown-extra-field",
)


def _violation(dimension: str, draw) -> tuple:
    """One illegal ``--set key=value`` override plus its message fragment.

    The returned fragment names the violated field or violation category
    (Requirement 3.2's rejection-message contract).
    """
    if dimension == "out-of-scope-language":
        return ("language", draw(st.sampled_from(_LANGUAGE_POOL)), "initial scope")
    if dimension == "out-of-scope-cwe":
        return ("cwe_ids", draw(st.sampled_from(_CWE_POOL)), "initial scope")
    if dimension == "non-allowlisted-adapter":
        return (
            "supported_static_adapters",
            draw(st.sampled_from(_ADAPTER_POOL)),
            "unsupported static adapter",
        )
    if dimension == "confirmatory-provider-misconfig":
        return (
            "confirmation_provider",
            draw(st.sampled_from(_PROVIDER_POOL)),
            "only static adapters may confirm",
        )
    if dimension == "brittle-per-route-enumeration":
        return (
            "discovery_strategies",
            draw(st.sampled_from(_ROUTES_POOL)),
            "per-route",
        )
    if dimension == "unsupported-ranking-profile":
        return (
            "ranking_profiles",
            draw(st.sampled_from(_RANKING_POOL)),
            "ranking profile",
        )
    if dimension == "blank-database-path":
        return ("database_path", "", "database_path")
    if dimension == "unknown-extra-field":
        key = draw(st.sampled_from(_EXTRA_KEY_POOL))
        return (key, "1", key)
    raise AssertionError(f"unknown violation dimension {dimension!r}")


@st.composite
def _illegal_overrides(draw) -> tuple:
    """At least one violation dimension as ``key=value`` override strings.

    A blank ``database_path`` never mixes with other dimensions: any other
    override is run under a group-level ``--database`` that would repair the
    blank via the documented merge order, masking the violation.
    """
    primary = draw(st.sampled_from(_DIMENSIONS))
    if primary == "blank-database-path":
        chosen = [primary]
    else:
        pool = [d for d in _DIMENSIONS if d not in (primary, "blank-database-path")]
        chosen = [primary, *draw(st.lists(st.sampled_from(pool), max_size=2))]
    overrides = []
    fragments = set()
    for dimension in chosen:
        key, value, fragment = _violation(dimension, draw)
        overrides.append(f"{key}={value}")
        fragments.add(fragment)
    return tuple(overrides), tuple(sorted(fragments))


@settings(max_examples=200, deadline=None)
@given(payload=_illegal_overrides())
def test_property_p2_cli_config_gate_closure(payload) -> None:
    """Feature: ecatsl-operationalization-and-bench-integration, Property P2: the CLI configuration gate is closed — any illegal configuration exits 2, writes zero repository state, and the message names the violation."""
    overrides, fragments = payload
    base = tempfile.mkdtemp(prefix="p2-gate-")
    try:
        input_file = os.path.join(base, "samples.jsonl")
        with open(input_file, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(SAMPLE_ROW) + "\n")

        db_path = os.path.join(base, "ecatsl.db")

        argv = ["--clock", CLOCK]
        if not any(override.startswith("database_path=") for override in overrides):
            argv += ["--database", db_path]
        for override in overrides:
            argv += ["--set", override]
        argv += ["dataset", "--input", input_file]

        result = runner.invoke(ecatsl, argv)

        assert result.exit_code == 2, result.output[-300:]
        assert not os.path.exists(db_path), (
            "rejected configuration wrote repository state"
        )
        assert any(fragment in result.output for fragment in fragments), (
            result.output[-300:]
        )
    finally:
        shutil.rmtree(base, ignore_errors=True)
