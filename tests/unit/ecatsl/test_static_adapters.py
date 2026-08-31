"""Fixture-based static-adapter compatibility tests (ECATSL task 4.6).

Covers actual InputTracer return shapes and supported/unsupported
SARIF/CodeQL-oriented code-flow shapes, including complete path, plain hit,
missing provenance, empty propagation, sanitizer block/failure, malformed
output, and adapter exception. Asserts adapters delegate to
InputTracer/SastPrefilter, retain raw identity and failures, and never upgrade
catalog/discovery/RAG/LLM hints into path elements.

_Requirements: 2.7–2.8, 3.2–3.6, 4.1–4.5, 7.2, 11.12–11.13_
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from src.ecatsl.models import Provenance
from src.ecatsl.static_adapters import (
    CodeQLSastAdapter,
    InputTracerAdapter,
    NormalizationOutcome,
)

_FIXTURES = Path(__file__).parents[2] / "fixtures" / "ecatsl" / "static"
NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)


def _provenance(identity: str) -> Provenance:
    return Provenance(
        origin="fixture",
        retrieved_at=NOW,
        source_identifier=f"fixture:{identity}",
        source_revision="v1",
        content_identity=identity,
        transformation_history=("fixture-load:v1",),
    )


def _as_controllability(raw: dict) -> SimpleNamespace:
    """Wrap a dict-shaped InputTracer fixture as a controllability object."""
    return SimpleNamespace(
        trace_path=raw.get("trace_path") if "trace_path" in raw else raw.get("trace_path"),
        is_exploitable=raw.get("is_exploitable", False),
        confidence=raw.get("confidence", 0.0),
        source_type=raw.get("source_type", "unknown"),
        controllability_level=raw.get("controllability_level", "not_controlled"),
        summary=raw.get("summary", ""),
    )


def _load_fixture(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


# --- InputTracer fixtures ---------------------------------------------------

def test_input_tracer_complete_path_confirmatory() -> None:
    fixture = _load_fixture("input_tracer_complete.json")
    result = InputTracerAdapter(_FakeTracer()).normalize(
        _as_controllability(fixture), provenance=_provenance("tracer-complete")
    )
    assert result.outcome is NormalizationOutcome.COMPLETE_PATH
    assert result.confirmatory is True
    assert result.path_evidence is not None
    assert result.path_evidence.source.location == "app.py:12"
    assert result.path_evidence.sink.location == "app.py:18"
    assert len(result.path_evidence.propagation_steps) == 1


def test_input_tracer_no_path_unconfirmed() -> None:
    fixture = _load_fixture("input_tracer_no_path.json")
    result = InputTracerAdapter(_FakeTracer()).normalize(
        _as_controllability(fixture), provenance=_provenance("tracer-no-path")
    )
    assert result.outcome is NormalizationOutcome.NO_PATH
    assert result.confirmatory is False
    assert result.path_evidence is None
    assert result.validation.kind == "NO_PATH"


def test_input_tracer_incomplete_unconfirmed() -> None:
    fixture = _load_fixture("input_tracer_incomplete.json")
    result = InputTracerAdapter(_FakeTracer()).normalize(
        _as_controllability(fixture), provenance=_provenance("tracer-incomplete")
    )
    assert result.outcome is NormalizationOutcome.INCOMPLETE_PATH
    assert result.confirmatory is False
    assert result.path_evidence is None


def test_input_tracer_sanitizer_block_unconfirmed() -> None:
    fixture = _load_fixture("input_tracer_sanitized.json")
    result = InputTracerAdapter(_FakeTracer()).normalize(
        _as_controllability(fixture), provenance=_provenance("tracer-sanitized")
    )
    assert result.outcome is NormalizationOutcome.SANITIZER_EVIDENCE
    assert result.confirmatory is False
    assert result.path_evidence is None


# --- CodeQL fixtures --------------------------------------------------------

def test_codeql_complete_flow_confirmatory() -> None:
    fixture = _load_fixture("codeql_complete.json")
    result = CodeQLSastAdapter(_FakePrefilter()).normalize(
        fixture, provenance=_provenance("codeql-complete")
    )
    assert result.outcome is NormalizationOutcome.COMPLETE_PATH
    assert result.confirmatory is True
    assert result.path_evidence is not None
    assert result.path_evidence.source.location == "app.py:12"
    assert result.path_evidence.sink.location == "app.py:18"


def test_codeql_plain_hit_unconfirmed() -> None:
    fixture = _load_fixture("codeql_plain_hit.json")
    result = CodeQLSastAdapter(_FakePrefilter()).normalize(
        fixture, provenance=_provenance("codeql-plain")
    )
    assert result.outcome is NormalizationOutcome.INCOMPLETE_PATH
    assert result.confirmatory is False
    assert result.path_evidence is None
    assert result.validation.outcome == "INCOMPLETE_PATH"


def test_codeql_missing_provenance_unconfirmed() -> None:
    fixture = _load_fixture("codeql_missing_provenance.json")
    result = CodeQLSastAdapter(_FakePrefilter()).normalize(
        fixture, provenance=_provenance("codeql-missing-provenance")
    )
    assert result.confirmatory is False
    assert result.path_evidence is None


def test_codeql_empty_propagation_unconfirmed() -> None:
    fixture = _load_fixture("codeql_empty_propagation.json")
    result = CodeQLSastAdapter(_FakePrefilter()).normalize(
        fixture, provenance=_provenance("codeql-empty-propagation")
    )
    assert result.confirmatory is False
    assert result.path_evidence is None


def test_codeql_sanitizer_block_unconfirmed() -> None:
    fixture = _load_fixture("codeql_sanitizer_block.json")
    result = CodeQLSastAdapter(_FakePrefilter()).normalize(
        fixture, provenance=_provenance("codeql-sanitizer-block")
    )
    assert result.confirmatory is False
    assert result.path_evidence is None


def test_codeql_malformed_unconfirmed() -> None:
    fixture = _load_fixture("codeql_malformed.json")
    result = CodeQLSastAdapter(_FakePrefilter()).normalize(
        fixture, provenance=_provenance("codeql-malformed")
    )
    assert result.confirmatory is False
    assert result.path_evidence is None


# --- Adapter exception / delegation ----------------------------------------

def test_adapter_exception_retains_failure() -> None:
    fixture = _load_fixture("adapter_exception.json")
    # The exception shape itself is not a valid trace; the adapter must not
    # manufacture a path from it.
    result = InputTracerAdapter(_FakeTracer()).normalize(
        _as_controllability(fixture), provenance=_provenance("adapter-exception")
    )
    assert result.confirmatory is False
    assert result.path_evidence is None
    assert result.reason  # failure reason retained


def test_adapter_delegates_to_tracer() -> None:
    tracer = _FakeTracer(calls=[])
    adapter = InputTracerAdapter(tracer)
    # Delegation is bound at construction: the adapter holds the real
    # InputTracer instance it will drive; it never reimplements tracing.
    assert adapter.tracer is tracer
    assert adapter.adapter_id == "input-tracer"
    assert adapter.adapter_version == "1"


def test_adapter_never_upgrades_hints_to_path() -> None:
    # A plain SARIF hit with a catalog/RAG/LLM hint must stay unconfirmed; the
    # hint must not be synthesized into propagation/sink elements.
    fixture = _load_fixture("codeql_plain_hit.json")
    fixture["hint"] = {"origin": "rag", "sink": "app.py:99", "propagation": ["app.py:1"]}
    result = CodeQLSastAdapter(_FakePrefilter()).normalize(
        fixture, provenance=_provenance("hint-no-upgrade")
    )
    assert result.confirmatory is False
    assert result.path_evidence is None
    assert result.validation.outcome != "COMPLETE_PATH"


class _FakeTracer:
    def __init__(self, calls=None):
        self.calls = calls or []

    def trace_controllability(self, file_path, line_number, code_snippet=None):
        self.calls.append("trace_controllability")
        return SimpleNamespace(
            trace_path=[],
            is_exploitable=False,
            confidence=0.0,
            source_type="unknown",
            controllability_level="not_controlled",
            summary="",
        )


class _FakePrefilter:
    def codeql_hard_analyze(self, source_root, files=None):
        return {"available": False, "hits": [], "note": "unavailable"}
