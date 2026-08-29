"""Regression coverage for the Pure-AI-only scan command."""

import asyncio

import pytest
from click.testing import CliRunner

from src.ai.pure_ai.configuration import (
    PureAIConfigurationError,
    PureAIInitializationError,
)
from src.cli.commands.scan_cmd import _apply_scan_args
from src.cli.main import cli
from src.core.config import Config
from src.core.scanner import SecurityScanner


def test_scan_help_exposes_pure_ai_but_not_legacy_ai() -> None:
    result = CliRunner().invoke(cli, ["scan", "--help"])

    assert result.exit_code == 0, result.output
    assert "--pure-ai" in result.output
    assert "\n  --ai " not in result.output


def test_scan_arguments_configure_pure_ai_runtime() -> None:
    config = Config.model_validate(
        {
            "ai": {
                "modules": {
                    "pure_ai": {"provider": "openai", "model": "previous-model"},
                }
            }
        }
    )
    _apply_scan_args(
        config,
        {
            "output": None,
            "workers": 3,
            "pure_ai": True,
            "ai_provider": "deepseek",
            "ai_model": "deepseek-v4-flash",
            "test": 2,
            "resume": True,
            "truncate_output": True,
            "max_duration": 30,
            "max_files": 5,
            "tool_chain": "semgrep,code_vuln_scanner",
            "priority_strategy": "security-first",
            "sandbox": True,
        },
    )

    assert config.pure_ai is True
    assert config.ai.provider == "deepseek"
    assert config.ai.model == "deepseek-v4-flash"
    assert config.ai.get_provider("pure_ai") == "deepseek"
    assert config.ai.get_model("pure_ai") == "deepseek-v4-flash"
    assert config.scan.max_workers == 3
    assert config.test_mode is True
    assert config.test_file_count == 2
    assert config.resume is True
    assert config.max_duration == 30
    assert config.max_files == 5
    assert config.tools.tool_chain == ["semgrep", "code_vuln_scanner"]
    assert config.scan.priority_strategy == "security-first"
    assert config.sandbox.enabled is True


def test_pure_ai_scan_without_key_fails_before_scanning(monkeypatch) -> None:
    for variable in (
        "HOS_LS_AI_API_KEY",
        "HOS_LS_DEEPSEEK_API_KEY",
        "DEEPSEEK_API_KEY",
        "DEEPINFRA_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DASHSCOPE_API_KEY",
    ):
        monkeypatch.delenv(variable, raising=False)

    result = CliRunner().invoke(cli, ["scan", "--pure-ai", "."])

    assert result.exit_code == 2
    assert "--pure-ai requires an API key for provider 'deepseek'" in result.output
    assert "Scanning target:" not in result.output


def test_pure_ai_key_resolution_does_not_cross_provider_boundaries(monkeypatch) -> None:
    from src.ai.pure_ai.configuration import resolve_pure_ai_api_key

    config = Config.model_validate({"ai": {"provider": "openai"}})
    monkeypatch.setenv("DEEPSEEK_API_KEY", "deepseek-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    assert resolve_pure_ai_api_key(config) is None


class _FailingPureAIAnalyzer:
    initialized = False

    async def _initialize(self) -> None:
        raise PureAIInitializationError("provider validation rejected the configured key")


def test_direct_pure_ai_scan_without_key_fails_before_session_setup(monkeypatch) -> None:
    for variable in (
        "HOS_LS_AI_API_KEY",
        "HOS_LS_DEEPSEEK_API_KEY",
        "DEEPSEEK_API_KEY",
    ):
        monkeypatch.delenv(variable, raising=False)

    scanner = object.__new__(SecurityScanner)
    scanner.config = Config.model_validate({"pure_ai": True})

    with pytest.raises(PureAIConfigurationError):
        asyncio.run(scanner.scan("."))


def _direct_scanner_with_failing_provider() -> SecurityScanner:
    """Build a minimal direct-call scanner without allowing file discovery."""
    scanner = object.__new__(SecurityScanner)
    scanner.config = Config.model_validate(
        {"pure_ai": True, "ai": {"api_key": "test-key"}}
    )
    scanner.pure_ai_analyzer = _FailingPureAIAnalyzer()
    scanner._setup_interrupt_handler = lambda: None
    scanner._start_session = lambda _target: None
    scanner._pre_scan_cost_check = lambda _target: None
    return scanner


def test_direct_pure_ai_provider_failure_aborts_before_discovery() -> None:
    scanner = _direct_scanner_with_failing_provider()

    with pytest.raises(PureAIInitializationError, match="provider validation rejected"):
        asyncio.run(scanner.scan("."))


def test_direct_pure_ai_initialization_timeout_aborts_before_discovery(monkeypatch) -> None:
    async def raise_timeout(awaitable, **_kwargs) -> None:
        awaitable.close()
        raise asyncio.TimeoutError

    scanner = _direct_scanner_with_failing_provider()
    monkeypatch.setattr("src.core.scanner.asyncio.wait_for", raise_timeout)

    with pytest.raises(PureAIInitializationError, match="timed out"):
        asyncio.run(scanner.scan("."))
