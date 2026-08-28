"""Regression coverage for the Pure-AI-only scan command."""

from click.testing import CliRunner

from src.cli.commands.scan_cmd import _apply_scan_args
from src.cli.main import cli
from src.core.config import Config


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
