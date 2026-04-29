"""配置模块测试"""

import pytest
from pathlib import Path
import tempfile

from src.core.config import (
    Config,
    ConfigManager,
    AIConfig,
    ScanConfig,
    RulesConfig,
    ReportConfig,
)


class TestAIConfig:
    def test_default_values(self):
        config = AIConfig()
        assert config.provider == "anthropic"
        assert config.model == "claude-3-5-sonnet-20241022"
        assert config.temperature == 0.0
        assert config.max_tokens == 4096
        assert config.timeout == 60

    def test_invalid_provider(self):
        with pytest.raises(ValueError):
            AIConfig(provider="invalid_provider")

    def test_valid_providers(self):
        for provider in ["anthropic", "openai", "deepseek", "local"]:
            config = AIConfig(provider=provider)
            assert config.provider == provider


class TestScanConfig:
    def test_default_values(self):
        config = ScanConfig()
        assert config.max_workers == 4
        assert config.cache_enabled is True
        assert config.incremental is True
        assert config.timeout == 300

    def test_exclude_patterns(self):
        config = ScanConfig()
        assert "node_modules/**" in config.exclude_patterns
        assert "__pycache__/**" in config.exclude_patterns

    def test_include_patterns(self):
        config = ScanConfig()
        assert "*.py" in config.include_patterns
        assert "*.js" in config.include_patterns


class TestRulesConfig:
    def test_default_values(self):
        config = RulesConfig()
        assert config.ruleset == "default"
        assert config.severity_threshold == "low"
        assert config.confidence_threshold == 0.5

    def test_invalid_severity(self):
        with pytest.raises(ValueError):
            RulesConfig(severity_threshold="invalid")

    def test_valid_severities(self):
        for severity in ["critical", "high", "medium", "low", "info"]:
            config = RulesConfig(severity_threshold=severity)
            assert config.severity_threshold == severity


class TestReportConfig:
    def test_default_values(self):
        config = ReportConfig()
        assert config.format == "html"
        assert config.output == "./security-report"
        assert config.include_code_snippets is True

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            ReportConfig(format="invalid_format")

    def test_valid_formats(self):
        for fmt in ["html", "markdown", "json", "sarif", "xml"]:
            config = ReportConfig(format=fmt)
            assert config.format == fmt


class TestConfig:
    def test_default_config(self):
        config = Config()
        assert config.version == "3.0.0"
        assert isinstance(config.ai, AIConfig)
        assert isinstance(config.scan, ScanConfig)
        assert isinstance(config.rules, RulesConfig)
        assert isinstance(config.report, ReportConfig)

    def test_nested_config(self):
        config = Config(
            ai={"provider": "openai", "model": "gpt-4"},
            scan={"max_workers": 8},
        )
        assert config.ai.provider == "openai"
        assert config.ai.model == "gpt-4"
        assert config.scan.max_workers == 8


class TestConfigManager:
    def test_singleton(self):
        manager1 = ConfigManager()
        manager2 = ConfigManager()
        assert manager1 is manager2

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
ai:
  provider: openai
  model: gpt-4
scan:
  max_workers: 8
""")
            f.flush()
            
            manager = ConfigManager()
            manager.reset()
            config = manager.load_from_file(f.name)
            
            assert config.ai.provider == "openai"
            assert config.ai.model == "gpt-4"
            assert config.scan.max_workers == 8

    def test_save_to_file(self):
        manager = ConfigManager()
        manager.reset()
        config = Config(ai={"provider": "deepseek"})
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"
            manager.save_to_file(path, config)
            
            assert path.exists()
            content = path.read_text()
            assert "deepseek" in content

    def test_auto_load_default(self):
        manager = ConfigManager()
        manager.reset()
        config = manager.auto_load()
        assert isinstance(config, Config)

    def test_update_config(self):
        manager = ConfigManager()
        manager.reset()
        config = manager.update(debug=True)
        assert config.debug is True
