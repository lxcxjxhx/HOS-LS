"""Configuration module tests"""

import os
import tempfile
import pytest
from pathlib import Path

from src.core.config import (
    Config, ConfigManager, AuditMode,
    AIModuleConfig, AliyunConfig, TierModelConfig, TieredArchitectureConfig,
    AIConfig, ScanConfig, RulesConfig, ReportConfig, DatabaseConfig,
    SandboxConfig, Neo4jConfig, RAGHybridConfig, RAGBM25Config,
    RAGRerankConfig, RAGConfig, NVDConfig, DataPreloadConfig,
    SemgrepConfig, TrivyConfig, SyftConfig, GitleaksConfig, ToolConfig,
    PriorityWeightsConfig, PriorityThresholdsConfig, PriorityConfig,
    ValidationConfig, AgentConfig, get_config,
)


class TestAuditMode:
    def test_audit_mode_values(self):
        assert AuditMode.STATIC.value == "static"
        assert AuditMode.DYNAMIC.value == "dynamic"
        assert AuditMode.HYBRID.value == "hybrid"


class TestAIModuleConfig:
    def test_default_values(self):
        config = AIModuleConfig()
        assert config.enabled is True
        assert config.model is None
        assert config.provider is None
        assert config.temperature is None
        assert config.max_tokens is None

    def test_custom_values(self):
        config = AIModuleConfig(
            enabled=False,
            model="test-model",
            provider="test-provider",
            temperature=0.5,
            max_tokens=1024,
        )
        assert config.enabled is False
        assert config.model == "test-model"
        assert config.provider == "test-provider"
        assert config.temperature == 0.5
        assert config.max_tokens == 1024


class TestAIConfig:
    def test_default_values(self):
        config = AIConfig()
        assert config.enabled is False
        assert config.provider == "deepseek"
        assert config.model == "deepseek-v4-flash"
        assert config.temperature == 0.0
        assert config.max_tokens == 4096
        assert config.timeout == 60
        assert config.enable_learning is True
        assert config.allow_fallback is True

    def test_get_model_module_specific(self):
        config = AIConfig()
        config.modules = {
            "pure_ai": AIModuleConfig(model="gpt-4"),
            "rag": AIModuleConfig(model="claude-3"),
        }
        assert config.get_model("pure_ai") == "gpt-4"
        assert config.get_model("rag") == "claude-3"
        assert config.get_model("unknown") == "deepseek-v4-flash"

    def test_get_model_env_fallback(self, monkeypatch):
        monkeypatch.setenv("HOS_LS_AI_MODEL", "env-model")
        config = AIConfig()
        assert config.get_model() == "env-model"
        monkeypatch.delenv("HOS_LS_AI_MODEL")

    def test_get_provider_module_specific(self):
        config = AIConfig()
        config.modules = {
            "pure_ai": AIModuleConfig(provider="openai"),
        }
        assert config.get_provider("pure_ai") == "openai"
        assert config.get_provider("unknown") == "deepseek"

    def test_get_provider_env_fallback(self, monkeypatch):
        monkeypatch.setenv("HOS_LS_AI_PROVIDER", "env-provider")
        config = AIConfig()
        assert config.get_provider() == "env-provider"
        monkeypatch.delenv("HOS_LS_AI_PROVIDER")

    def test_get_temperature(self):
        config = AIConfig(temperature=0.7)
        config.modules = {
            "pure_ai": AIModuleConfig(temperature=0.9),
        }
        assert config.get_temperature("pure_ai") == 0.9
        assert config.get_temperature("unknown") == 0.7

    def test_get_max_tokens(self):
        config = AIConfig(max_tokens=2048)
        config.modules = {
            "pure_ai": AIModuleConfig(max_tokens=4096),
        }
        assert config.get_max_tokens("pure_ai") == 4096
        assert config.get_max_tokens("unknown") == 2048

    def test_invalid_provider(self):
        with pytest.raises(Exception):
            AIConfig(provider="invalid")


class TestScanConfig:
    def test_default_values(self):
        config = ScanConfig()
        assert config.max_workers == 4
        assert config.cache_enabled is True
        assert config.incremental is True
        assert config.timeout == 300
        assert config.max_file_size == 10 * 1024 * 1024
        assert config.port_scan_enabled is False
        assert config.ports_only is False
        assert config.port_range == "1-65535"
        assert config.priority_strategy == "full-scan"

    def test_exclude_patterns(self):
        config = ScanConfig()
        assert "*.min.js" in config.exclude_patterns
        assert "node_modules/**" in config.exclude_patterns
        assert ".git/**" in config.exclude_patterns

    def test_include_patterns(self):
        config = ScanConfig()
        assert "*.py" in config.include_patterns
        assert "*.js" in config.include_patterns


class TestRulesConfig:
    def test_default_values(self):
        config = RulesConfig()
        assert config.enabled == []
        assert config.disabled == []
        assert config.ruleset == "default"
        assert config.severity_threshold == "low"
        assert config.confidence_threshold == 0.5
        assert config.poc_severity_threshold == "high"

    def test_invalid_severity_threshold(self):
        with pytest.raises(Exception):
            RulesConfig(severity_threshold="invalid")


class TestReportConfig:
    def test_default_values(self):
        config = ReportConfig()
        assert config.format == "html"
        assert config.output == "./security-report"
        assert config.include_code_snippets is True
        assert config.include_fix_suggestions is True
        assert config.category_filter == "all"

    def test_invalid_format(self):
        with pytest.raises(Exception):
            ReportConfig(format="invalid")


class TestDatabaseConfig:
    def test_default_values(self):
        config = DatabaseConfig()
        assert config.url == "sqlite:///hos-ls.db"
        assert config.wal_mode is True
        assert config.pool_size == 5
        assert config.max_overflow == 10
        assert config.echo is False


class TestSandboxConfig:
    def test_default_values(self):
        config = SandboxConfig()
        assert config.enabled is True
        assert config.mode == AuditMode.HYBRID
        assert config.max_memory == 512 * 1024 * 1024
        assert config.max_cpu_time == 30
        assert config.network_access is False
        assert config.file_system_access is False


class TestRAGConfig:
    def test_default_values(self):
        config = RAGConfig()
        assert config.hybrid.enabled is True
        assert config.hybrid.hybrid_search_weight == 0.7
        assert config.hybrid.top_k == 10
        assert config.bm25.enabled is True
        assert config.bm25.k1 == 1.2
        assert config.bm25.b == 0.75
        assert config.rerank.enabled is False


class TestNVDConfig:
    def test_default_values(self):
        config = NVDConfig()
        assert config.enabled is True
        assert config.min_cvss_score == 5.0
        assert config.prefer_kev is True
        assert config.query_timeout == 30
        assert config.auto_connect is True


class TestToolConfig:
    def test_default_values(self):
        config = ToolConfig()
        assert config.enabled is True
        assert "semgrep" in config.tool_chain
        assert "trivy" in config.tool_chain
        assert "gitleaks" in config.tool_chain
        assert config.segrep.enabled is True
        assert config.trivy.enabled is True


class TestValidationConfig:
    def test_default_values(self):
        config = ValidationConfig()
        assert config.enabled is True
        assert config.auto_validate_high is True
        assert config.auto_validate_medium is False
        assert config.min_confidence_threshold == 0.7
        assert config.enable_verification is True
        assert config.enable_fuzzy_matching is True
        assert config.poc_generation_enabled is True
        assert config.poc_execution_enabled is False


class TestConfig:
    def test_default_config(self):
        config = Config()
        assert config.version == "3.0.0"
        assert config.debug is False
        assert config.verbose is False
        assert config.quiet is False
        assert config.test_mode is False
        assert config.pure_ai is False
        assert config.scan_mode == "auto"
        assert config.language == "zh"
        assert config.filter_hallucinations is True
        assert config.resume is False
        assert config.precision_mode is False

    def test_ai_config(self):
        config = Config()
        assert isinstance(config.ai, AIConfig)

    def test_scan_config(self):
        config = Config()
        assert isinstance(config.scan, ScanConfig)

    def test_rules_config(self):
        config = Config()
        assert isinstance(config.rules, RulesConfig)

    def test_report_config(self):
        config = Config()
        assert isinstance(config.report, ReportConfig)

    def test_database_config(self):
        config = Config()
        assert isinstance(config.database, DatabaseConfig)

    def test_sandbox_config(self):
        config = Config()
        assert isinstance(config.sandbox, SandboxConfig)

    def test_neo4j_config(self):
        config = Config()
        assert isinstance(config.neo4j, Neo4jConfig)
        assert config.neo4j.uri == "neo4j://localhost:7687"
        assert config.neo4j.username == "neo4j"
        assert config.neo4j.password == "password"

    def test_rag_config(self):
        config = Config()
        assert isinstance(config.rag, RAGConfig)

    def test_nvd_config(self):
        config = Config()
        assert isinstance(config.nvd, NVDConfig)

    def test_tools_config(self):
        config = Config()
        assert isinstance(config.tools, ToolConfig)

    def test_priority_config(self):
        config = Config()
        assert isinstance(config.priority, PriorityConfig)
        assert config.priority.enabled is True
        assert config.priority.weights.cvss == 0.40
        assert config.priority.weights.exploitability == 0.35
        assert config.priority.weights.reachability == 0.25
        assert config.priority.thresholds.critical == 9.0
        assert config.priority.thresholds.high == 7.0
        assert config.priority.thresholds.medium == 4.0

    def test_validation_config(self):
        config = Config()
        assert isinstance(config.validation, ValidationConfig)

    def test_agent_config(self):
        config = Config()
        assert isinstance(config.agent, AgentConfig)
        assert config.agent.dynamic_selection is True
        assert config.agent.skip_context_if_sufficient is True

    def test_pure_ai_model_property(self):
        config = Config()
        model = config.pure_ai_model
        assert isinstance(model, str)

    def test_pure_ai_provider_property(self):
        config = Config()
        provider = config.pure_ai_provider
        assert isinstance(provider, str)


class TestConfigManager:
    def test_singleton(self):
        manager1 = ConfigManager()
        manager2 = ConfigManager()
        assert manager1 is manager2

    def test_default_config(self):
        manager = ConfigManager()
        config = manager.config
        assert config is not None
        assert isinstance(config, Config)

    def test_load_from_env(self):
        manager = ConfigManager()
        config = manager.load_from_env()
        assert config is not None
        assert isinstance(config, Config)

    def test_reset(self):
        manager = ConfigManager()
        manager.update(debug=True)
        assert manager.config.debug is True
        manager.reset()
        assert manager.config.debug is False

    def test_update(self):
        manager = ConfigManager()
        config = manager.update(debug=True, verbose=True)
        assert config.debug is True
        assert config.verbose is True

    def test_get_write_count(self):
        manager = ConfigManager()
        count = manager.get_write_count()
        assert isinstance(count, int)

    def test_clear_cache(self):
        manager = ConfigManager()
        manager.clear_cache()

    def test_load_from_yaml_file(self):
        manager = ConfigManager()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("debug: true\nverbose: true\n")
            f.flush()
            config = manager.load_from_file(f.name)
            assert config.debug is True
            assert config.verbose is True

    def test_load_from_nonexistent_file(self):
        manager = ConfigManager()
        with pytest.raises(FileNotFoundError):
            manager.load_from_file("/nonexistent/path/config.yaml")

    def test_auto_load_no_file(self):
        manager = ConfigManager()
        config = manager.auto_load()
        assert config is not None
        assert isinstance(config, Config)

    def test_load_env_var_resolution(self):
        manager = ConfigManager()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("debug: ${HOS_LS_TEST_DEBUG}\n")
            f.flush()
            os.environ["HOS_LS_TEST_DEBUG"] = "true"
            try:
                manager.clear_cache()
                config = manager.load_from_file(f.name)
                assert str(config.debug) == "true"
            finally:
                del os.environ["HOS_LS_TEST_DEBUG"]

    def test_save_to_file(self):
        manager = ConfigManager()
        with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False) as f:
            path = f.name
            manager.save_to_file(path)
            assert os.path.exists(path)
