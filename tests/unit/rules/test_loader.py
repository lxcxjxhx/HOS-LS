"""Rules loader module tests"""

import json
import tempfile
import pytest
from pathlib import Path

from src.rules.loader import RuleLoader, SourceSinkMatcher
from src.rules.base import RuleDefinition
from src.rules.registry import RuleRegistry


class TestSourceSinkMatcher:
    def test_init(self):
        matcher = SourceSinkMatcher()
        assert matcher._source_patterns == {}
        assert matcher._sink_patterns == {}
        assert matcher._sanitizer_patterns == {}

    def test_load_rules(self):
        matcher = SourceSinkMatcher()
        rule = RuleDefinition(
            id="TEST001",
            cwe="CWE-89",
            name="SQL Injection",
            description="Test",
            severity="high",
            category="injection",
            languages=["python"],
            sources=["request.GET", "request.POST"],
            sinks=["cursor.execute", "db.query"],
            sanitizers=["escape", "sanitize"],
        )
        matcher.load_rules([rule])
        assert "python" in matcher._source_patterns
        assert "python" in matcher._sink_patterns
        assert "python" in matcher._sanitizer_patterns

    def test_match_source(self):
        matcher = SourceSinkMatcher()
        rule = RuleDefinition(
            id="TEST001",
            cwe="CWE-89",
            name="Test",
            description="Test",
            severity="high",
            category="injection",
            languages=["python"],
            sources=["request.GET"],
            sinks=[],
            sanitizers=[],
        )
        matcher.load_rules([rule])
        matches = matcher.match_source("data = request.GET['id']", "python")
        assert len(matches) > 0

    def test_match_sink(self):
        matcher = SourceSinkMatcher()
        rule = RuleDefinition(
            id="TEST001",
            cwe="CWE-89",
            name="Test",
            description="Test",
            severity="high",
            category="injection",
            languages=["python"],
            sources=[],
            sinks=["cursor.execute"],
            sanitizers=[],
        )
        matcher.load_rules([rule])
        matches = matcher.match_sink("cursor.execute(query)", "python")
        assert len(matches) > 0

    def test_match_sanitizer(self):
        matcher = SourceSinkMatcher()
        rule = RuleDefinition(
            id="TEST001",
            cwe="CWE-89",
            name="Test",
            description="Test",
            severity="high",
            category="injection",
            languages=["python"],
            sources=[],
            sinks=[],
            sanitizers=["escape_html"],
        )
        matcher.load_rules([rule])
        matches = matcher.match_sanitizer("clean = escape_html(data)", "python")
        assert len(matches) > 0

    def test_has_sanitizer(self):
        matcher = SourceSinkMatcher()
        rule = RuleDefinition(
            id="TEST001",
            cwe="CWE-89",
            name="Test",
            description="Test",
            severity="high",
            category="injection",
            languages=["python"],
            sources=[],
            sinks=[],
            sanitizers=["escape_html"],
        )
        matcher.load_rules([rule])
        assert matcher.has_sanitizer("escape_html(data)", "python") is True
        assert matcher.has_sanitizer("no_match(data)", "python") is False

    def test_match_unsupported_language(self):
        matcher = SourceSinkMatcher()
        matches = matcher.match_source("some code", "unknown_lang")
        assert matches == []

    def test_load_disabled_rule(self):
        matcher = SourceSinkMatcher()
        rule = RuleDefinition(
            id="TEST001",
            cwe="CWE-89",
            name="Test",
            description="Test",
            severity="high",
            category="injection",
            languages=["python"],
            sources=["source"],
            sinks=["sink"],
            sanitizers=[],
            enabled=False,
        )
        matcher.load_rules([rule])
        assert "python" not in matcher._source_patterns

    def test_invalid_regex_pattern(self):
        matcher = SourceSinkMatcher()
        rule = RuleDefinition(
            id="TEST001",
            cwe="CWE-89",
            name="Test",
            description="Test",
            severity="high",
            category="injection",
            languages=["python"],
            sources=["[invalid("],
            sinks=[],
            sanitizers=[],
        )
        matcher.load_rules([rule])


class TestRuleLoader:
    def setup_method(self):
        self.registry = RuleRegistry()
        self.registry.clear()
        self.loader = RuleLoader(self.registry)

    def test_init(self):
        loader = RuleLoader()
        assert loader._loaded_modules == {}

    def test_load_builtin_rules(self):
        count = self.loader.load_builtin_rules()
        assert count > 0
        assert self.registry.has("HOS001")

    def test_load_from_nonexistent_module(self):
        count = self.loader.load_from_module("nonexistent.module")
        assert count == 0

    def test_load_from_directory_nonexistent(self):
        count = self.loader.load_from_directory(Path("/nonexistent/dir"))
        assert count == 0

    def test_get_loaded_modules(self):
        modules = self.loader.get_loaded_modules()
        assert isinstance(modules, list)

    def test_reload_rules(self):
        self.loader.load_builtin_rules()
        count = self.loader.reload_rules()
        assert count > 0

    def test_load_from_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([
                {
                    "id": "JSON001",
                    "cwe": "CWE-89",
                    "name": "JSON Rule",
                    "description": "Test rule from JSON",
                    "severity": "high",
                    "category": "injection",
                    "languages": ["python"],
                    "sources": [],
                    "sinks": [],
                    "sanitizers": [],
                }
            ], f)
            f.flush()
            count = self.loader.load_from_json(Path(f.name))
            assert count == 1

    def test_load_from_json_invalid_file(self):
        count = self.loader.load_from_json(Path("/nonexistent/rules.json"))
        assert count == 0

    def test_load_from_json_invalid_content(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json {{{")
            f.flush()
            count = self.loader.load_from_json(Path(f.name))
            assert count == 0

    def test_load_json_rules_from_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = Path(tmpdir) / "rules.json"
            with open(json_file, 'w') as f:
                json.dump({
                    "rules": [
                        {
                            "id": "JSON002",
                            "cwe": "CWE-89",
                            "name": "JSON Rule 2",
                            "description": "Test",
                            "severity": "high",
                            "category": "injection",
                            "languages": ["python"],
                            "sources": [],
                            "sinks": [],
                            "sanitizers": [],
                        }
                    ]
                }, f)
            count = self.loader.load_json_rules(Path(tmpdir))
            assert count == 1

    def test_load_from_config(self):
        config = {"enabled": []}
        count = self.loader.load_from_config(config)
        assert count == 0

    def test_load_from_json_with_list_format(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([
                {
                    "id": "JSON003",
                    "cwe": "CWE-79",
                    "name": "List Format Rule",
                    "description": "Test",
                    "severity": "medium",
                    "category": "xss",
                    "languages": ["javascript"],
                    "sources": [],
                    "sinks": [],
                    "sanitizers": [],
                }
            ], f)
            f.flush()
            count = self.loader.load_from_json(Path(f.name))
            assert count == 1
