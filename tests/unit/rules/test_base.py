"""规则基类测试"""

import pytest
from pathlib import Path
import tempfile

from src.rules.base import (
    BaseRule,
    PatternRule,
    RuleMetadata,
    RuleResult,
    RuleSeverity,
    RuleCategory,
)


class TestRuleSeverity:
    def test_ordering(self):
        assert RuleSeverity.INFO < RuleSeverity.LOW
        assert RuleSeverity.LOW < RuleSeverity.MEDIUM
        assert RuleSeverity.MEDIUM < RuleSeverity.HIGH
        assert RuleSeverity.HIGH < RuleSeverity.CRITICAL

    def test_comparison(self):
        assert RuleSeverity.CRITICAL > RuleSeverity.HIGH
        assert RuleSeverity.HIGH >= RuleSeverity.HIGH
        assert RuleSeverity.LOW <= RuleSeverity.MEDIUM


class TestRuleCategory:
    def test_all_categories_exist(self):
        categories = [
            RuleCategory.INJECTION,
            RuleCategory.AUTHENTICATION,
            RuleCategory.AUTHORIZATION,
            RuleCategory.CRYPTOGRAPHY,
            RuleCategory.DATA_PROTECTION,
            RuleCategory.ERROR_HANDLING,
            RuleCategory.LOGGING,
            RuleCategory.CONFIGURATION,
            RuleCategory.DEPENDENCY,
            RuleCategory.PERFORMANCE,
            RuleCategory.CODE_QUALITY,
            RuleCategory.AI_SECURITY,
        ]
        assert len(categories) == 12


class TestRuleResult:
    def test_default_values(self):
        result = RuleResult(
            rule_id="TEST001",
            rule_name="Test Rule",
            passed=False,
            message="Test message",
        )
        
        assert result.rule_id == "TEST001"
        assert result.confidence == 1.0
        assert result.code_snippet == ""
        assert result.fix_suggestion == ""

    def test_to_dict(self):
        result = RuleResult(
            rule_id="TEST001",
            rule_name="Test Rule",
            passed=False,
            message="Test message",
            severity=RuleSeverity.HIGH,
            confidence=0.9,
        )
        
        data = result.to_dict()
        
        assert data["rule_id"] == "TEST001"
        assert data["severity"] == "high"
        assert data["confidence"] == 0.9


class TestRuleMetadata:
    def test_default_values(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            language="python",
        )
        
        assert metadata.version == "1.0.0"
        assert metadata.enabled is True
        assert metadata.deprecated is False
        assert metadata.references == []
        assert metadata.tags == []

    def test_full_metadata(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            language="python",
            version="2.0.0",
            author="Test Author",
            references=["https://example.com"],
            tags=["security", "injection"],
        )
        
        assert metadata.version == "2.0.0"
        assert metadata.author == "Test Author"
        assert len(metadata.references) == 1
        assert len(metadata.tags) == 2


class ConcreteRule(BaseRule):
    def check(self, target):
        return [
            RuleResult(
                rule_id=self.id,
                rule_name=self.name,
                passed=False,
                message="Found issue",
            )
        ]


class TestBaseRule:
    def test_rule_properties(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            language="python",
        )
        rule = ConcreteRule(metadata)
        
        assert rule.id == "TEST001"
        assert rule.name == "Test Rule"
        assert rule.severity == RuleSeverity.HIGH
        assert rule.category == RuleCategory.INJECTION
        assert rule.language == "python"

    def test_is_enabled(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            language="python",
        )
        rule = ConcreteRule(metadata)
        
        assert rule.is_enabled()
        
        metadata.enabled = False
        assert not rule.is_enabled()

    def test_matches_language(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            language="python",
        )
        rule = ConcreteRule(metadata)
        
        assert rule.matches_language("python")
        assert rule.matches_language("Python")
        assert not rule.matches_language("javascript")

    def test_matches_all_languages(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            language="*",
        )
        rule = ConcreteRule(metadata)
        
        assert rule.matches_language("python")
        assert rule.matches_language("javascript")
        assert rule.matches_language("java")

    def test_to_dict(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            language="python",
        )
        rule = ConcreteRule(metadata)
        
        data = rule.to_dict()
        
        assert data["id"] == "TEST001"
        assert data["name"] == "Test Rule"
        assert data["severity"] == "high"
        assert data["category"] == "injection"

    def test_initialize_shutdown(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            language="python",
        )
        rule = ConcreteRule(metadata)
        
        assert not rule.is_initialized
        
        rule.initialize()
        assert rule.is_initialized
        
        rule.shutdown()
        assert not rule.is_initialized


class TestPatternRule:
    def test_pattern_matching(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Pattern Rule",
            description="A test pattern rule",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            language="*",
        )
        
        patterns = [r"password\s*=\s*[\"'][^\"']+[\"']"]
        rule = PatternRule(metadata, patterns)
        
        code = 'password = "secret123"'
        results = rule.check(code)
        
        assert len(results) == 1
        assert results[0].rule_id == "TEST001"
        assert "password" in results[0].code_snippet.lower()

    def test_pattern_from_file(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Pattern Rule",
            description="A test pattern rule",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            language="*",
        )
        
        patterns = [r"eval\s*\("]
        rule = PatternRule(metadata, patterns)
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("eval(user_input)")
            f.flush()
            
            results = rule.check(Path(f.name))
            assert len(results) == 1

    def test_no_match(self):
        metadata = RuleMetadata(
            id="TEST001",
            name="Test Pattern Rule",
            description="A test pattern rule",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.INJECTION,
            language="*",
        )
        
        patterns = [r"password\s*=\s*[\"'][^\"']+[\"']"]
        rule = PatternRule(metadata, patterns)
        
        code = "password = get_password()"
        results = rule.check(code)
        
        assert len(results) == 0
