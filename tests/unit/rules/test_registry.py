"""规则注册表测试"""

import pytest

from src.rules.registry import RuleRegistry, get_registry, register_rule, get_rule, list_rules
from src.rules.base import BaseRule, RuleMetadata, RuleCategory, RuleSeverity


class MockRule(BaseRule):
    def __init__(self, rule_id="TEST001", name="Test Rule"):
        metadata = RuleMetadata(
            id=rule_id,
            name=name,
            description="A test rule",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.INJECTION,
            language="*",
        )
        super().__init__(metadata)

    def check(self, target):
        return []


class TestRuleRegistry:
    def test_register_rule(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule = MockRule()
        registry.register(rule)
        
        assert registry.has("TEST001")
        assert registry.get("TEST001") is rule

    def test_register_duplicate_rule(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule1 = MockRule()
        rule2 = MockRule()
        
        registry.register(rule1)
        
        with pytest.raises(ValueError):
            registry.register(rule2)

    def test_unregister_rule(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule = MockRule()
        registry.register(rule)
        assert registry.has("TEST001")
        
        registry.unregister("TEST001")
        assert not registry.has("TEST001")

    def test_get_nonexistent_rule(self):
        registry = RuleRegistry()
        registry.clear()
        
        assert registry.get("NONEXISTENT") is None

    def test_list_rules(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule1 = MockRule("TEST001", "Rule 1")
        rule2 = MockRule("TEST002", "Rule 2")
        
        registry.register(rule1)
        registry.register(rule2)
        
        rules = registry.list_rules(enabled_only=False)
        assert len(rules) == 2

    def test_list_rules_by_category(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule = MockRule()
        registry.register(rule)
        
        rules = registry.get_rules_by_category(RuleCategory.INJECTION)
        assert len(rules) == 1

    def test_list_rules_by_severity(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule = MockRule()
        registry.register(rule)
        
        rules = registry.get_rules_by_severity(RuleSeverity.MEDIUM)
        assert len(rules) == 1

    def test_enable_disable_rule(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule = MockRule()
        registry.register(rule)
        
        assert rule.is_enabled()
        
        registry.disable_rule("TEST001")
        assert not rule.is_enabled()
        
        registry.enable_rule("TEST001")
        assert rule.is_enabled()

    def test_get_statistics(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule1 = MockRule("TEST001", "Rule 1")
        rule2 = MockRule("TEST002", "Rule 2")
        
        registry.register(rule1)
        registry.register(rule2)
        registry.disable_rule("TEST002")
        
        stats = registry.get_statistics()
        
        assert stats["total"] == 2
        assert stats["enabled"] == 1
        assert stats["disabled"] == 1

    def test_load_builtin_rules(self):
        registry = RuleRegistry()
        registry.clear()
        
        count = registry.load_builtin_rules()
        
        assert count > 0
        assert registry.has("HOS001")
        assert registry.has("HOS002")

    def test_to_dict(self):
        registry = RuleRegistry()
        registry.clear()
        
        rule = MockRule()
        registry.register(rule)
        
        data = registry.to_dict()
        
        assert "rules" in data
        assert "statistics" in data
        assert "TEST001" in data["rules"]


class TestGlobalFunctions:
    def test_get_registry(self):
        registry1 = get_registry()
        registry2 = get_registry()
        assert registry1 is registry2

    def test_register_rule_function(self):
        registry = get_registry()
        registry.clear()
        
        rule = MockRule("GLOBAL001", "Global Rule")
        register_rule(rule)
        
        assert registry.has("GLOBAL001")

    def test_get_rule_function(self):
        registry = get_registry()
        registry.clear()
        
        rule = MockRule("GLOBAL002", "Global Rule 2")
        register_rule(rule)
        
        retrieved = get_rule("GLOBAL002")
        assert retrieved is rule

    def test_list_rules_function(self):
        registry = get_registry()
        registry.clear()
        
        rule = MockRule("GLOBAL003", "Global Rule 3")
        register_rule(rule)
        
        rules = list_rules()
        assert len(rules) >= 1
