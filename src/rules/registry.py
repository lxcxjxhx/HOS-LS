"""规则注册表模块

提供安全规则的注册、管理和查询功能。
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleSeverity, RuleDefinition


class RuleRegistry:
    """规则注册表

    管理所有安全规则的注册和查询。
    """

    _instance: Optional["RuleRegistry"] = None
    _rules: Dict[str, BaseRule] = {}
    _initialized: bool = False

    def __new__(cls) -> "RuleRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self._rules = {}
            self._initialized = True

    def register(self, rule: BaseRule) -> None:
        """注册规则

        Args:
            rule: 规则实例
        """
        if rule.id in self._rules:
            raise ValueError(f"规则 '{rule.id}' 已注册")

        self._rules[rule.id] = rule

    def unregister(self, rule_id: str) -> None:
        """注销规则

        Args:
            rule_id: 规则 ID
        """
        if rule_id in self._rules:
            del self._rules[rule_id]

    def get(self, rule_id: str) -> Optional[BaseRule]:
        """获取规则

        Args:
            rule_id: 规则 ID

        Returns:
            规则实例，如果未找到则返回 None
        """
        return self._rules.get(rule_id)

    def has(self, rule_id: str) -> bool:
        """检查规则是否存在

        Args:
            rule_id: 规则 ID

        Returns:
            是否存在
        """
        return rule_id in self._rules

    def list_rules(
        self,
        language: Optional[str] = None,
        category: Optional[RuleCategory] = None,
        severity: Optional[RuleSeverity] = None,
        enabled_only: bool = True,
    ) -> List[BaseRule]:
        """列出规则

        Args:
            language: 语言过滤
            category: 类别过滤
            severity: 严重级别过滤
            enabled_only: 只返回启用的规则

        Returns:
            规则列表
        """
        rules = list(self._rules.values())

        if enabled_only:
            rules = [r for r in rules if r.is_enabled()]

        if language:
            rules = [r for r in rules if r.matches_language(language)]

        if category:
            rules = [r for r in rules if r.category == category]

        if severity:
            rules = [r for r in rules if r.severity == severity]

        return rules

    def list_rule_ids(
        self,
        language: Optional[str] = None,
        category: Optional[RuleCategory] = None,
        enabled_only: bool = True,
    ) -> List[str]:
        """列出规则 ID

        Args:
            language: 语言过滤
            category: 类别过滤
            enabled_only: 只返回启用的规则

        Returns:
            规则 ID 列表
        """
        rules = self.list_rules(language, category, None, enabled_only)
        return [r.id for r in rules]

    def get_rules_by_category(self, category: RuleCategory) -> List[BaseRule]:
        """按类别获取规则

        Args:
            category: 规则类别

        Returns:
            规则列表
        """
        return [r for r in self._rules.values() if r.category == category]

    def get_rules_by_severity(self, severity: RuleSeverity) -> List[BaseRule]:
        """按严重级别获取规则

        Args:
            severity: 严重级别

        Returns:
            规则列表
        """
        return [r for r in self._rules.values() if r.severity == severity]

    def get_rules_by_language(self, language: str) -> List[BaseRule]:
        """按语言获取规则

        Args:
            language: 语言

        Returns:
            规则列表
        """
        return [r for r in self._rules.values() if r.matches_language(language)]

    def enable_rule(self, rule_id: str) -> bool:
        """启用规则

        Args:
            rule_id: 规则 ID

        Returns:
            是否成功
        """
        rule = self._rules.get(rule_id)
        if rule:
            rule.metadata.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """禁用规则

        Args:
            rule_id: 规则 ID

        Returns:
            是否成功
        """
        rule = self._rules.get(rule_id)
        if rule:
            rule.metadata.enabled = False
            return True
        return False

    def clear(self) -> None:
        """清空所有规则"""
        self._rules.clear()

    def load_builtin_rules(self) -> int:
        """加载内置规则
        
        Returns:
            加载的规则数量
        """
        from src.rules.loader import RuleLoader
        loader = RuleLoader(self)
        return loader.load_builtin_rules()

    def load_rules_from_directory(self, directory: Union[str, Path]) -> int:
        """从目录加载规则

        Args:
            directory: 规则目录

        Returns:
            加载的规则数量
        """
        # 这里将实现从文件加载规则的功能
        # 在后续开发中实现
        return 0

    def get_statistics(self) -> Dict[str, Any]:
        """获取规则统计信息

        Returns:
            统计信息字典
        """
        total = len(self._rules)
        enabled = sum(1 for r in self._rules.values() if r.is_enabled())
        disabled = total - enabled

        by_category = {}
        for category in RuleCategory:
            count = len(self.get_rules_by_category(category))
            if count > 0:
                by_category[category.value] = count

        by_severity = {}
        for severity in RuleSeverity:
            count = len(self.get_rules_by_severity(severity))
            if count > 0:
                by_severity[severity.value] = count

        return {
            "total": total,
            "enabled": enabled,
            "disabled": disabled,
            "by_category": by_category,
            "by_severity": by_severity,
        }

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "rules": {rule_id: rule.to_dict() for rule_id, rule in self._rules.items()},
            "statistics": self.get_statistics(),
        }


# 全局注册表实例
_registry: Optional[RuleRegistry] = None


def get_registry() -> RuleRegistry:
    """获取全局规则注册表实例

    Returns:
        规则注册表实例
    """
    global _registry
    if _registry is None:
        _registry = RuleRegistry()
    return _registry


def register_rule(rule: BaseRule) -> None:
    """注册规则

    Args:
        rule: 规则实例
    """
    get_registry().register(rule)


def get_rule(rule_id: str) -> Optional[BaseRule]:
    """获取规则

    Args:
        rule_id: 规则 ID

    Returns:
        规则实例
    """
    return get_registry().get(rule_id)


def list_rules(
    language: Optional[str] = None,
    category: Optional[RuleCategory] = None,
    severity: Optional[RuleSeverity] = None,
) -> List[BaseRule]:
    """列出规则

    Args:
        language: 语言过滤
        category: 类别过滤
        severity: 严重级别过滤

    Returns:
        规则列表
    """
    return get_registry().list_rules(language, category, severity)
