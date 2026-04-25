"""安全规则基类模块

提供安全规则的抽象基类和通用实现。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class RuleSeverity(Enum):
    """规则严重级别"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: "RuleSeverity") -> bool:
        order = [RuleSeverity.INFO, RuleSeverity.LOW, RuleSeverity.MEDIUM, RuleSeverity.HIGH, RuleSeverity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "RuleSeverity") -> bool:
        return self == other or self < other

    def __gt__(self, other: "RuleSeverity") -> bool:
        return not self <= other

    def __ge__(self, other: "RuleSeverity") -> bool:
        return not self < other


class RuleCategory(Enum):
    """规则类别"""

    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    DATA_PROTECTION = "data_protection"
    ERROR_HANDLING = "error_handling"
    LOGGING = "logging"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    PERFORMANCE = "performance"
    CODE_QUALITY = "code_quality"
    AI_SECURITY = "ai_security"


@dataclass
class RuleResult:
    """规则执行结果"""

    rule_id: str
    rule_name: str
    passed: bool
    message: str = ""
    severity: RuleSeverity = RuleSeverity.MEDIUM
    confidence: float = 1.0
    location: Optional[Dict[str, Any]] = None
    code_snippet: str = ""
    fix_suggestion: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "passed": self.passed,
            "message": self.message,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "location": self.location,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class RuleMetadata:
    """规则元数据"""

    id: str
    name: str
    description: str
    severity: RuleSeverity
    category: RuleCategory
    language: str
    version: str = "1.0.0"
    author: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    deprecated: bool = False
    replacement: Optional[str] = None


class BaseRule(ABC):
    """安全规则基类

    所有安全规则都应继承此类。
    """

    def __init__(self, metadata: RuleMetadata, config: Optional[Dict[str, Any]] = None) -> None:
        self.metadata = metadata
        self.config = config or {}
        self._initialized = False

    def initialize(self) -> None:
        """初始化规则"""
        self._initialized = True

    def shutdown(self) -> None:
        """关闭规则"""
        self._initialized = False

    @property
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized

    @property
    def id(self) -> str:
        """规则 ID"""
        return self.metadata.id

    @property
    def name(self) -> str:
        """规则名称"""
        return self.metadata.name


@dataclass
class RuleDefinition:
    """JSON 规则定义

    用于 JSON 驱动的规则配置，包含 source/sink/sanitizer 模式匹配。
    """
    id: str
    cwe: str
    name: str
    description: str
    severity: str
    category: str
    languages: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    version: str = "1.0.0"
    author: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cwe": self.cwe,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "languages": self.languages,
            "sources": self.sources,
            "sinks": self.sinks,
            "sanitizers": self.sanitizers,
            "patterns": self.patterns,
            "references": self.references,
            "tags": self.tags,
            "enabled": self.enabled,
            "version": self.version,
            "author": self.author,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleDefinition":
        return cls(
            id=data.get("id", ""),
            cwe=data.get("cwe", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            category=data.get("category", ""),
            languages=data.get("languages", []),
            sources=data.get("sources", []),
            sinks=data.get("sinks", []),
            sanitizers=data.get("sanitizers", []),
            patterns=data.get("patterns", []),
            references=data.get("references", []),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True),
            version=data.get("version", "1.0.0"),
            author=data.get("author", ""),
        )

    def matches_language(self, language: str) -> bool:
        if not self.languages:
            return True
        return language.lower() in [l.lower() for l in self.languages]

    def get_severity_value(self) -> float:
        severity_map = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 1.0,
        }
        return severity_map.get(self.severity.lower(), 5.0)

    def is_enabled(self) -> bool:
        return self.enabled

    @property
    def severity(self) -> RuleSeverity:
        """规则严重级别"""
        return self.metadata.severity

    @property
    def category(self) -> RuleCategory:
        """规则类别"""
        return self.metadata.category

    @property
    def language(self) -> str:
        """规则适用的语言"""
        return self.metadata.language

    @abstractmethod
    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行规则检查

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
        pass

    def is_enabled(self) -> bool:
        """检查规则是否启用"""
        return self.metadata.enabled and not self.metadata.deprecated

    def matches_language(self, language: str) -> bool:
        """检查规则是否匹配语言

        Args:
            language: 语言标识

        Returns:
            是否匹配
        """
        return self.metadata.language.lower() == language.lower() or self.metadata.language == "*"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.metadata.id,
            "name": self.metadata.name,
            "description": self.metadata.description,
            "severity": self.metadata.severity.value,
            "category": self.metadata.category.value,
            "language": self.metadata.language,
            "version": self.metadata.version,
            "author": self.metadata.author,
            "references": self.metadata.references,
            "tags": self.metadata.tags,
            "enabled": self.metadata.enabled,
            "deprecated": self.metadata.deprecated,
            "replacement": self.metadata.replacement,
        }


class PatternRule(BaseRule):
    """基于模式的规则

    使用正则表达式或字符串匹配来检测安全问题。
    """

    def __init__(
        self,
        metadata: RuleMetadata,
        patterns: List[str],
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(metadata, config)
        self.patterns = patterns
        import re

        self._compiled_patterns = [re.compile(p) for p in patterns]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行模式匹配检查

        Args:
            target: 检查目标

        Returns:
            规则执行结果列表
        """
        results = []

        # 获取代码内容
        if isinstance(target, Path):
            content = target.read_text(encoding="utf-8")
        elif isinstance(target, str):
            content = target
        elif isinstance(target, dict):
            content = target.get("content", "")
        else:
            return results

        # 执行模式匹配
        for pattern in self._compiled_patterns:
            for match in pattern.finditer(content):
                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"匹配到危险模式: {pattern.pattern}",
                    severity=self.metadata.severity,
                    confidence=0.7,
                    location={
                        "line": content[: match.start()].count("\n") + 1,
                        "column": match.start() - content[: match.start()].rfind("\n") - 1,
                    },
                    code_snippet=match.group(),
                    references=self.metadata.references,
                )
                results.append(result)

        return results


class ASTRule(BaseRule):
    """基于 AST 的规则

    使用抽象语法树分析来检测安全问题。
    """

    def __init__(
        self,
        metadata: RuleMetadata,
        node_types: List[str],
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(metadata, config)
        self.node_types = node_types

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行 AST 分析检查

        Args:
            target: 检查目标

        Returns:
            规则执行结果列表
        """
        results = []

        # 这里应该使用 AST 分析器进行实际的分析
        # 目前只是一个框架实现

        return results

    @abstractmethod
    def check_node(self, node: Any, context: Dict[str, Any]) -> Optional[RuleResult]:
        """检查单个节点

        Args:
            node: AST 节点
            context: 上下文信息

        Returns:
            规则执行结果，如果没有问题则返回 None
        """
        pass
