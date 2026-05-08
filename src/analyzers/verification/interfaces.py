from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ValidationResult:
    """验证结果"""
    is_valid: Optional[bool]
    is_false_positive: Optional[bool]
    confidence: float
    reason: str
    evidence: Optional[Dict[str, Any]] = None
    poc_script: Optional[str] = None
    verification_steps: Optional[List[str]] = None


@dataclass
class VulnContext:
    """漏洞上下文"""
    file_path: str
    line_number: int
    code_snippet: str
    vuln_type: str
    project_root: str
    finding_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class Validator(ABC):
    """验证器抽象基类"""

    @property
    @abstractmethod
    def name(self) -> str:
        """验证器名称"""
        pass

    @property
    @abstractmethod
    def vuln_types(self) -> List[str]:
        """支持的漏洞类型"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """验证器描述"""
        pass

    @property
    @abstractmethod
    def confidence_level(self) -> str:
        """置信度级别: high, medium, low"""
        pass

    @abstractmethod
    def validate(self, context: VulnContext) -> ValidationResult:
        """执行验证"""
        pass

    @abstractmethod
    def check_applicability(self, context: VulnContext) -> bool:
        """检查此验证器是否适用于给定上下文"""
        pass


def create_false_positive_result(
    reason: str,
    confidence: float = 0.9,
    evidence: Dict[str, Any] = None
) -> ValidationResult:
    """创建误报结果"""
    return ValidationResult(
        is_valid=False,
        is_false_positive=True,
        confidence=confidence,
        reason=reason,
        evidence=evidence or {}
    )


def create_valid_result(
    reason: str,
    confidence: float = 0.8,
    evidence: Dict[str, Any] = None
) -> ValidationResult:
    """创建有效漏洞结果"""
    return ValidationResult(
        is_valid=True,
        is_false_positive=False,
        confidence=confidence,
        reason=reason,
        evidence=evidence or {}
    )


def create_uncertain_result(
    reason: str,
    confidence: float = 0.5
) -> ValidationResult:
    """创建不确定结果"""
    return ValidationResult(
        is_valid=None,
        is_false_positive=None,
        confidence=confidence,
        reason=reason
    )
