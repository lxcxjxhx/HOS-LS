from abc import ABC, abstractmethod
from dataclasses import dataclass
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

    @property
    @abstractmethod
    def vuln_types(self) -> List[str]:
        """支持的漏洞类型"""

    @property
    @abstractmethod
    def description(self) -> str:
        """验证器描述"""

    @property
    @abstractmethod
    def confidence_level(self) -> str:
        """置信度级别: high, medium, low"""

    @abstractmethod
    def validate(self, context: VulnContext) -> ValidationResult:
        """执行验证"""

    @abstractmethod
    def check_applicability(self, context: VulnContext) -> bool:
        """检查此验证器是否适用于给定上下文"""

    def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行验证并返回字典格式结果（可选实现）

        默认实现调用 validate 方法并转换结果。子类可以覆盖此方法。
        """
        try:
            vuln_context = VulnContext(
                file_path=context.get("file_path", ""),
                line_number=context.get("line_number", 0),
                code_snippet=context.get("code_snippet", ""),
                vuln_type=context.get("vuln_type", ""),
                project_root=context.get("project_root", ""),
                finding_id=context.get("finding_id"),
                metadata=context.get("metadata"),
            )
            result = self.validate(vuln_context)
            return {
                "is_valid": result.is_valid,
                "is_false_positive": result.is_false_positive,
                "confidence": result.confidence,
                "reason": result.reason,
                "evidence": result.evidence,
                "poc_script": result.poc_script,
                "verification_steps": result.verification_steps,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}


def create_false_positive_result(
    reason: str, confidence: float = 0.9, evidence: Dict[str, Any] = None
) -> ValidationResult:
    """创建误报结果"""
    return ValidationResult(
        is_valid=False,
        is_false_positive=True,
        confidence=confidence,
        reason=reason,
        evidence=evidence or {},
    )


def create_valid_result(
    reason: str, confidence: float = 0.8, evidence: Dict[str, Any] = None
) -> ValidationResult:
    """创建有效漏洞结果"""
    return ValidationResult(
        is_valid=True,
        is_false_positive=False,
        confidence=confidence,
        reason=reason,
        evidence=evidence or {},
    )


def create_uncertain_result(reason: str, confidence: float = 0.5) -> ValidationResult:
    """创建不确定结果"""
    return ValidationResult(
        is_valid=None, is_false_positive=None, confidence=confidence, reason=reason
    )
