"""AI 模块数据模型

定义 AI 分析相关的数据模型。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AIProvider(Enum):
    """AI 提供商"""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    LOCAL = "local"


class AnalysisLevel(Enum):
    """分析级别"""

    FUNCTION = "function"
    FILE = "file"
    PROJECT = "project"


@dataclass
class AIContent:
    """AI 内容"""
    type: str  # text 或 image
    content: str  # 文本内容或图像 base64 编码


@dataclass
class AIRequest:
    """AI 请求"""

    prompt: str
    system_prompt: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 4096
    model: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    multimodal_content: Optional[List[AIContent]] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "prompt": self.prompt,
            "system_prompt": self.system_prompt,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "model": self.model,
            "context": self.context,
        }
        if self.multimodal_content:
            result["multimodal_content"] = [
                {"type": c.type, "content": c.content} for c in self.multimodal_content
            ]
        return result


@dataclass
class AIResponse:
    """AI 响应"""

    content: str
    model: str
    provider: AIProvider
    usage: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_response: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider.value,
            "usage": self.usage,
            "metadata": self.metadata,
        }


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""

    rule_id: str
    rule_name: str
    description: str
    severity: str
    confidence: float
    location: Dict[str, Any] = field(default_factory=dict)
    code_snippet: str = ""
    fix_suggestion: str = ""
    explanation: str = ""
    references: List[str] = field(default_factory=list)
    exploit_scenario: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": self.location,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "explanation": self.explanation,
            "references": self.references,
            "exploit_scenario": self.exploit_scenario,
            "metadata": self.metadata,
        }


@dataclass
class SecurityAnalysisResult:
    """安全分析结果"""

    findings: List[VulnerabilityFinding] = field(default_factory=list)
    false_positives: List[VulnerabilityFinding] = field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "false_positives": [f.to_dict() for f in self.false_positives],
            "risk_score": self.risk_score,
            "summary": self.summary,
            "recommendations": self.recommendations,
            "metadata": self.metadata,
        }


@dataclass
class AnalysisContext:
    """分析上下文"""

    file_path: str
    code_content: str
    language: str
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    analysis_level: AnalysisLevel = AnalysisLevel.FILE
    metadata: Dict[str, Any] = field(default_factory=dict)
    multimodal_content: Optional[List[AIContent]] = None


@dataclass
class ContextInfo:
    """上下文信息"""

    file_path: str
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    related_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "file_path": self.file_path,
            "function_name": self.function_name,
            "class_name": self.class_name,
            "imports": self.imports,
            "dependencies": self.dependencies,
            "related_files": self.related_files,
        }
