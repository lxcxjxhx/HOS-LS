"""分析器基类模块

提供统一的分析器抽象接口。
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class AnalysisType(Enum):
    """分析类型"""

    AST = "ast"
    CST = "cst"
    SEMANTIC = "semantic"
    TAINT = "taint"
    PATTERN = "pattern"
    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"
    SECURITY = "security"
    PERFORMANCE = "performance"
    CODE_QUALITY = "code_quality"


class AnalysisStatus(Enum):
    """分析状态"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(Enum):
    """严重程度"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AnalysisContext:
    """分析上下文"""

    file_path: Path
    file_content: str
    language: str
    project_root: Optional[Path] = None
    dependencies: List[str] = field(default_factory=list)
    git_context: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "file_path": str(self.file_path),
            "language": self.language,
            "project_root": str(self.project_root) if self.project_root else None,
            "dependencies": self.dependencies,
            "git_context": self.git_context,
            "metadata": self.metadata,
        }


@dataclass
class AnalysisIssue:
    """分析问题"""

    rule_id: str
    message: str
    line: int = 0
    column: int = 0
    end_line: int = 0
    end_column: int = 0
    severity: str = "medium"
    confidence: float = 1.0
    code_snippet: str = ""
    fix_suggestion: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "severity": self.severity,
            "confidence": self.confidence,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "metadata": self.metadata,
        }


@dataclass
class AnalysisError:
    """分析错误"""

    error_type: str
    message: str
    traceback: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "error_type": self.error_type,
            "message": self.message,
            "traceback": self.traceback,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class PerformanceMetrics:
    """性能指标"""

    duration: float
    memory_used: Optional[int] = None
    cpu_used: Optional[float] = None
    issues_found: int = 0
    errors_encountered: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "duration": self.duration,
            "memory_used": self.memory_used,
            "cpu_used": self.cpu_used,
            "issues_found": self.issues_found,
            "errors_encountered": self.errors_encountered,
        }


@dataclass
class AnalysisResult:
    """分析结果"""

    analysis_type: AnalysisType
    status: AnalysisStatus
    context: AnalysisContext
    issues: List[AnalysisIssue] = field(default_factory=list)
    errors: List[AnalysisError] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    performance: Optional[PerformanceMetrics] = None

    def add_issue(self, issue: AnalysisIssue) -> None:
        """添加问题"""
        self.issues.append(issue)

    def add_error(self, error: Union[AnalysisError, str]) -> None:
        """添加错误"""
        if isinstance(error, str):
            error_obj = AnalysisError(error_type="general", message=error)
            self.errors.append(error_obj)
        else:
            self.errors.append(error)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "analysis_type": self.analysis_type.value,
            "status": self.status.value,
            "context": self.context.to_dict(),
            "issues": [i.to_dict() for i in self.issues],
            "errors": [e.to_dict() for e in self.errors],
            "metadata": self.metadata,
            "performance": self.performance.to_dict() if self.performance else None,
        }

    @property
    def has_issues(self) -> bool:
        """是否有问题"""
        return len(self.issues) > 0

    @property
    def has_errors(self) -> bool:
        """是否有错误"""
        return len(self.errors) > 0

    def get_issues_by_severity(self, severity: str) -> List[AnalysisIssue]:
        """按严重程度获取问题"""
        return [i for i in self.issues if i.severity == severity]


class BaseAnalyzer(ABC):
    """分析器基类

    所有分析器都应继承此类。
    """

    name: str = "base"
    version: str = "1.0.0"
    supported_languages: List[str] = []
    supported_analysis_types: List[AnalysisType] = []

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self._initialized = False
        self._performance_history: List[PerformanceMetrics] = []

    def initialize(self) -> None:
        """初始化分析器"""
        self._initialized = True

    def shutdown(self) -> None:
        """关闭分析器"""
        self._initialized = False

    @property
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """执行分析

        Args:
            context: 分析上下文

        Returns:
            分析结果
        """
        pass

    def analyze_with_metrics(self, context: AnalysisContext) -> AnalysisResult:
        """执行分析并记录性能指标

        Args:
            context: 分析上下文

        Returns:
            分析结果
        """
        start_time = time.time()

        try:
            result = self.analyze(context)
        finally:
            duration = time.time() - start_time
            metrics = PerformanceMetrics(
                duration=duration,
                issues_found=len(result.issues),
                errors_encountered=len(result.errors),
            )
            result.performance = metrics
            self._performance_history.append(metrics)

        return result

    def supports_language(self, language: str) -> bool:
        """检查是否支持语言

        Args:
            language: 语言标识

        Returns:
            是否支持
        """
        return language.lower() in [lang.lower() for lang in self.supported_languages]

    def supports_analysis_type(self, analysis_type: Union[AnalysisType, str]) -> bool:
        """检查是否支持分析类型

        Args:
            analysis_type: 分析类型

        Returns:
            是否支持
        """
        if isinstance(analysis_type, str):
            try:
                analysis_type = AnalysisType(analysis_type)
            except ValueError:
                return False
        return analysis_type in self.supported_analysis_types

    def supports_file(self, file_path: Union[str, Path]) -> bool:
        """检查是否支持文件

        Args:
            file_path: 文件路径

        Returns:
            是否支持
        """
        path = Path(file_path)
        extension = path.suffix.lower()

        # 根据扩展名判断语言
        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".jsx": "javascript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".php": "php",
            ".cs": "csharp",
            ".swift": "swift",
            ".kt": "kotlin",
        }

        language = language_map.get(extension)
        if language:
            return self.supports_language(language)

        return False

    def get_performance_statistics(self) -> Dict[str, Any]:
        """获取性能统计

        Returns:
            性能统计信息
        """
        if not self._performance_history:
            return {
                "total_analyses": 0,
                "avg_duration": 0,
                "total_issues": 0,
                "total_errors": 0,
            }

        total_duration = sum(m.duration for m in self._performance_history)
        total_issues = sum(m.issues_found for m in self._performance_history)
        total_errors = sum(m.errors_encountered for m in self._performance_history)

        return {
            "total_analyses": len(self._performance_history),
            "avg_duration": total_duration / len(self._performance_history),
            "total_issues": total_issues,
            "total_errors": total_errors,
            "avg_issues_per_analysis": total_issues / len(self._performance_history),
            "avg_errors_per_analysis": total_errors / len(self._performance_history),
        }

    def get_info(self) -> Dict[str, Any]:
        """获取分析器信息

        Returns:
            分析器信息
        """
        return {
            "name": self.name,
            "version": self.version,
            "supported_languages": self.supported_languages,
            "supported_analysis_types": [t.value for t in self.supported_analysis_types],
            "is_initialized": self._initialized,
            "performance": self.get_performance_statistics(),
        }

    def create_issue(
        self,
        rule_id: str,
        message: str,
        **kwargs,
    ) -> AnalysisIssue:
        """创建分析问题

        Args:
            rule_id: 规则ID
            message: 消息
            **kwargs: 其他参数

        Returns:
            分析问题
        """
        return AnalysisIssue(
            rule_id=rule_id,
            message=message,
            **kwargs,
        )

    def create_error(
        self,
        error_type: str,
        message: str,
        **kwargs,
    ) -> AnalysisError:
        """创建分析错误

        Args:
            error_type: 错误类型
            message: 消息
            **kwargs: 其他参数

        Returns:
            分析错误
        """
        return AnalysisError(
            error_type=error_type,
            message=message,
            **kwargs,
        )

    def create_result(
        self,
        analysis_type: Union[AnalysisType, str],
        status: Union[AnalysisStatus, str],
        context: AnalysisContext,
        **kwargs,
    ) -> AnalysisResult:
        """创建分析结果

        Args:
            analysis_type: 分析类型
            status: 状态
            context: 分析上下文
            **kwargs: 其他参数

        Returns:
            分析结果
        """
        if isinstance(analysis_type, str):
            analysis_type = AnalysisType(analysis_type)
        if isinstance(status, str):
            status = AnalysisStatus(status)

        return AnalysisResult(
            analysis_type=analysis_type,
            status=status,
            context=context,
            **kwargs,
        )
