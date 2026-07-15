"""通用类型定义模块

集中管理项目中通用的枚举和常量定义，避免重复定义。
"""

from enum import Enum


class Severity(Enum):
    """严重级别枚举"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value


class ScanStatus(Enum):
    """扫描状态枚举"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuditMode(Enum):
    """审计模式枚举"""

    FULL = "full"
    INCREMENTAL = "incremental"
    QUICK = "quick"


class RuleSeverity(Enum):
    """规则严重级别枚举"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value


class RuleCategory(Enum):
    """规则类别枚举"""

    SECURITY = "security"
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    MAINTAINABILITY = "maintainability"
    BEST_PRACTICE = "best_practice"


class AIProvider(Enum):
    """AI提供商枚举"""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    LOCAL = "local"


class AnalysisLevel(Enum):
    """分析级别枚举"""

    BASIC = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"
    EXPERT = "expert"
