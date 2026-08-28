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

    STATIC = "static"  # 纯静态分析，不加载动态组件
    DYNAMIC = "dynamic"  # 纯动态AI红队POC测试，不进行静态扫描
    HYBRID = "hybrid"  # 静动态混合，原有行为


class RuleSeverity(Enum):
    """规则严重级别枚举"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value

    def __lt__(self, other: "RuleSeverity") -> bool:
        order = [
            RuleSeverity.INFO,
            RuleSeverity.LOW,
            RuleSeverity.MEDIUM,
            RuleSeverity.HIGH,
            RuleSeverity.CRITICAL,
        ]
        return order.index(self) < order.index(other)

    def __le__(self, other: "RuleSeverity") -> bool:
        return self == other or self < other

    def __gt__(self, other: "RuleSeverity") -> bool:
        return not self <= other

    def __ge__(self, other: "RuleSeverity") -> bool:
        return not self < other


class RuleCategory(Enum):
    """规则类别枚举"""

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


class AIProvider(Enum):
    """AI提供商枚举"""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    ALIYUN = "aliyun"
    LOCAL = "local"


class AnalysisLevel(Enum):
    """分析级别枚举"""

    FUNCTION = "function"
    FILE = "file"
    PROJECT = "project"
