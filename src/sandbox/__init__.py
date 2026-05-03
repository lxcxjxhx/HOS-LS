"""沙盒模块

提供代码执行、渗透测试、动态分析等功能。
"""

from src.sandbox.aware_fallback import AwareFallbackSystem
from src.sandbox.pentest_executor import (
    PentestExecutor,
    PentestConfig,
    PentestResult,
    PentestStatus,
)
from src.sandbox.pentest_manager import (
    PentestManager,
    PentestTarget,
    ScanConfig,
    ScanMode,
    ScanReport,
    create_pentest_manager,
)
from src.sandbox.ai_pentest_helper import (
    AIPentestHelper,
    AIPentestConfig,
)
from src.sandbox.executor_pool import (
    SandboxExecutorPool,
    PoolConfig,
    TaskInfo,
)

__all__ = [
    "AwareFallbackSystem",
    "PentestExecutor",
    "PentestConfig",
    "PentestResult",
    "PentestStatus",
    "PentestManager",
    "PentestTarget",
    "ScanConfig",
    "ScanMode",
    "ScanReport",
    "create_pentest_manager",
    "AIPentestHelper",
    "AIPentestConfig",
    "SandboxExecutorPool",
    "PoolConfig",
    "TaskInfo",
]
