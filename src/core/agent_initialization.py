"""内置 Agent 注册

自动注册所有内置 Agent 到全局 Registry。
在应用启动时调用此模块以启用所有核心能力。
"""

from .agent_registry import get_agent_registry, register_agent
from .builtin_agents import (
    ScannerAgent,
    ReasoningAgent,
    POCGeneratorAgent,
    ReportGeneratorAgent,
    AttackChainAgent
)


def register_builtin_agents():
    """注册所有内置 Agent 到全局 Registry

    应该在应用启动时调用此函数。
    """
    registry = get_agent_registry()

    # 1. Scanner Agent - 代码扫描
    registry.register(
        name="scan",
        agent_class=ScannerAgent,
        category="behavior",
        description="代码扫描 - 检测安全漏洞和代码问题",
        dependencies=[],
        flags=["--scan", "-s"],
        aliases=["scanning", "scanner"],
        priority=1
    )

    # 2. Reasoning Agent - 漏洞推理
    registry.register(
        name="reason",
        agent_class=ReasoningAgent,
        category="behavior",
        description="漏洞推理分析 - 深度分析漏洞原因和影响",
        dependencies=["scan"],
        flags=["--reason", "-r"],
        aliases=["analyze", "analysis", "reasoning"],
        priority=2
    )

    # 3. Attack Chain Agent - 攻击链分析
    registry.register(
        name="attack-chain",
        agent_class=AttackChainAgent,
        category="behavior",
        description="攻击链分析 - 构建完整攻击路径",
        dependencies=["scan", "reason"],
        flags=["--attack-chain", "--ac"],
        aliases=["attack", "chain"],
        priority=3
    )

    # 4. POC Generator Agent - POC生成
    registry.register(
        name="poc",
        agent_class=POCGeneratorAgent,
        category="behavior",
        description="POC生成 - 生成漏洞利用代码（概念验证）",
        dependencies=["scan", "reason"],
        flags=["--poc", "-p"],
        aliases=["exploit", "generate-exploit"],
        priority=4
    )

    # 5. Report Generator Agent - 报告生成
    registry.register(
        name="report",
        agent_class=ReportGeneratorAgent,
        category="behavior",
        description="报告生成 - 生成安全扫描报告",
        dependencies=["scan"],  # 最少需要 scan
        flags=["--report", "-R"],
        aliases=["generate-report"],
        priority=10
    )

    # === 宏命令（Macro Commands） ===

    # Quick Scan: scan + report
    registry.register(
        name="quick-scan",
        agent_class=None,  # 宏命令没有对应的 Agent 类
        category="macro",
        description="快速扫描 - 扫描并生成报告",
        dependencies=[],
        flags=["--quick-scan", "-qs"],
        aliases=["quick"],
        priority=0,
        expands_to=["scan", "report"]
    )

    # Full Audit: 完整审计
    registry.register(
        name="full-audit",
        agent_class=None,
        category="macro",
        description="完整审计 - 全流程深度安全审计",
        dependencies=[],
        flags=["--full-audit", "-fa"],
        aliases=["audit", "full"],
        priority=0,
        expands_to=["scan", "reason", "attack-chain", "poc", "report"]
    )

    # Deep Audit: 深度审计（包含验证）
    registry.register(
        name="deep-audit",
        agent_class=None,
        category="macro",
        description="深度审计 - 包含漏洞验证的完整审计",
        dependencies=[],
        flags=["--deep-audit", "-da"],
        aliases=["deep"],
        priority=0,
        expands_to=["scan", "reason", "attack-chain", "poc", "verify", "report"]
    )

    # Red Team Mode: 红队模式
    registry.register(
        name="red-team",
        agent_class=None,
        category="macro",
        description="红队模式 - 模拟攻击者视角的全面测试",
        dependencies=[],
        flags=["--red-team", "-rt"],
        aliases=["redteam", "offensive"],
        priority=0,
        expands_to=["scan", "reason", "attack-chain", "poc", "verify"]
    )

    # Bug Bounty: 漏洞赏金模式
    registry.register(
        name="bug-bounty",
        agent_class=None,
        category="macro",
        description="漏洞赏金模式 - 针对漏洞赏金的高效扫描",
        dependencies=[],
        flags=["--bug-bounty", "-bb"],
        aliases=["bounty"],
        priority=0,
        expands_to=["scan", "reason", "poc", "report"]
    )

    # Compliance: 合规检查模式
    registry.register(
        name="compliance",
        agent_class=None,
        category="macro",
        description="合规模式 - 符合安全合规要求的检查",
        dependencies=[],
        flags=["--compliance", "-c"],
        aliases=["comply"],
        priority=0,
        expands_to=["scan", "reason", "report"]
    )


def initialize_agent_system():
    """完整初始化 Agent 系统

    包括：
    1. 注册内置 Agent
    2. 验证依赖关系
    3. 输出统计信息
    """
    import sys

    register_builtin_agents()

    registry = get_agent_registry()
    stats = registry.get_statistics()

    if stats['total_agents'] > 0:
        print(f"[INFO] Agent 系统初始化完成")
        print(f"       已注册 {stats['total_agents']} 个 Agent 能力")

        if hasattr(sys.stderr, 'writing'):  # 检查是否在调试模式
            for cat, count in stats['by_category'].items():
                print(f"       - {cat}: {count} 个")
    else:
        print("[WARNING] 未注册任何 Agent")


# 导出便捷函数
__all__ = [
    'register_builtin_agents',
    'initialize_agent_system',
    'get_agent_registry'
]
