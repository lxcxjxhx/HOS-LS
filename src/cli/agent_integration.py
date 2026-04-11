"""CLI 集成模块

提供 CLI 与 Agent 能力系统的集成功能：
- 动态 flag 注册
- 统一执行入口
- 向后兼容层
"""

import click
from typing import Dict, List, Any, Optional

# 🔧 BUG FIX #2: 修正导入路径 - 这些模块在 src/core/ 而非 src/cli/
from src.core.agent_registry import get_agent_registry, AgentCapabilityRegistry
from src.core.agent_initialization import register_builtin_agents, initialize_agent_system
from src.core.unified_execution_engine import (
    UnifiedExecutionEngine,
    ExecutionRequest,
    ExecutionResult
)
from src.core.base_agent import ExecutionContext


def initialize_cli_agent_system():
    """在 CLI 启动时初始化 Agent 系统"""
    try:
        initialize_agent_system()
        return True
    except Exception as e:
        print(f"[WARNING] Agent 系统初始化失败: {e}")
        return False


def get_unified_engine(config=None):
    """获取统一执行引擎实例

    Args:
        config: 配置对象（可选）

    Returns:
        UnifiedExecutionEngine 实例
    """
    return UnifiedExecutionEngine(
        config=config,
        registry=get_agent_registry()
    )


def collect_behavior_flags_from_kwargs(**kwargs) -> List[str]:
    """从 CLI 参数中收集 behavior 类 flags

    扫描 kwargs 中所有为 True 的行为类 flag。

    Args:
        **kwargs: CLI 参数字典

    Returns:
        收集到的 flag 列表（如 ["--scan", "--reason"]）
    """
    registry = get_agent_registry()
    behavior_flags = []

    for key, value in kwargs.items():
        if value and key in [
            'scan', 'reason', 'attack_chain', 'poc',
            'verify', 'fix', 'report'
        ]:
            capability = registry.get(key)
            if capability and capability.category == "behavior":
                behavior_flags.append(f"--{key}")

    # 收集宏命令
    macro_flags = []
    for key, value in kwargs.items():
        if value and key in [
            'full_audit', 'quick_scan', 'deep_audit',
            'red_team', 'bug_bounty', 'compliance'
        ]:
            macro_name = key.replace('_', '-')
            capability = registry.get(macro_name)
            if capability and capability.category == "macro":
                macro_flags.append(f"--{macro_name}")

    return behavior_flags + macro_flags


async def execute_with_unified_engine(
    config,
    target: str,
    behavior_flags: List[str],
    mode: str = "auto",
    **context_kwargs
) -> ExecutionResult:
    """使用统一执行引擎执行请求

    Args:
        config: 配置对象
        target: 目标路径
        behavior_flags: 行为类 flags 列表
        mode: 执行模式 (auto/pure-ai/standard/langgraph)
        **context_kwargs: 额外的上下文参数（如 ask, focus 等）

    Returns:
        ExecutionResult: 执行结果
    """
    engine = get_unified_engine(config)

    request = ExecutionRequest(
        target=target,
        flags=behavior_flags,
        mode=mode,
        context=context_kwargs
    )

    result = await engine.execute(request, mode=mode)

    return result


def display_unified_result(result: ExecutionResult, console, quiet=False):
    """显示统一执行结果

    Args:
        result: 执行结果
        console: Rich Console 实例
        quiet: 是否静默模式
    """
    if quiet:
        return

    # 显示摘要
    console.print(f"[bold cyan]{result.message}[/bold cyan]")

    # 显示 Pipeline
    if result.pipeline_used:
        pipeline_str = " → ".join(result.pipeline_used)
        console.print(f"[dim]Pipeline: {pipeline_str}[/dim]")

    # 显示模式
    console.print(f"[dim]模式: {result.mode.upper()} | 耗时: {result.execution_time:.2f}s[/dim]")

    # 显示发现的问题数量
    if result.total_findings > 0:
        console.print(f"[bold yellow]⚠ 发现 {result.total_findings} 个问题[/bold yellow]")
    else:
        console.print("[green]✓ 未发现问题[/green]")

    # 显示各 Agent 结果详情
    if not quiet and result.results:
        console.print("\n[bold]详细结果:[/bold]")
        for agent_name, agent_result in result.results.items():
            status_icon = "✅" if agent_result.is_success else "❌"
            confidence_color = "green" if agent_result.confidence >= 0.8 else "yellow" if agent_result.confidence >= 0.5 else "red"

            console.print(
                f"  {status_icon} [{agent_name}] "
                f"{agent_result.message[:80]} "
                f"[{confidence_color}]{agent_result.confidence:.0%}[/{confidence_color}]"
            )


def create_dynamic_scan_command_options():
    """动态生成 scan 命令的选项装饰器列表

    从 Registry 获取所有已注册的 Agent 的 flags，
    动态生成 @click.option 装饰器。

    Returns:
        装饰器函数列表
    """
    registry = get_agent_registry()
    decorators = []

    # 添加控制类选项（固定）
    decorators.extend([
        click.option("--mode", "-m", type=click.Choice(['auto', 'pure-ai', 'standard', 'langgraph']),
                      default="auto", help="执行模式（auto=AI自适应选择）"),
        click.option("--explain", is_flag=True, help="解释执行流程"),
        click.option("--ask", help="自然语言查询"),
        click.option("--focus", help="关注特定文件或目录"),
    ])

    return decorators


class LegacyFallbackExecutor:
    """回退到旧版执行逻辑的包装器

    当新架构不可用时，使用旧的硬编码逻辑。
    确保向后兼容。
    """

    @staticmethod
    def execute_pure_ai_legacy(config, target, workers, incremental, ruleset, output_format, output):
        """纯 AI 模式的旧版执行逻辑"""
        import os
        from src.core.scanner import create_scanner

        os.environ["HOS_LS_MODE"] = "PURE_AI"
        config.scan.max_workers = workers
        config.scan.incremental = incremental
        if ruleset:
            config.rules.ruleset = ruleset
        config.report.format = output_format
        if output:
            config.report.output = output
        config.ai.enabled = True
        config.pure_ai = True
        config.pure_ai_provider = config.ai.provider or "deepseek"
        config.pure_ai_model = config.ai.model or "deepseek-chat"

        scanner = create_scanner(config)
        return scanner.scan_sync(target)

    @staticmethod
    def execute_langgraph_legacy(config, target, pipeline, ask, focus):
        """LangGraph 模式的旧版执行逻辑"""
        import asyncio
        from pathlib import Path
        from src.core.langgraph_flow import run_pipeline

        target_path = Path(target)
        if target_path.is_file():
            with open(target_path, 'r', encoding='utf-8') as f:
                code = f.read()
        else:
            code = f"目录扫描: {target}"

        return asyncio.run(run_pipeline(pipeline, code, ask=ask, focus=focus))

    @staticmethod
    def execute_standard_legacy(config, target):
        """标准模式的旧版执行逻辑"""
        from src.core.scanner import create_scanner

        scanner = create_scanner(config)
        return scanner.scan_sync(target)


__all__ = [
    'initialize_cli_agent_system',
    'get_unified_engine',
    'collect_behavior_flags_from_kwargs',
    'execute_with_unified_engine',
    'display_unified_result',
    'create_dynamic_scan_command_options',
    'LegacyFallbackExecutor'
]
