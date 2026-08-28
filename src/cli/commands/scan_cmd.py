"""扫描命令。

默认执行确定性静态扫描；``--pure-ai`` 启用完整的 Pure-AI 7-Agent 流水线。
已移除不可运行的 legacy ``--ai`` 模式。
"""

from typing import Any, Dict, Optional

import click

from src.cli.main import cli, console
from src.core.config import Config, ConfigManager


@cli.command()
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.option("--output", "-o", help="报告输出文件路径")
@click.option("--workers", "-w", type=click.IntRange(1, 32), default=4, show_default=True,
              help="Pure-AI 批处理并发数")
@click.option("--pure-ai", is_flag=True, help="启用 Pure-AI 7-Agent 深度语义解析模式")
@click.option("--ai-provider", help="Pure-AI 提供商覆盖，例如 deepseek")
@click.option("--ai-model", help="Pure-AI 模型覆盖")
@click.option("--test", type=click.IntRange(1), help="仅扫描前 N 个高优先级文件")
@click.option("--resume", is_flag=True, help="从 Pure-AI 断点恢复")
@click.option("--truncate-output", is_flag=True, help="达到资源限制时保存断点并截断")
@click.option("--max-duration", type=click.IntRange(1), help="最大扫描时长（秒）")
@click.option("--max-files", type=click.IntRange(1), help="最大扫描文件数")
@click.option("--tool-chain", help="静态工具链，使用逗号分隔")
@click.option(
    "--priority-strategy",
    type=click.Choice(["full-scan", "api-first", "security-first", "performance-first", "balanced"]),
    help="文件扫描优先级策略",
)
@click.option("--sandbox", is_flag=True, help="启用已配置的沙箱验证")
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    output: Optional[str],
    workers: int,
    pure_ai: bool,
    ai_provider: Optional[str],
    ai_model: Optional[str],
    test: Optional[int],
    resume: bool,
    truncate_output: bool,
    max_duration: Optional[int],
    max_files: Optional[int],
    tool_chain: Optional[str],
    priority_strategy: Optional[str],
    sandbox: bool,
) -> None:
    """执行安全扫描。TARGET 默认为当前目录。"""
    root_context = ctx.find_root()
    config = root_context.obj.get("config") if root_context.obj else None
    if config is None:
        config = ConfigManager.load()
    _apply_scan_args(
        config,
        {
            "output": output,
            "workers": workers,
            "pure_ai": pure_ai,
            "ai_provider": ai_provider,
            "ai_model": ai_model,
            "test": test,
            "resume": resume,
            "truncate_output": truncate_output,
            "max_duration": max_duration,
            "max_files": max_files,
            "tool_chain": tool_chain,
            "priority_strategy": priority_strategy,
            "sandbox": sandbox,
        },
    )

    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    _run_scan(config, target, output)


def _apply_scan_args(config: Config, args: Dict[str, Any]) -> None:
    """将已实现的 CLI 参数映射至配置模型。"""
    if args["pure_ai"]:
        config.pure_ai = True
    if args["ai_provider"]:
        config.ai.provider = args["ai_provider"]
        module_config = config.ai.modules.get("pure_ai")
        if module_config is not None:
            module_config.provider = args["ai_provider"]
    if args["ai_model"]:
        config.ai.model = args["ai_model"]
        module_config = config.ai.modules.get("pure_ai")
        if module_config is not None:
            module_config.model = args["ai_model"]

    config.scan.max_workers = args["workers"]
    if args["test"] is not None:
        config.test_mode = True
        config.test_file_count = args["test"]
    if args["resume"]:
        config.resume = True
    if args["truncate_output"]:
        config.truncate_output = True
    if args["max_duration"] is not None:
        config.max_duration = args["max_duration"]
    if args["max_files"] is not None:
        config.max_files = args["max_files"]
    if args["tool_chain"]:
        config.tools.tool_chain = [item.strip() for item in args["tool_chain"].split(",") if item.strip()]
    if args["priority_strategy"]:
        config.scan.priority_strategy = args["priority_strategy"]
    if args["sandbox"]:
        config.sandbox.enabled = True


def _run_scan(config: Config, target: str, output: Optional[str]) -> None:
    """运行同步扫描并按需生成报告。"""
    from src.core.scanner import SecurityScanner

    scanner = SecurityScanner(config)
    result = scanner.scan_sync(target)

    if output:
        from src.reporting.generator import generate_report

        generate_report(result, output)

    if not config.quiet:
        console.print("\n[bold green]✓ 扫描完成[/bold green]")
        console.print(f"  发现 [bold red]{len(result.findings)}[/bold red] 个安全问题")
