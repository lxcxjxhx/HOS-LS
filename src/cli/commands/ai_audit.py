"""AI 安全审计命令

提供完整的 AI 驱动代码审计流水线 CLI 入口。
串联：静态预扫描 → AI深度分析 → 攻击链分析 → 报告生成

注意：POC 验证功能已移除（ai-audit 模式聚焦代码审计而非利用验证）。
如需 POC 验证，请使用 `hos-ls pentest <target> --use-orchestrator` 命令。
"""

import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table

console = Console(emoji=False, force_terminal=True, legacy_windows=False)
logger = logging.getLogger("ai_audit")


@click.command("ai-audit")
@click.argument("target")
@click.option("--ai", is_flag=True, default=True, help="启用AI深度分析（默认启用）")
@click.option("--no-ai", is_flag=True, help="禁用AI深度分析，仅静态预扫描")
@click.option("--deep", is_flag=True, help="启用 PureAIAnalyzer 深度语义分析模式")
@click.option("--max-files", type=int, default=None, help="限制最大分析文件数")
@click.option("--output", "-o", default=None, help="报告输出路径 (JSON/Markdown)")
@click.option("--format", "report_format", type=click.Choice(["json", "markdown"]), default="markdown", help="报告格式")
@click.option("--skip-data-update", is_flag=True, help="跳过数据源更新检查")
@click.option("--debug", "-d", is_flag=True, help="启用详细调试日志")
@click.pass_context
def ai_audit(
    ctx: click.Context,
    target: str,
    ai: bool,
    no_ai: bool,
    deep: bool,
    max_files: Optional[int],
    output: Optional[str],
    report_format: str,
    skip_data_update: bool,
    debug: bool,
) -> None:
    """AI 驱动的代码安全审计流水线

    TARGET: 目标文件或目录路径

    审计流程：静态预扫描 → AI深度分析 → 攻击链分析 → 报告生成
    注意：本模式不包含 POC 验证（使用 pentest 命令替代）

    示例:
        hos-ls ai-audit ./src/
        hos-ls ai-audit ./vulnerable_code.py --output report.md
        hos-ls ai-audit ./src/ --no-ai  # 仅静态预扫描
    """
    t0 = time.time()
    config = ctx.obj.get("config")
    if config is None:
        from src.core.config import Config
        config = Config()

    if debug:
        config.debug = True

    # 标志位覆盖
    enable_ai = ai and not no_ai

    # 审计模式
    audit_mode = "deep" if deep else ("quick" if not enable_ai else "standard")

    # Banner
    if not config.quiet:
        mode_colors = {"deep": "magenta", "standard": "green", "quick": "yellow"}
        mode_color = mode_colors.get(audit_mode, "white")
        console.print(Panel(
            f"[bold cyan]AI 安全审计引擎[/bold cyan]\n"
            f"  目标: {target}\n"
            f"  AI分析: {'[green]启用[/green]' if enable_ai else '[dim]禁用[/dim]'}\n"
            f"  审计模式: [{mode_color}]{audit_mode}[/{mode_color}]\n"
            f"  POC验证: [dim]已移除（使用 pentest 命令）[/dim]",
            title="[bold]HOS-LS AI Audit[/bold]",
            border_style="cyan",
        ))

    # 异步执行
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            _run_ai_audit(
                target=target,
                config=config,
                enable_ai=enable_ai,
                deep=deep,
                max_files=max_files,
                debug=debug,
            )
        )
    except Exception as e:
        console.print(f"[bold red]AI审计执行失败: {e}[/bold red]")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(2)

    # 展示结果
    _display_results(result, config)

    # 保存报告
    report_path = output
    if report_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if report_format == "json":
            report_path = f"ai_audit_{ts}.json"
        else:
            report_path = f"ai_audit_{ts}.md"

    if report_path.endswith(".json"):
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump({
                "target": result.target,
                "timestamp": result.timestamp,
                "total_findings": result.total_findings,
                "verified_findings": result.verified_findings,
                "findings": result.findings,
                "stage_results": result.stage_results,
                "attack_chains": result.attack_chains,
                "summary": result.summary,
            }, fh, ensure_ascii=False, indent=2, default=str)
    else:
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(result.report)

    if not config.quiet:
        console.print(f"[bold green][OK] 报告已保存: {report_path}[/bold green]")

    elapsed = time.time() - t0
    if not config.quiet:
        console.print(f"[dim]总耗时: {elapsed:.1f}s[/dim]")


async def _run_ai_audit(
    target: str,
    config,
    enable_ai: bool,
    deep: bool,
    max_files: Optional[int],
    debug: bool,
):
    """执行 AI 审计流水线的异步核心"""
    from src.pentest.pipeline.ai_pentest_pipeline import AIPentestPipeline
    from rich.progress import Progress, TextColumn, BarColumn

    quiet = getattr(config, "quiet", False)

    # 初始化 AI 客户端
    ai_client = None
    if enable_ai:
        try:
            from src.core.config import Config
            from src.ai.client import get_model_manager
            from src.ai.models import AIProvider

            cfg = config if isinstance(config, Config) else Config()
            model_manager = await get_model_manager(cfg)

            # 根据配置动态获取客户端
            provider_map = {
                "anthropic": AIProvider.ANTHROPIC,
                "openai": AIProvider.OPENAI,
                "deepseek": AIProvider.DEEPSEEK,
                "aliyun": AIProvider.ALIYUN,
                "local": AIProvider.LOCAL,
            }
            target_provider = provider_map.get(cfg.ai.provider, AIProvider.DEEPSEEK)
            ai_client = model_manager.get_client(target_provider)

            # 如果目标客户端不可用，尝试获取默认客户端
            if not ai_client:
                ai_client = model_manager.get_default_client()

            if ai_client:
                logger.info(f"AI客户端已初始化 (provider={cfg.ai.provider})")
            else:
                registered = list(model_manager._clients.keys())
                logger.warning(f"AI客户端不可用 (provider={cfg.ai.provider}), 已注册: {registered}，将降级为纯静态分析")
        except Exception as e:
            logger.warning(f"AI客户端初始化失败: {e}")
            import traceback
            logger.warning(traceback.format_exc())

    # 创建管线（POC 已禁用）
    pipeline = AIPentestPipeline(
        target=target,
        config=config,
        ai_client=ai_client,
        enable_poc=False,  # ai-audit 模式下强制禁用 POC
        enable_ai_analysis=enable_ai,
        enable_learning=False,  # 无 POC 结果，无需学习
    )

    # Deep 模式：注入 PureAIAnalyzer
    if deep and ai_client:
        from src.ai.pure_ai_analyzer import PureAIAnalyzer
        pure_analyzer = PureAIAnalyzer(config=config)
        pipeline.enable_pure_ai_analyzer(pure_analyzer)
        pipeline.set_audit_mode("deep")
        logger.info("[ai_audit] Deep 模式已启用，PureAIAnalyzer 已注入管线")

    # 执行
    if not quiet:
        with Progress(
            TextColumn("[bold cyan][ {task.description} ][/bold cyan]"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("AI 安全审计进行中...", total=None)

            def _progress_cb():
                stages_done = sum(1 for sr in pipeline.stage_results if sr.success)
                total_stages = 5  # 5 个阶段（无 POC/学习）
                progress.update(
                    task,
                    description=f"阶段 {stages_done}/{total_stages} 完成 | "
                                f"发现: {len(pipeline._verified_findings)}",
                )

            result = await pipeline.execute()
            progress.update(task, description="[bold green]AI 审计完成![/bold green]")
    else:
        result = await pipeline.execute()

    return result


def _display_results(result, config) -> None:
    """展示审计结果摘要"""
    if config.quiet:
        return

    from rich.panel import Panel

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in result.findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    total = result.total_findings
    verified = result.verified_findings

    risk_level = (
        "critical" if severity_counts["critical"] > 0
        else "high" if severity_counts["high"] > 0
        else "medium" if severity_counts["medium"] > 0
        else "low"
    )
    risk_colors = {"critical": "red", "high": "orange_red1", "medium": "yellow", "low": "green"}
    risk_color = risk_colors.get(risk_level, "white")

    console.print(Panel(
        f"[bold]AI 安全审计完成[/bold]\n"
        f"  风险级别: [{risk_color}]{risk_level.upper()}[/{risk_color}]\n"
        f"  总发现: [yellow]{total}[/yellow] | "
        f"验证通过: [green]{verified}[/green]\n"
        f"  Critical: [red]{severity_counts['critical']}[/red] | "
        f"High: [orange_red1]{severity_counts['high']}[/orange_red1] | "
        f"Medium: [yellow]{severity_counts['medium']}[/yellow] | "
        f"Low: [green]{severity_counts['low']}[/green] | "
        f"Info: [dim]{severity_counts['info']}[/dim]\n"
        f"  攻击链: [cyan]{len(result.attack_chains)}[/cyan] 条",
        title="[bold]HOS-LS AI Audit Results[/bold]",
        border_style=risk_color,
    ))

    if result.findings:
        table = Table(title="[bold]发现列表[/bold]")
        table.add_column("#", style="dim", width=4)
        table.add_column("严重级别", width=10)
        table.add_column("规则", width=20)
        table.add_column("置信度", width=10)
        table.add_column("来源", width=8)
        table.add_column("位置", width=35)

        for i, f in enumerate(result.findings[:20], 1):
            sev = f.get("severity", "info").lower()
            sev_style = {"critical": "red", "high": "orange_red1", "medium": "yellow", "low": "green"}.get(sev, "dim")
            conf = f.get("confidence", 0)
            conf_color = "green" if conf >= 0.8 else "yellow" if conf >= 0.5 else "red"
            location = f.get("location", {})
            file_path = location.get("file_path", "")
            line = location.get("line", "")
            loc_str = f"{file_path}:{line}" if line else file_path
            source = f.get("source", f.get("sources", ""))
            if isinstance(source, list):
                source = ",".join(source)

            table.add_row(
                str(i),
                f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                f.get("rule_name", f.get("rule_id", "?"))[:20],
                f"[{conf_color}]{conf:.0%}[/{conf_color}]",
                source[:8],
                loc_str[:35],
            )
        console.print(table)

        if len(result.findings) > 20:
            console.print(f"[dim]... 还有 {len(result.findings) - 20} 条发现未显示[/dim]")

    # 攻击链展示
    if result.attack_chains:
        console.print(Panel(
            "\n".join(
                f"[cyan]{i}.[/cyan] {chain.get('description', '未知攻击链')} "
                f"[{chain.get('risk_level', 'high')}] "
                f"(可信度: {chain.get('confidence', 0):.0%})"
                for i, chain in enumerate(result.attack_chains[:5], 1)
            ),
            title="[bold]攻击链[/bold]",
            border_style="cyan",
        ))
        if len(result.attack_chains) > 5:
            console.print(f"[dim]... 还有 {len(result.attack_chains) - 5} 条攻击链未显示[/dim]")

    # 阶段执行详情
    if result.stage_results:
        table2 = Table(title="[bold]管线执行详情[/bold]")
        table2.add_column("阶段", width=20)
        table2.add_column("状态", width=8)
        table2.add_column("发现数", width=10)
        table2.add_column("耗时(s)", width=10)

        for sr in result.stage_results:
            status = "[green]✅[/green]" if sr.get("success") else "[red]❌[/red]"
            table2.add_row(
                sr.get("stage", "?"),
                status,
                str(sr.get("findings_count", 0)),
                f"{sr.get('elapsed', 0):.1f}",
            )
        console.print(table2)
