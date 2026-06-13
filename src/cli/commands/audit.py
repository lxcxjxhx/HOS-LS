"""AI 安全审计命令

提供完整的 AI 驱动的代码审计流水线 CLI 入口。
串联：AST预分析 → 污点追踪 → 输入可控性 → 调用图 → 静态预扫描 → AI深度分析 → 跨文件分析 → 修复建议 → 合并去重 → 三重验证 → 攻击链分析 → 报告生成

注意：本命令为纯代码审计，不包含任何渗透测试/运行时验证/POC利用功能。
如需渗透测试，请使用 `hos-ls pentest <target>` 命令。
"""

import asyncio
import json
import logging
import os
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
logger = logging.getLogger("audit")


# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------

def _configure_logging(debug: bool = False, quiet: bool = False) -> None:
    """配置审计命令的日志级别

    - debug=True: 显示 DEBUG+ 级别日志
    - quiet=True: 仅显示 WARNING+ 级别
    - 默认(都不设置): 显示 WARNING+ 级别，抑制 INFO/DEBUG
    """
    if debug:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.WARNING  # 默认抑制 INFO/DEBUG

    # 设置根日志记录器级别
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # 设置 hos-ls 相关日志记录器
    for name in ("hos-ls", "audit", "AuditPipeline", "src"):
        log = logging.getLogger(name)
        log.setLevel(level)
        # 移除现有的 RichHandler，避免与 progress bar 冲突
        log.handlers.clear()

    # 抑制 litellm 日志
    logging.getLogger("litellm").setLevel(logging.WARNING)
    logging.getLogger("litellm.proxy").setLevel(logging.WARNING)

    # 添加一个简单的 stderr handler（仅 debug 模式）
    if debug:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
        root_logger.addHandler(handler)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

AUDIT_MODE_CONFIG = {
    "quick": {
        "enable_ai": True,
        "enable_deep_analysis": False,
        "description": "静态预扫描 + 基础 AI 分析",
    },
    "standard": {
        "enable_ai": True,
        "enable_deep_analysis": False,
        "description": "完整审计流水线（默认）",
    },
    "deep": {
        "enable_ai": True,
        "enable_deep_analysis": True,
        "description": "启用 PureAIAnalyzer 深度分析",
    },
}

# ---------------------------------------------------------------------------
# Click 命令
# ---------------------------------------------------------------------------

@click.command("audit")
@click.argument("target")
@click.option("--mode", type=click.Choice(["quick", "standard", "deep"], case_sensitive=False),
              default="standard", help="审计模式 (quick=快速扫描, standard=标准审计, deep=深度分析)")
@click.option("--output", "-o", default=None, help="报告输出路径")
@click.option("--format", "report_format", type=click.Choice(["json", "markdown", "html"]),
              default="markdown", help="报告格式")
@click.option("--ai-provider", type=str, default=None,
              help="指定 AI 提供商 (anthropic, openai, deepseek, aliyun, local)")
@click.option("--workers", "-w", type=int, default=4, help="并发工作线程数 (默认: 4)")
@click.option("--max-files", type=int, default=None, help="限制最大分析文件数")
@click.option("--debug", "-d", is_flag=True, help="启用详细调试日志")
@click.pass_context
def ai_audit(
    ctx: click.Context,
    target: str,
    mode: str,
    output: Optional[str],
    report_format: str,
    ai_provider: Optional[str],
    workers: int,
    max_files: Optional[int],
    debug: bool,
) -> None:
    """AI 驱动的代码安全审计流水线

    TARGET: 目标文件或目录路径

    审计流程：AST预分析 → 污点追踪 → AI深度分析 → 攻击链分析 → 报告生成
    注意：本命令为纯代码审计，不包含渗透测试功能

    审计模式:
        quick    - 仅静态预扫描 + 基础 AI 分析（快速）
        standard - 完整审计流水线（默认）
        deep     - 启用 PureAIAnalyzer 深度语义分析（最全面）

    示例:
        hos-ls audit ./src/
        hos-ls audit ./src/ --mode quick -o report.md
        hos-ls audit ./vulnerable_code.py --mode deep --format html
        hos-ls audit ./src/ --mode standard --ai-provider deepseek -w 8
    """
    t0 = time.time()
    config = ctx.obj.get("config")
    if config is None:
        from src.core.config import Config
        config = Config()

    # Configure logging BEFORE anything else
    # Default: WARNING+ only (suppress DEBUG/INFO from sub-modules)
    # When --debug: enable DEBUG level
    _configure_logging(debug=debug, quiet=config.quiet)

    if debug:
        config.debug = True
        # Also ensure quiet is False when debug is on
        config.quiet = False
    else:
        # Non-debug runs: set quiet to suppress verbose sub-module output
        if not hasattr(config, "quiet") or not config.quiet:
            config.quiet = True

    # 模式配置解析
    mode = mode.lower()
    mode_cfg = AUDIT_MODE_CONFIG.get(mode, AUDIT_MODE_CONFIG["standard"])
    enable_ai = mode_cfg["enable_ai"]
    enable_deep_analysis = mode_cfg["enable_deep_analysis"]

    # AI 提供商覆盖
    if ai_provider:
        try:
            config.ai.provider = ai_provider
        except AttributeError:
            pass

    # 工作线程数
    try:
        config.scan.max_workers = workers
    except AttributeError:
        config.__dict__['workers'] = workers

    # Banner
    if not config.quiet:
        console.print(Panel(
            f"[bold cyan]HOS-LS 安全审计引擎[/bold cyan]\n"
            f"  目标: {target}\n"
            f"  模式: {mode} ({mode_cfg['description']})\n"
            f"  AI分析: {'[green]启用[/green]' if enable_ai else '[dim]禁用[/dim]'}\n"
            f"  深度分析: {'[green]是[/green]' if enable_deep_analysis else '[dim]否[/dim]'}\n"
            f"  工作线程: {workers}",
            title="[bold]HOS-LS Audit Engine[/bold]",
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
                enable_deep_analysis=enable_deep_analysis,
                max_files=max_files,
                debug=debug,
            )
        )
    except Exception as e:
        console.print(f"[bold red]审计执行失败: {e}[/bold red]")
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
        fmt_map = {"json": ".json", "markdown": ".md", "html": ".html"}
        ext = fmt_map.get(report_format, ".md")
        report_path = f"audit_{ts}{ext}"

    _save_report(result, report_path, report_format, config)

    elapsed = time.time() - t0
    if not config.quiet:
        console.print(f"[dim]总耗时: {elapsed:.1f}s[/dim]")


async def _run_ai_audit(
    target: str,
    config,
    enable_ai: bool,
    enable_deep_analysis: bool,
    max_files: Optional[int],
    debug: bool,
):
    """执行 AI 审计流水线的异步核心"""
    from src.audit.pipeline.audit_pipeline import AuditPipeline
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

    # 创建纯审计管线（无渗透测试能力）
    pipeline = AuditPipeline(
        target=target,
        config=config,
        ai_client=ai_client,
        enable_ai_analysis=enable_ai,
        max_files=max_files,
    )

    # deep 模式启用 PureAIAnalyzer
    if enable_deep_analysis:
        try:
            from src.ai.pure_ai_analyzer import PureAIAnalyzer
            pipeline.enable_pure_ai_analyzer(PureAIAnalyzer(config=config))
            logger.info("PureAIAnalyzer 深度分析已启用")
        except Exception as e:
            logger.warning(f"PureAIAnalyzer 初始化失败: {e}")

    # 执行
    # quiet=True 时: 无进度条，干净输出
    # quiet=False (debug模式): 显示单一进度条
    if not quiet:
        with Progress(
            TextColumn("[bold cyan][ {task.description} ][/bold cyan]"),
            BarColumn(bar_width=40),
            TextColumn("[dim]{task.fields[details]}[/dim]"),
            console=console,
            transient=True,
            refresh_per_second=2,
        ) as progress:
            task = progress.add_task("AUDIT", details="正在初始化...")

            def _progress_cb():
                stages_done = sum(1 for sr in pipeline.stage_results if sr.success)
                total_stages = 7
                progress.update(
                    task,
                    description=f"阶段 {stages_done}/{total_stages}",
                    details=f"发现: {len(pipeline._verified_findings)}",
                )

            result = await pipeline.execute()
            progress.update(task, description="[bold green]完成[/bold green]", details="")
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
        f"[bold]安全审计完成[/bold]\n"
        f"  风险级别: [{risk_color}]{risk_level.upper()}[/{risk_color}]\n"
        f"  总发现: [yellow]{total}[/yellow] | "
        f"验证通过: [green]{verified}[/green]\n"
        f"  Critical: [red]{severity_counts['critical']}[/red] | "
        f"High: [orange_red1]{severity_counts['high']}[/orange_red1] | "
        f"Medium: [yellow]{severity_counts['medium']}[/yellow] | "
        f"Low: [green]{severity_counts['low']}[/green] | "
        f"Info: [dim]{severity_counts['info']}[/dim]\n"
        f"  攻击链: [cyan]{len(result.attack_chains)}[/cyan] 条",
        title="[bold]HOS-LS Audit Results[/bold]",
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


def _save_report(result, output_path: str, report_format: str, config) -> None:
    """保存审计报告（支持 JSON/Markdown/HTML）"""
    # 确保输出目录存在
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    if report_format == "json":
        with open(output_path, "w", encoding="utf-8") as fh:
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
    elif report_format == "html":
        _generate_audit_html(result, output_path, config)
    else:
        # markdown
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(result.report)

    if not config.quiet:
        console.print(f"[bold green][OK] 报告已保存: {output_path}[/bold green]")


def _generate_audit_html(result, output_path: str, config) -> None:
    """生成审计 HTML 报告"""
    try:
        findings = result.findings
        target = getattr(result, 'target', 'unknown')
        timestamp = getattr(result, 'timestamp', datetime.now().isoformat())

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        html_path = output_path.replace(".json", ".html") if output_path.endswith(".json") else output_path + ".html"

        # 构建 findings HTML
        findings_html = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info").lower()
            rule_name = f.get("rule_name", f.get("rule_id", ""))
            confidence = f.get("confidence", 0)
            location = f.get("location", {})
            file_path = location.get("file_path", "")
            line = location.get("line", "")
            loc_str = f"{file_path}:{line}" if line else file_path
            description = f.get("description", "")
            evidence = f.get("evidence", "")

            findings_html += f'''
            <div class="finding {sev}">
                <div class="finding-header">
                    <span class="severity-badge {sev}">{sev.upper()}</span>
                    <strong>#{i} {rule_name}</strong>
                    <span class="confidence">置信度: {confidence:.0%}</span>
                </div>
                <div class="finding-location">位置: {loc_str}</div>
                <div class="finding-summary">{description}</div>
                {f'<div class="finding-evidence"><strong>证据:</strong><pre>{evidence}</pre></div>' if evidence else ''}
            </div>
            '''

        total_findings = getattr(result, 'total_findings', len(findings))
        verified_findings = getattr(result, 'verified_findings', 0)
        attack_chain_count = len(getattr(result, 'attack_chains', []))

        html_content = f'''<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HOS-LS 审计报告 - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f0f2f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 28px; }}
        .header .meta {{ opacity: 0.9; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }}
        .summary-card .count {{ font-size: 36px; font-weight: bold; }}
        .summary-card .label {{ color: #666; font-size: 14px; }}
        .critical .count {{ color: #dc3545; }}
        .high .count {{ color: #fd7e14; }}
        .medium .count {{ color: #ffc107; }}
        .low .count {{ color: #28a745; }}
        .info .count {{ color: #17a2b8; }}
        .finding {{ background: white; padding: 20px; margin-bottom: 15px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 4px solid #ddd; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding.info {{ border-left-color: #17a2b8; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }}
        .severity-badge.critical {{ background: #dc3545; }}
        .severity-badge.high {{ background: #fd7e14; }}
        .severity-badge.medium {{ background: #ffc107; color: #333; }}
        .severity-badge.low {{ background: #28a745; }}
        .severity-badge.info {{ background: #17a2b8; }}
        .confidence {{ color: #888; font-size: 13px; }}
        .finding-location {{ color: #666; font-size: 14px; margin-bottom: 10px; font-family: monospace; }}
        .finding-summary {{ margin-bottom: 10px; }}
        .finding-evidence {{ background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; }}
        .finding-evidence pre {{ margin: 5px 0 0 0; overflow-x: auto; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#x1F512; HOS-LS 安全审计报告</h1>
            <div class="meta">
                <span>目标: {target}</span> | 
                <span>时间: {timestamp}</span>
            </div>
        </div>

        <div class="summary-cards">
            <div class="summary-card">
                <div class="count">{total_findings}</div>
                <div class="label">总发现</div>
            </div>
            <div class="summary-card">
                <div class="count">{verified_findings}</div>
                <div class="label">已验证</div>
            </div>
            <div class="summary-card">
                <div class="count">{attack_chain_count}</div>
                <div class="label">攻击链</div>
            </div>
            <div class="summary-card critical">
                <div class="count">{severity_counts['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{severity_counts['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{severity_counts['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{severity_counts['low']}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{severity_counts['info']}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <h2>发现详情 ({len(findings)})</h2>
        {findings_html}
    </div>
</body>
</html>'''

        with open(html_path, "w", encoding="utf-8") as fp:
            fp.write(html_content)

        if not getattr(config, "quiet", False):
            console.print(f"[bold green][OK] HTML 报告已生成: {html_path}[/bold green]")
    except Exception as e:
        if not getattr(config, "quiet", False):
            console.print(f"[yellow][WARN] HTML 报告生成失败: {e}[/yellow]")
