"""实时扫描命令"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

console = Console(emoji=False, force_terminal=True)


@click.command()
@click.argument("url")
@click.option("--cookie", "-c", type=click.Path(exists=True), help="Cookie 文件路径，用于认证")
@click.option("--scope", "-s", type=click.Path(exists=True), help="范围配置文件路径")
@click.option("--deep-analysis", "-d", is_flag=True, help="启用 AI 深度分析")
@click.option("--output", "-o", help="输出报告路径")
@click.option("--format", "-f", "output_format", default="html", help="输出格式 (html, json, markdown)")
@click.pass_context
def live_scan(
    ctx: click.Context,
    url: str,
    cookie: Optional[str],
    scope: Optional[str],
    deep_analysis: bool,
    output: Optional[str],
    output_format: str,
) -> None:
    """对运行中的 Web 应用进行实时扫描"""
    config = ctx.obj.get("config") if ctx.obj else None
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print(f"[bold cyan]> hosls live-scan {url}[/bold cyan]")
        console.print(f"[dim]目标: {url}[/dim]")
        if cookie:
            console.print(f"[dim]Cookie 文件: {cookie}[/dim]")
        if scope:
            console.print(f"[dim]范围配置: {scope}[/dim]")
        if deep_analysis:
            console.print("[dim]AI 深度分析: 已启用[/dim]")

    cookie_data = None
    if cookie:
        try:
            cookie_path = Path(cookie)
            cookie_data = cookie_path.read_text(encoding="utf-8").strip()
        except Exception as e:
            console.print(f"[bold red]读取 Cookie 文件失败: {e}[/bold red]")
            sys.exit(1)

    scope_config = None
    if scope:
        try:
            import yaml
            scope_path = Path(scope)
            with open(scope_path, "r", encoding="utf-8") as f:
                scope_config = yaml.safe_load(f)
        except ImportError:
            import json
            scope_path = Path(scope)
            with open(scope_path, "r", encoding="utf-8") as f:
                scope_config = json.load(f)
        except Exception as e:
            console.print(f"[bold red]读取范围配置文件失败: {e}[/bold red]")
            sys.exit(1)

    try:
        from src.scanners.live_scanner import LiveScanner

        scanner = LiveScanner(config)

        if not quiet:
            console.print("[bold yellow]开始实时扫描...[/bold yellow]")

        result = scanner.scan(
            url,
            cookies=cookie_data,
            scope=scope_config,
            deep_analysis=deep_analysis,
        )

        if not quiet:
            findings = getattr(result, "findings", []) or []
            console.print(Panel(
                f"[bold]扫描完成[/bold]\n"
                f"目标: {url}\n"
                f"发现: {len(findings)} 个问题",
                border_style="green" if not findings else "yellow",
            ))

            if findings:
                from rich.table import Table
                table = Table(title="发现的问题")
                table.add_column("#", style="dim")
                table.add_column("严重级别", style="red")
                table.add_column("描述")

                for i, finding in enumerate(findings[:20], 1):
                    severity = getattr(finding, "severity", "info")
                    if hasattr(severity, "value"):
                        severity = severity.value
                    message = getattr(finding, "message", str(finding))[:80]
                    table.add_row(str(i), str(severity), message)

                console.print(table)

                if len(findings) > 20:
                    console.print(f"[dim]... 还有 {len(findings) - 20} 个问题[/dim]")

        if output:
            _export_report(result, output, output_format, quiet)

    except ImportError as e:
        console.print(f"[bold red]实时扫描模块不可用: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]实时扫描失败: {e}[/bold red]")
        sys.exit(2)


def _export_report(result, output: str, output_format: str, quiet: bool) -> None:
    """导出扫描报告"""
    try:
        from src.reporting.generator import ReportGenerator

        generator = ReportGenerator()
        report_path = generator.generate([result], output, output_format)

        if not quiet:
            console.print(f"[bold green]报告已生成: {report_path}[/bold green]")
    except Exception as e:
        console.print(f"[yellow]报告导出失败: {e}[/yellow]")
