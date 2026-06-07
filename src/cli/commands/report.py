"""报告管理命令"""

import sys
import os
from typing import Optional
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(emoji=False, force_terminal=True)


# ============================================================================
# Internal helper functions used by scan.py
# ============================================================================

def print_banner() -> None:
    """打印HOS-LS扫描横幅"""
    console.print()
    console.print(Panel(
        "[bold cyan]HOS-LS[/bold cyan]  AI-Powered Code Security Scanner v0.3.4\n"
        "[dim]https://github.com/HOS-LS/HOS-LS[/dim]",
        border_style="cyan",
        padding=(1, 2),
    ))
    console.print()


def _check_data_preload_status(config) -> None:
    """检查数据预加载状态"""
    try:
        from src.integration.data_preloader import DataPreloader

        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir)
        )

        status = preloader.check_status()
        needs_download = False

        for src_info in status.get("sources", []):
            if src_info.get("needs_download", True):
                needs_download = True
                break

        if needs_download:
            console.print("[yellow][INFO] 检测到数据源需要更新，请先运行: hosls data-preload run[/yellow]")
            console.print("[yellow]       或使用 --skip-data-update 跳过此检查[/yellow]\n")
    except Exception:
        # 数据预加载模块不可用时静默跳过
        pass


def _generate_report(result, output: str, output_format: str, config) -> None:
    """生成扫描报告"""
    try:
        from src.reporting.generator import ReportGenerator

        generator = ReportGenerator()
        report_path = generator.generate(result, output, output_format)

        if not getattr(config, "quiet", False):
            console.print(f"[bold green][OK] 报告已生成: {report_path}[/bold green]")
    except Exception as e:
        if not getattr(config, "quiet", False):
            console.print(f"[bold red]报告生成失败: {e}[/bold red]")
            console.print(f"[yellow]尝试使用备用方式生成报告...[/yellow]")
        _fallback_report(result, output, config)


def _fallback_report(result, output: str, config) -> None:
    """备用报告生成（简单HTML）"""
    try:
        findings = getattr(result, "findings", []) or []

        html_content = f"""<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>HOS-LS 扫描报告</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
.container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
.finding {{ padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; background: #f8f9fa; }}
.critical {{ border-color: #dc3545; }}
.high {{ border-color: #fd7e14; }}
.medium {{ border-color: #ffc107; }}
.low {{ border-color: #28a745; }}
</style></head>
<body><div class="container">
<h1>HOS-LS 扫描报告</h1>
<p>目标: {getattr(result, 'target', 'unknown')}</p>
<p>发现总数: {len(findings)}</p>
"""
        for f in findings:
            severity = str(getattr(f, "severity", "info")).lower()
            message = getattr(f, "message", str(f))
            file_path = getattr(f, "file_path", "")
            html_content += f'<div class="finding {severity}"><strong>[{severity.upper()}]</strong> {message}'
            if file_path:
                html_content += f'<br><em>{file_path}</em>'
            html_content += "</div>"

        html_content += "</div></body></html>"

        with open(output, "w", encoding="utf-8") as fp:
            fp.write(html_content)

        if not getattr(config, "quiet", False):
            console.print(f"[bold green][OK] 备用报告已生成: {output}[/bold green]")
    except Exception as e2:
        console.print(f"[bold red]备用报告生成也失败: {e2}[/bold red]")


# ============================================================================
# CLI command group
# ============================================================================


@click.group()
def report() -> None:
    """报告生成与管理"""
    pass


@report.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["html", "json", "markdown", "sarif", "csv"]), default="html", help="输出格式")
@click.option("--output", "-o", help="输出文件路径")
@click.pass_context
def generate(ctx: click.Context, input_file: str, output_format: str, output: Optional[str]) -> None:
    """从扫描结果生成报告"""
    config = ctx.obj.get("config")
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print(f"[bold cyan]正在生成报告: {input_file}[/bold cyan]")

    try:
        from src.reporting.generator import ReportGenerator
        from src.reporting.loader import load_scan_result

        results = load_scan_result(input_file)
        generator = ReportGenerator()

        if not output:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = output_format if output_format != "markdown" else "md"
            output = f"report_{timestamp}.{ext}"

        report_path = generator.generate(results, output, output_format)
        if not quiet:
            console.print(f"[bold green]报告已生成: {report_path}[/bold green]")
    except ImportError as e:
        console.print(f"[bold red]报告模块不可用: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]报告生成失败: {e}[/bold red]")
        sys.exit(2)


@report.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["html", "json", "markdown", "sarif", "csv"]), required=True, help="目标格式")
@click.option("--output", "-o", help="输出文件路径")
@click.pass_context
def convert(ctx: click.Context, input_file: str, output_format: str, output: Optional[str]) -> None:
    """转换报告格式"""
    config = ctx.obj.get("config")
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print(f"[bold cyan]正在转换报告: {input_file} -> {output_format}[/bold cyan]")

    try:
        from src.reporting.generator import ReportGenerator
        from src.reporting.loader import load_scan_result

        results = load_scan_result(input_file)
        generator = ReportGenerator()

        if not output:
            from pathlib import Path
            src = Path(input_file)
            ext = output_format if output_format != "markdown" else "md"
            output = str(src.with_suffix(f".{ext}"))

        report_path = generator.generate(results, output, output_format)
        if not quiet:
            console.print(f"[bold green]报告已转换: {report_path}[/bold green]")
    except ImportError as e:
        console.print(f"[bold red]报告模块不可用: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]报告转换失败: {e}[/bold red]")
        sys.exit(2)


@report.command()
@click.argument("file1", type=click.Path(exists=True))
@click.argument("file2", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["html", "json", "markdown", "sarif", "csv"]), default="markdown", help="对比输出格式")
@click.option("--output", "-o", help="输出文件路径")
@click.pass_context
def compare(ctx: click.Context, file1: str, file2: str, output_format: str, output: Optional[str]) -> None:
    """对比两份扫描报告"""
    config = ctx.obj.get("config")
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print(f"[bold cyan]正在对比报告:[/bold cyan]")
        console.print(f"  文件1: {file1}")
        console.print(f"  文件2: {file2}")

    try:
        from src.reporting.loader import load_scan_result

        results1 = load_scan_result(file1)
        results2 = load_scan_result(file2)

        summary1 = _summarize_results(results1)
        summary2 = _summarize_results(results2)

        if not quiet:
            table = Table(title="报告对比摘要")
            table.add_column("指标", style="cyan")
            table.add_column("文件1", style="green")
            table.add_column("文件2", style="yellow")
            table.add_row("发现总数", str(summary1["total"]), str(summary2["total"]))
            table.add_row("Critical", str(summary1["critical"]), str(summary2["critical"]))
            table.add_row("High", str(summary1["high"]), str(summary2["high"]))
            table.add_row("Medium", str(summary1["medium"]), str(summary2["medium"]))
            table.add_row("Low", str(summary1["low"]), str(summary2["low"]))
            console.print(table)

            diff = summary2["total"] - summary1["total"]
            if diff > 0:
                console.print(f"[yellow]文件2比文件1多出 {diff} 个发现[/yellow]")
            elif diff < 0:
                console.print(f"[green]文件2比文件1少 {abs(diff)} 个发现[/green]")
            else:
                console.print("[green]两份报告发现数量一致[/green]")

        if output:
            _write_comparison(output, output_format, summary1, summary2, results1, results2)
            if not quiet:
                console.print(f"[bold green]对比结果已保存: {output}[/bold green]")
    except ImportError as e:
        console.print(f"[bold red]报告模块不可用: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]报告对比失败: {e}[/bold red]")
        sys.exit(2)


def _summarize_results(results) -> dict:
    """汇总扫描结果统计"""
    findings = []
    if hasattr(results, "findings"):
        findings = results.findings
    elif isinstance(results, list):
        for r in results:
            if hasattr(r, "findings"):
                findings.extend(r.findings)
    elif isinstance(results, dict):
        findings = results.get("findings", [])

    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity = getattr(f, "severity", None)
        if severity:
            sev_str = str(severity).lower() if not isinstance(severity, str) else severity.lower()
            if sev_str in summary:
                summary[sev_str] += 1
    return summary


def _write_comparison(output: str, fmt: str, summary1: dict, summary2: dict, results1, results2) -> None:
    """写入对比结果"""
    import json

    comparison = {
        "file1_summary": summary1,
        "file2_summary": summary2,
        "difference": {k: summary2.get(k, 0) - summary1.get(k, 0) for k in summary1},
    }

    with open(output, "w", encoding="utf-8") as f:
        if fmt == "json":
            json.dump(comparison, f, ensure_ascii=False, indent=2)
        else:
            f.write("# 扫描报告对比\n\n")
            for key in summary1:
                f.write(f"- {key}: {summary1[key]} -> {summary2[key]} (变化: {comparison['difference'][key]})\n")
