"""导入扫描命令

导入外部扫描结果和回放日志的命令。
"""

from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console

from src.cli.main import cli, console
from src.core.config import Config, ConfigManager


@cli.command()
@click.argument("cache_file", type=click.Path(exists=True))
@click.option("-o", "--output", "output_file", default=None, help="输出报告路径")
@click.option(
    "--format", "-f", "report_format", type=click.Choice(["json", "html", "md", "sarif"]),
    default="html", help="报告格式 (默认: html)"
)
@click.option("--show-progress", is_flag=True, default=False, help="显示扫描进度")
def import_scan(cache_file, output_file, report_format, show_progress):
    """导入外部扫描缓存文件并生成报告"""
    config = ConfigManager.load()
    from src.reporting.generator import generate_report_from_cache

    generate_report_from_cache(
        cache_file, output_file=output_file,
        report_format=report_format, show_progress=show_progress
    )


@cli.command()
@click.argument("log_file", type=click.Path(exists=True))
@click.option("-s", "--speed", default=1.0, help="重放速度倍数 (0.5=半速, 2.0=2倍速)")
@click.option("-c", "--color/--no-color", default=True, help="是否启用彩色输出")
def replay(log_file, speed, color):
    """重放日志文件"""
    from src.replay import ReplayEngine

    engine = ReplayEngine(log_file, speed=speed, color=color)
    engine.run()