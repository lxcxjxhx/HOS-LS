"""CLI 主模块

HOS-LS 的命令行入口。
"""

import asyncio
import os
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import Any, Optional

import click
from pydantic import BaseModel
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src import __version__
from src.core.config import Config, ConfigManager

warnings.filterwarnings("ignore", message="Failed to find CUDA.")
warnings.filterwarnings(
    "ignore",
    category=RuntimeWarning,
    message="Redirects are currently not supported in Windows or MacOs.",
)
warnings.filterwarnings(
    "ignore",
    category=RuntimeWarning,
    message="'src.cli.main' found in sys.modules after import of package 'src.cli'",
)
warnings.filterwarnings("ignore", message=".*cpp extensions.*")
warnings.filterwarnings("ignore", message="Skipping import of cpp extensions.*")

os.environ["PYTHONWARNINGS"] = "ignore"


console = Console(emoji=False, force_terminal=True)


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """打印启动横幅"""
    console.print(Panel.fit(
        "[bold cyan]╔══════════════════════════════════════╗\n"
        "║       HOS-LS Security Scanner v{}      ║\n"
        "║  Hybrid Open-Source + LLM Security Audit  ║\n"
        "╚══════════════════════════════════════════╝[/bold cyan]".format(__version__),
        border_style="cyan",
    ))


def show_scan_progress() -> None:
    """显示扫描进度"""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    )
    return progress


def show_agent_status() -> None:
    """显示代理状态"""
    from rich.table import Table
    table = Table(title="AI Agent Status", show_header=True)
    table.add_column("Agent", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Progress", style="yellow")
    return table


def show_risk_bar(percentage: float) -> None:
    """显示风险条
    
    Args:
        percentage: 风险百分比 (0-100)
    """
    bar_width = 40
    filled = int(bar_width * percentage / 100)
    bar = "█" * filled + "░" * (bar_width - filled)
    color = "red" if percentage > 60 else "yellow" if percentage > 30 else "green"
    console.print(f"[{color}]{bar} {percentage:.1f}%[/{color}]")


# ---------------------------------------------------------------------------
# 主 CLI 入口
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="hos-ls")
@click.option("--config", "-c", type=click.Path(), help="配置文件路径")
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
@click.option("--quiet", "-q", is_flag=True, help="静默模式")
@click.option("--debug", "-d", is_flag=True, help="调试模式")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool, quiet: bool, debug: bool) -> None:
    """HOS-LS Security Scanner - 混合开源 + LLM 安全审计工具"""
    if config:
        ConfigManager.load(config)
    if verbose:
        os.environ["HOS_LS_VERBOSE"] = "1"
    if quiet:
        os.environ["HOS_LS_QUIET"] = "1"
    if debug:
        os.environ["HOS_LS_DEBUG"] = "1"
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    ctx.ensure_object(dict)


# `scan` 必须在 Click 解析子命令前注册；在 group callback 内注册会导致
# `hos-ls scan ...` 于参数解析阶段被误判为未知命令。
from src.cli.commands.scan_cmd import scan as _scan_command  # noqa: E402
cli.add_command(_scan_command)


# ---------------------------------------------------------------------------
# 内联命令 (config, panel, serial, chat, index, rules, init)
# 这些命令直接在 main.py 中定义，不单独抽取文件
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--export", "-e", type=click.Choice(["json", "yaml"]), default=None, help="导出配置")
@click.option("--import", "import_file", "-i", type=click.Path(exists=True), default=None, help="导入配置文件")
@click.option("--output", "-o", type=click.Path(), default=None, help="导出文件路径")
@click.pass_context
def config(ctx: click.Context, export: str, import_file: str, output: str) -> None:
    """配置管理"""
    if export:
        ConfigManager.export(export, output)
    elif import_file:
        ConfigManager.import_config(import_file)
    else:
        cfg = ctx.obj.get("config") or ConfigManager.load()
        console.print(cfg.to_json())


@cli.command()
@click.pass_context
def panel(ctx: click.Context) -> None:
    """显示控制面板"""
    from src.ui.panel import SecurityPanel
    panel = SecurityPanel()
    panel.run()


@cli.command()
@click.pass_context
def serial(ctx: click.Context) -> None:
    """串口设备扫描"""
    from src.integration.serial_scanner import SerialScanner
    scanner = SerialScanner()
    loop = asyncio.new_event_loop()
    loop.run_until_complete(scanner.scan_serial())


@cli.command()
@click.pass_context
def chat(ctx: click.Context) -> None:
    """交互式聊天模式"""
    config = ctx.obj.get("config") or ConfigManager.load()
    from src.ai.chat import AIChat
    chat = AIChat(config=config)
    asyncio.run(chat.start())


@cli.group()
def index() -> None:
    """索引管理"""


@index.command()
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.pass_context
def index_status(ctx: click.Context, target: str) -> None:
    """查看索引状态"""
    config = ctx.obj.get("config") or ConfigManager.load()
    from src.scanner import Scanner
    scanner = Scanner(config)
    loop = scanner._get_event_loop()
    loop.run_until_complete(scanner.show_index_status(target))


@index.command()
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.pass_context
def index_rebuild(ctx: click.Context, target: str) -> None:
    """重建索引"""
    import shutil
    config = ctx.obj.get("config") or ConfigManager.load()
    index_dir = Path(config.get_index_dir())
    if index_dir.exists():
        shutil.rmtree(str(index_dir))
    console.print("[bold green]索引已清除，下次扫描将自动重建[/bold green]")


@cli.group()
def rules() -> None:
    """规则管理"""


@rules.command()
@click.pass_context
def rules_list(ctx: click.Context) -> None:
    """列出可用规则"""
    from src.analyzers.rule_manager import RuleManager
    manager = RuleManager()
    manager.list_rules()


@cli.command()
def init() -> None:
    """初始化项目配置"""
    from src.core.config import init_project
    init_project()


# ---------------------------------------------------------------------------
# 程序入口
# ---------------------------------------------------------------------------

def main() -> None:
    """主程序入口"""
    print_banner()
    cli()


if __name__ == "__main__":
    main()