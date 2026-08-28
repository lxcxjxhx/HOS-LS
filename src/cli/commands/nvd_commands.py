"""NVD 数据库命令

NVD 漏洞数据库的更新和查询命令。
"""

from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console

from src.cli.main import cli, console
from src.core.config import Config, ConfigManager


@cli.group()
def nvd() -> None:
    """NVD 漏洞数据库管理"""


@nvd.command()
@click.option("--zip", "-z", type=click.Path(exists=True), default=None, help="本地 ZIP 文件路径 (用于离线更新)")
@click.option("--dir", "-d", type=click.Path(exists=True), default=None, help="本地目录路径 (用于离线更新)")
@click.option("--limit", "-l", type=int, default=None, help="限制处理的文件数量 (用于测试)")
@click.option("--no-rag", is_flag=True, help="不导入到RAG库，仅解析")
@click.option("--batch-size", "-b", type=int, default=1000, help="批量处理大小 (默认: 1000)")
@click.option("--resume", type=int, default=0, help="从指定文件开始续传")
@click.option(
    "--model",
    type=click.Choice(["local", "api"]),
    default="api",
    help="更新模式: local=本地解析, api=API查询 (默认: api)",
)
@click.pass_context
def update(ctx, zip, dir, limit, no_rag, batch_size, resume, model) -> None:
    """更新 NVD 漏洞数据库"""
    config = ConfigManager.load()
    from src.nvd.nvd_update import NVDUpdater

    updater = NVDUpdater(config=config)
    loop = updater._get_event_loop()

    limit = limit or config.nvd.get("max_files", 0) or 0
    no_rag = no_rag or not config.nvd.get("enable_rag", True)

    console.print("[bold cyan][NVD] 开始更新漏洞数据库...[/bold cyan]")

    if model == "local":
        result = loop.run_until_complete(
            updater.process_offline_updates(
                zip_path=zip,
                dir_path=dir,
                limit=limit,
                no_rag=no_rag,
                batch_size=batch_size,
                resume=resume,
            )
        )
    else:
        result = loop.run_until_complete(
            updater.update(
                limit=limit,
                no_rag=no_rag,
                batch_size=batch_size,
                resume=resume,
            )
        )

    if result:
        console.print(f"[bold green][OK] NVD 更新完成，新增 {result} 条记录[/bold green]")
    else:
        console.print("[bold yellow][WARN] NVD 更新未产生新记录[/bold yellow]")


@nvd.command()
@click.pass_context
def show_checkpoint(ctx) -> None:
    """显示 NVD 更新检查点状态"""
    config = ConfigManager.load()
    from src.nvd.nvd_update import NVDUpdater

    updater = NVDUpdater(config=config)
    updater._show_check_status()


@nvd.command()
@click.option("--force", "-", is_flag=True, help="强制清理，无需确认")
@click.pass_context
def clean_checkpoints(ctx, force) -> None:
    """清理 NVD 更新检查点"""
    config = ConfigManager.load()
    from src.nvd.nvd_update import NVDUpdater

    updater = NVDUpdater(config=config)
    updater._clean_checkpoints(force=force)