"""数据预加载命令

数据源预加载和管理的命令。
"""

from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console

from src.cli.main import cli, console
from src.core.config import Config, ConfigManager


@cli.group()
def data_preload() -> None:
    """数据预加载管理"""


@data_preload.command()
@click.option("--incremental", is_flag=True, help="启用增量下载（默认启用智能检测）")
@click.option("--force", "-", is_flag=True, help="强制重新下载所有数据源")
@click.option("--source", "-s", help="指定单个数据源")
@click.option("--check-only", is_flag=True, help="仅检查状态，不执行下载")
@click.pass_context
def data_preload_run(
    ctx: click.Context,
    incremental: bool,
    force: bool,
    source: Optional[str],
    check_only: bool,
) -> None:
    """执行数据预加载"""
    config = ConfigManager.load()
    from src.nvd.nvd_updater import NVDDataLoader

    loader = NVDDataLoader(config=config)
    asyncio.run(loader.run(incremental=incremental, force=force, source=source, check_only=check_only))


@data_preload.command()
@click.pass_context
def data_preload_status(ctx: click.Context) -> None:
    """查看数据预加载状态"""
    config = ConfigManager.load()
    from src.nvd.nvd_updater import NVDDataLoader

    loader = NVDDataLoader(config=config)
    loader.show_status()


@data_preload.command()
@click.option("--force", "-", is_flag=True, help="强制清理，无需确认")
@click.pass_context
def data_preload_clean(ctx: click.Context, force: bool) -> None:
    """清理数据缓存"""
    config = ConfigManager.load()
    from src.nvd.nvd_updater import NVDDataLoader

    loader = NVDDataLoader(config=config)
    loader.clean(force=force)