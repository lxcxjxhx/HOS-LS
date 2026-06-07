"""索引相关命令"""

from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(emoji=False, force_terminal=True)


@click.group()
def index() -> None:
    """增量索引管理命令"""
    pass


@index.command(name="status")
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.pass_context
def index_status(ctx: click.Context, target: str) -> None:
    """显示项目增量索引状态"""
    from src.core.config import Config

    config: Config = ctx.obj["config"]

    try:
        from src.ai.pure_ai.incremental_index import IncrementalIndexManager

        index_manager = IncrementalIndexManager(target, {"project_path": target})

        if not index_manager.is_index_valid():
            console.print("[yellow]未找到有效的索引，请先执行一次完整扫描[/yellow]")
            return

        indexed_files = index_manager.get_indexed_files()

        console.print(Panel(f"[bold]索引状态: {target}[/bold]"))
        console.print(f"已索引文件: [green]{len(indexed_files)}[/green]")

        table = Table(title="索引信息")
        table.add_column("项目", style="cyan")
        table.add_column("值", style="green")
        table.add_row("索引路径", str(index_manager._index_path))
        table.add_row("已索引文件数", str(len(indexed_files)))
        table.add_row("索引目录", str(index_manager.index_dir))
        console.print(table)

    except Exception as e:
        console.print(f"[bold red]获取索引状态失败: {e}[/bold red]")


@index.command(name="rebuild")
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.pass_context
def index_rebuild(ctx: click.Context, target: str) -> None:
    """重建项目增量索引"""
    from src.core.config import Config

    config: Config = ctx.obj["config"]

    console.print(f"[bold blue]正在重建索引: {target}[/bold blue]")

    try:
        from src.ai.pure_ai.incremental_index import IncrementalIndexManager
        from src.utils.file_discovery import FileDiscoveryEngine

        index_manager = IncrementalIndexManager(target, {"project_path": target})

        file_discovery = FileDiscoveryEngine()
        files = file_discovery.discover_files(Path(target))
        file_paths = [str(f.path) for f in files]

        indexed_count = index_manager.build_index(file_paths)

        console.print(f"[bold green][OK] 索引重建完成，已索引 {indexed_count} 个文件[/bold green]")

    except Exception as e:
        console.print(f"[bold red]重建索引失败: {e}[/bold red]")
