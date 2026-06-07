"""数据预加载管理命令"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(emoji=False, force_terminal=True)


def _show_check_status(preloader, source_filter: Optional[str] = None) -> None:
    """显示检查状态"""
    status = preloader.check_status()

    table = Table(title="数据源检查状态")
    table.add_column("数据源", style="cyan")
    table.add_column("ZIP文件", style="green")
    table.add_column("状态", style="yellow")
    table.add_column("原因/大小", style="magenta")

    for src_info in status.get("sources", []):
        if source_filter and source_filter.lower() not in src_info.get("name", "").lower():
            continue

        name = src_info.get("name", "unknown")
        zip_file = src_info.get("zip_file", "N/A")
        needs_dl = src_info.get("needs_download", True)
        reason = src_info.get("reason", "")

        if src_info.get("zip_exists"):
            size = src_info.get("zip_size", 0)
            if size:
                size_str = f"{size / 1024 / 1024:.2f} MB" if size > 1024 * 1024 else f"{size / 1024:.2f} KB"
                reason = f"{reason} ({size_str})"

        status_icon = "[green]✓ 跳过[/green]" if not needs_dl else "[yellow]↓ 需下载[/yellow]"
        table.add_row(name, zip_file, status_icon, reason)

    console.print(table)

    stats = preloader.get_statistics()
    console.print(f"\n[cyan]统计信息:[/cyan]")
    console.print(f"  配置数据源: {stats.get('configured_sources', 0)}")
    console.print(f"  已下载ZIP: {stats.get('downloaded_zips', 0)}")
    console.print(f"  已解压目录: {stats.get('extracted_dirs', 0)}")
    console.print(f"  增量策略: skip_on_checksum_match={stats.get('skip_on_checksum_match', True)}")
    console.print(f"  合并策略: {stats.get('merge_strategy', 'smart')}")


@click.group()
def data_preload() -> None:
    """数据预加载管理命令"""
    pass


@data_preload.command(name="run")
@click.option("--incremental", is_flag=True, help="启用增量下载（默认启用智能检测）")
@click.option("--force", "-f", is_flag=True, help="强制重新下载所有数据源")
@click.option("--source", "-s", help="指定单个数据源")
@click.option("--check-only", is_flag=True, help="仅检查状态，不执行下载")
@click.pass_context
def data_preload_run(ctx: click.Context, incremental: bool, force: bool, source: Optional[str], check_only: bool) -> None:
    """执行完整数据预加载"""
    from src.core.config import Config

    config: Config = ctx.obj["config"]

    try:
        from src.integration.data_preloader import DataPreloader
    except ImportError:
        console.print("[bold red]错误: DataPreloader 模块不可用[/bold red]")
        console.print("[yellow]请确保 src.integration.data_preloader 模块存在[/yellow]")
        sys.exit(1)

    console.print(Panel("[bold blue]数据预加载[/bold blue]"))

    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir)
        )

        if check_only:
            console.print("[cyan]检查模式，仅显示状态...[/cyan]\n")
            return _show_check_status(preloader, source)

        urls = preloader.config.urls

        if source:
            urls = [url for url in urls if source.lower() in url.lower()]
            console.print(f"[cyan]过滤后待处理数据源: {len(urls)}[/cyan]\n")

        console.print(f"[cyan]待处理数据源: {len(urls)}[/cyan]")
        console.print(f"[dim]force={force}, incremental={incremental}[/dim]\n")

        results = preloader.download_all(
            parallel=not incremental,
            force=force,
            source_filter=source
        )

        success_count = sum(1 for v in results.values() if v)
        fail_count = len(results) - success_count

        console.print(f"\n[cyan]成功: {success_count}, 失败: {fail_count}[/cyan]")

        if fail_count > 0:
            console.print("[bold yellow]部分数据源下载失败[/bold yellow]")
            for src, success in results.items():
                if not success:
                    console.print(f"  [red]X[/red] {src}")

        console.print("[bold green][OK] 数据预加载完成[/bold green]")

    except Exception as e:
        console.print(f"[bold red]预加载失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@data_preload.command(name="status")
@click.pass_context
def data_preload_status(ctx: click.Context) -> None:
    """显示各数据源状态"""
    from src.core.config import Config

    config: Config = ctx.obj["config"]

    try:
        from src.integration.data_preloader import DataPreloader
    except ImportError:
        console.print("[bold red]错误: DataPreloader 模块不可用[/bold red]")
        console.print("[yellow]请确保 src.integration.data_preloader 模块存在[/yellow]")
        sys.exit(1)

    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir)
        )
        sources_status = preloader.get_download_status()

        table = Table(title="数据源状态")
        table.add_column("数据源", style="cyan")
        table.add_column("文件名", style="green")
        table.add_column("大小", style="yellow")
        table.add_column("最后下载时间", style="magenta")

        records = sources_status.get("records", [])
        if not records:
            console.print("[yellow]没有下载记录[/yellow]")
            return

        for record in records:
            name = record.get("source", "unknown")
            file_name = record.get("file_name", "N/A")
            file_size = record.get("file_size", 0)
            downloaded_at = record.get("downloaded_at", "从未下载")

            if isinstance(file_size, int):
                size_str = f"{file_size / 1024 / 1024:.2f} MB" if file_size > 1024 * 1024 else f"{file_size / 1024:.2f} KB"
            else:
                size_str = str(file_size)

            table.add_row(name, file_name, size_str, str(downloaded_at))

        console.print(table)

        stats = preloader.get_statistics()
        console.print(f"\n[cyan]统计: 配置数据源 {stats.get('configured_sources', 0)}, "
                     f"已下载 ZIP {stats.get('downloaded_zips', 0)}, "
                     f"已解压目录 {stats.get('extracted_dirs', 0)}[/cyan]")

    except Exception as e:
        console.print(f"[bold red]获取状态失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@data_preload.command(name="clean")
@click.option("--force", "-f", is_flag=True, help="强制清理，无需确认")
@click.pass_context
def data_preload_clean(ctx: click.Context, force: bool) -> None:
    """清理缓存数据"""
    from src.core.config import Config

    config: Config = ctx.obj["config"]

    try:
        from src.integration.data_preloader import DataPreloader
    except ImportError:
        console.print("[bold red]错误: DataPreloader 模块不可用[/bold red]")
        console.print("[yellow]请确保 src.integration.data_preloader 模块存在[/yellow]")
        sys.exit(1)

    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir)
        )

        zip_dir = preloader.temp_zip_dir
        if not zip_dir.exists():
            console.print("[bold green]没有缓存数据需要清理[/bold green]")
            return

        zip_files = list(zip_dir.glob('*.zip'))
        if not zip_files:
            console.print("[bold green]没有 ZIP 文件需要清理[/bold green]")
            return

        total_size = sum(f.stat().st_size for f in zip_files)
        total_size_mb = total_size / 1024 / 1024

        console.print(Panel("[bold red]清理缓存数据[/bold red]"))
        console.print(f"[cyan]发现 {len(zip_files)} 个 ZIP 文件，共 {total_size_mb:.2f} MB[/cyan]")

        if not force:
            try:
                if not click.confirm("确定要清理所有 ZIP 缓存文件吗？", default=False):
                    console.print("[yellow]已取消清理[/yellow]")
                    return
            except Exception:
                console.print("[yellow]无法获取确认，使用 --force 参数强制清理[/yellow]")
                return

        count = preloader.cleanup_zip_files()

        console.print(f"[bold green][OK] 缓存清理完成，删除了 {count} 个文件[/bold green]")

    except Exception as e:
        console.print(f"[bold red]清理失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)
