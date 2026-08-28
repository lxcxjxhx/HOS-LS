"""数据预加载状态检查"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

import click
from rich.console import Console

console = Console()


def check_data_preload_status(config) -> None:
    """检查数据预加载状态"""
    from src.integration.data_preloader import DataPreloader

    db_path = Path(config.nvd.database_path)
    if not db_path.exists():
        console.print("[bold yellow]警告: NVD 数据库不存在，使用内置 DB 降级[/bold yellow]")
        console.print(f"[yellow]数据库路径: {db_path}[/yellow]")
        console.print("[dim]如需完整 CVE 匹配，请手动运行: hos-ls data-preload run[/dim]")
        return
    if not db_path.is_file() or db_path.stat().st_size < 1024 * 1024:
        console.print("[bold yellow]警告: NVD 数据库文件异常（缺失或过小），使用内置 DB 降级[/bold yellow]")
        return
    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir),
            skip_on_checksum_match=config.data_preload.skip_on_checksum_match,
            merge_strategy=config.data_preload.merge_strategy,
        )
        sources_status = preloader.get_download_status()
        records = sources_status.get("records", [])
        if records:
            latest_record = records[0]
            downloaded_at_str = latest_record.get("downloaded_at")
            if downloaded_at_str:
                try:
                    downloaded_at = datetime.fromisoformat(downloaded_at_str)
                    threshold_date = datetime.now() - timedelta(days=config.data_preload.update_threshold_days)
                    if downloaded_at < threshold_date:
                        days_since_update = (datetime.now() - downloaded_at).days
                        console.print(f"[bold yellow]警告: NVD 数据已超过 {days_since_update} 天未更新[/bold yellow]")
                        console.print(f"[yellow]最后更新时间: {downloaded_at.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                        if click.confirm("是否执行数据预加载更新?", default=False):
                            console.print("[bold cyan]开始执行数据预加载...[/bold cyan]")
                            try:
                                preloader.download_all(parallel=True)
                                console.print("[bold green]数据预加载完成[/bold green]")
                            except Exception as e:
                                console.print(f"[bold red]数据预加载失败: {e}[/bold red]")
                                if not click.confirm("是否继续扫描?", default=True):
                                    sys.exit(1)
                except Exception:
                    pass
    except Exception as e:
        console.print(f"[yellow]检查数据预加载状态时出错: {e}[/yellow]")