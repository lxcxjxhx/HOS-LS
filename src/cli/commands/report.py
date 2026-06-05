"""报告生成和数据预加载检查相关函数"""

import sys
import os
import time
import asyncio
import threading
from pathlib import Path
from typing import Optional
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import click
from rich.console import Console
from rich.panel import Panel

console = Console(emoji=False, force_terminal=True)


def print_banner() -> None:
    """打印欢迎横幅"""
    console.print(Panel(
        "[bold]HOS-LS[/bold] · AI Code Security Scanner\n"
        "[dim]Multi-Agent · Semantic Analysis · Risk Detection[/dim]",
        border_style="dim",
    ))


def clear_screen() -> None:
    """跨平台清屏"""
    sys.stdout.write('\033[2J\033[H')
    sys.stdout.flush()


class AsyncWorker:
    """异步Worker类，用于处理后台任务"""
    
    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.queue = Queue()
        self.running = False
    
    def start(self):
        """启动Worker"""
        self.running = True
        def run_event_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.create_task(self._process_queue())
            loop.run_forever()
        
        thread = threading.Thread(target=run_event_loop)
        thread.daemon = True
        thread.start()
    
    def stop(self):
        """停止Worker"""
        self.running = False
        self.executor.shutdown()
    
    def add_task(self, task, *args, **kwargs):
        """添加任务到队列"""
        self.queue.put((task, args, kwargs))
    
    async def _process_queue(self):
        """处理队列中的任务"""
        while self.running:
            if not self.queue.empty():
                task, args, kwargs = self.queue.get()
                try:
                    await asyncio.to_thread(task, *args, **kwargs)
                except Exception as e:
                    console.print(f"[bold red]任务执行失败: {e}[/bold red]")
                finally:
                    self.queue.task_done()
            await asyncio.sleep(0.1)


def _generate_report(result, output: str, format: str, config=None) -> None:
    """生成报告"""
    from src.reporting.generator import ReportGenerator

    try:
        from src.utils.cache_manager import get_cache_manager
        cache_manager = get_cache_manager()
        state_file = cache_manager.get_path('scan_state', 'scan_state.json')
        scan_state_info = None
        is_truncated = False
        truncation_reason = None

        if state_file.exists():
            from src.core.scan_state import ScanState
            state = ScanState.load(str(state_file))
            if state:
                scan_state_info = state.get_progress()
                is_truncated = state.truncated
                truncation_reason = state.truncation_reason

        if hasattr(result, 'metadata') and result.metadata is not None:
            result.metadata['scan_state'] = scan_state_info
            result.metadata['truncated'] = is_truncated
            result.metadata['truncation_reason'] = truncation_reason
        elif isinstance(result, dict):
            if 'metadata' not in result:
                result['metadata'] = {}
            result['metadata']['scan_state'] = scan_state_info
            result['metadata']['truncated'] = is_truncated
            result['metadata']['truncation_reason'] = truncation_reason

        generator = ReportGenerator(config)
        report_path = generator.generate([result], output, format)
        console.print(f"[bold green]报告已生成: {report_path}[/bold green]")

        if is_truncated and scan_state_info:
            console.print(f"[bold yellow][!] 警告: 扫描已被截断 ({truncation_reason})，报告仅包含部分结果[/bold yellow]")
            console.print(f"[yellow]  已完成: {scan_state_info['completed']}/{scan_state_info['total']} 文件[/yellow]")
    except Exception as e:
        console.print(f"[bold red]报告生成失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()


def _check_data_preload_status(config) -> None:
    """检查数据预加载状态"""
    from src.integration.data_preloader import DataPreloader

    db_path = Path(config.nvd.database_path)

    if not db_path.exists():
        console.print("[bold yellow]警告: NVD 数据库不存在[/bold yellow]")
        console.print(f"[yellow]数据库路径: {db_path}[/yellow]")
        if click.confirm("是否执行数据预加载 (hos-ls data-preload run)?", default=True):
            console.print("[bold cyan]开始执行数据预加载...[/bold cyan]")
            try:
                preloader = DataPreloader(
                    sources_file=Path(config.data_preload.sources_file),
                    temp_zip_dir=Path(config.data_preload.temp_zip_dir),
                    temp_data_dir=Path(config.data_preload.temp_data_dir),
                    skip_on_checksum_match=config.data_preload.skip_on_checksum_match,
                    merge_strategy=config.data_preload.merge_strategy
                )
                preloader.download_all(parallel=True)
                console.print("[bold green]数据预加载完成[/bold green]")
            except Exception as e:
                console.print(f"[bold red]数据预加载失败: {e}[/bold red]")
                if click.confirm("是否继续扫描（可能影响扫描结果）?", default=False):
                    console.print("[yellow]继续执行扫描...[/yellow]")
                else:
                    sys.exit(1)
        return

    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir),
            skip_on_checksum_match=config.data_preload.skip_on_checksum_match,
            merge_strategy=config.data_preload.merge_strategy
        )
        sources_status = preloader.get_download_status()

        records = sources_status.get("records", [])
        if records:
            latest_record = records[0]
            downloaded_at_str = latest_record.get("downloaded_at")

            if downloaded_at_str:
                try:
                    downloaded_at = datetime.fromisoformat(downloaded_at_str)
                    threshold_days = config.data_preload.update_threshold_days
                    threshold_date = datetime.now() - timedelta(days=threshold_days)

                    if downloaded_at < threshold_date:
                        days_since_update = (datetime.now() - downloaded_at).days
                        console.print(f"[bold yellow]警告: NVD 数据已超过 {days_since_update} 天未更新[/bold yellow]")
                        console.print(f"[yellow]最后更新时间: {downloaded_at.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                        console.print(f"[yellow]建议在 {threshold_days} 天内更新数据[/yellow]")
                        if click.confirm("是否执行数据预加载更新?", default=False):
                            console.print("[bold cyan]开始执行数据预加载...[/bold cyan]")
                            try:
                                preloader.download_all(parallel=True)
                                console.print("[bold green]数据预加载完成[/bold green]")
                            except Exception as e:
                                console.print(f"[bold red]数据预加载失败: {e}[/bold red]")
                                if click.confirm("是否继续扫描?", default=True):
                                    console.print("[yellow]继续执行扫描...[/yellow]")
                                else:
                                    sys.exit(1)
                except Exception:
                    pass
    except Exception as e:
        console.print(f"[yellow]检查数据预加载状态时出错: {e}[/yellow]")
