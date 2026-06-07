"""NVD漏洞库管理命令"""

import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console(emoji=False, force_terminal=True)


@click.group()
def nvd() -> None:
    """NVD漏洞库管理命令"""
    pass


@nvd.command()
@click.option("--zip", "-z", type=click.Path(), default="nvd-json-data-feeds-main.zip", help="NVD压缩包路径 (默认: nvd-json-data-feeds-main.zip)")
@click.option("--dir", "-d", type=click.Path(exists=True, file_okay=False, dir_okay=True), help="NVD数据目录路径")
@click.option("--limit", "-l", type=int, default=None, help="限制处理的文件数量 (用于测试)")
@click.option("--no-rag", is_flag=True, help="不导入到RAG库，仅解析")
@click.option("--batch-size", "-b", type=int, default=1000, help="批量处理大小 (默认: 1000)")
@click.option("--resume", type=int, default=0, help="从指定文件开始续传")
@click.option("--model", "-m", default="Qwen/Qwen3-Embedding-0.6B", help="嵌入模型名称 (默认: Qwen/Qwen3-Embedding-0.6B)")
@click.pass_context
def update(ctx, zip, dir, limit, no_rag, batch_size, resume, model) -> None:
    """更新NVD漏洞库，解压并同步到本地RAG库"""
    from src.core.config import Config
    from src.integration.nvd_update import run_update

    config: Config = ctx.obj["config"]
    
    temp_data_base = Path(r"c:\1AAA_PROJECT\HOS\HOS-LS\All Vulnerabilities\temp_data")
    nvd_data_dir = temp_data_base / "nvd-json-data-feeds"

    if dir is None and zip is None:
        if nvd_data_dir.exists() and any(nvd_data_dir.iterdir()):
            input_path = nvd_data_dir
            console.print(f"[bold green]自动检测到数据目录: {input_path}[/bold green]")
        else:
            preloader_zip = temp_data_base / "temp_zip" / "nvd-json-data-feeds-main.zip"
            if preloader_zip.exists():
                input_path = preloader_zip
                console.print(f"[bold green]使用预下载的压缩包: {input_path}[/bold green]")
            else:
                console.print("[bold yellow]未检测到数据源，请先执行 'hos-ls data-preload run' 下载数据[/bold yellow]")
                console.print(f"[dim]或者使用 --dir 参数指定数据目录[/dim]")
                console.print(f"[dim]或者使用 --zip 参数指定压缩包路径[/dim]")
                return

    if dir:
        input_path = Path(dir)
        console.print(f"[bold green]使用目录导入: {input_path}[/bold green]")
    else:
        input_path = Path(zip)
        if not input_path.exists():
            script_dir = Path(__file__).parent.parent.parent
            script_zip = script_dir / zip
            if script_zip.exists():
                input_path = script_zip
            else:
                console.print(f"[bold red]错误: 找不到压缩包: {zip}[/bold red]")
                console.print(f"请确保文件存在于: {input_path.absolute()}")
                return
        console.print(f"[bold green]使用压缩包导入: {input_path}[/bold green]")
    
    rag_base = None
    if not no_rag:
        try:
            from src.storage.rag_knowledge_base import get_rag_knowledge_base
            rag_base = get_rag_knowledge_base(model_name=model)
            console.print(f"[bold green]已连接到RAG知识库，使用模型: {model}[/bold green]")
        except Exception as e:
            console.print(f"[bold yellow]警告: 无法初始化RAG知识库: {e}[/bold yellow]")
            console.print("[bold yellow]将仅解析数据，不导入RAG[/bold yellow]")
    
    console.print("[bold blue]开始更新NVD漏洞库...[/bold blue]")
    
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[progress.description]{task.description}"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[progress.completed]{task.completed}/{task.total}"),
        console=console
    ) as progress:
        phase1 = progress.add_task("[cyan]1/3: 解压和解析数据...", total=100)
        phase2 = progress.add_task("[green]2/3: 生成嵌入向量...", total=100)
        phase3 = progress.add_task("[blue]3/3: 构建知识图谱...", total=100)
        
        from src.cli.commands.report import AsyncWorker
        worker = AsyncWorker(max_workers=4)
        worker.start()
        
        try:
            def progress_callback(phase: str, current: int, total: int):
                if phase == "extract":
                    progress.update(phase1, completed=current, total=total)
                elif phase == "embed":
                    progress.update(phase2, completed=current, total=total)
                elif phase == "graph":
                    progress.update(phase3, completed=current, total=total)
            
            stats = run_update(
                str(input_path),
                rag_base=rag_base,
                limit=limit,
                batch_size=batch_size,
                resume_from=resume,
                progress_callback=progress_callback,
                model_name=model
            )
            
            progress.update(phase1, completed=100, total=100)
            progress.update(phase2, completed=100, total=100)
            progress.update(phase3, completed=100, total=100)
            
        finally:
            worker.stop()
    
    console.print("\n" + "=" * 60)
    console.print("[bold]统计摘要[/bold]")
    console.print("=" * 60)
    for key, value in stats.items():
        console.print(f"  {key}: {value}")


@nvd.command()
@click.pass_context
def show_checkpoint(ctx) -> None:
    """显示当前断点状态"""
    checkpoint_path = Path("nvd_update_checkpoint.json")
    
    if not checkpoint_path.exists():
        console.print("[bold yellow]未找到断点文件[/bold yellow]")
        return
    
    try:
        with open(checkpoint_path, "r", encoding="utf-8") as f:
            checkpoint = json.load(f)
        
        console.print(Panel("[bold blue]断点信息[/bold blue]"))
        
        version = checkpoint.get("version", "1.0")
        last_processed = checkpoint.get("last_processed", 0)
        temp_dir = checkpoint.get("temp_dir")
        current_stage = checkpoint.get("current_stage", "unknown")
        batch_count = checkpoint.get("batch_count", 0)
        stats_checkpoint = checkpoint.get("stats", {})
        stage_progress = checkpoint.get("stage_progress", {})
        timestamp = checkpoint.get("timestamp")
        
        table = Table(title="断点详情")
        table.add_column("项目", style="cyan")
        table.add_column("值", style="green")
        
        table.add_row("版本", version)
        table.add_row("上次处理到文件", str(last_processed))
        table.add_row("当前阶段", current_stage)
        table.add_row("已完成批次", str(batch_count))
        if temp_dir:
            table.add_row("临时目录", temp_dir)
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                table.add_row("保存时间", dt.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception:
                table.add_row("保存时间", timestamp)
        
        console.print(table)
        
        if stats_checkpoint:
            console.print("\n[bold]统计信息:[/bold]")
            stats_table = Table()
            stats_table.add_column("统计项", style="cyan")
            stats_table.add_column("值", style="green")
            for key, value in stats_checkpoint.items():
                stats_table.add_row(str(key), str(value))
            console.print(stats_table)
        
        if stage_progress:
            console.print("\n[bold]阶段进度:[/bold]")
            progress_table = Table()
            progress_table.add_column("阶段", style="cyan")
            progress_table.add_column("状态", style="green")
            progress_table.add_column("进度", style="yellow")
            
            stage_names = {"extract": "解压", "embed": "嵌入", "graph": "图谱构建"}
            
            for stage, info in stage_progress.items():
                stage_name = stage_names.get(stage, stage)
                done = info.get("done", False)
                progress_val = info.get("progress", 0)
                
                status = "✅ 完成" if done else "⏳ 进行中"
                progress_str = str(progress_val) if progress_val else "-"
                
                progress_table.add_row(stage_name, status, progress_str)
            
            console.print(progress_table)
        
    except Exception as e:
        console.print(f"[bold red]读取断点文件失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()


@nvd.command()
@click.option("--force", "-f", is_flag=True, help="强制清理，无需确认")
@click.pass_context
def clean_checkpoints(ctx, force) -> None:
    """清理断点残留文件"""
    files_to_clean = [
        "nvd_update_checkpoint.json",
        "nvd_batch_checkpoint.json",
        "nvd_batch_checkpoint.txt"
    ]
    
    console.print(Panel("[bold red]清理断点残留文件[/bold red]"))
    
    found_files = []
    for filename in files_to_clean:
        file_path = Path(filename)
        if file_path.exists():
            found_files.append(file_path)
    
    found_dirs = []
    for item in Path(".").iterdir():
        if item.is_dir() and item.name.startswith("nvd_update_"):
            found_dirs.append(item)
    
    if not found_files and not found_dirs:
        console.print("[bold green]没有发现断点残留文件[/bold green]")
        return
    
    console.print("\n[bold]发现以下文件/目录将被清理:[/bold]")
    
    if found_files:
        console.print("\n[cyan]文件:[/cyan]")
        for file_path in found_files:
            size = file_path.stat().st_size
            console.print(f"  - {file_path.name} ({size} bytes)")
    
    if found_dirs:
        console.print("\n[cyan]临时目录:[/cyan]")
        for dir_path in found_dirs:
            dir_size = 0
            for f in dir_path.rglob("*"):
                if f.is_file():
                    dir_size += f.stat().st_size
            size_mb = dir_size / (1024 * 1024)
            console.print(f"  - {dir_path.name} ({size_mb:.2f} MB)")
    
    if not force:
        console.print()
        try:
            if not click.confirm("确定要清理以上文件/目录吗？", default=False):
                console.print("[yellow]已取消清理[/yellow]")
                return
        except Exception as e:
            console.print(f"[yellow]无法获取确认，使用 --force 参数强制清理: {e}[/yellow]")
            return
    
    console.print("\n[bold]开始清理...[/bold]")
    
    deleted_count = 0
    
    for file_path in found_files:
        try:
            file_path.unlink()
            console.print(f"  [green][OK][/green] 已删除: {file_path.name}")
            deleted_count += 1
        except Exception as e:
            console.print(f"  [red][FAIL][/red] 删除失败: {file_path.name} - {e}")
    
    for dir_path in found_dirs:
        try:
            shutil.rmtree(dir_path, ignore_errors=True)
            if not dir_path.exists():
                console.print(f"  [green][OK][/green] 已删除: {dir_path.name}")
                deleted_count += 1
            else:
                console.print(f"  [yellow][WARN][/yellow] 目录可能未完全删除: {dir_path.name}")
        except Exception as e:
            console.print(f"  [red][FAIL][/red] 删除失败: {dir_path.name} - {e}")
    
    console.print(f"\n[bold green]清理完成！共删除 {deleted_count} 项[/bold green]")
