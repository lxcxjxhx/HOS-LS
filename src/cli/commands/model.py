"""模型管理命令"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console(emoji=False, force_terminal=True)


@click.group()
def model() -> None:
    """模型管理命令"""
    pass


@model.command()
@click.option("--model", "-m", default="Qwen/Qwen3-Embedding-0.6B", help="模型名称 (默认: Qwen/Qwen3-Embedding-0.6B)")
@click.option("--output", "-o", type=click.Path(), help="输出目录")
@click.option("--force", is_flag=True, help="强制覆盖现有模型")
@click.option("--token", "-t", required=True, help="Hugging Face 登录 token")
@click.pass_context
def download(ctx, model, output, force, token) -> None:
    """下载模型"""
    from src.core.config import Config
    
    config: Config = ctx.obj["config"]
    
    console.print(f"[bold blue]开始下载模型: {model}[/bold blue]")
    
    if not output:
        model_cache = Path.home() / ".cache" / "huggingface" / "hub"
        model_dir_name = f"models--{model.replace('/', '--')}"
        output = model_cache / model_dir_name
    else:
        output = Path(output)
    
    output.mkdir(parents=True, exist_ok=True)
    console.print(f"[info]模型将保存到: {output}[/info]")
    
    try:
        from huggingface_hub import snapshot_download
        
        with Progress(
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]下载模型...", total=100)
            
            console.print("[info]开始下载，这可能需要几分钟时间...[/info]")
            result = snapshot_download(
                repo_id=model,
                local_dir=output,
                force_download=force,
                token=token
            )
            
            progress.update(task, completed=100)
        
        console.print(f"[bold green]模型下载成功: {model}[/bold green]")
        console.print(f"[info]模型保存位置: {result}[/info]")
        
    except Exception as e:
        console.print(f"[bold red]下载失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)
