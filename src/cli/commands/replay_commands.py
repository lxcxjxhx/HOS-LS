"""日志重放命令"""
import re
import sys
import time
from pathlib import Path

import click
from rich.console import Console

from src.cli.main import cli

console = Console()


@cli.command()
@click.argument("log_file", type=click.Path(exists=True))
@click.option("-s", "--speed", default=1.0, help="重放速度倍数")
@click.option("-c", "--color/--no-color", default=True, help="是否启用彩色输出")
def replay(log_file: str, speed: float, color: bool) -> None:
    """重放扫描日志文件，便于演示"""
    log_path = Path(log_file)
    if not log_path.exists():
        console.print(f"[bold red]错误: 日志文件不存在: {log_file}[/bold red]")
        return
    console.print(f"[bold cyan]重放日志: {log_path.name}[/bold cyan]")
    console.print(f"[dim]速度: {speed}x[/dim]")
    console.print("-" * 60)
    ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
    PROGRESS_PATTERN = re.compile(r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]")
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        last_line_was_progress = False
        for line in lines:
            line = line.rstrip("\n\r")
            is_progress = bool(PROGRESS_PATTERN.search(line))
            if is_progress:
                if last_line_was_progress:
                    sys.stdout.write("\r" + " " * 100 + "\r")
                sys.stdout.write("\r" + line)
                sys.stdout.flush()
                last_line_was_progress = True
                time.sleep(0.05 / speed)
            else:
                if last_line_was_progress:
                    sys.stdout.write("\r" + " " * 100 + "\r")
                    sys.stdout.write("\n")
                    last_line_was_progress = False
                if color:
                    colored_line = line
                    colored_line = re.sub(r"\[DEBUG\]", "[dim cyan][DEBUG][/dim cyan]", colored_line)
                    colored_line = re.sub(r"\[INFO\]", "[cyan][INFO][/cyan]", colored_line)
                    colored_line = re.sub(r"\[WARN\]", "[bold yellow][WARN][/bold yellow]", colored_line)
                    colored_line = re.sub(r"\[ERROR\]", "[bold red][ERROR][/bold red]", colored_line)
                    colored_line = re.sub(r"\[OK\]", "[bold green][OK][/bold green]", colored_line)
                    colored_line = re.sub(r"\[CRITICAL\]", "[bold red blink][CRITICAL][/bold red blink]", colored_line)
                    colored_line = re.sub(r"\[TOKEN\]", "[magenta][TOKEN][/magenta]", colored_line)
                    colored_line = re.sub(r"\[CACHE\]", "[blue][CACHE][/blue]", colored_line)
                    colored_line = re.sub(r"\[PURE-AI\]", "[green][PURE-AI][/green]", colored_line)
                    if colored_line != line:
                        console.print(colored_line)
                    else:
                        print(line)
                else:
                    clean_line = ANSI_ESCAPE.sub("", line)
                    print(clean_line)
                time.sleep(0.02 / speed)
        if last_line_was_progress:
            sys.stdout.write("\n")
        console.print("-" * 60)
        console.print("[bold green]日志重放完成[/bold green]")
    except KeyboardInterrupt:
        console.print("\n[yellow]重放已中断[/yellow]")
    except Exception as e:
        console.print(f"[bold red]重放失败: {e}[/bold red]")
        import traceback; traceback.print_exc()