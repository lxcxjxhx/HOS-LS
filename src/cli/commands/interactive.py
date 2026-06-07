"""交互式模式命令"""

import sys
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

console = Console(emoji=False, force_terminal=True)


@click.command()
@click.option("--mode", "-m", type=click.Choice(["terminal", "web"], case_sensitive=False),
              default="terminal", help="交互模式: terminal(终端), web(网页)")
@click.option("--port", "-p", type=int, default=8080, help="Web 模式端口号")
@click.pass_context
def interactive(ctx: click.Context, mode: str, port: int) -> None:
    """启动交互式安全问答界面"""
    config = ctx.obj.get("config") if ctx.obj else None
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print(Panel(
            "[bold]HOS-LS 交互模式[/bold]\n"
            f"[dim]模式: {mode} | 端口: {port}[/dim]\n"
            "[dim]支持: AI安全问答 · 代码分析 · 攻击链解释 · 知识库检索[/dim]",
            border_style="cyan",
        ))

    if mode == "terminal":
        _run_terminal_mode(config, quiet)
    elif mode == "web":
        _run_web_mode(config, port, quiet)


def _run_terminal_mode(config, quiet: bool) -> None:
    """运行终端交互模式（优先使用chat命令作为fallback）"""
    if not quiet:
        console.print("[yellow]正在启动终端交互模式...[/yellow]")

    # 优先尝试Textual TUI
    try:
        from src.tui.app import run_tui
        run_tui(config)
        return
    except ImportError:
        pass

    # 回退到现有chat命令
    console.print("[yellow]Textual TUI 未安装，使用标准对话模式[/yellow]")
    console.print("[dim]提示: 安装 Textual 可获得更好的交互体验: pip install textual[/dim]")
    try:
        from src.core.chat.main import run_chat
        import asyncio
        asyncio.run(run_chat(config))
    except ImportError as e:
        console.print(f"[bold red]对话功能不可用: {e}[/bold red]")
        console.print("[yellow]请确保已安装所有依赖[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]启动对话失败: {e}[/bold red]")
        sys.exit(1)


def _run_web_mode(config, port: int, quiet: bool) -> None:
    """运行 Web 交互模式（NiceGUI备选方案）"""
    if not quiet:
        console.print(f"[yellow]正在启动 Web 交互模式 (端口: {port})...[/yellow]")

    # 尝试NiceGUI
    try:
        from src.interactive.web_gui import run_web_gui
        run_web_gui(config, port=port)
        return
    except (ImportError, AttributeError):
        pass

    console.print("[bold red]Web 界面不可用[/bold red]")
    console.print("[yellow]提示: Web 模式需要 NiceGUI: pip install nicegui[/yellow]")
    console.print("[yellow]或使用终端模式: hosls interactive --mode terminal[/yellow]")
    sys.exit(1)
