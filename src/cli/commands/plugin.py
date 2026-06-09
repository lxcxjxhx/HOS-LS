"""插件管理命令"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console(emoji=False, force_terminal=True)


@click.group()
def plugin() -> None:
    """插件管理"""
    pass


@plugin.command("list")
@click.pass_context
def list_plugins(ctx: click.Context) -> None:
    """列出已安装的插件"""
    config = ctx.obj.get("config") if ctx.obj else None
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print("[bold cyan]> hosls plugin list[/bold cyan]")

    try:
        from src.plugins.manager import get_plugin_manager

        manager = get_plugin_manager()
        plugins = manager.list_installed()

        if not plugins:
            console.print("[yellow]未安装任何插件[/yellow]")
            return

        table = Table(title="已安装插件")
        table.add_column("名称", style="cyan")
        table.add_column("版本", style="green")
        table.add_column("状态", style="yellow")
        table.add_column("描述")

        for p in plugins:
            name = p.get("name", "unknown")
            version = p.get("version", "0.0.0")
            enabled = p.get("enabled", True)
            description = p.get("description", "")[:50]
            status = "[green]已启用" if enabled else "[dim]已禁用"
            table.add_row(name, version, status, description)

        console.print(table)
        console.print(f"\n[dim]共 {len(plugins)} 个插件[/dim]")

    except ImportError as e:
        console.print(f"[bold red]插件管理器不可用: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]列出插件失败: {e}[/bold red]")
        sys.exit(2)


@plugin.command("install")
@click.argument("name")
@click.option("--version", "-v", default=None, help="指定版本号")
@click.option("--source", "-s", default=None, help="插件源 URL")
@click.pass_context
def install_plugin(ctx: click.Context, name: str, version: Optional[str], source: Optional[str]) -> None:
    """安装插件"""
    config = ctx.obj.get("config") if ctx.obj else None
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print(f"[bold cyan]> hosls plugin install {name}[/bold cyan]")

    try:
        from src.plugins.manager import get_plugin_manager

        manager = get_plugin_manager()

        if not quiet:
            console.print(f"[yellow]正在安装插件 {name}...[/yellow]")

        result = manager.install(name, version=version, source=source)

        if result.get("success"):
            console.print(f"[bold green]插件 {name} 安装成功[/bold green]")
            if result.get("version"):
                console.print(f"[dim]版本: {result['version']}[/dim]")
        else:
            console.print(f"[bold red]安装失败: {result.get('error', '未知错误')}[/bold red]")
            sys.exit(1)

    except ImportError as e:
        console.print(f"[bold red]插件管理器不可用: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]安装插件失败: {e}[/bold red]")
        sys.exit(2)


@plugin.command("remove")
@click.argument("name")
@click.option("--force", "-f", is_flag=True, help="强制删除")
@click.pass_context
def remove_plugin(ctx: click.Context, name: str, force: bool) -> None:
    """删除插件"""
    config = ctx.obj.get("config") if ctx.obj else None
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print(f"[bold cyan]> hosls plugin remove {name}[/bold cyan]")

    try:
        from src.plugins.manager import get_plugin_manager

        manager = get_plugin_manager()

        if not quiet:
            console.print(f"[yellow]正在删除插件 {name}...[/yellow]")

        result = manager.remove(name, force=force)

        if result.get("success"):
            console.print(f"[bold green]插件 {name} 已删除[/bold green]")
        else:
            console.print(f"[bold red]删除失败: {result.get('error', '未知错误')}[/bold red]")
            sys.exit(1)

    except ImportError as e:
        console.print(f"[bold red]插件管理器不可用: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]删除插件失败: {e}[/bold red]")
        sys.exit(2)
