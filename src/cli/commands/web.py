"""Web GUI 命令组

提供 `hos-ls web` 命令，用于启动 Web GUI 服务器。
"""

import sys
import webbrowser
from typing import Optional

import click
from rich.console import Console

console = Console(emoji=False, force_terminal=True, legacy_windows=False)


@click.command("web")
@click.option("--host", default=None, help="监听地址 (默认: 127.0.0.1)")
@click.option("--port", default=None, type=int, help="监听端口 (默认: 8080)")
@click.option("--open", "open_browser", is_flag=True, help="启动后自动打开浏览器")
@click.option("--dev", is_flag=True, help="开发模式（热重载）")
@click.option("--config", "-c", "config_file", type=click.Path(), help="配置文件路径")
@click.pass_context
def web(
    ctx: click.Context,
    host: Optional[str],
    port: Optional[int],
    open_browser: bool,
    dev: bool,
    config_file: Optional[str],
) -> None:
    """启动 Web GUI 服务器

    示例:
        hos-ls web
        hos-ls web --host 0.0.0.0 --port 3000
        hos-ls web --open
        hos-ls web --dev
    """
    import uvicorn

    # ── 加载配置 ──
    from src.core.config import ConfigManager

    config_manager = ConfigManager()
    if config_file:
        cfg = config_manager.load_from_file(config_file)
    else:
        cfg = config_manager.auto_load()

    # ── CLI 选项覆盖配置 ──
    web_cfg = getattr(cfg, "web", None)

    final_host = host
    final_port = port
    if final_host is None:
        final_host = getattr(web_cfg, "host", "127.0.0.1") if web_cfg else "127.0.0.1"
    if final_port is None:
        final_port = getattr(web_cfg, "port", 8080) if web_cfg else 8080

    # ── Banner ──
    if not cfg.quiet:
        console.print(f"[bold cyan]HOS-LS Web GUI[/bold cyan]")
        console.print(f"  地址: http://{final_host}:{final_port}")
        console.print(f"  开发模式: {'[green]是[/green]' if dev else '[dim]否[/dim]'}")
        console.print(f"  自动打开浏览器: {'[green]是[/green]' if open_browser else '[dim]否[/dim]'}")
        console.print()

    # ── 创建 FastAPI 应用 ──
    from src.web.app import create_app

    app = create_app(config=cfg)

    # ── 自动打开浏览器 ──
    if open_browser:
        url = f"http://{final_host}:{final_port}"
        webbrowser.open(url)

    # ── 启动 uvicorn ──
    uvicorn_config = {
        "app": app,
        "host": final_host,
        "port": final_port,
        "log_level": "debug" if dev else "info",
    }

    if dev:
        uvicorn_config["reload"] = True

    try:
        uvicorn.run(**uvicorn_config)
    except KeyboardInterrupt:
        if not cfg.quiet:
            console.print("\n[yellow]Web 服务器已停止[/yellow]")
        sys.exit(0)
