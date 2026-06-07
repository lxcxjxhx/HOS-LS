"""会话管理命令"""

import sys
import os
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console(emoji=False, force_terminal=True)


def _get_manager():
    """延迟导入 ChatSessionManager，直接加载模块以避免 __init__.py 的副作用"""
    import importlib.util
    sm_path = os.path.join(os.path.dirname(__file__), "..", "..", "core", "chat", "session_manager.py")
    sm_path = os.path.abspath(sm_path)
    spec = importlib.util.spec_from_file_location("session_manager", sm_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["session_manager"] = mod
    spec.loader.exec_module(mod)
    return mod.ChatSessionManager()


@click.group()
def sessions():
    """管理历史聊天会话"""
    pass


@sessions.command("list")
def list_sessions():
    """列出所有聊天会话"""
    manager = _get_manager()
    sessions_list = manager.list_sessions()

    if not sessions_list:
        console.print(Panel("暂无任何会话记录", title="会话列表", border_style="yellow"))
        return

    table = Table(title=f"聊天会话 (共 {len(sessions_list)} 个)", show_lines=True)
    table.add_column("Session ID", style="cyan", no_wrap=True)
    table.add_column("主题", style="green")
    table.add_column("创建时间", style="magenta")
    table.add_column("消息数", justify="right", style="yellow")
    table.add_column("目标路径", style="blue")

    for s in sessions_list:
        msg_count = len(s.messages)
        table.add_row(
            s.session_id,
            s.topic,
            s.created_at[:19] if s.created_at else "",
            str(msg_count),
            s.target_path or "-",
        )

    console.print(table)


@sessions.command("show")
@click.argument("session_id")
def show_session(session_id: str):
    """查看会话详情"""
    manager = _get_manager()
    session = manager.load_session(session_id)

    if not session:
        console.print(f"[red]错误: 找不到会话 {session_id}[/red]")
        return

    # 元数据面板
    meta_lines = [
        f"[bold]Session ID:[/bold] {session.session_id}",
        f"[bold]主题:[/bold] {session.topic}",
        f"[bold]创建时间:[/bold] {session.created_at[:19]}",
        f"[bold]更新时间:[/bold] {session.updated_at[:19]}",
        f"[bold]目标路径:[/bold] {session.target_path or '-'}",
        f"[bold]消息数:[/bold] {len(session.messages)}",
    ]
    console.print(Panel("\n".join(meta_lines), title="会话元数据", border_style="cyan"))

    # 最近 10 条消息
    recent = session.messages[-10:]
    if recent:
        msg_lines = []
        for msg in recent:
            role_label = "[bold green]User[/bold green]" if msg.role == "user" else "[bold blue]Assistant[/bold blue]"
            msg_lines.append(f"{role_label} ({msg.timestamp[:19]}):")
            msg_lines.append(f"  {msg.content[:200]}{'...' if len(msg.content) > 200 else ''}")
            msg_lines.append("")
        console.print(Panel("\n".join(msg_lines).rstrip(), title="最近对话", border_style="green"))
    else:
        console.print("[yellow]此会话暂无消息[/yellow]")

    # 关联扫描结果
    if session.scan_results:
        console.print(Panel(
            f"发现 {len(session.scan_results)} 个扫描结果",
            title="关联扫描结果",
            border_style="magenta",
        ))


@sessions.command("resume")
@click.argument("session_id")
def resume_session(session_id: str):
    """恢复指定会话并进入聊天界面"""
    manager = _get_manager()
    session = manager.load_session(session_id)

    if not session:
        console.print(f"[red]错误: 找不到会话 {session_id}[/red]")
        return

    console.print(f"[green]已恢复会话: {session.topic} ({session_id})[/green]")
    console.print("[yellow]正在启动聊天界面...[/yellow]")

    # 启动聊天界面（使用主聊天入口）
    from src.core.chat.main import run_chat
    import asyncio
    asyncio.run(run_chat())


@sessions.command("delete")
@click.argument("session_id")
def delete_session(session_id: str):
    """删除指定会话"""
    manager = _get_manager()
    deleted = manager.delete_session(session_id)

    if deleted:
        console.print(f"[green]已删除会话 {session_id}[/green]")
    else:
        console.print(f"[red]错误: 找不到会话 {session_id}[/red]")


@sessions.command("clear")
@click.option("--yes", "-y", is_flag=True, help="跳过确认")
def clear_sessions(yes: bool):
    """清除所有会话"""
    if not yes:
        click.confirm("确定要清除所有会话记录吗? 此操作不可恢复", abort=True)

    manager = _get_manager()
    count = manager.clear_all()
    console.print(f"[green]已清除 {count} 个会话[/green]")
