from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.live import Live
from typing import Optional, List, Dict, Any, ContextManager
from contextlib import contextmanager
import sys


class TerminalUI:
    def __init__(self):
        self.console = Console()
        self._progress: Optional[Progress] = None

    def print_header(self, title: str, subtitle: Optional[str] = None) -> None:
        if subtitle:
            content = f"[bold]{title}[/bold]\n[dim]{subtitle}[/dim]"
        else:
            content = f"[bold]{title}[/bold]"
        self.console.print(Panel(content, border_style="cyan"))

    def print_success(self, message: str) -> None:
        self.console.print(f"[bold green]✔ {message}[/bold green]")

    def print_error(self, message: str) -> None:
        self.console.print(f"[bold red]✘ {message}[/bold red]")

    def print_warning(self, message: str) -> None:
        self.console.print(f"[bold yellow]⚠ {message}[/bold yellow]")

    def print_info(self, message: str) -> None:
        self.console.print(f"[bold blue]ℹ {message}[/bold blue]")

    def print_code(self, code: str, language: str = "python") -> None:
        syntax = Syntax(code, language, theme="monokai", line_numbers=True)
        self.console.print(Panel(syntax, title=f"[cyan]{language.upper()}[/cyan]", border_style="dim"))

    def print_markdown(self, markdown_text: str) -> None:
        md = Markdown(markdown_text)
        self.console.print(md)

    def print_table(self, headers: List[str], rows: List[List[str]], title: Optional[str] = None) -> None:
        table = Table(title=title, show_header=True, header_style="bold cyan")
        for header in headers:
            table.add_column(header, style="white")
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        self.console.print(table)

    def print_findings_table(self, findings: List[Dict[str, Any]]) -> None:
        if not findings:
            self.print_info("未发现安全问题")
            return
        table = Table(title="安全发现", show_header=True, header_style="bold red")
        table.add_column("严重级别", style="cyan")
        table.add_column("规则", style="white")
        table.add_column("文件", style="white")
        table.add_column("描述", style="white")
        for finding in findings:
            severity = finding.get("severity", "unknown")
            severity_style = "red" if severity in ["critical", "high"] else "yellow" if severity == "medium" else "blue"
            table.add_row(
                f"[{severity_style}]{severity}[/{severity_style}]",
                finding.get("rule_name", "N/A"),
                finding.get("file", "N/A"),
                finding.get("message", "N/A")[:60]
            )
        self.console.print(table)

    def print_scan_progress(self, current: int, total: int, file_name: str, status: str) -> None:
        percentage = (current / total * 100) if total > 0 else 0
        bar_length = 30
        filled = int(bar_length * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_length - filled)
        self.console.print(
            f"[cyan]{bar}[/cyan] [yellow]{percentage:.1f}%[/yellow] "
            f"[white]{current}/{total}[/white] [dim]{file_name}[/dim] [green]{status}[/green]"
        )

    def start_progress(self, description: str, total: int) -> Progress:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[progress.completed]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=self.console
        )
        progress.start()
        task_id = progress.add_task(f"[cyan]{description}[/cyan]", total=total)
        return progress

    def update_progress(self, progress: Progress, task_id: int, advance: int = 1, **kwargs) -> None:
        progress.update(task_id, advance=advance, **kwargs)

    def stop_progress(self, progress: Progress) -> None:
        progress.stop()

    def print_chat_message(self, role: str, message: str, timestamp: Optional[str] = None) -> None:
        role_colors = {
            "user": "blue",
            "assistant": "green",
            "system": "yellow",
            "agent": "magenta"
        }
        color = role_colors.get(role.lower(), "white")
        if timestamp:
            self.console.print(f"[dim]{timestamp}[/dim] [bold {color}]{role}[/bold {color}]: {message}")
        else:
            self.console.print(f"[bold {color}]{role}[/bold {color}]: {message}")

    def print_agent_status(self, agent_name: str, status: str, details: Optional[str] = None) -> None:
        status_colors = {
            "running": "yellow",
            "completed": "green",
            "failed": "red",
            "pending": "dim"
        }
        color = status_colors.get(status.lower(), "white")
        if details:
            self.console.print(f"[bold cyan]{agent_name}[/bold cyan] [bold {color}]{status}[/bold {color}] - [dim]{details}[/dim]")
        else:
            self.console.print(f"[bold cyan]{agent_name}[/bold cyan] [bold {color}]{status}[/bold {color}]")

    def get_prompt(self, session_id: str = "", session_topic: str = "", context_hint: str = "") -> str:
        parts = ["[bold cyan]HOS-LS[/bold cyan]"]
        session_parts = []
        if session_id:
            session_parts.append(f"session: {session_id}")
        if session_topic:
            session_parts.append(f"topic: {session_topic}")
        if session_parts:
            parts.append(f"[dim]({' | '.join(session_parts)})[/dim]")
        parts.append("> ")
        if context_hint:
            parts.append(f"[dim gray]{context_hint}[/dim gray]")
        return " ".join(parts)

    def print_typing_animation(self, text: str, speed: int = 50, skip_on_key: bool = True) -> None:
        import time

        skip_animation = False

        def _check_key_pressed():
            if sys.platform == "win32":
                try:
                    import msvcrt
                    if msvcrt.kbhit():
                        msvcrt.getch()
                        return True
                except ImportError:
                    pass
            else:
                try:
                    import select
                    if select.select([sys.stdin], [], [], 0)[0]:
                        sys.stdin.read(1)
                        return True
                except (ImportError, ValueError):
                    pass
            return False

        in_code_block = False
        code_buffer = ""
        current_pos = 0

        try:
            while current_pos < len(text):
                if skip_on_key and _check_key_pressed():
                    skip_animation = True

                # Detect code block markers
                if text[current_pos:current_pos+3] == "```":
                    if in_code_block:
                        in_code_block = False
                        # Print accumulated code at once
                        self.console.print(Syntax(code_buffer, "auto", theme="monokai"))
                        code_buffer = ""
                        current_pos += 3
                        continue
                    else:
                        in_code_block = True
                        self.console.print("```")
                        current_pos += 3
                        continue

                if in_code_block:
                    # Collect code block content
                    end_marker = text.find("```", current_pos)
                    if end_marker != -1:
                        code_buffer = text[current_pos:end_marker]
                        current_pos = end_marker
                    else:
                        code_buffer = text[current_pos:]
                        current_pos = len(text)
                    continue

                # Print character by character
                char = text[current_pos]
                self.console.print(char, end="")
                self.console.file.flush()
                current_pos += 1

                if not skip_animation:
                    delay = 1.0 / speed
                    time.sleep(delay)

            # Print remaining code buffer if ended in code block
            if code_buffer:
                self.console.print(Syntax(code_buffer, "auto", theme="monokai"))

            self.console.print()

        except KeyboardInterrupt:
            # Print remaining text immediately
            self.console.print(text[current_pos:])
            self.console.print()

    @contextmanager
    def show_thinking_spinner(self, message: str = "思考中...") -> ContextManager:
        with Live(
            f"[dim yellow]⏳[/dim yellow] {message}",
            console=self.console,
            refresh_per_second=10,
            transient=True
        ) as live:
            try:
                yield live
            except KeyboardInterrupt:
                pass

    def print_quick_actions(self, actions: List[str]) -> None:
        action_strs = "  ".join(f"[dim]{a}[/dim]" for a in actions)
        self.console.print(f"[dim gray]快捷操作:[/dim gray] {action_strs}")

    def print_context_hint(self, hint: str) -> None:
        self.console.print(f"  [dim yellow]💡 {hint}[/dim yellow]")

    def print_live_progress(
        self, current: int, total: int, file_name: str,
        findings_count: int, elapsed: float
    ) -> None:
        percentage = (current / total * 100) if total > 0 else 0
        bar_length = 30
        filled = int(bar_length * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_length - filled)

        self.console.print(
            f"[cyan]{bar}[/cyan] [yellow]{percentage:.1f}%[/yellow] "
            f"[white]{current}/{total}[/white] | "
            f"[dim]{file_name}[/dim] | "
            f"[bold magenta]发现: {findings_count}[/bold magenta] | "
            f"[dim]{elapsed:.1f}s[/dim]"
        )

    def print_scan_summary_panel(
        self, total: int, critical: int, high: int, medium: int,
        low: int, info: int, elapsed: float, files_scanned: int
    ) -> None:
        severity_colors = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "blue",
            "Info": "dim"
        }
        counts = {
            "Critical": critical,
            "High": high,
            "Medium": medium,
            "Low": low,
            "Info": info
        }

        lines = [f"[bold green]✓ 扫描完成[/bold green]  [dim]共 {total} 个问题, 扫描 {files_scanned} 个文件, 耗时 {elapsed:.2f}s[/dim]\n"]
        for sev, count in counts.items():
            color = severity_colors.get(sev, "white")
            lines.append(f"  [{color}]{sev:>8}[/][{color}]: {count}[/{color}]")

        content = "\n".join(lines)
        self.console.print(Panel(content, border_style="green", title="[bold]扫描摘要[/bold]"))

    def print_finding_alert(self, severity: str, rule: str, file_path: str, line: int) -> None:
        if severity in ("critical", "high"):
            color = "bold red"
            icon = "⚡"
        elif severity == "medium":
            color = "bold yellow"
            icon = "⚠"
        else:
            color = "bold blue"
            icon = "ℹ"

        self.console.print(
            f"  [{color}]{icon} NEW FINDING[/{color}] [{severity.upper()}] {rule} at {file_path}:{line}"
        )
