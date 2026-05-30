from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.live import Live
from typing import Optional, List, Dict, Any


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
