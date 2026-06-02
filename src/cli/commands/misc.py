"""其他杂项命令"""

import sys
import os
import time
import re
from pathlib import Path
from datetime import datetime as dt
from typing import Optional
from dataclasses import asdict

import click
from rich.console import Console
from rich.panel import Panel

console = Console(emoji=False, force_terminal=True)


@click.command()
@click.pass_context
def panel(ctx: click.Context) -> None:
    """启动交互式配置面板"""
    try:
        from .panel import ConfigPanel

        cfg = ctx.obj["config"]
        config_dict = {
            "debug": cfg.debug,
            "verbose": cfg.verbose,
            "quiet": cfg.quiet,
            "test_mode": cfg.test_mode,
            "filter_hallucinations": cfg.filter_hallucinations,
            "language": cfg.language,
            "ai": {
                "provider": cfg.ai.provider,
                "model": cfg.ai.model,
                "max_tokens": cfg.ai.max_tokens,
                "temperature": cfg.ai.temperature,
            },
            "scan": {
                "max_workers": cfg.scan.max_workers,
                "incremental": cfg.scan.incremental,
                "cache_enabled": cfg.scan.cache_enabled,
            },
            "validation": {
                "line_number_tolerance": cfg.validation.line_number_tolerance,
                "min_confidence_threshold": cfg.validation.min_confidence_threshold,
            },
        }

        config_panel = ConfigPanel(config_dict)

        def get_key():
            if os.name == 'nt':
                import msvcrt
                char = msvcrt.getch()
                if char == b'\xe0':
                    char = msvcrt.getch()
                    if char == b'H':
                        return "up"
                    elif char == b'P':
                        return "down"
                    elif char == b'M':
                        return "right"
                    elif char == b'K':
                        return "left"
                elif char == b'\r':
                    return "enter"
                elif char == b' ':
                    return "space"
                elif char == b'\x08':
                    return "backspace"
                elif char == b'\x1b':
                    return "esc"
                elif char == b'\t':
                    return "tab"
                elif char in (b'q', b'Q'):
                    return "quit"
            return None

        console.print("[yellow]交互式配置面板正在启动...[/yellow]")
        console.print("[yellow]请使用方向键导航，Space/Tab 切换选项，Q 退出[/yellow]")

        result = config_panel.run()

        if config_panel.is_modified():
            console.print("[green]配置已修改[/green]")
        else:
            console.print("[dim]未修改配置[/dim]")

    except ImportError as e:
        console.print(f"[red]无法导入面板模块: {e}[/red]")
        console.print("[yellow]提示: 交互式面板需要 curses/msvcrt 支持[/yellow]")


@click.command()
@click.pass_context
def serial(ctx: click.Context) -> None:
    """启动交互式串口工具"""
    try:
        from .serial_port import SerialPortPanel, SerialManager

        if not SerialManager.is_available():
            console.print("[red]错误: pyserial 库未安装[/red]")
            console.print("[yellow]请运行: pip install pyserial[/yellow]")
            return

        console.print("[yellow]交互式串口工具正在启动...[/yellow]")
        console.print("[yellow]按 Q 退出，C 连接/D 断开，S 扫描串口，T 切换 HEX/ASCII[/yellow]")

        serial_panel = SerialPortPanel()
        serial_panel.run()

    except ImportError as e:
        console.print(f"[red]无法导入串口模块: {e}[/red]")
        console.print("[yellow]提示: 串口工具需要 pyserial 支持[/yellow]")
    except Exception as e:
        console.print(f"[red]串口工具启动失败: {e}[/red]")


@click.command()
@click.pass_context
def chat(ctx: click.Context) -> None:
    """启动交互式安全对话中心"""
    config = ctx.obj["config"]

    if not config.quiet:
        console.print(Panel(
            "[bold]HOS-LS 安全对话中心[/bold]\n"
            "[dim]自然语言交互 · Multi-Agent · 智能分析[/dim]",
            border_style="cyan",
        ))
        console.print("[dim]输入 /help 查看可用命令[/dim]\n")

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


@click.command()
@click.pass_context
def rules(ctx: click.Context) -> None:
    """列出可用规则"""
    from src.rules.registry import get_registry

    cfg = ctx.obj["config"]
    registry = get_registry()

    registry.load_builtin_rules()

    stats = registry.get_statistics()

    console.print(Panel(f"[bold]规则统计[/bold]\n总计: {stats['total']}, 启用: {stats['enabled']}, 禁用: {stats['disabled']}"))

    if stats["by_category"]:
        from rich.table import Table
        table = Table(title="按类别统计")
        table.add_column("类别", style="cyan")
        table.add_column("数量", style="green")
        for category, count in stats["by_category"].items():
            table.add_row(category, str(count))
        console.print(table)

    if stats["by_severity"]:
        from rich.table import Table
        table = Table(title="按严重级别统计")
        table.add_column("严重级别", style="cyan")
        table.add_column("数量", style="green")
        for severity, count in stats["by_severity"].items():
            table.add_row(severity, str(count))
        console.print(table)


@click.command()
def init() -> None:
    """初始化配置文件"""
    from src.core.config import ConfigManager

    config_path = Path.home() / ".hos-ls" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config_manager = ConfigManager()
    config_manager.save_to_file(config_path)

    console.print(f"[bold green]配置文件已创建: {config_path}[/bold green]")


@click.command()
@click.argument('cache_file', type=click.Path(exists=True))
@click.option('-o', '--output', 'output_file', default=None, help='输出报告路径')
@click.option('-f', '--format', 'report_format', default='html', type=click.Choice(['html', 'json', 'markdown']), help='报告格式')
@click.option('--show-progress', is_flag=True, default=False, help='显示扫描进度')
def import_scan(cache_file: str, output_file: str, report_format: str, show_progress: bool) -> None:
    """从扫描缓存导入结果并生成报告"""
    from src.core.scan_cache import get_scan_cache_manager
    from src.core.engine import ScanResult, Finding, Location, Severity, ScanStatus
    from src.reporting.generator import ReportGenerator

    console.print(f"[bold cyan]正在导入扫描缓存: {cache_file}[/bold cyan]")

    cache_manager = get_scan_cache_manager()
    session = cache_manager.import_session(cache_file)

    if not session:
        console.print(f"[bold red]导入失败: 无法读取缓存文件[/bold red]")
        return

    console.print(f"[green]会话ID: {session.session_id}[/green]")
    console.print(f"[green]目标: {session.target}[/green]")
    console.print(f"[green]开始时间: {session.start_time}[/green]")
    console.print(f"[green]已完成文件: {session.progress.completed_files}/{session.progress.total_files}[/green]")
    console.print(f"[green]发现漏洞: {len(session.results)}[/green]")

    if session.progress.completed_files == 0:
        console.print(f"[bold yellow]警告: 缓存中没有扫描结果[/bold yellow]")
        return

    findings = []
    for result in session.results:
        result_dict = result if isinstance(result, dict) else asdict(result) if hasattr(result, '__dataclass_fields__') else {}
        file_path = result.get('file_path', '') if isinstance(result, dict) else getattr(result, 'file_path', '')
        
        for vuln in result_dict.get('vulnerabilities', []):
            try:
                location_dict = vuln.get('location', {}) if isinstance(vuln, dict) else {}
                location = Location(
                    file=str(location_dict.get('file', file_path)),
                    line=location_dict.get('line', 0),
                    column=location_dict.get('column', 0),
                    end_line=location_dict.get('end_line', 0),
                    end_column=location_dict.get('end_column', 0)
                )
                
                severity_str = vuln.get('severity', 'info') if isinstance(vuln, dict) else getattr(vuln, 'severity', 'info')
                if isinstance(severity_str, str):
                    severity_str = severity_str.upper() if severity_str.upper() in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] else severity_str.lower()
                    severity_str = severity_str.capitalize() if severity_str.lower() in ['critical', 'high', 'medium', 'low', 'info'] else 'Info'
                    severity = Severity(severity_str.lower()) if severity_str.lower() in ['critical', 'high', 'medium', 'low', 'info'] else Severity.INFO
                else:
                    severity = Severity.INFO
                
                finding = Finding(
                    rule_id=vuln.get('rule_id', 'UNKNOWN') if isinstance(vuln, dict) else getattr(vuln, 'rule_id', 'UNKNOWN'),
                    rule_name=vuln.get('rule_name', vuln.get('title', 'Unknown')) if isinstance(vuln, dict) else getattr(vuln, 'rule_name', getattr(vuln, 'title', 'Unknown')),
                    description=vuln.get('description', '') if isinstance(vuln, dict) else getattr(vuln, 'description', ''),
                    severity=severity,
                    location=location,
                    confidence=vuln.get('confidence', 0.5) if isinstance(vuln, dict) else getattr(vuln, 'confidence', 0.5),
                    message=vuln.get('message', vuln.get('description', '')) if isinstance(vuln, dict) else getattr(vuln, 'message', getattr(vuln, 'description', '')),
                    code_snippet=vuln.get('code_snippet', '') if isinstance(vuln, dict) else getattr(vuln, 'code_snippet', ''),
                    fix_suggestion=vuln.get('fix_suggestion', '') if isinstance(vuln, dict) else getattr(vuln, 'fix_suggestion', ''),
                    metadata=vuln.get('metadata', {}) if isinstance(vuln, dict) else getattr(vuln, 'metadata', {}),
                    references=vuln.get('references', []) if isinstance(vuln, dict) else getattr(vuln, 'references', [])
                )
                findings.append(finding)
            except Exception as e:
                if console:
                    console.print(f"[yellow]跳过无效漏洞数据: {e}[/yellow]")

    console.print(f"[green]共 {len(findings)} 个漏洞[/green]")

    if output_file is None:
        timestamp = dt.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"report_{session.session_id}_{timestamp}.{report_format}"

    metadata = {
        'target': session.target,
        'scan_type': 'imported',
        'session_id': session.session_id,
        'start_time': session.start_time,
        'end_time': session.last_update,
        'total_files': session.progress.total_files,
        'completed_files': session.progress.completed_files,
        'total_vulnerabilities': len(findings),
        'truncated': session.progress.completed_files < session.progress.total_files,
        'truncation_reason': 'partial_scan' if session.progress.completed_files < session.progress.total_files else None
    }

    scan_result = ScanResult(
        target=session.target,
        status=ScanStatus.COMPLETED,
        start_time=dt.fromisoformat(session.start_time) if isinstance(session.start_time, str) else session.start_time,
        findings=findings,
        metadata=metadata
    )

    generator = ReportGenerator()
    try:
        report_path = generator.generate([scan_result], output_file, report_format)
        console.print(f"[bold green]报告已生成: {report_path}[/bold green]")

        if session.progress.completed_files < session.progress.total_files:
            console.print(f"[bold yellow]注意: 此为部分扫描报告 ({session.progress.completed_files}/{session.progress.total_files})[/bold yellow]")
            console.print(f"[yellow]如需完成扫描，请运行: hos-ls scan {session.target} --resume --session-id {session.session_id}[/yellow]")
    except Exception as e:
        console.print(f"[bold red]报告生成失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()


@click.command()
@click.argument('log_file', type=click.Path(exists=True))
@click.option('-s', '--speed', default=1.0, help='重放速度倍数 (0.5=半速, 2.0=2倍速)')
@click.option('-c', '--color/--no-color', default=True, help='是否启用彩色输出')
def replay(log_file: str, speed: float, color: bool) -> None:
    """重放扫描日志文件，便于演示"""
    log_path = Path(log_file)
    if not log_path.exists():
        console.print(f"[bold red]错误: 日志文件不存在: {log_file}[/bold red]")
        return
    
    console.print(f"[bold cyan]重放日志: {log_path.name}[/bold cyan]")
    console.print(f"[dim]速度: {speed}x[/dim]")
    console.print("-" * 60)
    
    ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')
    PROGRESS_PATTERN = re.compile(r'[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]')
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        
        last_line_was_progress = False
        
        for line in lines:
            line = line.rstrip('\n\r')
            
            is_progress = bool(PROGRESS_PATTERN.search(line))
            
            if is_progress:
                if last_line_was_progress:
                    sys.stdout.write('\r' + ' ' * 100 + '\r')
                sys.stdout.write('\r' + line)
                sys.stdout.flush()
                last_line_was_progress = True
                time.sleep(0.05 / speed)
            else:
                if last_line_was_progress:
                    sys.stdout.write('\r' + ' ' * 100 + '\r')
                    sys.stdout.write('\n')
                    last_line_was_progress = False
                
                if color:
                    colored_line = line
                    colored_line = re.sub(r'\[DEBUG\]', '[dim cyan][DEBUG][/dim cyan]', colored_line)
                    colored_line = re.sub(r'\[INFO\]', '[cyan][INFO][/cyan]', colored_line)
                    colored_line = re.sub(r'\[WARN\]', '[bold yellow][WARN][/bold yellow]', colored_line)
                    colored_line = re.sub(r'\[ERROR\]', '[bold red][ERROR][/bold red]', colored_line)
                    colored_line = re.sub(r'\[OK\]', '[bold green][OK][/bold green]', colored_line)
                    colored_line = re.sub(r'\[CRITICAL\]', '[bold red blink][CRITICAL][/bold red blink]', colored_line)
                    colored_line = re.sub(r'\[TOKEN\]', '[magenta][TOKEN][/magenta]', colored_line)
                    colored_line = re.sub(r'\[CACHE\]', '[blue][CACHE][/blue]', colored_line)
                    colored_line = re.sub(r'\[PURE-AI\]', '[green][PURE-AI][/green]', colored_line)
                    
                    if colored_line != line:
                        console.print(colored_line)
                    else:
                        print(line)
                else:
                    clean_line = ANSI_ESCAPE.sub('', line)
                    print(clean_line)
                
                time.sleep(0.02 / speed)
        
        if last_line_was_progress:
            sys.stdout.write('\n')
        
        console.print("-" * 60)
        console.print(f"[bold green]日志重放完成[/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]重放已中断[/yellow]")
    except Exception as e:
        console.print(f"[bold red]重放失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()
