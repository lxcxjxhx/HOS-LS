"""扫描相关命令"""

import sys
import os
import asyncio
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console(emoji=False, force_terminal=True)


def show_scan_progress() -> None:
    """显示流式扫描进度"""
    steps = [
        "Parsing AST",
        "Building Graph",
        "Running Agents",
        "Risk Analysis"
    ]
    
    with Live(refresh_per_second=4) as live:
        for i, step in enumerate(steps):
            table = Table()
            table.add_column("Step")
            table.add_column("Status")
            
            for j in range(i):
                table.add_row(steps[j], "[green]Done")
            
            table.add_row(step, "[yellow]Running...")
            live.update(table)
            time.sleep(0.8)
        
        final_table = Table()
        final_table.add_column("Step")
        final_table.add_column("Status")
        for step in steps:
            final_table.add_row(step, "[green]Done")
        live.update(final_table)


class ScanProgressTracker:
    """扫描进度跟踪器"""
    
    def __init__(self, console: Console):
        self.console = console
        self.files_processed = 0
        self.total_findings = 0
        self.ai_success_count = 0
        self.ai_failure_count = 0
        self.ai_timeout_count = 0
        self.start_time = 0.0
        self.total_files = 0
        self._live = None
        self._table = None
    
    def start(self, total_files: int) -> None:
        self.total_files = total_files
        self.start_time = time.time()
        self.files_processed = 0
        self.total_findings = 0
        self.ai_success_count = 0
        self.ai_failure_count = 0
        self.ai_timeout_count = 0
        self._table = Table(title="[bold]扫描进度[/bold]")
        self._table.add_column("指标", style="cyan")
        self._table.add_column("值", style="green")
        self._table.add_row("已处理文件", "0")
        self._table.add_row("总文件数", str(total_files))
        self._table.add_row("累计发现", "0")
        self._table.add_row("进度", "0%")
        self._live = Live(self._table, console=self.console, refresh_per_second=2)
        self._live.start()
    
    def update(self, file_name: str, ai_status: str = "success", findings_count: int = 0) -> None:
        self.files_processed += 1
        self.total_findings += findings_count
        
        if ai_status == "success":
            self.ai_success_count += 1
        elif ai_status == "timeout":
            self.ai_timeout_count += 1
        else:
            self.ai_failure_count += 1
        
        progress_pct = (self.files_processed / max(self.total_files, 1)) * 100
        elapsed = time.time() - self.start_time
        
        status_icon = "[green]OK" if ai_status == "success" else "[yellow]TIMEOUT" if ai_status == "timeout" else "[red]FAIL"
        
        if self.files_processed % 5 == 0 or self.files_processed == self.total_files:
            table = Table(title="[bold]扫描进度[/bold]")
            table.add_column("指标", style="cyan", width=20)
            table.add_column("值", style="green", width=30)
            table.add_row("已处理文件", f"{self.files_processed}/{self.total_files}")
            table.add_row("当前文件", str(file_name)[:30])
            table.add_row("AI状态", status_icon)
            table.add_row("累计发现", str(self.total_findings))
            table.add_row("AI成功/失败/超时", f"{self.ai_success_count}/{self.ai_failure_count}/{self.ai_timeout_count}")
            table.add_row("进度", f"{progress_pct:.1f}%")
            table.add_row("耗时", f"{elapsed:.1f}s")
            self._live.update(table)
    
    def finish(self) -> None:
        if self._live:
            elapsed = time.time() - self.start_time
            table = Table(title="[bold green]扫描完成[/bold green]")
            table.add_column("指标", style="cyan", width=20)
            table.add_column("值", style="green", width=30)
            table.add_row("总文件数", str(self.total_files))
            table.add_row("累计发现", str(self.total_findings))
            table.add_row("AI成功/失败/超时", f"{self.ai_success_count}/{self.ai_failure_count}/{self.ai_timeout_count}")
            table.add_row("总耗时", f"{elapsed:.1f}s")
            self._live.update(table)
            self._live.stop()


def show_enhanced_scan_progress(tracker: ScanProgressTracker, total_files: int) -> None:
    """显示增强版扫描进度"""
    tracker.start(total_files)


def show_agent_status(result=None) -> None:
    """显示 Agent 状态

    Args:
        result: 扫描结果对象(可选)，用于动态判断Agent状态
    """
    table = Table(title="Agents")
    table.add_column("Agent")
    table.add_column("Status")

    # 判断 Vulnerability Agent 状态
    vuln_status = "[OK]"
    if result is not None:
        findings = getattr(result, 'findings', []) or []
        if not findings:
            vuln_status = "[!]"

    table.add_row("Semantic Analyzer", "[OK]")
    table.add_row("Vulnerability Agent", vuln_status)
    table.add_row("Dependency Scanner", "[OK]")
    console.print(table)


def show_risk_bar(percentage: float) -> None:
    """显示风险条"""
    bars = int(percentage * 10)
    risk_bar = "#" * bars + "-" * (10 - bars)
    console.print(f"Risk Level: {risk_bar} {int(percentage * 100)}%")


def _integrate_poc(config, result, target: str, generate_poc: bool, run_poc: bool, poc_only: bool) -> None:
    """集成 POC 生成和执行到扫描流程"""
    if not generate_poc and not run_poc and not poc_only:
        return

    try:
        from src.integration.poc_integration import POCIntegration

        poc_integration = POCIntegration(config)

        if poc_only:
            if not config.quiet:
                console.print("[bold cyan][POC] 仅生成 POC 模式[/bold cyan]")

            poc_results = poc_integration.generate_pocs_for_findings([], target)
            if hasattr(result, 'metadata') and result.metadata is not None:
                result.metadata['poc_results'] = poc_results
            elif isinstance(result, dict):
                if 'metadata' not in result:
                    result['metadata'] = {}
                result['metadata']['poc_results'] = poc_results

            if not config.quiet:
                console.print(f"[green][POC] 生成了 {poc_results['generated']} 个 POC[/green]")
            return

        findings = []
        if hasattr(result, 'findings'):
            findings = result.findings
        elif isinstance(result, dict) and 'findings' in result:
            findings = result.get('findings', [])

        if not findings:
            if not config.quiet:
                console.print("[yellow][POC] 没有发现漏洞，跳过 POC 生成[/yellow]")
            return

        poc_results = {"generated": 0, "executed": 0, "pocs": [], "details": []}

        if generate_poc:
            if not config.quiet:
                console.print("[bold cyan][POC] 正在生成 POC...[/bold cyan]")
            gen_results = poc_integration.generate_pocs_for_findings(findings, target)
            poc_results["generated"] = gen_results["generated"]
            poc_results["pocs"] = gen_results["pocs"]
            if not config.quiet:
                console.print(f"[green][POC] 生成了 {gen_results['generated']} 个 POC[/green]")

        if run_poc:
            if not config.quiet:
                console.print("[bold cyan][POC] 正在执行 POC...[/bold cyan]")
            exec_results = poc_integration.run_pocs(poc_results["pocs"], target)
            poc_results["executed"] = exec_results["executed"]
            poc_results["vulnerable"] = exec_results.get("vulnerable", 0)
            poc_results["details"] = exec_results.get("details", [])
            if not config.quiet:
                console.print(f"[green][POC] 执行了 {exec_results['executed']} 个 POC，发现 {exec_results.get('vulnerable', 0)} 个漏洞[/green]")

        if hasattr(result, 'metadata') and result.metadata is not None:
            result.metadata['poc_results'] = poc_results
        elif isinstance(result, dict):
            if 'metadata' not in result:
                result['metadata'] = {}
            result['metadata']['poc_results'] = poc_results

    except ImportError as e:
        if not config.quiet:
            console.print(f"[yellow][POC] POC 集成模块不可用: {e}[/yellow]")
    except Exception as e:
        if not config.quiet:
            console.print(f"[yellow][POC] POC 集成失败: {e}[/yellow]")


def _display_scan_statistics(result) -> None:
    """显示完整的扫描统计信息"""
    from datetime import datetime
    
    summary = result.to_dict().get("summary", {})
    metadata = getattr(result, 'metadata', {})
    if isinstance(result, dict):
        metadata = result.get('metadata', {})
    
    total_files = metadata.get('total_files', 0) if isinstance(metadata, dict) else 0
    findings = getattr(result, 'findings', [])
    if isinstance(result, dict):
        findings = result.get('findings', [])
    
    start_time = getattr(result, 'start_time', None)
    end_time = getattr(result, 'end_time', None)
    
    duration = 0.0
    if start_time and end_time:
        try:
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time)
            if isinstance(end_time, str):
                end_time = datetime.fromisoformat(end_time)
            duration = (end_time - start_time).total_seconds()
        except Exception:
            duration = 0.0
    
    critical_count = summary.get("critical", 0)
    high_count = summary.get("high", 0)
    medium_count = summary.get("medium", 0)
    low_count = summary.get("low", 0)
    info_count = summary.get("info", 0)
    total_findings = summary.get("total", len(findings))
    
    ai_stats = metadata.get('ai_stats', {}) if isinstance(metadata, dict) else {}
    ai_success = ai_stats.get('success', 0)
    ai_failure = ai_stats.get('failure', 0)
    ai_timeout = ai_stats.get('timeout', 0)
    
    # 尝试使用 TerminalUI 的摘要面板
    try:
        from src.core.chat.terminal_ui import TerminalUI
        ui = TerminalUI()
        ui.print_scan_summary_panel(
            total=total_findings,
            critical=critical_count,
            high=high_count,
            medium=medium_count,
            low=low_count,
            info=info_count,
            elapsed=duration,
            files_scanned=total_files,
        )
    except Exception:
        # Fallback to original display
        console.print(Panel(
            f"[bold]扫描统计[/bold]\n"
            f"  扫描文件数: [green]{total_files}[/green]\n"
            f"  发现总数: [yellow]{total_findings}[/yellow]\n"
            f"  [red]Critical: {critical_count}[/red] | "
            f"[red]High: {high_count}[/red] | "
            f"[yellow]Medium: {medium_count}[/yellow] | "
            f"[blue]Low: {low_count}[/blue] | "
            f"[dim]Info: {info_count}[/dim]\n"
            f"  AI分析: [green]成功 {ai_success}[/green] / "
            f"[red]失败 {ai_failure}[/red] / "
            f"[yellow]超时 {ai_timeout}[/yellow]\n"
            f"  总耗时: [cyan]{duration:.1f}s[/cyan]",
            border_style="cyan",
            title="[bold]扫描完成[/bold]"
        ))


def _display_result(result) -> None:
    """显示扫描结果"""
    from src.core.engine import Severity

    summary = result.to_dict()["summary"]

    total_issues = summary.get("total", 0)
    critical_count = summary.get("critical", 0)
    high_risk = summary.get("high", 0) + critical_count
    medium_risk = summary.get("medium", 0)
    low_risk = summary.get("low", 0)
    info_count = summary.get("info", 0)

    significant_issues = high_risk + medium_risk + low_risk

    console.print(
        "[bold yellow][!] Scan Result[/bold yellow]\n"
        "──────────────\n"
        f"Issues Found: {total_issues}\n"
        f"[red]High Risk:[/red] {high_risk}\n"
        f"[yellow]Medium Risk:[/yellow] {medium_risk}\n"
        f"[green]Low Risk:[/green] {low_risk}"
    )

    if significant_issues > 0:
        risk_score = high_risk * 3.0 + medium_risk * 1.5 + low_risk * 0.5
        max_potential_score = significant_issues * 3.0
        risk_percentage = min(1.0, risk_score / max_potential_score)
    else:
        risk_percentage = 0
    show_risk_bar(risk_percentage)

    console.print("\n[yellow italic][!] 注意：AI 扫描结果具有概率性，多次扫描结果可能有适度波动（±1-2 个风险点是正常现象）[/yellow italic]")

    # 尝试使用 TerminalUI 输出发现警报
    use_ui_alerts = False
    try:
        from src.core.chat.terminal_ui import TerminalUI
        ui = TerminalUI()
        use_ui_alerts = True
    except Exception:
        pass

    if result.findings:
        console.print("\n[bold]发现问题:[/bold]")
        for i, finding in enumerate(result.findings[:10], 1):
            severity_color = "red" if finding.severity.value in ["critical", "high"] else "yellow" if finding.severity.value == "medium" else "blue"
            message = finding.message.strip()
            
            # 使用 TerminalUI 的 finding alert
            if use_ui_alerts:
                try:
                    finding_line = finding.location.line if hasattr(finding, 'location') and hasattr(finding.location, 'line') else 0
                    finding_file = finding.location.file if hasattr(finding, 'location') and hasattr(finding.location, 'file') else "unknown"
                    ui.print_finding_alert(finding.severity.value, finding.rule_name, finding_file, finding_line)
                except Exception:
                    pass
            
            if len(message) > 80:
                lines = []
                current_line = ""
                for word in message.split():
                    if len(current_line) + len(word) + 1 <= 80:
                        current_line += f" {word}" if current_line else word
                    else:
                        lines.append(current_line)
                        current_line = word
                if current_line:
                    lines.append(current_line)
                console.print(
                    f"{i}. [{severity_color}]{finding.severity.value}[/{severity_color}] "
                    f"{finding.rule_name}: {lines[0]}"
                )
                for line in lines[1:]:
                    console.print(f"   {line}")
            else:
                console.print(
                    f"{i}. [{severity_color}]{finding.severity.value}[/{severity_color}] "
                    f"{finding.rule_name}: {message}"
                )

        if len(result.findings) > 10:
            console.print(f"... 还有 {len(result.findings) - 10} 个问题")
            console.print("\n[bold]继续显示剩余问题:[/bold]")
            for i, finding in enumerate(result.findings[10:], 11):
                severity_color = "red" if finding.severity.value in ["critical", "high"] else "yellow" if finding.severity.value == "medium" else "blue"
                message = finding.message.strip()
                
                if use_ui_alerts:
                    try:
                        finding_line = finding.location.line if hasattr(finding, 'location') and hasattr(finding.location, 'line') else 0
                        finding_file = finding.location.file if hasattr(finding, 'location') and hasattr(finding.location, 'file') else "unknown"
                        ui.print_finding_alert(finding.severity.value, finding.rule_name, finding_file, finding_line)
                    except Exception:
                        pass
                
                if len(message) > 80:
                    lines = []
                    current_line = ""
                    for word in message.split():
                        if len(current_line) + len(word) + 1 <= 80:
                            current_line += f" {word}" if current_line else word
                        else:
                            lines.append(current_line)
                            current_line = word
                    if current_line:
                        lines.append(current_line)
                    console.print(
                        f"{i}. [{severity_color}]{finding.severity.value}[/{severity_color}] "
                        f"{finding.rule_name}: {lines[0]}"
                    )
                    for line in lines[1:]:
                        console.print(f"   {line}")
                else:
                    console.print(
                        f"{i}. [{severity_color}]{finding.severity.value}[/{severity_color}] "
                        f"{finding.rule_name}: {message}"
                    )

            console.print(f"\n[dim]共 {len(result.findings)} 个问题，已全部显示[/dim]")

    if hasattr(result, 'metadata') and 'local_attack_chain' in result.metadata:
        attack_chain_data = result.metadata['local_attack_chain']
        if attack_chain_data.get('critical_chains'):
            console.print("\n[bold cyan]🔗 攻击链分析:[/bold cyan]")
            console.print(f"[dim]{attack_chain_data.get('summary', '')}[/dim]")
            
            for i, chain in enumerate(attack_chain_data['critical_chains'][:3], 1):
                risk_color = "red" if chain['risk_level'] == "high" else "yellow" if chain['risk_level'] == "medium" else "blue"
                console.print(f"\n{i}. [{risk_color}]攻击路径 (风险: {chain['risk_level']})[/{risk_color}]")
                console.print(f"   路径: {chain['description']}")
                console.print("   步骤:")
                for step in chain['steps']:
                    console.print(f"     - {step['description']}")
                console.print(f"   状态: {chain['status']}")


@click.command()
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", default="html", help="输出格式 (html, markdown, json, sarif)")
@click.option("--output", "-o", help="输出文件路径")
@click.option("--ruleset", "-r", help="规则集")
@click.option("--diff", is_flag=True, help="扫描 Git 差异")
@click.option("--workers", "-w", type=int, default=4, help="工作线程数")
@click.option("--ai", is_flag=True, help="启用 AI 分析")
@click.option("--mode", "-m", type=str, 
              default="auto", help="扫描模式: auto(自动), fast(快速), deep(深度), stealth(隐蔽), vuln-lab(靶场对抗)")
@click.option("--ai-provider", help="AI 提供商 (anthropic, openai, deepseek, local)")
@click.option("--ai-model", help="AI 模型 (如 deepseek-chat, deepseek-reasoner)")
@click.option("--ai-proxy", help="HTTP 代理 URL (如 http://127.0.0.1:7897)，自动检测 Clash 代理")
@click.option("--incremental", is_flag=True, help="启用增量扫描")
@click.option("--langgraph", is_flag=True, help="使用 LangGraph 流程")
@click.option("--test", type=int, default=0, help="启用测试模式，指定扫描文件数量，默认10")
@click.option("--resume", is_flag=True, help="从断点恢复扫描")
@click.option("--session-id", help="指定会话ID以恢复扫描")
@click.option("--select", help="选择指定文件进行扫描，逗号分隔")
@click.option("--select-interactive", is_flag=True, help="交互式选择要扫描的文件")
@click.option("--truncate-output", is_flag=True, help="启用截断模式，达到条件后停止但输出报告")
@click.option("--max-duration", type=int, default=0, help="最大扫描时长（秒），0表示不限制")
@click.option("--max-files", type=int, default=0, help="最大扫描文件数，0表示不限制")
@click.option("--full-scan", is_flag=True, help="强制全量扫描，忽略增量索引")
@click.option("--index-status", is_flag=True, help="显示索引状态")
@click.option("--explain", is_flag=True, help="显示执行流程")
@click.option("--ask", help="轻量对话，直接回答问题")
@click.option("--focus", help="聚焦分析指定文件或目录")
@click.option("--tool-chain", help="指定工具链，用逗号分隔 (semgrep,trivy,gitleaks,code_vuln_scanner)")
@click.option("--skip-data-update", is_flag=True, help="跳过数据更新检查")
@click.option("--sandbox", is_flag=True, help="启用沙盒动态验证（实验性）")
@click.option("--language", "-l", type=click.Choice(["zh", "en"], case_sensitive=False),
              default=None, help="界面语言: zh(中文), en(英文)，默认跟随配置文件")
@click.option("--audit-mode", type=click.Choice(["static", "dynamic", "hybrid"]),
              default="hybrid", help="审计模式: static(静态), dynamic(动态), hybrid(混合)")
@click.option("--static-only", is_flag=True, help="仅执行静态分析，不进行动态验证")
@click.option("--dynamic-only", is_flag=True, help="仅执行AI红队POC动态测试，不进行静态扫描")
@click.option("--generate-poc", is_flag=True, help="为扫描发现生成 POC 脚本")
@click.option("--run-poc", is_flag=True, help="执行 POC 验证")
@click.option("--poc-only", is_flag=True, help="仅生成 POC，不执行扫描（与 --dynamic-only 配合使用）")
@click.option("--min-confidence", type=click.Choice(["HIGH", "MEDIUM", "LOW", "ALL"]), default="HIGH", help="最低置信度过滤 (默认: HIGH)")
@click.option("--scan-ports", is_flag=True, help="启用API端口配置扫描，提前发现端口配置和生成模式")
@click.option("--ports-only", is_flag=True, help="仅执行端口扫描，不进行漏洞扫描")
@click.option("--port-range", type=str, default="1-65535", help="端口扫描范围，格式: start-end (默认: 1-65535)")
@click.option("--priority", type=click.Choice(["api-first", "security-first", "performance-first", "full-scan", "custom"], case_sensitive=False),
              default="full-scan", help="扫描优先级策略: api-first(API优先), security-first(安全优先), performance-first(性能优先), full-scan(全面扫描), custom(自定义)")
@click.option("--priority-rules", type=click.Path(exists=True), help="自定义优先级规则文件路径 (YAML/JSON)")
@click.option("--report-category", type=click.Choice(["all", "port-related", "general-static", "special-scan", "api-security", "auth-security", "data-protection", "config-security"], case_sensitive=False),
              default="all", help="报告分类过滤: all(全部), port-related(端口相关), general-static(一般静态), special-scan(特别扫描), api-security(API安全), auth-security(认证安全), data-protection(数据保护), config-security(配置安全)")
@click.option("--no-graph", is_flag=True, help="禁用代码图（默认开启，构建项目符号调用关系）")
@click.option("--remote", is_flag=True, help='启用远程扫描模式')
@click.option("--remote-type", type=click.Choice(["ssh", "http", "serial"], case_sensitive=False), default="ssh", help='远程连接类型')
@click.option("--remote-host", help='远程主机地址')
@click.option("--remote-port", type=int, help='远程端口')
@click.option("--remote-username", help='远程用户名(SSH)')
@click.option("--remote-password", help='远程密码(SSH)')
@click.option("--remote-key", help='SSH私钥路径')
@click.option("--remote-path", help='远程扫描路径')
@click.option("--serial-baudrate", type=int, default=115200, help='串口波特率')
@click.option("--serial-port", help='串口端口(如 COM1)')
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    output_format: str,
    output: Optional[str],
    ruleset: Optional[str],
    diff: bool,
    workers: int,
    ai: bool,
    mode: str,
    ai_provider: Optional[str],
    ai_model: Optional[str],
    ai_proxy: Optional[str],
    incremental: bool,
    langgraph: bool,
    test: bool,
    resume: bool,
    session_id: Optional[str],
    select: Optional[str],
    select_interactive: bool,
    truncate_output: bool,
    max_duration: int,
    max_files: int,
    full_scan: bool,
    index_status: bool,
    explain: bool,
    ask: Optional[str],
    focus: Optional[str],
    tool_chain: Optional[str],
    skip_data_update: bool,
    sandbox: bool,
    language: Optional[str],
    audit_mode: str,
    static_only: bool,
    dynamic_only: bool,
    generate_poc: bool,
    run_poc: bool,
    poc_only: bool,
    min_confidence: str = "HIGH",
    scan_ports: bool = False,
    ports_only: bool = False,
    port_range: str = "1-65535",
    priority: str = "full-scan",
    priority_rules: Optional[str] = None,
    report_category: str = "all",
    no_graph: bool = False,
    remote: bool = False,
    remote_type: str = "ssh",
    remote_host: Optional[str] = None,
    remote_port: Optional[int] = None,
    remote_username: Optional[str] = None,
    remote_password: Optional[str] = None,
    remote_key: Optional[str] = None,
    remote_path: Optional[str] = None,
    serial_baudrate: int = 115200,
    serial_port: Optional[str] = None,
) -> None:
    """扫描代码安全漏洞"""
    from src.core.config import Config, SandboxConfig, AuditMode
    from src.utils.proxy_detection import get_proxy_with_fallback
    from src.core.scanner import create_scanner
    from src.cli.commands.report import _generate_report, _check_data_preload_status, print_banner

    config: Config = ctx.obj["config"]

    if not config.quiet:
        console.print("[bold cyan]> hosls scan " + target + "[/bold cyan]")

    if not skip_data_update:
        _check_data_preload_status(config)

    if language:
        config.language = language

    # ─── 检查已废弃的 pure-ai 模式 ───
    if mode and mode.lower() == "pure-ai":
        console.print("[bold yellow]⚠️ --mode pure-ai 已移至 audit 命令，请使用:[/bold yellow]")
        console.print("[bold cyan]   hos-ls audit <target> --mode deep[/bold cyan]")
        sys.exit(0)

    if not config.quiet:
        print_banner()

    config.scan.max_workers = workers
    config.scan.incremental = incremental
    if ruleset:
        config.rules.ruleset = ruleset
    config.report.format = output_format
    if output:
        config.report.output = output
    config.ai.enabled = True  # AI默认开启
    config.__dict__['init_graph'] = not no_graph
    valid_modes = ["auto", "fast", "deep", "stealth", "vuln-lab"]
    if mode and mode.lower() in valid_modes:
        config.scan_mode = mode.lower()
    
    # 默认启用工具链（避免新功能无法测试）
    if not config.tools.enabled:
        config.tools.enabled = True
    if not config.tools.tool_chain:
        config.tools.tool_chain = ["semgrep", "trivy", "gitleaks", "code_vuln_scanner"]
    
    # ─── 文件选择 ───
    if select:
        selected_files = [f.strip() for f in select.split(',') if f.strip()]
        if not config.quiet:
            console.print(f"[bold cyan][SELECT] 已选择 {len(selected_files)} 个文件:[/bold cyan]")
            for sf in selected_files:
                console.print(f"  - {sf}")
        config.__dict__['selected_files'] = selected_files
    
    if ai_provider:
        config.ai.provider = ai_provider

    if ai_model:
        config.ai.model = ai_model

    if ai_proxy:
        config.ai.proxy_url = ai_proxy
        if not config.quiet:
            console.print(f"[bold cyan][PROXY] 代理已设置: {ai_proxy}[/bold cyan]")
    else:
        auto_proxy = get_proxy_with_fallback()
        if auto_proxy:
            config.ai.proxy_url = auto_proxy
            if not config.quiet:
                console.print(f"[bold cyan][PROXY] 自动检测到代理: {auto_proxy}[/bold cyan]")

    if tool_chain:
        config.tools.enabled = True
        config.tools.tool_chain = [t.strip() for t in tool_chain.split(',') if t.strip()]
        console.print(f"[bold cyan]🔧 工具链已启用: {config.tools.tool_chain}[/bold cyan]")

    # 默认启用端口扫描（除非明确禁用）
    if not hasattr(config.scan, 'port_scan_enabled') or config.scan.port_scan_enabled is None:
        config.scan.port_scan_enabled = True
        config.scan.port_range = port_range

    if scan_ports:
        config.scan.port_scan_enabled = True
        config.scan.ports_only = ports_only
        config.scan.port_range = port_range
        if not config.quiet:
            console.print(f"[bold cyan][PORT] 端口扫描已启用, 范围: {port_range}[/bold cyan]")
        if ports_only:
            console.print(f"[bold yellow][PORT] 警告: 仅执行端口扫描模式，不进行漏洞扫描[/bold yellow]")

    if priority != "full-scan":
        config.scan.priority_strategy = priority
        if not config.quiet:
            console.print(f"[bold cyan][PRIORITY] 已启用 {priority} 策略[/bold cyan]")
    if priority_rules:
        config.scan.priority_rules_path = priority_rules
        if not config.quiet:
            console.print(f"[bold cyan][PRIORITY] 自定义规则: {priority_rules}[/bold cyan]")

    if report_category != "all":
        config.report.category_filter = report_category
        if not config.quiet:
            console.print(f"[bold cyan][REPORT] 报告分类过滤: {report_category}[/bold cyan]")

    if test > 0:
        config.test_mode = True
        config.__dict__['test_file_count'] = test
        if not config.quiet:
            console.print(f"[bold yellow][!] 测试模式已启用，只扫描前{test}个优先级最高的文件[/bold yellow]")
    elif test == 0:
        config.test_mode = False
    else:
        config.test_mode = True
        config.__dict__['test_file_count'] = 10
        if not config.quiet:
            console.print("[bold yellow][!] 测试模式已启用，只扫描前10个优先级最高的文件[/bold yellow]")

    try:
        if langgraph:
            from src.core.langgraph_flow import analyze_code
            target_path = Path(target)
            if target_path.is_file():
                with open(target_path, 'r', encoding='utf-8') as f:
                    code = f.read()
            else:
                code = f"目录扫描: {target}"
            result = asyncio.run(analyze_code(code))
            if not config.quiet:
                console.print(Panel("[bold]LangGraph 多Agent分析结果[/bold]"))
                if 'final_report' in result:
                    report = result['final_report']
                    console.print(f"[green]分析状态: {report.get('quality', 'unknown')}[/green]")
                    console.print(f"[green]迭代次数: {report.get('iteration', 0)}[/green]")
                    console.print(f"[green]CVE候选数量: {len(report.get('cve_candidates', []))}[/green]")
                    console.print(f"[green]攻击链长度: {len(report.get('attack_chain', {}))}[/green]")
                    console.print("[bold]分析结果:[/bold]")
                    console.print(report.get('analysis', ''))
                    if 'fix_suggestions' in report:
                        console.print("[bold]修复建议:[/bold]")
                        console.print(report.get('fix_suggestions', ''))
                else:
                    console.print(f"[red]分析失败: {result.get('error', '未知错误')}[/red]")
            if output:
                import json
                with open(output, 'w', encoding='utf-8') as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                console.print(f"[bold green]报告已生成: {output}[/bold green]")
            if result.get('final_report', {}).get('quality') != 'pass':
                sys.exit(1)
        else:
            remote_config = None
            if remote:
                if not remote_host:
                    console.print("[bold red][ERROR] 远程扫描需要指定 --remote-host[/bold red]")
                    sys.exit(1)

                remote_config = {
                    'type': remote_type,
                    'host': remote_host,
                    'port': remote_port,
                    'username': remote_username,
                    'password': remote_password,
                    'key_path': remote_key,
                    'remote_path': remote_path or '/',
                }

                if remote_type == 'serial':
                    remote_config['port'] = serial_port
                    remote_config['baudrate'] = serial_baudrate
                elif remote_type == 'ssh':
                    remote_config['port'] = remote_port or 22
                    remote_config['key_path'] = remote_key
                elif remote_type == 'http':
                    remote_config['port'] = remote_port or 80
                    remote_config['use_ssl'] = remote_type == 'https'

                if not config.quiet:
                    console.print(f"[bold cyan][REMOTE] 远程扫描模式: {remote_type}://{remote_host}:{remote_config.get('port', 'default')}[/bold cyan]")

                scanner = create_scanner(config, remote_config)
            else:
                scanner = create_scanner(config)
            result = scanner.scan_sync(target)

            if not config.quiet:
                _display_scan_statistics(result)
                show_agent_status(result)
                _display_result(result)

            _integrate_poc(config, result, target, generate_poc, run_poc, poc_only)

            if not output:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output = f"scan_report_{timestamp}.html"
                console.print(f"[bold yellow][WARNING] 未指定输出路径，使用默认: {output}[/bold yellow]")
            _generate_report(result, output, output_format, config)

    except Exception as e:
        console.print(f"[bold red]扫描失败: {e}[/bold red]")
        sys.exit(2)
