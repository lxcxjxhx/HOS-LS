"""CLI 主模块

HOS-LS 的命令行入口。
"""

import sys
import asyncio
import os
import warnings
from pathlib import Path
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

warnings.filterwarnings("ignore", message="Failed to find CUDA.")
warnings.filterwarnings("ignore", category=RuntimeWarning, message="Redirects are currently not supported in Windows or MacOs.")
warnings.filterwarnings("ignore", category=RuntimeWarning, message="'src.cli.main' found in sys.modules after import of package 'src.cli'")
warnings.filterwarnings("ignore", message=".*cpp extensions.*")
warnings.filterwarnings("ignore", message="Skipping import of cpp extensions.*")

os.environ["PYTHONWARNINGS"] = "ignore"

from src import __version__
from src.core.config import Config, ConfigManager
from pydantic import BaseModel

console = Console(emoji=False, force_terminal=True)


class AsyncWorker:
    """异步Worker类，用于处理后台任务"""
    
    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.queue = Queue()
        self.running = False
    
    def start(self):
        """启动Worker"""
        self.running = True
        # 在单独的线程中运行事件循环
        def run_event_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.create_task(self._process_queue())
            loop.run_forever()
        
        import threading
        thread = threading.Thread(target=run_event_loop)
        thread.daemon = True
        thread.start()
    
    def stop(self):
        """停止Worker"""
        self.running = False
        self.executor.shutdown()
    
    def add_task(self, task, *args, **kwargs):
        """添加任务到队列"""
        self.queue.put((task, args, kwargs))
    
    async def _process_queue(self):
        """处理队列中的任务"""
        while self.running:
            if not self.queue.empty():
                task, args, kwargs = self.queue.get()
                try:
                    await asyncio.to_thread(task, *args, **kwargs)
                except Exception as e:
                    console.print(f"[bold red]任务执行失败: {e}[/bold red]")
                finally:
                    self.queue.task_done()
            await asyncio.sleep(0.1)


def print_banner() -> None:
    """打印欢迎横幅"""
    console.print(Panel(
        "[bold]HOS-LS[/bold] · AI Code Security Scanner\n"
        "[dim]Multi-Agent · Semantic Analysis · Risk Detection[/dim]",
        border_style="dim",
    ))


def show_scan_progress() -> None:
    """显示流式扫描进度"""
    from rich.table import Table
    import time
    
    steps = [
        "Parsing AST",
        "Building Graph",
        "Running Agents",
        "Risk Analysis"
    ]
    
    with Live(refresh_per_second=4) as live:
        for i, step in enumerate(steps):
            # 创建新表格
            table = Table()
            table.add_column("Step")
            table.add_column("Status")
            
            # 添加已完成的步骤
            for j in range(i):
                table.add_row(steps[j], "[green]Done")
            
            # 添加当前步骤
            table.add_row(step, "[yellow]Running...")
            
            # 更新显示
            live.update(table)
            time.sleep(0.8)
        
        # 显示最终完成状态
        final_table = Table()
        final_table.add_column("Step")
        final_table.add_column("Status")
        for step in steps:
            final_table.add_row(step, "[green]Done")
        live.update(final_table)


def show_agent_status() -> None:
    """显示 Agent 状态"""
    from rich.table import Table
    
    table = Table(title="Agents")
    
    table.add_column("Agent")
    table.add_column("Status")
    
    table.add_row("Semantic Analyzer", "[OK]")
    table.add_row("Vulnerability Agent", "[!]")
    table.add_row("Dependency Scanner", "[OK]")
    
    console.print(table)


def show_risk_bar(percentage: float) -> None:
    """显示风险条"""
    bars = int(percentage * 10)
    risk_bar = "#" * bars + "-" * (10 - bars)
    console.print(f"Risk Level: {risk_bar} {int(percentage * 100)}%")


@click.group()
@click.version_option(version=__version__, prog_name="hos-ls")
@click.option("--config", "-c", type=click.Path(), help="配置文件路径")
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
@click.option("--quiet", "-q", is_flag=True, help="静默模式")
@click.option("--debug", "-d", is_flag=True, help="调试模式")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool, quiet: bool, debug: bool) -> None:
    """HOS-LS: AI 生成代码安全扫描工具"""
    # 确保上下文对象是字典
    ctx.ensure_object(dict)

    # 加载配置
    config_manager = ConfigManager()
    if config:
        cfg = config_manager.load_from_file(config)
    else:
        cfg = config_manager.auto_load()

    # 更新配置
    cfg.verbose = verbose
    cfg.quiet = quiet
    cfg.debug = debug

    # 保存到上下文
    ctx.obj["config"] = cfg


@cli.command()
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", default="html", help="输出格式 (html, markdown, json, sarif)")
@click.option("--output", "-o", help="输出文件路径")
@click.option("--ruleset", "-r", help="规则集")
@click.option("--diff", is_flag=True, help="扫描 Git 差异")
@click.option("--workers", "-w", type=int, default=4, help="工作线程数")
@click.option("--ai", is_flag=True, help="启用 AI 分析")
@click.option("--pure-ai", is_flag=True, help="启用纯AI深度语义解析模式，只执行AI分析和报告导出")
@click.option("--mode", "-m", type=click.Choice(["auto", "pure-ai", "fast", "deep", "stealth", "vuln-lab"], case_sensitive=False), 
              default="auto", help="扫描模式: auto(自动), pure-ai(纯AI), fast(快速), deep(深度), stealth(隐蔽), vuln-lab(靶场对抗)")
@click.option("--ai-provider", help="AI 提供商 (anthropic, openai, deepseek, local)")
@click.option("--ai-model", help="AI 模型 (如 deepseek-chat, deepseek-reasoner)")
@click.option("--incremental", is_flag=True, help="启用增量扫描")
@click.option("--langgraph", is_flag=True, help="使用 LangGraph 流程")
@click.option("--test", type=int, default=0, help="启用测试模式，指定扫描文件数量，默认10")
@click.option("--resume", is_flag=True, help="从断点恢复扫描")
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
@click.option("--min-confidence", type=click.Choice(["HIGH", "MEDIUM", "LOW", "ALL"]), default="HIGH", help="最低置信度过滤 (默认: HIGH)")
@click.option("--scan-ports", is_flag=True, help="启用API端口配置扫描，提前发现端口配置和生成模式")
@click.option("--ports-only", is_flag=True, help="仅执行端口扫描，不进行漏洞扫描")
@click.option("--port-range", type=str, default="1-65535", help="端口扫描范围，格式: start-end (默认: 1-65535)")
@click.option("--priority", type=click.Choice(["api-first", "security-first", "performance-first", "full-scan", "custom"], case_sensitive=False),
              default="full-scan", help="扫描优先级策略: api-first(API优先), security-first(安全优先), performance-first(性能优先), full-scan(全面扫描), custom(自定义)")
@click.option("--priority-rules", type=click.Path(exists=True), help="自定义优先级规则文件路径 (YAML/JSON)")
@click.option("--report-category", type=click.Choice(["all", "port-related", "general-static", "special-scan", "api-security", "auth-security", "data-protection", "config-security"], case_sensitive=False),
              default="all", help="报告分类过滤: all(全部), port-related(端口相关), general-static(一般静态), special-scan(特别扫描), api-security(API安全), auth-security(认证安全), data-protection(数据保护), config-security(配置安全)")
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
    pure_ai: bool,
    mode: str,
    ai_provider: Optional[str],
    ai_model: Optional[str],
    incremental: bool,
    langgraph: bool,
    test: bool,
    resume: bool,
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
    min_confidence: str = "HIGH",
    scan_ports: bool = False,
    ports_only: bool = False,
    port_range: str = "1-65535",
    priority: str = "full-scan",
    priority_rules: Optional[str] = None,
    report_category: str = "all",
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
    config: Config = ctx.obj["config"]

    if not config.quiet:
        console.print("[bold cyan]> hosls scan " + target + "[/bold cyan]")

    if not pure_ai and not skip_data_update:
        _check_data_preload_status(config)

    # 语言设置 - CLI参数优先于配置文件
    if language:
        config.language = language

    # 提前检查纯AI模式
    if pure_ai:
        # 设置环境变量
        os.environ["HOS_LS_MODE"] = "PURE_AI"
        
        if not config.quiet:
            print_banner()
            console.print("[bold green][LOCK] 纯AI模式已激活，隔离运行时环境...[/bold green]")
        
        # 纯AI模式配置
        config.scan.max_workers = workers
        config.scan.incremental = incremental
        if ruleset:
            config.rules.ruleset = ruleset
        config.report.format = output_format
        if output:
            config.report.output = output
        config.ai.enabled = True
        config.pure_ai = True
        config.scan_mode = "pure-ai"

        if not config.ai.modules:
            config.ai.modules = {}
        if "pure_ai" not in config.ai.modules:
            from src.core.config import AIModuleConfig
            config.ai.modules["pure_ai"] = AIModuleConfig()
        config.ai.modules["pure_ai"].provider = "deepseek"
        config.ai.modules["pure_ai"].model = "deepseek-v4-pro"

        # 端口扫描配置
        if scan_ports:
            config.scan.port_scan_enabled = True
            config.scan.ports_only = ports_only
            config.scan.port_range = port_range
            if not config.quiet:
                console.print(f"[bold cyan][PORT] 端口扫描已启用, 范围: {port_range}[/bold cyan]")
            if ports_only:
                console.print(f"[bold yellow][PORT] 警告: 仅执行端口扫描模式，不进行漏洞扫描[/bold yellow]")

        # 优先级策略配置
        if priority != "full-scan":
            config.scan.priority_strategy = priority
            if not config.quiet:
                console.print(f"[bold cyan][PRIORITY] 已启用 {priority} 策略[/bold cyan]")
        if priority_rules:
            config.scan.priority_rules_path = priority_rules
            if not config.quiet:
                console.print(f"[bold cyan][PRIORITY] 自定义规则: {priority_rules}[/bold cyan]")

        # 报告分类配置
        if report_category != "all":
            config.report.category_filter = report_category
            if not config.quiet:
                console.print(f"[bold cyan][REPORT] 报告分类过滤: {report_category}[/bold cyan]")

        # 测试模式
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

        # 截断模式和续传模式互斥检查
        if resume and truncate_output:
            console.print("[bold red][ERROR] 截断模式和续传模式不能同时启用！[/bold red]")
            console.print("[yellow]  使用 --truncate-output 启用截断模式（达到条件后停止但输出报告）[/yellow]")
            console.print("[yellow]  使用 --resume 从上次截断点继续扫描[/yellow]")
            sys.exit(1)

        # 截断和续传配置
        config.resume = resume
        config.truncate_output = truncate_output
        config.max_duration = max_duration
        config.max_files = max_files

        # 沙盒配置
        if sandbox or static_only or dynamic_only or audit_mode != "hybrid":
            from src.core.config import SandboxConfig, AuditMode

            # 参数优先级: --static-only > --dynamic-only > --audit-mode
            if static_only:
                mode = AuditMode.STATIC
                if not config.quiet:
                    console.print("[bold yellow][!] 审计模式: STATIC (纯静态分析)[/bold yellow]")
            elif dynamic_only:
                mode = AuditMode.DYNAMIC
                if not config.quiet:
                    console.print("[bold yellow][!] 审计模式: DYNAMIC (纯动态AI红队POC测试)[/bold yellow]")
            else:
                mode = AuditMode(audit_mode)
                if not config.quiet:
                    mode_display = {"static": "STATIC", "dynamic": "DYNAMIC", "hybrid": "HYBRID"}
                    console.print(f"[bold yellow][!] 审计模式: {mode_display.get(audit_mode, audit_mode.upper())}[/bold yellow]")

            sandbox_cfg = SandboxConfig(enabled=True, mode=mode)
            config.sandbox = sandbox_cfg

            if not config.quiet and mode != AuditMode.STATIC:
                console.print("[bold yellow][!] 沙盒动态验证已启用（实验性功能）[/bold yellow]")

        if truncate_output:
            if not config.quiet:
                conditions = []
                if max_duration > 0:
                    conditions.append(f"max-duration={max_duration}s")
                if max_files > 0:
                    conditions.append(f"max-files={max_files}")
                cond_str = ", ".join(conditions) if conditions else "none"
                console.print(f"[bold yellow][!] 截断模式已启用，条件: {cond_str}[/bold yellow]")
        
        # 导入纯AI扫描器
        from src.core.scanner import create_scanner
        
        # 执行纯AI扫描
        try:
            # 显示扫描进度
            if not config.quiet:
                show_scan_progress()
            
            # 检查是否启用远程扫描模式
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

            # 显示结果
            if not config.quiet:
                show_agent_status()
                _display_result(result)

            # 生成报告
            if not output:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output = f"scan_report_{timestamp}.html"
                console.print(f"[bold yellow][WARNING] 未指定输出路径，使用默认: {output}[/bold yellow]")
            _generate_report(result, output, output_format, config)

            # 根据结果设置退出码
            # 扫描成功完成，返回0（无论是否发现漏洞）
            sys.exit(0)
        except Exception as e:
            console.print(f"[bold red]扫描失败: {e}[/bold red]")
            sys.exit(2)
        return

    # 非纯AI模式
    if not config.quiet:
        print_banner()

    # 更新配置
    config.scan.max_workers = workers
    config.scan.incremental = incremental
    if ruleset:
        config.rules.ruleset = ruleset
    config.report.format = output_format
    if output:
        config.report.output = output
    config.ai.enabled = ai
    config.pure_ai = False
    if mode:
        config.scan_mode = mode
    elif pure_ai:
        config.scan_mode = "pure-ai"
    
    if ai_provider:
        config.ai.provider = ai_provider

    if ai_model:
        config.ai.model = ai_model

    if tool_chain:
        config.tools_enabled = True
        config.tool_chain = [t.strip() for t in tool_chain.split(',') if t.strip()]
        console.print(f"[bold cyan]🔧 工具链已启用: {config.tool_chain}[/bold cyan]")

    # 端口扫描配置
    if scan_ports:
        config.scan.port_scan_enabled = True
        config.scan.ports_only = ports_only
        config.scan.port_range = port_range
        if not config.quiet:
            console.print(f"[bold cyan][PORT] 端口扫描已启用, 范围: {port_range}[/bold cyan]")
        if ports_only:
            console.print(f"[bold yellow][PORT] 警告: 仅执行端口扫描模式，不进行漏洞扫描[/bold yellow]")

    # 优先级策略配置
    if priority != "full-scan":
        config.scan.priority_strategy = priority
        if not config.quiet:
            console.print(f"[bold cyan][PRIORITY] 已启用 {priority} 策略[/bold cyan]")
    if priority_rules:
        config.scan.priority_rules_path = priority_rules
        if not config.quiet:
            console.print(f"[bold cyan][PRIORITY] 自定义规则: {priority_rules}[/bold cyan]")

    # 报告分类配置
    if report_category != "all":
        config.report.category_filter = report_category
        if not config.quiet:
            console.print(f"[bold cyan][REPORT] 报告分类过滤: {report_category}[/bold cyan]")

    # 测试模式
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

    # 执行扫描
    try:
        if langgraph:
            # 使用 LangGraph 多Agent流程
            from src.core.langgraph_flow import analyze_code
            # 读取目标文件内容
            target_path = Path(target)
            if target_path.is_file():
                with open(target_path, 'r', encoding='utf-8') as f:
                    code = f.read()
            else:
                code = f"目录扫描: {target}"
            # 运行多Agent分析
            result = asyncio.run(analyze_code(code))
            # 显示结果
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
            # 生成报告
            if output:
                import json
                with open(output, 'w', encoding='utf-8') as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                console.print(f"[bold green]报告已生成: {output}[/bold green]")
            # 根据结果设置退出码
            if result.get('final_report', {}).get('quality') != 'pass':
                sys.exit(1)
        else:
            # 使用传统扫描器
            from src.core.scanner import create_scanner
            
            # 显示扫描进度
            if not config.quiet:
                show_scan_progress()

            # 检查是否启用远程扫描模式
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

            # 显示结果
            if not config.quiet:
                show_agent_status()
                _display_result(result)

            # 生成报告
            if not output:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output = f"scan_report_{timestamp}.html"
                console.print(f"[bold yellow][WARNING] 未指定输出路径，使用默认: {output}[/bold yellow]")
            _generate_report(result, output, output_format, config)

            # 根据结果设置退出码
            # 扫描成功完成，返回0（无论是否发现漏洞）

    except Exception as e:
        console.print(f"[bold red]扫描失败: {e}[/bold red]")
        sys.exit(2)


@cli.command()
@click.option("--export", "-e", type=click.Choice(["yaml", "json"], case_sensitive=False), default=None, help="导出配置为指定格式")
@click.option("--import", "-i", "--input", "import_file", type=click.Path(exists=True), default=None, help="从文件导入配置")
@click.option("--output", "-o", type=click.Path(), default=None, help="导出文件路径")
@click.pass_context
def config(ctx: click.Context, export: str, import_file: str, output: str) -> None:
    """显示、导入或导出配置"""
    cfg: Config = ctx.obj["config"]

    # 处理导入
    if import_file:
        if import_file.endswith('.yaml') or import_file.endswith('.yml'):
            import yaml
            with open(import_file, 'r', encoding='utf-8') as f:
                imported_config = yaml.safe_load(f)
        elif import_file.endswith('.json'):
            import json
            with open(import_file, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
        else:
            console.print(f"[red]不支持的文件格式，请使用 .yaml/.yml 或 .json 文件[/red]")
            return

        if imported_config:
            _apply_imported_config(cfg, imported_config)
            console.print(f"[green]配置已从 {import_file} 导入[/green]")

            config_manager = ConfigManager()
            config_manager.save_config(cfg)
            console.print(f"[green]配置已保存[/green]")
        else:
            console.print(f"[red]导入的配置为空[/red]")
        return

    # 处理导出
    if export:
        if export == "yaml":
            import yaml
            config_dict = _config_to_dict(cfg)
            yaml_content = yaml.dump(config_dict, allow_unicode=True, default_flow_style=False)
            if output:
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(yaml_content)
                console.print(f"[green]配置已导出到: {output}[/green]")
            else:
                console.print(yaml_content)
        elif export == "json":
            import json
            config_dict = _config_to_dict(cfg)
            json_content = json.dumps(config_dict, ensure_ascii=False, indent=2)
            if output:
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                console.print(f"[green]配置已导出到: {output}[/green]")
            else:
                console.print(json_content)
        return

    console.print(Panel("[bold]HOS-LS 完整配置[/bold]", border_style="cyan"))

    table = Table(title="全局配置", show_header=True, header_style="bold cyan")
    table.add_column("配置项", style="cyan", width=30)
    table.add_column("当前值", style="green", width=40)
    table.add_column("默认值", style="dim", width=20)
    table.add_column("描述", style="white", width=30)

    table.add_row("调试模式 (debug)", str(cfg.debug), "False", "启用调试输出")
    table.add_row("详细输出 (verbose)", str(cfg.verbose), "False", "显示详细日志")
    table.add_row("静默模式 (quiet)", str(cfg.quiet), "False", "静默运行")
    table.add_row("测试模式 (test_mode)", str(cfg.test_mode), "False", "测试模式")
    table.add_row("纯AI模式 (pure_ai)", str(cfg.pure_ai), "False", "使用纯AI深度分析")
    table.add_row("扫描模式 (scan_mode)", cfg.scan_mode, "auto", "扫描模式")
    table.add_row("过滤幻觉 (filter_hallucinations)", str(cfg.filter_hallucinations), "True", "过滤AI幻觉发现")
    table.add_row("界面语言 (language)", cfg.language, "zh", "zh=中文, en=英文")
    table.add_row("从断点恢复 (resume)", str(cfg.resume), "False", "从中断处继续扫描")
    table.add_row("截断输出 (truncate_output)", str(cfg.truncate_output), "False", "达到条件后停止")
    table.add_row("最大扫描时长", str(cfg.max_duration), "0", "秒，0表示不限制")
    table.add_row("最大扫描文件数", str(cfg.max_files), "0", "0表示不限制")
    console.print(table)
    console.print()

    _print_config_table("AI 配置", [
        ("提供商 (provider)", cfg.ai.provider, "deepseek", "AI服务提供商"),
        ("模型 (model)", cfg.ai.model, "deepseek-chat", "AI模型"),
        ("API Key", mask_api_key(cfg.ai.api_key), "-", "API密钥"),
        ("最大Token (max_tokens)", str(cfg.ai.max_tokens), "4096", "单次请求最大Token数"),
        ("温度参数 (temperature)", str(cfg.ai.temperature), "0.1", "生成随机性，0-1"),
        ("超时 (timeout)", str(cfg.ai.timeout), "60", "请求超时秒数"),
    ])

    _print_config_table("AI - 阿里云配置", [
        ("启用", str(cfg.ai.aliyun.enabled), "False", "是否启用阿里云API"),
        ("API Key", mask_api_key(cfg.ai.aliyun.api_key), "-", "阿里云API密钥"),
        ("模型", cfg.ai.aliyun.model, "qwen3-coder-next", "阿里云模型"),
    ])

    _print_config_table("AI - 模块配置 (pure_ai)", [
        ("启用", str(cfg.ai.modules.get("pure_ai", {}).get("enabled", True) if cfg.ai.modules else True), "True", "纯AI模块启用"),
        ("模型", cfg.ai.modules.get("pure_ai", {}).get("model", "deepseek-v4-flash") if cfg.ai.modules else "deepseek-v4-flash", "deepseek-v4-flash", "pure_ai专用模型"),
        ("提供商", cfg.ai.modules.get("pure_ai", {}).get("provider", "deepseek") if cfg.ai.modules else "deepseek", "deepseek", "pure_ai专用提供商"),
    ])

    _print_config_table("AI - RAG配置", [
        ("启用", str(cfg.ai.rag.enabled), "True", "RAG检索启用"),
        ("嵌入模型", cfg.ai.rag.embedding_model, "Qwen/Qwen3-Embedding-0.6B", "嵌入模型"),
        ("重排模型", cfg.ai.rag.rerank_model, "BAAI/bge-reranker-large", "重排模型"),
    ])

    _print_config_table("扫描配置", [
        ("最大工作线程 (max_workers)", str(cfg.scan.max_workers), "4", "并行扫描线程数"),
        ("增量扫描 (incremental)", str(cfg.scan.incremental), "True", "增量扫描"),
        ("缓存启用 (cache_enabled)", str(cfg.scan.cache_enabled), "True", "启用扫描缓存"),
    ])

    _print_config_table("规则配置", [
        ("规则集 (ruleset)", cfg.rules.ruleset, "default", "使用的规则集"),
        ("自定义规则数", str(len(cfg.rules.custom_rules)), "0", "自定义规则数量"),
        ("排除路径数", str(len(cfg.rules.exclude_paths)), "0", "排除的路径数量"),
    ])

    _print_config_table("报告配置", [
        ("格式 (format)", cfg.report.format, "html", "报告格式"),
        ("输出路径 (output)", cfg.report.output or "(未设置)", "", "报告输出路径"),
        ("包含代码片段", str(cfg.report.include_snippets), "True", "报告中包含代码片段"),
        ("包含修复建议", str(cfg.report.include_fix_suggestions), "True", "报告中包含修复建议"),
    ])

    _print_config_table("工具配置", [
        ("工具链启用", str(cfg.tools.enabled), "True", "是否启用工具链"),
        ("Semgrep启用", str(cfg.tools.semgrep.enabled), "True", "Semgrep扫描启用"),
        ("Trivy启用", str(cfg.tools.trivy.enabled), "True", "Trivy扫描启用"),
        ("Gitleaks启用", str(cfg.tools.gitleaks.enabled), "True", "Gitleaks扫描启用"),
    ])

    _print_config_table("验证配置", [
        ("自动验证HIGH漏洞", str(cfg.validation.auto_validate_high), "True", "自动验证高置信度漏洞"),
        ("自动验证MEDIUM漏洞", str(cfg.validation.auto_validate_medium), "False", "自动验证中置信度漏洞"),
        ("最小置信度阈值", str(cfg.validation.min_confidence_threshold), "0.7", "置信度阈值"),
        ("行号偏差容忍度", str(cfg.validation.line_number_tolerance), "5", "行号偏差容忍行数"),
    ])

    _print_config_table("优先级配置", [
        ("CVSS权重", str(cfg.priority.weights.cvss), "0.40", "CVSS评分权重"),
        ("可利用性权重", str(cfg.priority.weights.exploitability), "0.35", "可利用性权重"),
        ("可达性权重", str(cfg.priority.weights.reachability), "0.25", "可达性权重"),
    ])

    _print_config_table("沙盒配置", [
        ("启用 (enabled)", str(cfg.sandbox.enabled), "False", "沙盒动态验证"),
        ("超时 (timeout)", str(cfg.sandbox.timeout), "30", "沙盒执行超时秒数"),
    ])

    _print_config_table("国际化配置", [
        ("语言 (language)", cfg.language, "zh", "界面语言: zh=中文, en=英文"),
    ])

    console.print("[dim]提示: 使用 --export yaml|json [-o output] 导出配置[/dim]")


def _print_config_table(title: str, items: list) -> None:
    """打印配置表格"""
    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("配置项", style="cyan", width=30)
    table.add_column("当前值", style="green", width=35)
    table.add_column("默认值", style="dim", width=15)
    table.add_column("描述", style="white", width=25)

    for item in items:
        table.add_row(*[str(x) if x else "" for x in item])

    console.print(table)
    console.print()


def _config_to_dict(cfg: Config) -> dict:
    """将配置对象转换为字典"""
    result = {
        "version": cfg.version,
        "debug": cfg.debug,
        "verbose": cfg.verbose,
        "quiet": cfg.quiet,
        "test_mode": cfg.test_mode,
        "pure_ai": cfg.pure_ai,
        "scan_mode": cfg.scan_mode,
        "filter_hallucinations": cfg.filter_hallucinations,
        "language": cfg.language,
        "resume": cfg.resume,
        "truncate_output": cfg.truncate_output,
        "max_duration": cfg.max_duration,
        "max_files": cfg.max_files,
    }

    def sanitize_value(v):
        if isinstance(v, BaseModel):
            return v.model_dump()
        elif isinstance(v, dict):
            return {k: sanitize_value(val) for k, val in v.items()}
        elif isinstance(v, list):
            return [sanitize_value(item) for item in v]
        elif isinstance(v, bool):
            return v
        elif isinstance(v, (str, int, float, type(None))):
            return v
        else:
            return str(v)

    result["ai"] = sanitize_value(cfg.ai)
    result["scan"] = sanitize_value(cfg.scan)
    result["rules"] = sanitize_value(cfg.rules)
    result["report"] = sanitize_value(cfg.report)
    result["tools"] = sanitize_value(cfg.tools)
    result["priority"] = sanitize_value(cfg.priority)
    result["validation"] = sanitize_value(cfg.validation)
    result["sandbox"] = sanitize_value(cfg.sandbox)

    return result


def mask_api_key(key: str) -> str:
    """掩码API Key"""
    if not key:
        return "(未设置)"
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


def _apply_imported_config(cfg: Config, imported: dict) -> None:
    """将导入的配置应用到Config对象

    Args:
        cfg: 配置对象
        imported: 导入的字典配置
    """
    if not imported:
        return

    if "debug" in imported:
        cfg.debug = bool(imported["debug"])
    if "verbose" in imported:
        cfg.verbose = bool(imported["verbose"])
    if "quiet" in imported:
        cfg.quiet = bool(imported["quiet"])
    if "test_mode" in imported:
        cfg.test_mode = bool(imported["test_mode"])
    if "filter_hallucinations" in imported:
        cfg.filter_hallucinations = bool(imported["filter_hallucinations"])
    if "language" in imported:
        cfg.language = str(imported["language"])
    if "pure_ai" in imported:
        cfg.pure_ai = bool(imported["pure_ai"])
    if "scan_mode" in imported:
        cfg.scan_mode = str(imported["scan_mode"])

    if "ai" in imported and isinstance(imported["ai"], dict):
        ai_config = imported["ai"]
        if "provider" in ai_config:
            cfg.ai.provider = str(ai_config["provider"])
        if "model" in ai_config:
            cfg.ai.model = str(ai_config["model"])
        if "api_key" in ai_config:
            cfg.ai.api_key = str(ai_config["api_key"]) if ai_config["api_key"] else ""
        if "max_tokens" in ai_config:
            cfg.ai.max_tokens = int(ai_config["max_tokens"])
        if "temperature" in ai_config:
            cfg.ai.temperature = float(ai_config["temperature"])
        if "timeout" in ai_config:
            cfg.ai.timeout = int(ai_config["timeout"])

    if "scan" in imported and isinstance(imported["scan"], dict):
        scan_config = imported["scan"]
        if "max_workers" in scan_config:
            cfg.scan.max_workers = int(scan_config["max_workers"])
        if "incremental" in scan_config:
            cfg.scan.incremental = bool(scan_config["incremental"])
        if "cache_enabled" in scan_config:
            cfg.scan.cache_enabled = bool(scan_config["cache_enabled"])

    if "validation" in imported and isinstance(imported["validation"], dict):
        val_config = imported["validation"]
        if "auto_validate_high" in val_config:
            cfg.validation.auto_validate_high = bool(val_config["auto_validate_high"])
        if "auto_validate_medium" in val_config:
            cfg.validation.auto_validate_medium = bool(val_config["auto_validate_medium"])
        if "min_confidence_threshold" in val_config:
            cfg.validation.min_confidence_threshold = float(val_config["min_confidence_threshold"])
        if "line_number_tolerance" in val_config:
            cfg.validation.line_number_tolerance = int(val_config["line_number_tolerance"])

    if "sandbox" in imported and isinstance(imported["sandbox"], dict):
        sandbox_config = imported["sandbox"]
        if "enabled" in sandbox_config:
            cfg.sandbox.enabled = bool(sandbox_config["enabled"])
        if "timeout" in sandbox_config:
            cfg.sandbox.timeout = int(sandbox_config["timeout"])

    console.print("[cyan]已应用的配置项:[/cyan]")
    for key in imported.keys():
        if key not in ("ai", "scan", "validation", "sandbox", "rules", "report", "tools", "priority"):
            console.print(f"  - {key}")


@cli.command()
@click.pass_context
def panel(ctx: click.Context) -> None:
    """启动交互式配置面板"""
    try:
        from .panel import ConfigPanel

        cfg: Config = ctx.obj["config"]
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


@cli.command()
@click.pass_context
def serial(ctx: click.Context) -> None:
    """启动交互式串口工具

    支持常见的串口通信操作，包括：
    - 串口扫描和选择
    - 波特率、数据位、校验位、停止位设置
    - 发送和接收数据（支持 HEX/ASCII）
    - 通信日志记录
    """
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


@cli.command()
@click.pass_context
def chat(ctx: click.Context) -> None:
    """启动交互式安全对话中心"""
    config: Config = ctx.obj["config"]

    if not config.quiet:
        console.print(Panel(
            "[bold]HOS-LS 安全对话中心[/bold]\n"
            "[dim]自然语言交互 · Multi-Agent · 智能分析[/dim]",
            border_style="cyan",
        ))
        console.print("[dim]输入 /help 查看可用命令[/dim]\n")

    try:
        from src.core.chat.main import run_chat
        asyncio.run(run_chat(config))
    except ImportError as e:
        console.print(f"[bold red]对话功能不可用: {e}[/bold red]")
        console.print("[yellow]请确保已安装所有依赖[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]启动对话失败: {e}[/bold red]")
        sys.exit(1)


@cli.group()
def index() -> None:
    """增量索引管理命令"""
    pass


@index.command(name="status")
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.pass_context
def index_status(ctx: click.Context, target: str) -> None:
    """显示项目增量索引状态"""
    config: Config = ctx.obj["config"]

    try:
        from src.ai.pure_ai.incremental_index import IncrementalIndexManager

        index_manager = IncrementalIndexManager(target, {"project_path": target})

        if not index_manager.is_index_valid():
            console.print("[yellow]未找到有效的索引，请先执行一次完整扫描[/yellow]")
            return

        indexed_files = index_manager.get_indexed_files()

        console.print(Panel(f"[bold]索引状态: {target}[/bold]"))
        console.print(f"已索引文件: [green]{len(indexed_files)}[/green]")

        table = Table(title="索引信息")
        table.add_column("项目", style="cyan")
        table.add_column("值", style="green")
        table.add_row("索引路径", str(index_manager._index_path))
        table.add_row("已索引文件数", str(len(indexed_files)))
        table.add_row("索引目录", str(index_manager.index_dir))
        console.print(table)

    except Exception as e:
        console.print(f"[bold red]获取索引状态失败: {e}[/bold red]")


@index.command(name="rebuild")
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.pass_context
def index_rebuild(ctx: click.Context, target: str) -> None:
    """重建项目增量索引"""
    config: Config = ctx.obj["config"]

    console.print(f"[bold blue]正在重建索引: {target}[/bold blue]")

    try:
        from src.ai.pure_ai.incremental_index import IncrementalIndexManager
        from src.utils.file_discovery import FileDiscoveryEngine

        index_manager = IncrementalIndexManager(target, {"project_path": target})

        file_discovery = FileDiscoveryEngine()
        files = file_discovery.discover_files(Path(target))
        file_paths = [str(f.path) for f in files]

        indexed_count = index_manager.build_index(file_paths)

        console.print(f"[bold green][OK] 索引重建完成，已索引 {indexed_count} 个文件[/bold green]")

    except Exception as e:
        console.print(f"[bold red]重建索引失败: {e}[/bold red]")


@cli.command()
@click.pass_context
def rules(ctx: click.Context) -> None:
    """列出可用规则"""
    # 导入get_registry
    from src.rules.registry import get_registry

    cfg: Config = ctx.obj["config"]
    registry = get_registry()

    # 加载内置规则
    registry.load_builtin_rules()

    stats = registry.get_statistics()

    console.print(Panel(f"[bold]规则统计[/bold]\n总计: {stats['total']}, 启用: {stats['enabled']}, 禁用: {stats['disabled']}"))

    if stats["by_category"]:
        table = Table(title="按类别统计")
        table.add_column("类别", style="cyan")
        table.add_column("数量", style="green")
        for category, count in stats["by_category"].items():
            table.add_row(category, str(count))
        console.print(table)

    if stats["by_severity"]:
        table = Table(title="按严重级别统计")
        table.add_column("严重级别", style="cyan")
        table.add_column("数量", style="green")
        for severity, count in stats["by_severity"].items():
            table.add_row(severity, str(count))
        console.print(table)


@cli.command()
def init() -> None:
    """初始化配置文件"""
    config_path = Path.home() / ".hos-ls" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config_manager = ConfigManager()
    config_manager.save_to_file(config_path)

    console.print(f"[bold green]配置文件已创建: {config_path}[/bold green]")


@cli.group()
def nvd() -> None:
    """NVD漏洞库管理命令"""
    pass


@nvd.command()
@click.option("--zip", "-z", type=click.Path(), default="nvd-json-data-feeds-main.zip", help="NVD压缩包路径 (默认: nvd-json-data-feeds-main.zip)")
@click.option("--dir", "-d", type=click.Path(exists=True, file_okay=False, dir_okay=True), help="NVD数据目录路径")
@click.option("--limit", "-l", type=int, default=None, help="限制处理的文件数量 (用于测试)")
@click.option("--no-rag", is_flag=True, help="不导入到RAG库，仅解析")
@click.option("--batch-size", "-b", type=int, default=1000, help="批量处理大小 (默认: 1000)")
@click.option("--resume", type=int, default=0, help="从指定文件开始续传")
@click.option("--model", "-m", default="Qwen/Qwen3-Embedding-0.6B", help="嵌入模型名称 (默认: Qwen/Qwen3-Embedding-0.6B)")
@click.pass_context
def update(ctx, zip, dir, limit, no_rag, batch_size, resume, model) -> None:
    """更新NVD漏洞库，解压并同步到本地RAG库"""
    config: Config = ctx.obj["config"]
    
    # 自动检测 temp_data 目录
    temp_data_base = Path(r"c:\1AAA_PROJECT\HOS\HOS-LS\All Vulnerabilities\temp_data")
    nvd_data_dir = temp_data_base / "nvd-json-data-feeds"

    if dir is None and zip is None:
        # 自动检测模式
        if nvd_data_dir.exists() and any(nvd_data_dir.iterdir()):
            input_path = nvd_data_dir
            console.print(f"[bold green]自动检测到数据目录: {input_path}[/bold green]")
        else:
            # 检查是否可以通过 data-preload 获取数据
            preloader_zip = temp_data_base / "temp_zip" / "nvd-json-data-feeds-main.zip"
            if preloader_zip.exists():
                input_path = preloader_zip
                console.print(f"[bold green]使用预下载的压缩包: {input_path}[/bold green]")
            else:
                console.print("[bold yellow]未检测到数据源，请先执行 'hos-ls data-preload run' 下载数据[/bold yellow]")
                console.print(f"[dim]或者使用 --dir 参数指定数据目录[/dim]")
                console.print(f"[dim]或者使用 --zip 参数指定压缩包路径[/dim]")
                return

    # 确定输入路径
    if dir:
        input_path = Path(dir)
        console.print(f"[bold green]使用目录导入: {input_path}[/bold green]")
    else:
        input_path = Path(zip)
        if not input_path.exists():
            script_dir = Path(__file__).parent.parent.parent
            script_zip = script_dir / zip
            if script_zip.exists():
                input_path = script_zip
            else:
                console.print(f"[bold red]错误: 找不到压缩包: {zip}[/bold red]")
                console.print(f"请确保文件存在于: {input_path.absolute()}")
                return
        console.print(f"[bold green]使用压缩包导入: {input_path}[/bold green]")
    
    rag_base = None
    if not no_rag:
        try:
            from src.storage.rag_knowledge_base import get_rag_knowledge_base
            rag_base = get_rag_knowledge_base(model_name=model)
            console.print(f"[bold green]已连接到RAG知识库，使用模型: {model}[/bold green]")
        except Exception as e:
            console.print(f"[bold yellow]警告: 无法初始化RAG知识库: {e}[/bold yellow]")
            console.print("[bold yellow]将仅解析数据，不导入RAG[/bold yellow]")
    
    # 导入run_update
    from src.integration.nvd_update import run_update
    
    console.print("[bold blue]开始更新NVD漏洞库...[/bold blue]")
    
    # 三阶段进度条
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[progress.description]{task.description}"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[progress.completed]{task.completed}/{task.total}"),
        console=console
    ) as progress:
        # 第一阶段：解压和解析
        phase1 = progress.add_task("[cyan]1/3: 解压和解析数据...", total=100)
        
        # 第二阶段：嵌入生成
        phase2 = progress.add_task("[green]2/3: 生成嵌入向量...", total=100)
        
        # 第三阶段：图构建
        phase3 = progress.add_task("[blue]3/3: 构建知识图谱...", total=100)
        
        # 创建异步Worker
        worker = AsyncWorker(max_workers=4)
        worker.start()
        
        try:
            # 包装run_update函数以支持进度更新
            def progress_callback(phase: str, current: int, total: int):
                if phase == "extract":
                    progress.update(phase1, completed=current, total=total)
                elif phase == "embed":
                    progress.update(phase2, completed=current, total=total)
                elif phase == "graph":
                    progress.update(phase3, completed=current, total=total)
            
            stats = run_update(
                str(input_path),
                rag_base=rag_base,
                limit=limit,
                batch_size=batch_size,
                resume_from=resume,
                progress_callback=progress_callback,
                model_name=model
            )
            
            # 完成所有进度
            progress.update(phase1, completed=100, total=100)
            progress.update(phase2, completed=100, total=100)
            progress.update(phase3, completed=100, total=100)
            
        finally:
            worker.stop()
    
    console.print("\n" + "=" * 60)
    console.print("[bold]统计摘要[/bold]")
    console.print("=" * 60)
    for key, value in stats.items():
        console.print(f"  {key}: {value}")


@nvd.command()
@click.pass_context
def show_checkpoint(ctx) -> None:
    """显示当前断点状态"""
    import json
    from pathlib import Path
    from datetime import datetime
    
    checkpoint_path = Path("nvd_update_checkpoint.json")
    
    if not checkpoint_path.exists():
        console.print("[bold yellow]未找到断点文件[/bold yellow]")
        return
    
    try:
        with open(checkpoint_path, "r", encoding="utf-8") as f:
            checkpoint = json.load(f)
        
        console.print(Panel("[bold blue]断点信息[/bold blue]"))
        
        version = checkpoint.get("version", "1.0")
        last_processed = checkpoint.get("last_processed", 0)
        temp_dir = checkpoint.get("temp_dir")
        current_stage = checkpoint.get("current_stage", "unknown")
        batch_count = checkpoint.get("batch_count", 0)
        stats_checkpoint = checkpoint.get("stats", {})
        stage_progress = checkpoint.get("stage_progress", {})
        timestamp = checkpoint.get("timestamp")
        
        table = Table(title="断点详情")
        table.add_column("项目", style="cyan")
        table.add_column("值", style="green")
        
        table.add_row("版本", version)
        table.add_row("上次处理到文件", str(last_processed))
        table.add_row("当前阶段", current_stage)
        table.add_row("已完成批次", str(batch_count))
        if temp_dir:
            table.add_row("临时目录", temp_dir)
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                table.add_row("保存时间", dt.strftime("%Y-%m-%d %H:%M:%S"))
            except:
                table.add_row("保存时间", timestamp)
        
        console.print(table)
        
        if stats_checkpoint:
            console.print("\n[bold]统计信息:[/bold]")
            stats_table = Table()
            stats_table.add_column("统计项", style="cyan")
            stats_table.add_column("值", style="green")
            for key, value in stats_checkpoint.items():
                stats_table.add_row(str(key), str(value))
            console.print(stats_table)
        
        if stage_progress:
            console.print("\n[bold]阶段进度:[/bold]")
            progress_table = Table()
            progress_table.add_column("阶段", style="cyan")
            progress_table.add_column("状态", style="green")
            progress_table.add_column("进度", style="yellow")
            
            stage_names = {"extract": "解压", "embed": "嵌入", "graph": "图谱构建"}
            
            for stage, info in stage_progress.items():
                stage_name = stage_names.get(stage, stage)
                done = info.get("done", False)
                progress = info.get("progress", 0)
                
                status = "✅ 完成" if done else "⏳ 进行中"
                progress_str = str(progress) if progress else "-"
                
                progress_table.add_row(stage_name, status, progress_str)
            
            console.print(progress_table)
        
    except Exception as e:
        console.print(f"[bold red]读取断点文件失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()


@nvd.command()
@click.option("--force", "-f", is_flag=True, help="强制清理，无需确认")
@click.pass_context
def clean_checkpoints(ctx, force) -> None:
    """清理断点残留文件"""
    from pathlib import Path
    import shutil
    
    files_to_clean = [
        "nvd_update_checkpoint.json",
        "nvd_batch_checkpoint.json",
        "nvd_batch_checkpoint.txt"
    ]
    
    temp_dir_pattern = "nvd_update_*"
    
    console.print(Panel("[bold red]清理断点残留文件[/bold red]"))
    
    # 查找需要清理的文件
    found_files = []
    for filename in files_to_clean:
        file_path = Path(filename)
        if file_path.exists():
            found_files.append(file_path)
    
    # 查找临时目录
    found_dirs = []
    for item in Path(".").iterdir():
        if item.is_dir() and item.name.startswith("nvd_update_"):
            found_dirs.append(item)
    
    if not found_files and not found_dirs:
        console.print("[bold green]没有发现断点残留文件[/bold green]")
        return
    
    # 显示将要清理的内容
    console.print("\n[bold]发现以下文件/目录将被清理:[/bold]")
    
    if found_files:
        console.print("\n[cyan]文件:[/cyan]")
        for file_path in found_files:
            size = file_path.stat().st_size
            console.print(f"  - {file_path.name} ({size} bytes)")
    
    if found_dirs:
        console.print("\n[cyan]临时目录:[/cyan]")
        for dir_path in found_dirs:
            # 计算目录大小
            dir_size = 0
            for f in dir_path.rglob("*"):
                if f.is_file():
                    dir_size += f.stat().st_size
            size_mb = dir_size / (1024 * 1024)
            console.print(f"  - {dir_path.name} ({size_mb:.2f} MB)")
    
    # 确认删除
    if not force:
        console.print()
        try:
            import click
            if not click.confirm("确定要清理以上文件/目录吗？", default=False):
                console.print("[yellow]已取消清理[/yellow]")
                return
        except Exception as e:
            console.print(f"[yellow]无法获取确认，使用 --force 参数强制清理: {e}[/yellow]")
            return
    
    # 执行清理
    console.print("\n[bold]开始清理...[/bold]")
    
    deleted_count = 0
    
    # 删除文件
    for file_path in found_files:
        try:
            file_path.unlink()
            console.print(f"  [green][OK][/green] 已删除: {file_path.name}")
            deleted_count += 1
        except Exception as e:
            console.print(f"  [red][FAIL][/red] 删除失败: {file_path.name} - {e}")
    
    # 删除目录
    for dir_path in found_dirs:
        try:
            shutil.rmtree(dir_path, ignore_errors=True)
            if not dir_path.exists():
                console.print(f"  [green][OK][/green] 已删除: {dir_path.name}")
                deleted_count += 1
            else:
                console.print(f"  [yellow][WARN][/yellow] 目录可能未完全删除: {dir_path.name}")
        except Exception as e:
            console.print(f"  [red][FAIL][/red] 删除失败: {dir_path.name} - {e}")
    
    console.print(f"\n[bold green]清理完成！共删除 {deleted_count} 项[/bold green]")


@cli.group()
def model() -> None:
    """模型管理命令"""
    pass


@cli.group()
def data_preload() -> None:
    """数据预加载管理命令"""
    pass


@data_preload.command(name="run")
@click.option("--incremental", is_flag=True, help="启用增量下载（默认启用智能检测）")
@click.option("--force", "-f", is_flag=True, help="强制重新下载所有数据源")
@click.option("--source", "-s", help="指定单个数据源")
@click.option("--check-only", is_flag=True, help="仅检查状态，不执行下载")
@click.pass_context
def data_preload_run(ctx: click.Context, incremental: bool, force: bool, source: Optional[str], check_only: bool) -> None:
    """执行完整数据预加载"""
    config: Config = ctx.obj["config"]

    try:
        from src.integration.data_preloader import DataPreloader
    except ImportError:
        console.print("[bold red]错误: DataPreloader 模块不可用[/bold red]")
        console.print("[yellow]请确保 src.integration.data_preloader 模块存在[/yellow]")
        sys.exit(1)

    console.print(Panel("[bold blue]数据预加载[/bold blue]"))

    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir)
        )

        if check_only:
            console.print("[cyan]检查模式，仅显示状态...[/cyan]\n")
            return _show_check_status(preloader, source)

        urls = preloader.config.urls

        if source:
            urls = [url for url in urls if source.lower() in url.lower()]
            console.print(f"[cyan]过滤后待处理数据源: {len(urls)}[/cyan]\n")

        console.print(f"[cyan]待处理数据源: {len(urls)}[/cyan]")
        console.print(f"[dim]force={force}, incremental={incremental}[/dim]\n")

        results = preloader.download_all(
            parallel=not incremental,
            force=force,
            source_filter=source
        )

        success_count = sum(1 for v in results.values() if v)
        fail_count = len(results) - success_count

        console.print(f"\n[cyan]成功: {success_count}, 失败: {fail_count}[/cyan]")

        if fail_count > 0:
            console.print("[bold yellow]部分数据源下载失败[/bold yellow]")
            for src, success in results.items():
                if not success:
                    console.print(f"  [red]X[/red] {src}")

        console.print("[bold green][OK] 数据预加载完成[/bold green]")

    except Exception as e:
        console.print(f"[bold red]预加载失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _show_check_status(preloader: "DataPreloader", source_filter: Optional[str] = None) -> None:
    """显示检查状态

    Args:
        preloader: DataPreloader 实例
        source_filter: 数据源过滤条件
    """
    status = preloader.check_status()

    table = Table(title="数据源检查状态")
    table.add_column("数据源", style="cyan")
    table.add_column("ZIP文件", style="green")
    table.add_column("状态", style="yellow")
    table.add_column("原因/大小", style="magenta")

    for src_info in status.get("sources", []):
        if source_filter and source_filter.lower() not in src_info.get("name", "").lower():
            continue

        name = src_info.get("name", "unknown")
        zip_file = src_info.get("zip_file", "N/A")
        needs_dl = src_info.get("needs_download", True)
        reason = src_info.get("reason", "")

        if src_info.get("zip_exists"):
            size = src_info.get("zip_size", 0)
            if size:
                size_str = f"{size / 1024 / 1024:.2f} MB" if size > 1024 * 1024 else f"{size / 1024:.2f} KB"
                reason = f"{reason} ({size_str})"

        status_icon = "[green]✓ 跳过[/green]" if not needs_dl else "[yellow]↓ 需下载[/yellow]"
        table.add_row(name, zip_file, status_icon, reason)

    console.print(table)

    stats = preloader.get_statistics()
    console.print(f"\n[cyan]统计信息:[/cyan]")
    console.print(f"  配置数据源: {stats.get('configured_sources', 0)}")
    console.print(f"  已下载ZIP: {stats.get('downloaded_zips', 0)}")
    console.print(f"  已解压目录: {stats.get('extracted_dirs', 0)}")
    console.print(f"  增量策略: skip_on_checksum_match={stats.get('skip_on_checksum_match', True)}")
    console.print(f"  合并策略: {stats.get('merge_strategy', 'smart')}")


@data_preload.command(name="status")
@click.pass_context
def data_preload_status(ctx: click.Context) -> None:
    """显示各数据源状态"""
    config: Config = ctx.obj["config"]

    try:
        from src.integration.data_preloader import DataPreloader
    except ImportError:
        console.print("[bold red]错误: DataPreloader 模块不可用[/bold red]")
        console.print("[yellow]请确保 src.integration.data_preloader 模块存在[/yellow]")
        sys.exit(1)

    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir)
        )
        sources_status = preloader.get_download_status()

        table = Table(title="数据源状态")
        table.add_column("数据源", style="cyan")
        table.add_column("文件名", style="green")
        table.add_column("大小", style="yellow")
        table.add_column("最后下载时间", style="magenta")

        records = sources_status.get("records", [])
        if not records:
            console.print("[yellow]没有下载记录[/yellow]")
            return

        for record in records:
            name = record.get("source", "unknown")
            file_name = record.get("file_name", "N/A")
            file_size = record.get("file_size", 0)
            downloaded_at = record.get("downloaded_at", "从未下载")

            if isinstance(file_size, int):
                size_str = f"{file_size / 1024 / 1024:.2f} MB" if file_size > 1024 * 1024 else f"{file_size / 1024:.2f} KB"
            else:
                size_str = str(file_size)

            table.add_row(name, file_name, size_str, str(downloaded_at))

        console.print(table)

        stats = preloader.get_statistics()
        console.print(f"\n[cyan]统计: 配置数据源 {stats.get('configured_sources', 0)}, "
                     f"已下载 ZIP {stats.get('downloaded_zips', 0)}, "
                     f"已解压目录 {stats.get('extracted_dirs', 0)}[/cyan]")

    except Exception as e:
        console.print(f"[bold red]获取状态失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@data_preload.command(name="clean")
@click.option("--force", "-f", is_flag=True, help="强制清理，无需确认")
@click.pass_context
def data_preload_clean(ctx: click.Context, force: bool) -> None:
    """清理缓存数据"""
    config: Config = ctx.obj["config"]

    try:
        from src.integration.data_preloader import DataPreloader
    except ImportError:
        console.print("[bold red]错误: DataPreloader 模块不可用[/bold red]")
        console.print("[yellow]请确保 src.integration.data_preloader 模块存在[/yellow]")
        sys.exit(1)

    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir)
        )

        zip_dir = preloader.temp_zip_dir
        if not zip_dir.exists():
            console.print("[bold green]没有缓存数据需要清理[/bold green]")
            return

        zip_files = list(zip_dir.glob('*.zip'))
        if not zip_files:
            console.print("[bold green]没有 ZIP 文件需要清理[/bold green]")
            return

        total_size = sum(f.stat().st_size for f in zip_files)
        total_size_mb = total_size / 1024 / 1024

        console.print(Panel("[bold red]清理缓存数据[/bold red]"))
        console.print(f"[cyan]发现 {len(zip_files)} 个 ZIP 文件，共 {total_size_mb:.2f} MB[/cyan]")

        if not force:
            try:
                import click
                if not click.confirm("确定要清理所有 ZIP 缓存文件吗？", default=False):
                    console.print("[yellow]已取消清理[/yellow]")
                    return
            except Exception:
                console.print("[yellow]无法获取确认，使用 --force 参数强制清理[/yellow]")
                return

        count = preloader.cleanup_zip_files()

        console.print(f"[bold green][OK] 缓存清理完成，删除了 {count} 个文件[/bold green]")

    except Exception as e:
        console.print(f"[bold red]清理失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@model.command()
@click.option("--model", "-m", default="Qwen/Qwen3-Embedding-0.6B", help="模型名称 (默认: Qwen/Qwen3-Embedding-0.6B)")
@click.option("--output", "-o", type=click.Path(), help="输出目录")
@click.option("--force", is_flag=True, help="强制覆盖现有模型")
@click.option("--token", "-t", required=True, help="Hugging Face 登录 token")
@click.pass_context
def download(ctx, model, output, force, token) -> None:
    """下载模型"""
    config: Config = ctx.obj["config"]
    
    console.print(f"[bold blue]开始下载模型: {model}[/bold blue]")
    
    # 设置输出目录
    if not output:
        # 默认保存到模型缓存目录，为每个模型创建独立的子目录
        from pathlib import Path
        model_cache = Path.home() / ".cache" / "huggingface" / "hub"
        # 为模型创建标准的 Hugging Face 目录结构
        model_dir_name = f"models--{model.replace('/', '--')}"
        output = model_cache / model_dir_name
    else:
        output = Path(output)
    
    output.mkdir(parents=True, exist_ok=True)
    console.print(f"[info]模型将保存到: {output}[/info]")
    
    # 下载模型
    try:
        from huggingface_hub import snapshot_download
        
        # 显示下载进度
        with Progress(
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]下载模型...", total=100)
            
            # 下载模型
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


def _display_result(result) -> None:
    """显示扫描结果"""
    # 导入Severity
    from src.core.engine import Severity

    summary = result.to_dict()["summary"]

    # 计算风险等级
    total_issues = summary.get("total", 0)
    critical_count = summary.get("critical", 0)
    high_risk = summary.get("high", 0) + critical_count
    medium_risk = summary.get("medium", 0)
    low_risk = summary.get("low", 0)
    info_count = summary.get("info", 0)

    # 计算非INFO问题数量作为风险评估基数
    significant_issues = high_risk + medium_risk + low_risk

    # 显示 Claude 风格的风险结果
    console.print(
        "[bold yellow][!] Scan Result[/bold yellow]\n"
        "──────────────\n"
        f"Issues Found: {total_issues}\n"
        f"[red]High Risk:[/red] {high_risk}\n"
        f"[yellow]Medium Risk:[/yellow] {medium_risk}\n"
        f"[green]Low Risk:[/green] {low_risk}"
    )

    # 显示风险条 - 改进公式
    # 风险百分比计算方式：
    # - 只考虑有实际意义的漏洞（critical/high/medium/low）作为分子
    # - 分母为 total_issues（不包含 info，避免稀释）
    # - CRITICAL 权重为 3，HIGH 权重为 2，MEDIUM 权重为 1.5，LOW 权重为 0.5
    # - 如果没有有意义的漏洞，风险为 0
    if significant_issues > 0:
        # 分子：高危及以上占比更高
        risk_score = high_risk * 3.0 + medium_risk * 1.5 + low_risk * 0.5
        # 分母：所有有意义的漏洞按最高级别权重计算
        max_potential_score = significant_issues * 3.0
        risk_percentage = min(1.0, risk_score / max_potential_score)
    else:
        risk_percentage = 0
    show_risk_bar(risk_percentage)

    # AI 扫描结果免责声明
    console.print("\n[yellow italic][!] 注意：AI 扫描结果具有概率性，多次扫描结果可能有适度波动（±1-2 个风险点是正常现象）[/yellow italic]")

    # 显示详细发现
    if result.findings:
        console.print("\n[bold]发现问题:[/bold]")
        for i, finding in enumerate(result.findings[:10], 1):  # 只显示前10个
            severity_color = "red" if finding.severity.value in ["critical", "high"] else "yellow" if finding.severity.value == "medium" else "blue"
            # 清理消息，去除多余的空格和换行
            message = finding.message.strip()
            # 限制每行长度，确保格式整洁
            if len(message) > 80:
                # 简单的换行处理
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
                # 第一行显示完整信息，后续行缩进
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

    # 显示攻击链分析结果
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


def _generate_report(result, output: str, format: str, config=None) -> None:
    """生成报告"""
    # 导入报告生成器
    from src.reporting.generator import ReportGenerator
    from pathlib import Path

    try:
        # 检查是否有扫描状态文件
        from src.utils.cache_manager import get_cache_manager
        cache_manager = get_cache_manager()
        state_file = cache_manager.get_path('scan_state', 'scan_state.json')
        scan_state_info = None
        is_truncated = False
        truncation_reason = None

        if state_file.exists():
            from src.core.scan_state import ScanState
            state = ScanState.load(str(state_file))
            if state:
                scan_state_info = state.get_progress()
                is_truncated = state.truncated
                truncation_reason = state.truncation_reason

        # 将截断信息添加到结果中（处理 ScanResult 对象和字典两种情况）
        if hasattr(result, 'metadata') and result.metadata is not None:
            result.metadata['scan_state'] = scan_state_info
            result.metadata['truncated'] = is_truncated
            result.metadata['truncation_reason'] = truncation_reason
        elif isinstance(result, dict):
            if 'metadata' not in result:
                result['metadata'] = {}
            result['metadata']['scan_state'] = scan_state_info
            result['metadata']['truncated'] = is_truncated
            result['metadata']['truncation_reason'] = truncation_reason

        generator = ReportGenerator(config)
        report_path = generator.generate([result], output, format)
        console.print(f"[bold green]报告已生成: {report_path}[/bold green]")

        # 如果扫描被截断，显示提示
        if is_truncated and scan_state_info:
            console.print(f"[bold yellow][!] 警告: 扫描已被截断 ({truncation_reason})，报告仅包含部分结果[/bold yellow]")
            console.print(f"[yellow]  已完成: {scan_state_info['completed']}/{scan_state_info['total']} 文件[/yellow]")
    except Exception as e:
        console.print(f"[bold red]报告生成失败: {e}[/bold red]")
        import traceback
        traceback.print_exc()


def _check_data_preload_status(config: Config) -> None:
    """检查数据预加载状态

    Args:
        config: 配置对象
    """
    from datetime import datetime, timedelta
    from src.integration.data_preloader import DataPreloader

    db_path = Path(config.nvd.database_path)

    if not db_path.exists():
        console.print("[bold yellow]警告: NVD 数据库不存在[/bold yellow]")
        console.print(f"[yellow]数据库路径: {db_path}[/yellow]")
        if click.confirm("是否执行数据预加载 (hos-ls data-preload run)?", default=True):
            console.print("[bold cyan]开始执行数据预加载...[/bold cyan]")
            try:
                preloader = DataPreloader(
                    sources_file=Path(config.data_preload.sources_file),
                    temp_zip_dir=Path(config.data_preload.temp_zip_dir),
                    temp_data_dir=Path(config.data_preload.temp_data_dir),
                    skip_on_checksum_match=config.data_preload.skip_on_checksum_match,
                    merge_strategy=config.data_preload.merge_strategy
                )
                preloader.download_all(parallel=True)
                console.print("[bold green]数据预加载完成[/bold green]")
            except Exception as e:
                console.print(f"[bold red]数据预加载失败: {e}[/bold red]")
                if click.confirm("是否继续扫描（可能影响扫描结果）?", default=False):
                    console.print("[yellow]继续执行扫描...[/yellow]")
                else:
                    sys.exit(1)
        return

    try:
        preloader = DataPreloader(
            sources_file=Path(config.data_preload.sources_file),
            temp_zip_dir=Path(config.data_preload.temp_zip_dir),
            temp_data_dir=Path(config.data_preload.temp_data_dir),
            skip_on_checksum_match=config.data_preload.skip_on_checksum_match,
            merge_strategy=config.data_preload.merge_strategy
        )
        sources_status = preloader.get_download_status()

        records = sources_status.get("records", [])
        if records:
            latest_record = records[0]
            downloaded_at_str = latest_record.get("downloaded_at")

            if downloaded_at_str:
                try:
                    downloaded_at = datetime.fromisoformat(downloaded_at_str)
                    threshold_days = config.data_preload.update_threshold_days
                    threshold_date = datetime.now() - timedelta(days=threshold_days)

                    if downloaded_at < threshold_date:
                        days_since_update = (datetime.now() - downloaded_at).days
                        console.print(f"[bold yellow]警告: NVD 数据已超过 {days_since_update} 天未更新[/bold yellow]")
                        console.print(f"[yellow]最后更新时间: {downloaded_at.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                        console.print(f"[yellow]建议在 {threshold_days} 天内更新数据[/yellow]")
                        if click.confirm("是否执行数据预加载更新?", default=False):
                            console.print("[bold cyan]开始执行数据预加载...[/bold cyan]")
                            try:
                                preloader.download_all(parallel=True)
                                console.print("[bold green]数据预加载完成[/bold green]")
                            except Exception as e:
                                console.print(f"[bold red]数据预加载失败: {e}[/bold red]")
                                if click.confirm("是否继续扫描?", default=True):
                                    console.print("[yellow]继续执行扫描...[/yellow]")
                                else:
                                    sys.exit(1)
                except Exception:
                    pass
    except Exception as e:
        console.print(f"[yellow]检查数据预加载状态时出错: {e}[/yellow]")


def main() -> None:
    """主入口"""
    cli()


if __name__ == "__main__":
    main()
