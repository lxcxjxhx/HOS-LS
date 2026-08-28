"""扫描命令模块

从 main.py 提取的 scan 命令。
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel

from src.cli.main import cli, console
from src.core.config import AuditMode, AIModuleConfig, SandboxConfig


def register_scan(cli_group):
    """注册 scan 命令到 CLI 组"""
@cli_group.command()
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.option(
    "--format", "-", "output_format", default="html", help="输出格式 (html, markdown, json, sarif)"
)
@click.option("--output", "-o", help="输出文件路径")
@click.option("--ruleset", "-r", help="规则集")
@click.option("--diff", is_flag=True, help="扫描 Git 差异")
@click.option("--workers", "-w", type=int, default=4, help="工作线程数")
@click.option("--ai", is_flag=True, help="启用 AI 分析")
@click.option("--pure-ai", is_flag=True, help="启用纯AI深度语义解析模式，只执行AI分析和报告导出")
@click.option(
    "--mode",
    "-m",
    type=click.Choice(
        ["auto", "pure-ai", "fast", "deep", "stealth", "vuln-lab"], case_sensitive=False
    ),
    default="auto",
    help="扫描模式: auto(自动), pure-ai(纯AI), fast(快速), deep(深度), stealth(隐蔽), vuln-lab(靶场对抗)",
)
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
@click.option(
    "--language",
    "-l",
    type=click.Choice(["zh", "en"], case_sensitive=False),
    default=None,
    help="界面语言: zh(中文), en(英文)，默认跟随配置文件",
)
@click.option(
    "--audit-mode",
    type=click.Choice(["static", "dynamic", "hybrid"]),
    default="hybrid",
    help="审计模式: static(静态), dynamic(动态), hybrid(混合)",
)
@click.option("--static-only", is_flag=True, help="仅执行静态分析，不进行动态验证")
@click.option("--dynamic-only", is_flag=True, help="仅执行AI红队POC动态测试，不进行静态扫描")
@click.option("--generate-poc", is_flag=True, help="为扫描发现生成 POC 脚本")
@click.option("--run-poc", is_flag=True, help="执行 POC 验证")
@click.option("--poc-only", is_flag=True, help="仅生成 POC，不执行扫描（与 --dynamic-only 配合使用）")
@click.option(
    "--min-confidence",
    type=click.Choice(["HIGH", "MEDIUM", "LOW", "ALL"]),
    default="HIGH",
    help="最低置信度过滤 (默认: HIGH)",
)
@click.option("--scan-ports", is_flag=True, help="启用API端口配置扫描，提前发现端口配置和生成模式")
@click.option("--ports-only", is_flag=True, help="仅执行端口扫描，不进行漏洞扫描")
@click.option(
    "--port-range",
    type=str,
    default="1-65535",
    help="端口扫描范围，格式: start-end (默认: 1-65535)",
)
@click.option(
    "--priority",
    type=click.Choice(
        ["api-first", "security-first", "performance-first", "full-scan", "custom"],
        case_sensitive=False,
    ),
    default="full-scan",
    help="扫描优先级策略: api-first(API优先), security-first(安全优先), performance-first(性能优先), full-scan(全面扫描), custom(自定义)",
)
@click.option("--priority-rules", type=click.Path(exists=True), help="自定义优先级规则文件路径 (YAML/JSON)")
@click.option(
    "--report-category",
    type=click.Choice(
        [
            "all",
            "port-related",
            "general-static",
            "special-scan",
            "api-security",
            "auth-security",
            "data-protection",
            "config-security",
        ],
        case_sensitive=False,
    ),
    default="all",
    help="报告分类过滤: all(全部), port-related(端口相关), general-static(一般静态), special-scan(特别扫描), api-security(API安全), auth-security(认证安全), data-protection(数据保护), config-security(配置安全)",
)
@click.option("--remote", is_flag=True, help="启用远程扫描模式")
@click.option(
    "--remote-type",
    type=click.Choice(["ssh", "http", "serial"], case_sensitive=False),
    default="ssh",
    help="远程连接类型",
)
@click.option("--remote-host", help="远程主机地址")
@click.option("--remote-port", type=int, help="远程端口")
@click.option("--remote-username", help="远程用户名(SSH)")
@click.option("--remote-password", help="远程密码(SSH)")
@click.option("--remote-key", help="SSH私钥路径")
@click.option("--remote-path", help="远程扫描路径")
@click.option("--serial-baudrate", type=int, default=115200, help="串口波特率")
@click.option("--serial-port", help="串口端口(如 COM1)")
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
        config.ai.modules["pure_ai"].model = "deepseek-v4-flash"

        # 端口扫描配置
        if scan_ports:
            config.scan.port_scan_enabled = True
            config.scan.ports_only = ports_only
            config.scan.port_range = port_range
            if not config.quiet:
                console.print(f"[bold cyan][PORT] 端口扫描已启用, 范围: {port_range}[/bold cyan]")
            if ports_only:
                console.print("[bold yellow][PORT] 警告: 仅执行端口扫描模式，不进行漏洞扫描[/bold yellow]")

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
            config.__dict__["test_file_count"] = test
            if not config.quiet:
                console.print(f"[bold yellow][!] 测试模式已启用，只扫描前{test}个优先级最高的文件[/bold yellow]")
        elif test == 0:
            config.test_mode = False
        else:
            config.test_mode = True
            config.__dict__["test_file_count"] = 10
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
            from src.core.config import AuditMode, SandboxConfig

            # 参数优先级: --static-only > --dynamic-only > --audit-mode
            audit_mode_enum: AuditMode
            if static_only:
                audit_mode_enum = AuditMode.STATIC
                if not config.quiet:
                    console.print("[bold yellow][!] 审计模式: STATIC (纯静态分析)[/bold yellow]")
            elif dynamic_only:
                audit_mode_enum = AuditMode.DYNAMIC
                if not config.quiet:
                    console.print("[bold yellow][!] 审计模式: DYNAMIC (纯动态AI红队POC测试)[/bold yellow]")
            else:
                audit_mode_enum = AuditMode(audit_mode)
                if not config.quiet:
                    mode_display = {"static": "STATIC", "dynamic": "DYNAMIC", "hybrid": "HYBRID"}
                    console.print(
                        f"[bold yellow][!] 审计模式: {mode_display.get(audit_mode, audit_mode.upper())}[/bold yellow]"
                    )

            sandbox_cfg = SandboxConfig(enabled=True, mode=audit_mode_enum)
            config.sandbox = sandbox_cfg

            if not config.quiet and audit_mode_enum != AuditMode.STATIC:
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
        from src.core.remote_scanner import create_scanner

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
                    "type": remote_type,
                    "host": remote_host,
                    "port": remote_port,
                    "username": remote_username,
                    "password": remote_password,
                    "key_path": remote_key,
                    "remote_path": remote_path or "/",
                }

                if remote_type == "serial":
                    remote_config["port"] = serial_port
                    remote_config["baudrate"] = serial_baudrate
                elif remote_type == "ssh":
                    remote_config["port"] = remote_port or 22
                    remote_config["key_path"] = remote_key
                elif remote_type == "http":
                    remote_config["port"] = remote_port or 80
                    remote_config["use_ssl"] = remote_type == "https"

                if not config.quiet:
                    console.print(
                        f"[bold cyan][REMOTE] 远程扫描模式: {remote_type}://{remote_host}:{remote_config.get('port', 'default')}[/bold cyan]"
                    )

                scanner = create_scanner(config, remote_config)
            else:
                scanner = create_scanner(config)
            result = scanner.scan_sync(target)

            # 显示结果
            if not config.quiet:
                show_agent_status()
                _display_result(result)

            _integrate_poc(config, result, target, generate_poc, run_poc, poc_only)

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

    if ai_provider:
        config.ai.provider = ai_provider

    if ai_model:
        config.ai.model = ai_model

    if tool_chain:
        config.tools.enabled = True
        config.tools.tool_chain = [t.strip() for t in tool_chain.split(",") if t.strip()]
        console.print(f"[bold cyan]🔧 工具链已启用: {config.tools.tool_chain}[/bold cyan]")

    # 端口扫描配置
    if scan_ports:
        config.scan.port_scan_enabled = True
        config.scan.ports_only = ports_only
        config.scan.port_range = port_range
        if not config.quiet:
            console.print(f"[bold cyan][PORT] 端口扫描已启用, 范围: {port_range}[/bold cyan]")
        if ports_only:
            console.print("[bold yellow][PORT] 警告: 仅执行端口扫描模式，不进行漏洞扫描[/bold yellow]")

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
        config.__dict__["test_file_count"] = test
        if not config.quiet:
            console.print(f"[bold yellow][!] 测试模式已启用，只扫描前{test}个优先级最高的文件[/bold yellow]")
    elif test == 0:
        config.test_mode = False
    else:
        config.test_mode = True
        config.__dict__["test_file_count"] = 10
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
                with open(target_path, "r", encoding="utf-8") as f:
                    code = f.read()
            else:
                code = f"目录扫描: {target}"
            # 运行多Agent分析
            result = asyncio.run(analyze_code(code))
            # 显示结果
            if not config.quiet:
                console.print(Panel("[bold]LangGraph 多Agent分析结果[/bold]"))
                if "final_report" in result:
                    report = result["final_report"]
                    console.print(f"[green]分析状态: {report.get('quality', 'unknown')}[/green]")
                    console.print(f"[green]迭代次数: {report.get('iteration', 0)}[/green]")
                    console.print(
                        f"[green]CVE候选数量: {len(report.get('cve_candidates', []))}[/green]"
                    )
                    console.print("[green]攻击链长度: {len(report.get('attack_chain', {}))}[/green]")
                    console.print("[bold]分析结果:[/bold]")
                    console.print(report.get("analysis", ""))
                    if "fix_suggestions" in report:
                        console.print("[bold]修复建议:[/bold]")
                        console.print(report.get("fix_suggestions", ""))
                else:
                    console.print(f"[red]分析失败: {result.get('error', '未知错误')}[/red]")
            # 生成报告
            if output:
                import json

                with open(output, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                console.print(f"[bold green]报告已生成: {output}[/bold green]")
            # 根据结果设置退出码
            if result.get("final_report", {}).get("quality") != "pass":
                sys.exit(1)
        else:
            # 使用传统扫描器
            from src.core.remote_scanner import create_scanner

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
                    "type": remote_type,
                    "host": remote_host,
                    "port": remote_port,
                    "username": remote_username,
                    "password": remote_password,
                    "key_path": remote_key,
                    "remote_path": remote_path or "/",
                }

                if remote_type == "serial":
                    remote_config["port"] = serial_port
                    remote_config["baudrate"] = serial_baudrate
                elif remote_type == "ssh":
                    remote_config["port"] = remote_port or 22
                    remote_config["key_path"] = remote_key
                elif remote_type == "http":
                    remote_config["port"] = remote_port or 80
                    remote_config["use_ssl"] = remote_type == "https"

                if not config.quiet:
                    console.print(
                        f"[bold cyan][REMOTE] 远程扫描模式: {remote_type}://{remote_host}:{remote_config.get('port', 'default')}[/bold cyan]"
                    )

                scanner = create_scanner(config, remote_config)
            else:
                scanner = create_scanner(config)
            result = scanner.scan_sync(target)

            # 显示结果
            if not config.quiet:
                show_agent_status()
                _display_result(result)

            _integrate_poc(config, result, target, generate_poc, run_poc, poc_only)

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


@cli_group.command()
@click.option(
    "--export",
    "-e",
    type=click.Choice(["yaml", "json"], case_sensitive=False),
    default=None,
    help="导出配置为指定格式",
)
@click.option(
    "--import",
    "-i",
    "--input",
    "import_file",
    type=click.Path(exists=True),
    default=None,
    help="从文件导入配置",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="导出文件路径")
@click.pass_context
