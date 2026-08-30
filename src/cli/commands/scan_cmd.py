"""扫描命令

HOS-LS 的主要扫描入口命令。
"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console

from src.core.config import Config, ConfigManager
from src.cli.main import cli, console


@cli.command()
@click.argument("target", required=False, default=".", type=click.Path(exists=True))
@click.option("--output", "-o", help="输出文件路径")
@click.option("--ruleset", "-r", help="规则集")
@click.option("--diff", is_flag=True, help="扫描 Git 差异")
@click.option("--workers", "-w", type=int, default=4, help="工作线程数")
@click.option("--ai", is_flag=True, help="启用 AI 分析")
@click.option("--pure-ai", is_flag=True, help="启用纯AI深度语义解析模式")
@click.option("--ai-provider", help="AI 提供商")
@click.option("--ai-model", help="AI 模型")
@click.option("--incremental", is_flag=True, help="启用增量扫描")
@click.option("--langgraph", is_flag=True, help="使用 LangGraph 流程")
@click.option("--test", type=int, default=0, help="启用测试模式")
@click.option("--resume", is_flag=True, help="从断点恢复扫描")
@click.option("--truncate-output", is_flag=True, help="启用截断模式")
@click.option("--max-duration", type=int, default=0, help="最大扫描时长（秒）")
@click.option("--max-files", type=int, default=0, help="最大扫描文件数")
@click.option("--full-scan", is_flag=True, help="强制全量扫描")
@click.option("--index-status", is_flag=True, help="显示索引状态")
@click.option("--explain", is_flag=True, help="显示执行流程")
@click.option("--ask", help="轻量对话")
@click.option("--focus", help="聚焦分析指定文件或目录")
@click.option("--tool-chain", help="工具链，用逗号分隔")
@click.option("--skip-data-update", is_flag=True, help="跳过数据更新检查")
@click.option("--sandbox", is_flag=True, help="启用沙盒动态验证")
@click.option("--priority-strategy", type=click.Choice(["full-scan", "api-first", "security-first", "performance-first", "balanced"]), default=None, help="扫描优先级策略")
@click.option("--static-only", is_flag=True, help="仅执行静态分析")
@click.option("--dynamic-only", is_flag=True, help="仅执行AI红队POC动态测试")
@click.option("--generate-poc", is_flag=True, help="生成 POC 脚本")
@click.option("--run-poc", is_flag=True, help="执行 POC 验证")
@click.option("--poc-only", is_flag=True, help="仅生成 POC")
@click.option("--poc-type", type=click.Choice(["default", "exploit_template"]), default="default", help="POC生成类型")
@click.option("--scan-ports", is_flag=True, help="启用API端口配置扫描")
@click.option("--ports-only", is_flag=True, help="仅执行端口扫描")
@click.option("--port-whitelist", multiple=True, type=int, default=None, help="端口白名单")
@click.option("--port-custom", multiple=True, type=int, default=None, help="自定义额外端口")
@click.option("--priority-rules", type=click.Path(exists=True), help="自定义优先级规则文件路径")
@click.option("--all-findings", is_flag=True, default=False, hidden=True, help="输出所有发现结果")
@click.option("--remote", is_flag=True, help="启用远程扫描模式")
@click.option("--remote-type", type=click.Choice(["ssh", "serial", "bluetooth", "api"]), default="ssh", help="远程连接类型")
@click.option("--remote-host", help="远程主机地址")
@click.option("--remote-port", type=int, help="远程端口")
@click.option("--remote-username", help="远程用户名(SSH)")
@click.option("--remote-password", help="远程密码(SSH)")
@click.option("--remote-key", help="SSH私钥路径")
@click.option("--remote-path", help="远程扫描路径")
@click.option("--serial-baudrate", type=int, default=115200, help="串口波特率")
@click.option("--serial-port", help="串口端口(如 COM1)")
@click.pass_context
def scan(ctx, target, output, ruleset, diff, workers, ai, pure_ai,
         ai_provider, ai_model, incremental, langgraph, test, resume,
         truncate_output, max_duration, max_files, full_scan, index_status,
         explain, ask, focus, tool_chain, skip_data_update, sandbox,
         priority_strategy, static_only, dynamic_only, generate_poc, run_poc,
         poc_only, poc_type, scan_ports, ports_only, port_whitelist,
         port_custom, priority_rules, all_findings, remote, remote_type,
         remote_host, remote_port, remote_username, remote_password,
         remote_key, remote_path, serial_baudrate, serial_port):
    """执行安全扫描
    TARGET: 要扫描的目标文件或目录 (默认: 当前目录)
    """
    config = ConfigManager.load()
    _apply_scan_args(config, {
        'output': output, 'ruleset': ruleset, 'workers': workers,
        'pure_ai': pure_ai, 'ai': ai, 'tool_chain': tool_chain,
        'test': test, 'resume': resume, 'incremental': incremental,
        'full_scan': full_scan, 'langgraph': langgraph,
        'truncate_output': truncate_output, 'all_findings': all_findings,
        'index_status': index_status, 'explain': explain, 'ask': ask,
        'focus': focus, 'skip_data_update': skip_data_update,
        'sandbox': sandbox, 'priority_strategy': priority_strategy,
        'static_only': static_only, 'dynamic_only': dynamic_only,
        'generate_poc': generate_poc, 'run_poc': run_poc,
        'poc_only': poc_only, 'scan_ports': scan_ports,
        'ports_only': ports_only, 'priority_rules': priority_rules,
    })

    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    _run_scan(config, target, output, remote, remote_type)


def _apply_scan_args(config, kwargs):
    """将命令行参数应用到配置对象"""
    if kwargs.get('pure_ai'):
        config.pure_ai = True
        config.scan.ai_enabled = True
    if kwargs.get('ai'):
        config.scan.ai_enabled = True
    if kwargs.get('tool_chain'):
        config.scan.tool_chain = kwargs['tool_chain'].split(',')
    if kwargs.get('test'):
        config.test_mode = True
        config.test_file_count = kwargs['test']
    if kwargs.get('resume'):
        config.resume = True
    if kwargs.get('incremental'):
        config.scan.incremental = True
    if kwargs.get('full_scan'):
        config.scan.full_scan = True
    if kwargs.get('langgraph'):
        config.scan.langgraph = True
    if kwargs.get('truncate_output'):
        config.truncate_output = True
    if kwargs.get('all_findings'):
        config.scan.all_findings = True
    if kwargs.get('index_status'):
        config.scan.index_status = True
    if kwargs.get('explain'):
        config.scan.explain = True
    if kwargs.get('ask'):
        config.scan.ask = kwargs['ask']
    if kwargs.get('focus'):
        config.scan.focus = kwargs['focus']
    if kwargs.get('skip_data_update'):
        config.scan.skip_data_update = True
    if kwargs.get('sandbox'):
        config.sandbox_enabled = True
    if kwargs.get('priority_strategy'):
        config.scan.priority_strategy = kwargs['priority_strategy']
    if kwargs.get('static_only'):
        config.scan.static_only = True
    if kwargs.get('dynamic_only'):
        config.scan.dynamic_only = True
    if kwargs.get('generate_poc'):
        config.scan.generate_poc = True
    if kwargs.get('run_poc'):
        config.scan.run_poc = True
    if kwargs.get('poc_only'):
        config.scan.poc_only = True
    if kwargs.get('scan_ports'):
        config.scan.scan_ports = True
    if kwargs.get('ports_only'):
        config.scan.ports_only = True
    if kwargs.get('priority_rules'):
        config.scan.priority_rules_path = kwargs['priority_rules']
    if kwargs.get('output'):
        from src.core import config as cfg
        cfg.set_config_value(config, 'report.output_file', kwargs['output'])
    if kwargs.get('ruleset'):
        config.scan.ruleset = kwargs['ruleset']


def _run_scan(config, target, output, remote, remote_type):
    """运行扫描"""
    from src.core.scanner import SecurityScanner
    from src.core.remote_scanner import RemoteSecurityScanner, create_scanner

    if remote:
        scanner = create_scanner(remote_type, config=config)
    else:
        scanner = SecurityScanner(config)

    if getattr(config.scan, "index_status", False):
        scanner._show_index_status(target)
        return

    if getattr(config.scan, "explain", False):
        scanner._show_execution_plan()
        return

    ask = getattr(config.scan, "ask", None)
    if ask:
        scanner._answer_question(ask)
        return

    result = scanner.scan_sync(target)

    if output:
        from src.reporting.generator import generate_report
        generate_report(result, output)

    if not config.quiet:
        console.print("\n[bold green]✓ 扫描完成[/bold green]")
        console.print(f"  发现 [bold red]{len(result.findings)}[/bold red] 个安全问题")