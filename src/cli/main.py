"""CLI 主模块

HOS-LS 的命令行入口。
"""

import sys
import os
import io
import contextlib

# [TEST MODE] 临时禁用stdout/stderr重定向以捕获完整输出
# _devnull = open(os.devnull, 'w')
# _old_stdout = sys.stdout
# _old_stderr = sys.stderr
# sys.stdout = _devnull
# sys.stderr = _devnull
_devnull = None
_old_stdout = sys.stdout
_old_stderr = sys.stderr

# 现在安全地执行所有导入（它们的输出会被丢弃）
import warnings
warnings.filterwarnings("ignore", message=".*Failed to find CUDA.*")
warnings.filterwarnings("ignore", message=".*Skipping import of cpp extensions due to incompatible torch version.*")
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Redirects are currently not supported.*")
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*found in sys.modules after import of package.*")

import asyncio
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

from src import __version__
from src.core.config import Config, ConfigManager
from src.cli.plan_commands import plan

# 导入统一 Agent 系统（新增）
from src.cli.agent_integration import (
    initialize_cli_agent_system,
    get_unified_engine,
    collect_behavior_flags_from_kwargs,
    execute_with_unified_engine,
    display_unified_result,
    LegacyFallbackExecutor
)

# 导入完成，恢复正常的 stdout/stderr
# sys.stdout = _old_stdout  # 已经是原始值
# sys.stderr = _old_stderr  # 已经是原始值
if _devnull:
    _devnull.close()

console = Console()


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
    
    table.add_row("Semantic Analyzer", "✔")
    table.add_row("Vulnerability Agent", "⚠")
    table.add_row("Dependency Scanner", "✔")
    
    console.print(table)


def show_risk_bar(percentage: float) -> None:
    """显示风险条"""
    bars = int(percentage * 10)
    risk_bar = "█" * bars + "░" * (10 - bars)
    console.print(f"Risk Level: {risk_bar} {int(percentage * 100)}%")


@click.group()
@click.version_option(version=__version__, prog_name="hos-ls")
@click.option("--config", "-c", type=click.Path(), help="配置文件路径")
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
@click.option("--quiet", "-q", is_flag=True, help="静默模式")
@click.option("--debug", "-d", is_flag=True, help="调试模式")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool, quiet: bool, debug: bool) -> None:
    """HOS-LS: AI 生成代码安全扫描工具（统一 Agent 架构）"""
    # 确保上下文对象是字典
    ctx.ensure_object(dict)

    # 🔥 初始化统一 Agent 系统（新增）
    initialize_cli_agent_system()

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
# 行为类Flag（Agent）
@click.option("--scan", is_flag=True, help="代码扫描（Scanner Agent）")
@click.option("--reason", is_flag=True, help="漏洞推理（Reasoning Agent）")
@click.option("--attack-chain", is_flag=True, help="攻击链分析（AttackGraph Agent）")
@click.option("--poc", is_flag=True, help="生成利用（Exploit Agent）")
@click.option("--verify", is_flag=True, help="验证漏洞（Verifier Agent）")
@click.option("--fix", is_flag=True, help="修复建议（Fix Agent）")
@click.option("--report", is_flag=True, help="报告生成（Report Agent）")
# 模式类Flag（Mode）
@click.option("--pure-ai", is_flag=True, help="纯AI模式")
@click.option("--fast", is_flag=True, help="快速模式")
@click.option("--deep", is_flag=True, help="深度模式")
@click.option("--stealth", is_flag=True, help="stealth模式")
# 控制类Flag（Control）
@click.option("--format", "-f", "output_format", default="html", help="输出格式 (html, markdown, json, sarif)")
@click.option("--output", "-o", help="输出文件路径")
@click.option("--ruleset", "-r", help="规则集")
@click.option("--diff", is_flag=True, help="扫描 Git 差异")
@click.option("--workers", "-w", type=int, default=4, help="工作线程数")
@click.option("--threads", type=int, default=4, help="线程数")
@click.option("--timeout", type=int, help="超时时间")
@click.option("--scope", help="扫描范围")
@click.option("--exclude", help="排除目录")
# 宏命令
@click.option("--full-audit", is_flag=True, help="完整审计（scan + reason + attack-chain + poc + verify + report）")
@click.option("--quick-scan", is_flag=True, help="快速扫描（scan + reason + report）")
@click.option("--deep-audit", is_flag=True, help="深度审计（scan + reason=deep + attack-chain + poc + verify）")
@click.option("--red-team", is_flag=True, help="红队模式（scan + reason + attack-chain + poc + verify）")
@click.option("--bug-bounty", is_flag=True, help="漏洞赏金模式（scan + reason + poc + report）")
@click.option("--compliance", is_flag=True, help="合规模式（scan + reason + report）")
# 特殊功能
@click.option("--explain", is_flag=True, help="解释执行流程")
@click.option("--ask", help="自然语言查询")
@click.option("--focus", help="关注特定文件或目录")
@click.option("--plan", help="使用指定的Plan执行")
# 向后兼容
@click.option("--ai", is_flag=True, help="启用 AI 分析")
@click.option("--pure-ai-fast", is_flag=True, help="使用纯AI快速模式")
@click.option("--pure-ai-batch-size", type=int, default=8, help="纯AI批量大小")
@click.option("--pure-ai-cache-ttl", default="7d", help="纯AI缓存TTL")
@click.option("--pure-ai-provider", help="纯AI提供商 (anthropic, openai, deepseek, local, ollama)")
@click.option("--poc-dir", default="./generated_pocs", help="POC输出目录")
@click.option("--poc-severity", default="high", help="POC生成的严重级别过滤")
@click.option("--poc-max", type=int, default=10, help="最大POC生成数量")
@click.option("--ai-provider", help="AI 提供商 (anthropic, openai, deepseek, local)")
@click.option("--incremental", is_flag=True, help="启用增量扫描")
@click.option("--langgraph", is_flag=True, help="使用 LangGraph 流程")
@click.option("--test", type=int, default=0, help="启用测试模式，指定扫描文件数量，默认10")
@click.option("--cn", is_flag=True, help="使用中文输出所有漏洞信息")
@click.option("--en", is_flag=True, help="使用英文输出所有漏洞信息")
# 远程扫描选项 (NEW)
@click.option("--target-type", "-t", 
              type=click.Choice(["local", "remote-server", "website", "direct-connect"]),
              default="local",
              help="目标类型: local(本地), remote-server(SSH远程服务器), website(网站), direct-connect(设备直连)")
@click.option("--host", help="远程主机地址 (用于 remote-server 或 website)")
@click.option("--port", type=int, default=None, help="端口号 (SSH默认22, HTTP默认80/443)")
@click.option("--username", "-u", help="用户名 (SSH认证)")
@click.option("--password", "-p", help="密码 (或使用环境变量 REMOTE_PASSWORD)")
@click.option("--key-file", "-k", type=click.Path(), help="SSH私钥文件路径")
@click.option("--protocol", 
              type=click.Choice(["ssh", "sftp", "http", "https", "serial"]),
              help="连接协议 (自动检测如果未指定)")
@click.option("--connection-config", "-c", type=click.Path(),
              help="连接配置文件路径 (.yaml/.json)")
@click.option("--scan-depth", 
              type=click.Choice(["shallow", "medium", "deep"]),
              default="medium",
              help="扫描深度: shallow(浅), medium(中), deep(深)")
@click.option("--concurrent-connections", "-n", type=int, default=5,
              help="并发连接数 (远程扫描)")
@click.option("--connection-timeout", type=int, default=30,
              help="连接超时时间（秒）")
@click.option("--proxy", help="代理服务器地址 (如 socks5://127.0.0.1:1080)")
@click.option("--serial-port", help="串口端口 (如 /dev/ttyUSB0 或 COM3)")
@click.option("--baudrate", type=int, default=9600, help="串口波特率")
# 企业内网/VPN 选项 (NEW - Enterprise)
@click.option("--vpn-config", type=click.Path(), help="VPN配置文件路径 (.ovpn/.conf)")
@click.option("--vpn-type",
              type=click.Choice(["openvpn", "wireguard", "ipsec"]),
              default=None,
              help="VPN类型: openvpn, wireguard, ipsec")
@click.option("--jump-host", multiple=True,
              help="跳板机地址 (可多次使用，格式: user@host:port 或 host:port)")
@click.option("--jump-host-key", "-jk", type=click.Path(), multiple=True,
              help="跳板机SSH密钥 (与--jump-host一一对应)")
@click.option("--proxy-chain", type=click.Path(),
              help="代理链配置文件路径 (.yaml)")
@click.option("--internal-scan", is_flag=True,
              help="启用内网子网扫描模式 (需要先连接VPN或跳板机)")
@click.option("--subnet", help="指定要扫描的内网子网 (如 192.168.1.0/24)")
@click.option("--discover-hosts", is_flag=True,
              help="自动发现并扫描内网所有主机")
@click.option("--deep-service-id", is_flag=True,
              help="深度服务识别 (Banner抓取+版本检测)")
@click.option("--network-topology", type=click.Path(),
              help="网络拓扑配置文件 (定义复杂网络环境)")
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    # 行为类Flag
    scan: bool,
    reason: bool,
    attack_chain: bool,
    poc: bool,
    verify: bool,
    fix: bool,
    report: bool,
    # 模式类Flag
    pure_ai: bool,
    fast: bool,
    deep: bool,
    stealth: bool,
    # 控制类Flag
    output_format: str,
    output: Optional[str],
    ruleset: Optional[str],
    diff: bool,
    workers: int,
    threads: int,
    timeout: Optional[int],
    scope: Optional[str],
    exclude: Optional[str],
    # 宏命令
    full_audit: bool,
    quick_scan: bool,
    deep_audit: bool,
    red_team: bool,
    bug_bounty: bool,
    compliance: bool,
    # 特殊功能
    explain: bool,
    ask: Optional[str],
    focus: Optional[str],
    plan: Optional[str],
    # 向后兼容
    ai: bool,
    pure_ai_fast: bool,
    pure_ai_batch_size: int,
    pure_ai_cache_ttl: str,
    pure_ai_provider: Optional[str],
    poc_dir: str,
    poc_severity: str,
    poc_max: int,
    ai_provider: Optional[str],
    incremental: bool,
    langgraph: bool,
    test: int,
    cn: bool,
    en: bool,
    # 远程扫描选项 (NEW)
    target_type: str,
    host: Optional[str],
    port: Optional[int],
    username: Optional[str],
    password: Optional[str],
    key_file: Optional[str],
    protocol: Optional[str],
    connection_config: Optional[str],
    scan_depth: str,
    concurrent_connections: int,
    connection_timeout: int,
    proxy: Optional[str],
    serial_port: Optional[str],
    baudrate: int,
    # 企业内网/VPN 选项 (NEW - Enterprise)
    vpn_config: Optional[str],
    vpn_type: Optional[str],
    jump_host: tuple,
    jump_host_key: tuple,
    proxy_chain: Optional[str],
    internal_scan: bool,
    subnet: Optional[str],
    discover_hosts: bool,
    deep_service_id: bool,
    network_topology: Optional[str],
) -> None:
    """扫描代码安全漏洞（支持本地、远程和企业内网）
    
    支持的目标类型：
    - 本地文件系统（默认）：./my-project
    - SSH远程服务器：ssh://user@host --target-type remote-server
    - 网站Web应用：https://example.com --target-type website
    - 物理设备直连：serial:///dev/ttyUSB0 --target-type direct-connect
    
    企业内网/VPN支持：
    - VPN连接：--vpn-config /path/to/vpn.ovpn --vpn-type openvpn
    - 跳板机：--jump-host user@bastion.com --jump-host-key ~/.ssh/id_rsa
    - 内网扫描：--internal-scan --subnet 192.168.1.0/24
    - 自动发现：--discover-hosts (自动发现内网所有主机)
    
    示例：
    \b
    本地扫描: hos-ls scan ./my-project --pure-ai
    远程SSH:  hos-ls scan /var/www/html --target-type remote-server --host 192.168.1.100 -u admin
    网站扫描: hos-ls scan https://example.com --target-type website --full-audit
    设备扫描: hos-ls scan --target-type direct-connect --serial-port COM3
    """
    config: Config = ctx.obj["config"]
    
    # 处理Plan选项
    if plan:
        from src.core.plan_manager import PlanManager
        from src.cli.plan_commands import _plan_to_cli_args
        
        plan_manager = PlanManager(config)
        try:
            # 加载Plan
            loaded_plan = plan_manager.load_plan(plan)
            
            # 转换为CLI参数
            plan_args = _plan_to_cli_args(loaded_plan)
            
            # 显示执行的Plan
            console.print(Panel("执行Plan", border_style="green"))
            from src.core.plan_dsl import PlanDSLParser
            console.print(PlanDSLParser.format_plan_for_display(loaded_plan))
            
            # 执行扫描
            ctx.invoke(scan, **plan_args)
            return
        except Exception as e:
            console.print(f"[bold red]错误: {e}[/bold red]")
            sys.exit(1)
    
    # 设置语言
    if cn and en:
        console.print("[bold red]错误: 不能同时使用 --cn 和 --en 参数[/bold red]")
        sys.exit(1)
    if cn:
        config.language = "cn"
    elif en:
        config.language = "en"
    
    # 🔥🔥🔥 远程扫描处理 (NEW)
    if target_type != 'local':
        try:
            import asyncio
            from src.remote.scanners import create_unified_scanner
            
            console.print(Panel(
                f"[bold cyan]远程扫描模式[/bold cyan]\n"
                f"目标类型: {target_type}\n"
                f"目标地址: {host or target}\n"
                f"AI模式: {'PureAI' if pure_ai else ('Heavy' if ai else 'Standard')}",
                border_style="cyan"
            ))
            
            remote_scanner = create_unified_scanner(
                config=config,
                target_type=target_type,
                target=target,
                host=host,
                port=port or (22 if target_type == 'remote-server' else None),
                username=username,
                password=password or os.environ.get('REMOTE_PASSWORD'),
                key_file=key_file,
                connection_type='serial' if serial_port else None,
                serial_port=serial_port,
                baudrate=baudrate
            )
            
            result = asyncio.run(remote_scanner.scan(target))
            
            _display_remote_result(result, console)
            
            if output:
                _generate_unified_report(result, output, output_format, config)
                
            sys.exit(1 if result.findings else 0)
            
        except ImportError as e:
            console.print(f"[red]错误: 缺少依赖库 - {e}[/red]")
            console.print("[yellow]提示: pip install asyncssh httpx pyserial[/yellow]")
            sys.exit(2)
        except Exception as e:
            console.print(f"[bold red]远程扫描失败: {e}[/bold red]")
            if config.debug:
                import traceback
                traceback.print_exc()
            sys.exit(2)
    
    # 🔥🔥🔥 企业内网/VPN扫描处理 (NEW - Enterprise)
    if vpn_config or jump_host or internal_scan or subnet:
        try:
            import asyncio
            from src.remote.enterprise import (
                create_vpn_connector,
                VPNConfig,
                JumpHostManager,
                ProxyChain,
                InternalNetworkScanner
            )
            
            console.print("\n" + "=" * 70)
            console.print("[bold blue]🏢 企业内网/VPN 安全扫描模式[/bold blue]")
            console.print("=" * 70)
            
            async def _run_enterprise_scan():
                """执行企业内网/VPN扫描的异步主逻辑"""
                
                chain = ProxyChain()
                
                # 1. 建立VPN连接（如果配置了）
                vpn_connector = None
                if vpn_config:
                    console.print(f"\n[cyan]📡 正在连接企业VPN...[/cyan]")
                    
                    vpn_cfg = VPNConfig(
                        config_file=vpn_config,
                        server_address=host,  # 可选：从--host参数获取
                        username=username,
                        password=password or os.environ.get('VPN_PASSWORD')
                    )
                    
                    vpn_connector = create_vpn_connector(
                        vpn_type or 'openvpn',
                        vpn_cfg
                    )
                    
                    result = await vpn_connector.connect()
                    
                    if not result.success:
                        console.print(f"[red]❌ VPN连接失败: {result.message}[/red]")
                        sys.exit(3)
                    
                    console.print(f"[green]✅ VPN已成功连接[/green]")
                    
                    # 显示VPN信息
                    if vpn_connector.connection_info:
                        info = vpn_connector.connection_info
                        console.print(f"   本地IP: {info.local_ip}")
                        console.print(f"   隧道接口: {info.tunnel_interface}")
                
                # 2. 建立跳板机链（如果配置了）
                if jump_host:
                    console.print(f"\n[cyan]🔗 正在建立跳板机连接链 ({len(jump_host)} 个跳板)...[/cyan]")
                    
                    jump_chain = []
                    for i, host_str in enumerate(jump_host):
                        host_info = _parse_jump_host(host_str)
                        
                        hop_config = {
                            'ssh_host': host_info['host'],
                            'ssh_port': host_info['port'],
                            'username': host_info['username']
                        }
                        
                        if i < len(jump_host_key):
                            hop_config['key_file'] = jump_host_key[i]
                        
                        jump_chain.append(hop_config)
                    
                    success = await chain.add_jump_hosts(jump_chain)
                    
                    if not success:
                        console.print("[red]❌ 跳板机连接失败[/red]")
                        sys.exit(3)
                    
                    console.print(f"[green]✅ 跳板机链已建立 ({len(jump_chain)} hops)[/green]")
                
                # 3. 执行内网扫描
                if internal_scan or subnet or discover_hosts:
                    targets_to_scan = []
                    
                    if subnet:
                        targets_to_scan.append(subnet)
                        console.print(f"\n[cyan]🎯 目标子网: [bold]{subnet}[/bold][/cyan]")
                    
                    if discover_hosts and not subnet:
                        console.print("\n[yellow]⚠️ --discover-hosts 需要 --subnet 参数指定基础网络[/yellow]")
                        console.print("   示例: --discover-hosts --subnet 192.168.0.0/16")
                    
                    if targets_to_scan:
                        console.print("\n[bold cyan]🔍 开始内网安全扫描...[/bold cyan]\n")
                        
                        scanner = InternalNetworkScanner(proxy_chain=chain if (jump_host or vpn_config) else None)
                        
                        scan_result = await scanner.full_scan(
                            targets=targets_to_scan,
                            deep_scan=deep_service_id
                        )
                        
                        # 显示详细结果
                        _display_internal_scan_result(scan_result, console)
                        
                        # 保存报告
                        if output:
                            _save_internal_scan_report(scan_result, output, output_format)
                        
                        console.print("\n[bold green]✅ 内网扫描完成！[/bold green]")
                
                # 拆除代理链和VPN
                if vpn_connector or jump_host:
                    console.print("\n[dim]正在清理连接...[/dim]")
                    await chain.teardown()
                    
                    if vpn_connector:
                        await vpn_connector.disconnect()
                        console.print("[dim]VPN已断开[/dim]")
            
            # 调用异步函数
            asyncio.run(_run_enterprise_scan())
            
            sys.exit(0)
            
        except ImportError as e:
            console.print(f"[red]错误: 缺少依赖库 - {e}[/red]")
            console.print("[yellow]提示: pip install asyncssh httpx pyyaml[/yellow]")
            sys.exit(3)
        except Exception as e:
            console.print(f"[bold red]内网/VPN扫描失败: {e}[/bold red]")
            if config.debug:
                import traceback
                traceback.print_exc()
            sys.exit(3)
    
    # 收集行为类Flag
    behavior_flags = []
    if scan:
        behavior_flags.append("scan")
    if reason:
        behavior_flags.append("reason")
    if attack_chain:
        behavior_flags.append("attack-chain")
    if poc:
        behavior_flags.append("poc")
    if verify:
        behavior_flags.append("verify")
    if fix:
        behavior_flags.append("fix")
    if report:
        behavior_flags.append("report")
    
    # 收集宏命令
    macro_flags = []
    if full_audit:
        macro_flags.append("full-audit")
    if quick_scan:
        macro_flags.append("quick-scan")
    if deep_audit:
        macro_flags.append("deep-audit")
    if red_team:
        macro_flags.append("red-team")
    if bug_bounty:
        macro_flags.append("bug-bounty")
    if compliance:
        macro_flags.append("compliance")
    
    # 合并所有flags
    all_flags = behavior_flags + macro_flags

    # 🔥 使用统一 Agent 系统的新架构（优先）
    if all_flags:  # 如果有行为类 flags，使用新架构
        try:
            import asyncio

            # 收集 flags（使用新的辅助函数）
            unified_flags = [f"--{flag}" for flag in all_flags]

            # 确定执行模式
            exec_mode = "pure-ai" if pure_ai else "auto"

            # 🔥🔥🔥 调用统一执行引擎（核心改动！）
            result = asyncio.run(execute_with_unified_engine(
                config=config,
                target=target,
                behavior_flags=unified_flags,
                mode=exec_mode,
                ask=ask,
                focus=focus
            ))

            # 显示结果
            display_unified_result(result, console, quiet=config.quiet)

            # 生成报告（如果需要）
            if output:
                _generate_unified_report(result, output, output_format, config)

            # 设置退出码
            if not result.success and result.total_findings > 0:
                sys.exit(1)
            return  # ✅ 新架构执行完成，直接返回

        except Exception as e:
            # 新架构失败时回退到旧逻辑（向后兼容）
            if config.debug:
                console.print(f"[yellow][DEBUG] 新架构执行失败，回退到旧逻辑: {e}[/yellow]")
            pass  # 继续执行下面的旧代码
    
    # === 以下是旧的硬编码逻辑（作为 fallback）===
    
    # 导入Pipeline构建器
    from src.core.agent_pipeline import PipelineBuilder
    
    # 构建Pipeline
    try:
        pipeline = PipelineBuilder.build_pipeline(all_flags)
    except ValueError as e:
        console.print(f"[bold red]错误: {e}[/bold red]")
        sys.exit(1)
    
    # 生成执行计划
    execution_plan = PipelineBuilder.create_execution_plan(pipeline, config)
    
    # 显示执行计划（如果需要）
    if explain:
        explanation = PipelineBuilder.generate_explanation(pipeline)
        console.print(Panel(explanation))
        return
    
    # 显示 Claude 风格的输入提示
    if not config.quiet:
        console.print("[bold cyan]> hosls " + " ".join(f"--{flag}" for flag in all_flags) + " " + target + "[/bold cyan]")

    # 提前检查纯AI模式
    if pure_ai:
        # 设置环境变量
        os.environ["HOS_LS_MODE"] = "PURE_AI"
        
        if not config.quiet:
            print_banner()
            console.print("[bold green]🔒 纯AI模式已激活，隔离运行时环境...[/bold green]")
        
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
        
        # 纯AI模式配置（从Config动态加载，零硬编码）
        config.pure_ai_provider = config.ai.provider or "deepseek"  # 从配置读取，有默认值
        config.pure_ai_model = config.ai.model or "deepseek-chat"  # 从配置读取，有默认值
        
        # 测试模式
        if test > 0:
            config.test_mode = True
            config.__dict__['test_file_count'] = test
            if not config.quiet:
                console.print(f"[bold yellow]⚠ 测试模式已启用，只扫描前{test}个优先级最高的文件[/bold yellow]")
        elif test == 0:
            config.test_mode = False
        else:
            config.test_mode = True
            config.__dict__['test_file_count'] = 10
            if not config.quiet:
                console.print("[bold yellow]⚠ 测试模式已启用，只扫描前10个优先级最高的文件[/bold yellow]")
        
        # 导入纯AI扫描器
        from src.core.scanner import create_scanner
        
        # 执行纯AI扫描
        try:
            # 显示扫描进度
            if not config.quiet:
                show_scan_progress()
            
            scanner = create_scanner(config)
            result = scanner.scan_sync(target)

            # 显示结果
            if not config.quiet:
                show_agent_status()
                _display_result(result)

            # 生成报告
            if output:
                _generate_report(result, output, output_format, config)

            # 根据结果设置退出码
            if result.findings:
                sys.exit(1)
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
    config.ai.enabled = ai or any(flag in all_flags for flag in ["reason", "attack-chain", "poc"])
    config.pure_ai = False
    
    if ai_provider:
        config.ai.provider = ai_provider
    # 测试模式
    if test > 0:
        config.test_mode = True
        config.__dict__['test_file_count'] = test
        if not config.quiet:
            console.print(f"[bold yellow]⚠ 测试模式已启用，只扫描前{test}个优先级最高的文件[/bold yellow]")
    elif test == 0:
        config.test_mode = False
    else:
        config.test_mode = True
        config.__dict__['test_file_count'] = 10
        if not config.quiet:
            console.print("[bold yellow]⚠ 测试模式已启用，只扫描前10个优先级最高的文件[/bold yellow]")

    # 执行扫描
    try:
        if langgraph or any(flag in all_flags for flag in ["reason", "attack-chain", "poc"]):
            # 使用 LangGraph 多Agent流程
            from src.core.langgraph_flow import run_pipeline
            # 读取目标文件内容
            target_path = Path(target)
            if target_path.is_file():
                with open(target_path, 'r', encoding='utf-8') as f:
                    code = f.read()
            else:
                code = f"目录扫描: {target}"
            # 运行多Agent分析
            result = asyncio.run(run_pipeline(pipeline, code, ask=ask, focus=focus))
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
            
            scanner = create_scanner(config)
            result = scanner.scan_sync(target)

            # 显示结果
            if not config.quiet:
                show_agent_status()
                _display_result(result)

            # 生成报告
            if output:
                _generate_report(result, output, output_format, config)

            # 根据结果设置退出码
            if result.findings:
                sys.exit(1)

    except Exception as e:
        console.print(f"[bold red]扫描失败: {e}[/bold red]")
        sys.exit(2)


@cli.command()
@click.pass_context
def config(ctx: click.Context) -> None:
    """显示当前配置"""
    cfg: Config = ctx.obj["config"]

    table = Table(title="HOS-LS 配置")
    table.add_column("配置项", style="cyan")
    table.add_column("值", style="green")

    table.add_row("AI 提供商", cfg.ai.provider)
    table.add_row("AI 模型", cfg.ai.model)
    table.add_row("最大工作线程数", str(cfg.scan.max_workers))
    table.add_row("缓存启用", str(cfg.scan.cache_enabled))
    table.add_row("增量扫描", str(cfg.scan.incremental))
    table.add_row("规则集", cfg.rules.ruleset)
    table.add_row("报告格式", cfg.report.format)
    table.add_row("调试模式", str(cfg.debug))

    console.print(table)


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
            console.print(f"  [green]✓[/green] 已删除: {file_path.name}")
            deleted_count += 1
        except Exception as e:
            console.print(f"  [red]✗[/red] 删除失败: {file_path.name} - {e}")
    
    # 删除目录
    for dir_path in found_dirs:
        try:
            shutil.rmtree(dir_path, ignore_errors=True)
            if not dir_path.exists():
                console.print(f"  [green]✓[/green] 已删除: {dir_path.name}")
                deleted_count += 1
            else:
                console.print(f"  [yellow]⚠[/yellow] 目录可能未完全删除: {dir_path.name}")
        except Exception as e:
            console.print(f"  [red]✗[/red] 删除失败: {dir_path.name} - {e}")
    
    console.print(f"\n[bold green]清理完成！共删除 {deleted_count} 项[/bold green]")


@cli.group()
def model() -> None:
    """模型管理命令"""
    pass


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
    high_risk = summary.get("high", 0) + summary.get("critical", 0)
    medium_risk = summary.get("medium", 0)
    
    # 显示 Claude 风格的风险结果
    console.print(
        "[bold yellow]⚠ Scan Result[/bold yellow]\n"
        "──────────────\n"
        f"Issues Found: {total_issues}\n"
        f"[red]High Risk:[/red] {high_risk}\n"
        f"[yellow]Medium Risk:[/yellow] {medium_risk}"
    )
    
    # 显示风险条
    risk_percentage = min(1.0, (high_risk * 2 + medium_risk) / (total_issues * 2) if total_issues > 0 else 0)
    show_risk_bar(risk_percentage)

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
            
            # 折叠式日志
            console.print("\n[bold cyan][+] Show Details[/bold cyan]")
            console.print("按 Enter 查看完整日志，按其他键继续...")
            
            try:
                import sys
                import termios
                import tty
                
                # 获取终端属性
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                
                try:
                    # 设置终端为原始模式
                    tty.setraw(fd)
                    # 读取一个字符
                    char = sys.stdin.read(1)
                    
                    # 如果是 Enter 键（ASCII 13），显示完整日志
                    if char == '\r':
                        console.print("\n[bold]完整问题列表:[/bold]")
                        for i, finding in enumerate(result.findings, 1):
                            severity_color = "red" if finding.severity.value in ["critical", "high"] else "yellow" if finding.severity.value == "medium" else "blue"
                            message = finding.message.strip()
                            console.print(
                                f"{i}. [{severity_color}]{finding.severity.value}[/{severity_color}] "
                                f"{finding.rule_name}: {message}"
                            )
                finally:
                    # 恢复终端设置
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                # 如果无法获取键盘输入（如在非交互式环境中），则跳过
                pass

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


def _display_remote_result(result, console) -> None:
    """显示远程扫描结果（增强版）"""
    from src.core.engine import Severity
    
    total_findings = len(result.findings) if hasattr(result, 'findings') else 0
    
    critical_count = sum(1 for f in result.findings if f.severity.value == 'critical') if hasattr(result, 'findings') else 0
    high_count = sum(1 for f in result.findings if f.severity.value == 'high') if hasattr(result, 'findings') else 0
    medium_count = sum(1 for f in result.findings if f.severity.value == 'medium') if hasattr(result, 'findings') else 0
    low_count = sum(1 for f in result.findings if f.severity.value == 'low') if hasattr(result, 'findings') else 0
    
    console.print("\n" + "=" * 60)
    console.print("[bold blue]📊 远程扫描报告[/bold blue]")
    console.print("=" * 60)
    
    console.print(f"\n[bold]目标:[/bold] {result.target if hasattr(result, 'target') else 'Unknown'}")
    console.print(f"[bold]状态:[/bold] {'✅ 完成' if result.status.value == 'COMPLETED' else '❌ 失败'}")
    console.print(f"[bold]发现的问题:[/bold] {total_findings}")
    
    if total_findings > 0:
        console.print(f"\n[bold]问题分布:[/bold]")
        console.print(f"  🔴 严重 (Critical): {critical_count}")
        console.print(f"  🟠 高危 (High):      {high_count}")
        console.print(f"  🟡 中危 (Medium):    {medium_count}")
        console.print(f"  🔵 低危 (Low):       {low_count}")
        
        risk_percentage = min(1.0, ((critical_count * 3 + high_count * 2 + medium_count) / (total_findings * 3)) if total_findings > 0 else 0)
        show_risk_bar(risk_percentage)
        
        console.print(f"\n[bold]Top 10 问题详情:[/bold]")
        
        sorted_findings = sorted(
            result.findings,
            key=lambda f: {
                'critical': 4,
                'high': 3,
                'medium': 2,
                'low': 1,
                'info': 0
            }.get(f.severity.value.lower() if hasattr(f.severity, 'value') else str(f.severity), 0),
            reverse=True
        )
        
        for i, finding in enumerate(sorted_findings[:10], 1):
            severity_value = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            
            if severity_value in ['critical', 'high']:
                color = 'red'
            elif severity_value == 'medium':
                color = 'yellow'
            else:
                color = 'blue'
                
            file_path = finding.location.file if hasattr(finding.location, 'file') else 'Unknown'
            
            is_remote = finding.metadata.get('is_remote', False) if hasattr(finding, 'metadata') else False
            
            location_info = f" [REMOTE]" if is_remote else ""
            
            console.print(
                f"\n{i}. [{color}][{severity_value.upper()}][/{color}] "
                f"{finding.rule_name}{location_info}"
            )
            console.print(f"   📍 文件: {file_path}:{getattr(finding.location, 'line', '?')}")
            console.print(f"   📝 描述: {finding.description[:100]}...")
            if finding.fix_suggestion:
                console.print(f"   💡 建议: {finding.fix_suggestion[:80]}...")
    
    console.print("\n" + "=" * 60)


def _generate_report(result, output: str, format: str, config=None) -> None:
    """生成报告（旧版）"""
    # 导入报告生成器
    from src.reporting.generator import ReportGenerator

    try:
        generator = ReportGenerator(config)
        report_path = generator.generate([result], output, format)
        console.print(f"[bold green]报告已生成: {report_path}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]报告生成失败: {e}[/bold red]")


def _convert_execution_result_to_scan_results(execution_result) -> List:
    """将 ExecutionResult 转换为 ScanResult 列表

    Args:
        execution_result: 统一执行结果对象

    Returns:
        ScanResult 列表，用于报告生成器
    """
    from src.core.engine import ScanResult, Finding, Severity, Location, ScanStatus

    scan_results = []
    target_path = getattr(execution_result, 'target', 'unknown')

    for agent_name, agent_result in execution_result.results.items():
        findings_list = []

        if hasattr(agent_result, 'findings') and agent_result.findings:
            for finding_data in agent_result.findings:
                try:
                    if isinstance(finding_data, dict):
                        finding = Finding(
                            rule_id=finding_data.get('rule_id', agent_name),
                            rule_name=finding_data.get('rule_name', agent_name),
                            description=finding_data.get('description', finding_data.get('message', '')),
                            severity=Severity(finding_data.get('severity', 'medium')),
                            location=Location(
                                file=finding_data.get('location', {}).get('file', finding_data.get('file', target_path)),
                                line=finding_data.get('location', {}).get('line', finding_data.get('line', 0)),
                                column=finding_data.get('location', {}).get('column', 0)
                            ),
                            confidence=float(finding_data.get('confidence', agent_result.confidence or 0.8)),
                            message=finding_data.get('message', ''),
                            code_snippet=finding_data.get('code_snippet', ''),
                            fix_suggestion=finding_data.get('fix_suggestion', ''),
                            metadata=finding_data.get('metadata', {})
                        )
                    elif hasattr(finding_data, 'rule_id'):
                        finding = finding_data
                    else:
                        continue

                    findings_list.append(finding)

                except (ValueError, TypeError, AttributeError) as e:
                    console.print(f"[yellow][WARN] 转换 finding 失败: {e}[/yellow]")
                    continue

        scan_result = ScanResult(
            target=target_path,
            status=ScanStatus.COMPLETED if agent_result.is_success else ScanStatus.FAILED,
            findings=findings_list,
            metadata={
                'agent_name': agent_name,
                'agent_status': agent_result.status.value if hasattr(agent_result.status, 'value') else str(agent_result.status),
                'execution_time': agent_result.execution_time,
                'message': agent_result.message
            }
        )

        scan_results.append(scan_result)

    return scan_results


def _ensure_output_extension(output_path: str, format: str) -> str:
    """确保输出文件有正确的扩展名

    Args:
        output_path: 原始输出路径
        format: 报告格式

    Returns:
        带正确扩展名的路径
    """
    from pathlib import Path

    path = Path(output_path)
    format_extensions = {
        'html': '.html',
        'htm': '.html',
        'markdown': '.md',
        'md': '.md',
        'json': '.json',
        'sarif': '.sarif',
        'sarif-json': '.sarif'
    }

    ext = format_extensions.get(format.lower())

    if ext and path.suffix.lower() != ext:
        if path.is_dir() or not path.suffix:
            if format.lower() in ['html', 'htm']:
                return str(path / 'report.html')
            return str(path.with_suffix(ext))
        elif format.lower() == 'html':
            html_path = path.parent / f'{path.stem}.html'
            return str(html_path)

    return output_path


def _generate_json_report(result, output: str) -> None:
    """生成 JSON 格式的报告（保留原有逻辑）

    Args:
        result: ExecutionResult 对象
        output: 输出文件路径
    """
    import json
    from datetime import datetime

    report_data = {
        'success': result.success,
        'mode': result.mode,
        'pipeline': result.pipeline_used,
        'execution_time': result.execution_time,
        'total_findings': result.total_findings,
        'message': result.message,
        'agents_results': {
            name: r.to_dict()
            for name, r in result.results.items()
        },
        'timestamp': datetime.now().isoformat()
    }

    with open(output, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)

    console.print(f"[bold green]JSON报告已生成: {output}[/bold green]")


def _generate_simple_text_report(result, output: str, format: str) -> None:
    """生成简单文本报告（降级方案）

    当无法转换为 ScanResult 时使用此方法

    Args:
        result: ExecutionResult 对象
        output: 输出文件路径
        format: 输出格式 (html/markdown)
    """
    from datetime import datetime

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if format.lower() in ['html', 'htm']:
        content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HOS-LS 安全扫描报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }}
        h1 {{ color: #2563eb; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
        .summary {{ background: #f8fafc; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .info {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #6b7280; }}
        .value {{ color: #111827; }}
        .agent {{ border-left: 4px solid #3b82f6; padding: 15px; margin: 15px 0; background: #f9fafb; }}
        .success {{ border-left-color: #10b981; }}
        .error {{ border-left-color: #ef4444; }}
    </style>
</head>
<body>
    <h1>🔒 HOS-LS 安全扫描报告</h1>
    <div class="summary">
        <div class="info"><span class="label">生成时间:</span> <span class="value">{timestamp}</span></div>
        <div class="info"><span class="label">扫描模式:</span> <span class="value">{result.mode.upper()}</span></div>
        <div class="info"><span class="label">执行 Pipeline:</span> <span class="value">{' → '.join(result.pipeline_used)}</span></div>
        <div class="info"><span class="label">总耗时:</span> <span class="value">{result.execution_time:.2f}秒</span></div>
        <div class="info"><span class="label">发现问题数:</span> <span class="value">{result.total_findings}</span></div>
        <div class="info"><span class="label">状态:</span> <span class="value">{'✅ 成功' if result.success else '❌ 失败'}</span></div>
    </div>

    <h2>🤖 Agent 执行详情</h2>
"""

        if result.results:
            for name, r in result.results.items():
                status_class = "success" if r.is_success else "error"
                status_icon = "✅" if r.is_success else "❌"
                content += f"""
    <div class="agent {status_class}">
        <h3>{status_icon} {name}</h3>
        <div class="info"><span class="label">状态:</span> <span class="value">{r.status.value if hasattr(r.status, 'value') else r.status}</span></div>
        <div class="info"><span class="label">消息:</span> <span class="value">{r.message}</span></div>
        <div class="info"><span class="label">置信度:</span> <span class="value">{r.confidence:.0%}</span></div>
        <div class="info"><span class="label">耗时:</span> <span class="value">{r.execution_time:.2f}秒</span></div>
        {'<div class="info"><span class="label">错误:</span> <span class="value" style="color:red;">{r.error}</span></div>' if r.error else ''}
    </div>
"""

        content += """
</body>
</html>
"""
    else:
        content = f"""# HOS-LS 安全扫描报告

**生成时间**: {timestamp}

## 扫描摘要

- **模式**: {result.mode.upper()}
- **Pipeline**: {' → '.join(result.pipeline_used)}
- **耗时**: {result.execution_time:.2f}秒
- **发现问题**: {result.total_findings}个
- **状态**: {'✅ 成功' if result.success else '❌ 失败'}

## Agent 执行详情

"""

        if result.results:
            for name, r in result.results.items():
                status_icon = "✅" if r.is_success else "❌"
                content += f"""### {status_icon} {name}

- **状态**: {r.status.value if hasattr(r.status, 'value') else r.status}
- **消息**: {r.message}
- **置信度**: {r.confidence:.0%}
- **耗时**: {r.execution_time:.2f}秒
{'- **错误**: ' + r.error + '\n' if r.error else ''}

"""

    with open(output, 'w', encoding='utf-8') as f:
        f.write(content)

    console.print(f"[bold green]{format.upper()}报告已生成: {output}[/bold green]")


def _generate_unified_report(result, output: str, format: str, config=None) -> None:
    """生成统一执行引擎的报告（新版）

    支持 html/json/markdown/sarif 格式，使用 ReportGenerator 生成完整报告

    Args:
        result: ExecutionResult 对象
        output: 输出路径
        format: 输出格式 (html/json/markdown/sarif)
        config: 配置对象
    """
    try:
        from src.reporting.generator import ReportGenerator

        format_lower = format.lower() if format else 'html'

        if format_lower == 'json':
            _generate_json_report(result, output)
            return

        scan_results = _convert_execution_result_to_scan_results(result)

        if not scan_results or all(len(sr.findings) == 0 for sr in scan_results):
            console.print("[dim][INFO] 未发现安全问题，生成简化版报告[/dim]")
            output_path = _ensure_output_extension(output, format_lower)
            _generate_simple_text_report(result, output_path, format_lower)
            return

        generator = ReportGenerator(config)
        output_path = _ensure_output_extension(output, format_lower)

        report_path = generator.generate(scan_results, output_path, format_lower)
        console.print(f"[bold green]{format_upper(format_lower)}报告已生成: {report_path}[/bold green]")

    except Exception as e:
        console.print(f"[bold red]统一报告生成失败: {e}[/bold red]")
        if config and config.debug:
            import traceback
            traceback.print_exc()

        console.print("[yellow][WARN] 尝试生成简化版报告...[/yellow]")
        try:
            output_path = _ensure_output_extension(output, format if format else 'html')
            _generate_simple_text_report(result, output_path, format if format else 'html')
        except Exception as fallback_error:
            console.print(f"[bold red]简化版报告也生成失败: {fallback_error}[/bold red]")


def format_upper(fmt: str) -> str:
    """格式化显示名称"""
    format_names = {
        'html': 'HTML',
        'htm': 'HTML',
        'markdown': 'Markdown',
        'md': 'Markdown',
        'json': 'JSON',
        'sarif': 'SARIF'
    }
    return format_names.get(fmt.lower(), fmt.upper())


def _parse_jump_host(host_str: str) -> Dict[str, Any]:
    """
    解析跳板机地址字符串
    
    支持格式：
    - user@host:port
    - host:port
    - user@host
    - host
    
    Returns:
        解析后的字典 {'host': ..., 'port': ..., 'username': ...}
    """
    result = {
        'host': '',
        'port': 22,
        'username': None
    }
    
    if '@' in host_str:
        username, rest = host_str.split('@', 1)
        result['username'] = username
        host_str = rest
    
    if ':' in host_str and not host_str.startswith('['):
        parts = host_str.rsplit(':', 1)
        try:
            result['host'] = parts[0]
            result['port'] = int(parts[1])
        except ValueError:
            result['host'] = host_str
    else:
        result['host'] = host_str
    
    return result


def _display_internal_scan_result(scan_result: Dict, console) -> None:
    """
    显示内网扫描结果（增强版）
    
    Args:
        scan_result: InternalNetworkScanner.full_scan() 返回的结果
        console: Rich Console 实例
    """
    stats = scan_result.get('statistics', {})
    risks = scan_result.get('risk_assessment', {})
    
    console.print("\n" + "━" * 70)
    console.print("[bold blue]📊 企业内网安全扫描报告[/bold blue]")
    console.print("━" * 70)
    
    # 基本信息
    scan_time = scan_result.get('scan_time', {})
    if scan_time.get('duration_seconds'):
        console.print(f"\n⏱️  扫描耗时: [bold]{scan_time['duration_seconds']:.1f}[/bold] 秒")
    
    # 统计信息
    console.print(f"\n[bold]📈 扫描统计:[/bold]")
    console.print(f"   🎯 目标总数: {stats.get('total_targets', 0)}")
    console.print(f"   💚 存活主机: [green]{stats.get('alive_hosts', 0)}[/green]")
    console.print(f"   🔓 开放端口: [yellow]{stats.get('total_open_ports', 0)}[/yellow]")
    console.print(f"   🛠️  发现服务: [cyan]{stats.get('unique_services', 0)}[/cyan] 种")
    
    # 服务列表
    services_list = stats.get('services_list', [])
    if services_list:
        console.print(f"\n[bold]🔧 发现的服务类型:[/bold]")
        for service in sorted(services_list)[:20]:
            console.print(f"   • {service}")
        if len(services_list) > 20:
            console.print(f"   ... 以及其他 {len(services_list) - 20} 种服务")
    
    # 高风险主机
    high_risk_hosts = risks.get('high_risk_hosts', [])
    if high_risk_hosts:
        console.print(f"\n[bold red]⚠️ 高风险主机 (TOP 10):[/bold red]")
        
        for i, host in enumerate(high_risk_hosts[:10], 1):
            risk_color = 'red' if host.get('risk_score', 0) >= 50 else ('yellow' if host.get('risk_score', 0) >= 20 else 'blue')
            
            console.print(
                f"\n{i}. [{risk_color}][风险分: {host.get('risk_score', 0)}][/{risk_color}] "
                f"[bold]{host.get('ip', 'Unknown')}[/bold]"
            )
            
            open_ports = host.get('open_ports', [])
            if open_ports:
                ports_str = ', '.join(map(str, sorted(open_ports)[:10]))
                console.print(f"   🔓 开放端口: {ports_str}")
                if len(open_ports) > 10:
                    console.print(f"      ... 等共 {len(open_ports)} 个端口")
            
            hostname = host.get('hostname')
            if hostname and hostname != 'Unknown':
                console.print(f"   🏷️  主机名: {hostname}")
    
    # 关键安全发现
    critical_findings = risks.get('critical_findings', [])
    if critical_findings:
        console.print(f"\n[bold red]🔴 关键安全发现:[/bold red]")
        
        for finding in critical_findings[:15]:
            severity_icon = '🔴' if finding.get('severity') == 'HIGH' else '🟡'
            
            console.print(
                f"\n{severity_icon} [bold]{finding.get('host')}:{finding.get('port')}[/bold]"
                f" - {finding.get('service')}"
            )
            console.print(f"   ⚠️  {finding.get('description')}")
            console.print(f"   💡 建议: {finding.get('recommendation', 'N/A')}")
        
        if len(critical_findings) > 15:
            console.print(f"\n[dim]... 还有 {len(critical_findings) - 15} 个关键发现[/dim]")
    
    # 子网详情
    subnets = scan_result.get('subnets', [])
    if subnets:
        console.print(f"\n[bold]🌐 子网详情:[/bold]")
        
        for subnet in subnets[:5]:  # 显示前5个子网
            network = subnet.get('network', 'Unknown')
            discovered = subnet.get('discovered', 0)
            alive = subnet.get('alive_hosts', 0)
            
            console.print(
                f"   • [cyan]{network}[/cyan] "
                f"(发现: {discovered}, 存活: {alive})"
            )
        
        if len(subnets) > 5:
            console.print(f"   ... 共扫描了 {len(subnets)} 个子网")
    
    console.print("\n" + "━" * 70)


def _save_internal_scan_report(scan_result: Dict, output_path: str, format: str = 'json'):
    """
    保存内网扫描报告到文件
    
    Args:
        scan_result: 扫描结果
        output_path: 输出文件路径
        format: 输出格式 (json/html/markdown)
    """
    import json
    from datetime import datetime
    
    try:
        if format.lower() in ['json', '.json']:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(scan_result, f, ensure_ascii=False, indent=2)
                
        elif format.lower() in ['markdown', '.md']:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# HOS-LS 企业内网安全扫描报告\n\n")
                f.write(f"**生成时间**: {datetime.now().isoformat()}\n\n")
                
                stats = scan_result.get('statistics', {})
                f.write("## 统计摘要\n\n")
                f.write(f"- 目标总数: {stats.get('total_targets', 0)}\n")
                f.write(f"- 存活主机: {stats.get('alive_hosts', 0)}\n")
                f.write(f"- 开放端口: {stats.get('total_open_ports', 0)}\n")
                f.write(f"- 发现服务: {stats.get('unique_services', 0)} 种\n\n")
                
                risks = scan_result.get('risk_assessment', {})
                findings = risks.get('critical_findings', [])
                
                if findings:
                    f.write("## 关键安全发现\n\n")
                    for finding in findings[:20]:
                        f.write(f"### {finding.get('host')}:{finding.get('port')} - {finding.get('service')}\n\n")
                        f.write(f"**严重性**: {finding.get('severity')}\n\n")
                        f.write(f"**描述**: {finding.get('description')}\n\n")
                        f.write(f"**建议**: {finding.get('recommendation')}\n\n")
                        f.write("---\n\n")
        
        from rich.console import Console
        console = Console()
        console.print(f"[green]✅ 内网扫描报告已保存: {output_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]保存报告失败: {e}[/red]")


@cli.command()
@click.option("--session", help="会话名称，用于保存对话历史")
@click.option("--model", help="AI 模型名称")
@click.pass_context
def chat(ctx: click.Context, session: Optional[str], model: Optional[str]) -> None:
    """进入智能交互模式（统一聊天+Agent编排）
    
    整合了聊天模式和Agent编排语言的统一体验：
    - 支持自然语言命令：'扫描当前目录'、'全面审计项目'
    - 支持CLI命令：'--full-audit'、'--scan+reason+poc'
    - 支持方案管理：'生成审计方案'、'执行方案'
    - 支持双向转换：'转换为CLI: 完整审计'
    
    示例:
    - '扫描当前目录并生成报告'
    - '用纯AI模式分析认证模块'
    - '生成完整审计方案'
    - '解释CLI: --full-audit'
    """
    config: Config = ctx.obj["config"]
    
    # 显示欢迎信息
    print_banner()
    
    # 使用增强的TerminalUI
    from src.utils.terminal_ui import TerminalUI
    terminal_ui = TerminalUI()
    terminal_ui.show_welcome_banner()
    
    # 验证AI配置
    from src.core.ai_config_validator import AIConfigValidator
    AIConfigValidator.ensure_configured(config)
    
    # 初始化统一交互引擎
    from src.core.unified_interaction_engine import UnifiedInteractionEngine
    engine = UnifiedInteractionEngine(config, session=session)
    
    # 对话循环
    while True:
        try:
            # 获取用户输入
            user_input = terminal_ui.get_input("[bold green]> [/bold green]")
            
            # 处理特殊命令
            if user_input.strip() in ["/exit", "/quit"]:
                engine.save_session()
                console.print("[bold cyan]💾 会话已保存[/bold cyan]")
                console.print("[bold cyan]再见！[/bold cyan]")
                break
            elif user_input.strip() == "/help":
                terminal_ui.show_unified_help()
                continue
            elif user_input.strip() == "/clear":
                terminal_ui.clear_screen()
                continue
            elif user_input.strip() == "/context":
                terminal_ui.show_context_summary(engine.conversation_manager.project_context)
                continue
            elif user_input.strip() == "/history":
                history = engine.get_conversation_history()
                console.print(f"[dim]共 {len(history.messages)} 条消息[/dim]")
                for msg in history.messages[-5:]:
                    role_label = "👤" if msg.role == "user" else "🤖"
                    content_preview = msg.content[:50] + "..." if len(msg.content) > 50 else msg.content
                    console.print(f"  {role_label} {content_preview}")
                continue
            
            # 处理空输入
            if not user_input.strip():
                continue
            
            # 显示思考状态
            terminal_ui.show_thinking()
            
            # 使用统一引擎处理
            result = engine.process(user_input)
            
            # 显示结果
            terminal_ui.show_result(result)
            
        except KeyboardInterrupt:
            engine.save_session()
            console.print("\n[bold cyan]💾 会话已保存[/bold cyan]")
            console.print("[bold cyan]再见！[/bold cyan]")
            break
        except Exception as e:
            console.print(f"[bold red]错误: {e}[/bold red]")
            continue


# 添加plan命令组
cli.add_command(plan)


def main() -> None:
    """主入口"""
    cli()


if __name__ == "__main__":
    main()
