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

from src import __version__
from src.core.config import Config, ConfigManager

console = Console(emoji=False)


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
) -> None:
    """扫描代码安全漏洞"""
    config: Config = ctx.obj["config"]
    
    # 显示 Claude 风格的输入提示
    if not config.quiet:
        console.print("[bold cyan]> hosls scan " + target + "[/bold cyan]")

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
        
        # 纯AI模式默认使用deepseek-chat
        config.pure_ai_provider = "deepseek"
        config.pure_ai_model = "deepseek-chat"
        
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
            return

        # 截断和续传配置
        config.resume = resume
        config.truncate_output = truncate_output
        config.max_duration = max_duration
        config.max_files = max_files

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
    config.ai.enabled = ai
    config.pure_ai = False
    if mode:
        config.scan_mode = mode
    elif pure_ai:
        config.scan_mode = "pure-ai"
    
    if ai_provider:
        config.ai.provider = ai_provider
    
    if tool_chain:
        config.tools_enabled = True
        config.tool_chain = [t.strip() for t in tool_chain.split(',') if t.strip()]
        console.print(f"[bold cyan]🔧 工具链已启用: {config.tool_chain}[/bold cyan]")
    
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
        state_file = Path(output).parent / '.scan_state.json'
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


def main() -> None:
    """主入口"""
    cli()


if __name__ == "__main__":
    main()
