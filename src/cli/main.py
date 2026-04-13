"""CLI 主模块

HOS-LS 的命令行入口。
"""

import sys
import os
import io
import contextlib
import threading
from queue import Queue, Empty

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
        self._lock = threading.RLock()  # 添加线程锁确保线程安全
    
    def start(self):
        """启动Worker"""
        with self._lock:
            if not self.running:
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
        with self._lock:
            if self.running:
                self.running = False
                self.executor.shutdown(wait=False)  # 非阻塞关闭
    
    def add_task(self, task, *args, **kwargs):
        """添加任务到队列"""
        if not callable(task):
            console.print(f"[bold red]错误: 任务必须是可调用对象[/bold red]")
            return
        
        with self._lock:
            if self.running:
                self.queue.put((task, args, kwargs))
            else:
                console.print(f"[bold yellow]警告: Worker 未运行，任务未添加[/bold yellow]")
    
    async def _process_queue(self):
        """处理队列中的任务"""
        while True:
            with self._lock:
                if not self.running and self.queue.empty():
                    break
            
            try:
                # 使用非阻塞方式获取任务，避免长时间阻塞
                try:
                    task, args, kwargs = self.queue.get(block=False)
                    try:
                        await asyncio.to_thread(task, *args, **kwargs)
                    except Exception as e:
                        console.print(f"[bold red]任务执行失败: {e}[/bold red]")
                    finally:
                        self.queue.task_done()
                except Empty:
                    await asyncio.sleep(0.1)
            except Exception as e:
                console.print(f"[bold red]队列处理错误: {e}[/bold red]")
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
@click.argument("query", nargs=-1)
# 简化的核心选项
@click.option("--mode", "-m", type=click.Choice(["auto", "pure-ai", "fast", "deep", "stealth"]), default="auto", help="运行模式")
@click.option("--format", "-f", "output_format", default="html", help="输出格式 (html, markdown, json, sarif)")
@click.option("--output", "-o", help="输出文件路径")
@click.option("--plan", help="使用指定的Plan执行")
@click.option("--lang", type=click.Choice(["cn", "en"]), help="输出语言")
@click.option("--test", type=int, default=0, help="启用测试模式，指定扫描文件数量")
# 宏命令选项
@click.option("--full-audit", is_flag=True, help="完整审计 - 全流程深度安全审计")
@click.option("--quick-scan", is_flag=True, help="快速扫描 - 扫描并生成报告")
@click.option("--deep-audit", is_flag=True, help="深度审计 - 包含漏洞验证的完整审计")
@click.option("--red-team", is_flag=True, help="红队模式 - 模拟攻击者视角的全面测试")
@click.option("--bug-bounty", is_flag=True, help="漏洞赏金模式 - 针对漏洞赏金的高效扫描")
@click.option("--compliance", is_flag=True, help="合规模式 - 符合安全合规要求的检查")
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    query: tuple,
    mode: str,
    output_format: str,
    output: Optional[str],
    plan: Optional[str],
    lang: Optional[str],
    test: int,
    full_audit: bool,
    quick_scan: bool,
    deep_audit: bool,
    red_team: bool,
    bug_bounty: bool,
    compliance: bool,
) -> None:
    """扫描代码安全漏洞（支持自然语言输入）
    
    示例：
    \b
    基本扫描: hos-ls scan ./my-project
    自然语言查询: hos-ls scan ./my-project "扫描SQL注入漏洞并生成修复方案"
    纯AI模式: hos-ls scan ./my-project --mode pure-ai
    快速模式: hos-ls scan ./my-project --mode fast
    """
    config: Config = ctx.obj["config"]
    
    # 设置语言
    if lang:
        config.language = lang
    
    # 处理Plan选项
    if plan:
        from src.core.plan_manager import PlanManager
        try:
            plan_manager = PlanManager(config)
            # 加载Plan
            loaded_plan = plan_manager.load_plan(plan)
            
            # 显示执行的Plan
            console.print(Panel("执行Plan", border_style="green"))
            console.print(f"目标: {loaded_plan.goal}")
            console.print(f"步骤数: {len(loaded_plan.steps)}")
            
            # 执行Plan
            result = asyncio.run(plan_manager.execute_plan(loaded_plan))
            
            # 显示结果
            # 转换结果为对象格式
            class ResultObject:
                def __init__(self, data):
                    self.__dict__.update(data)
            result_obj = ResultObject(result)
            display_unified_result(result_obj, console, quiet=config.quiet)
            
            # 生成报告
            if output:
                # 转换结果为对象格式
                class ResultObject:
                    def __init__(self, data):
                        self.__dict__.update(data)
                result_obj = ResultObject(result)
                _generate_unified_report(result_obj, output, output_format, config)
            
            # 设置退出码
            if not result.get("success", True) and result.get("total_findings", 0) > 0:
                sys.exit(1)
            return
        except Exception as e:
            console.print(f"[bold red]错误: {e}[/bold red]")
            sys.exit(1)
    
    # 处理自然语言查询
    user_query = " ".join(query)
    
    # 测试模式配置
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
    
    # 生成执行计划
    from src.core.plan import AIPlanner
    from src.core.ai_client import get_ai_client
    
    ai_client = get_ai_client(config)
    planner = AIPlanner(ai_client)
    
    # 构建上下文
    context = {
        "file_system": {
            "target": target,
            "exists": os.path.exists(target),
            "is_dir": os.path.isdir(target)
        },
        "tools": ["scan", "analyze", "exploit", "fix", "report"]
    }
    
    # 生成计划
    if user_query:
        console.print(f"[bold cyan]分析查询: {user_query}[/bold cyan]")
        plan = planner.generate_plan(user_query, context)
    else:
        # 默认计划
        plan = planner.generate_plan(f"扫描 {target} 的安全漏洞", context)
    
    # 显示生成的计划
    if not config.quiet:
        console.print(Panel("[bold green]生成的执行计划[/bold green]"))
        for i, step in enumerate(plan.steps, 1):
            console.print(f"{i}. [{step.risk_level.upper()}] {step.type.value}: {step.description}")
            if step.estimated_tokens > 0:
                console.print(f"   预估Token: {step.estimated_tokens}")
    
    # 执行计划
    try:
        import asyncio
        from src.cli.agent_integration import execute_with_unified_engine
        
        # 构建行为flags
        behavior_flags = []
        
        # 处理宏命令
        if full_audit:
            behavior_flags.extend(['scan', 'reason', 'attack-chain', 'poc', 'report'])
        elif quick_scan:
            behavior_flags.extend(['scan', 'report'])
        elif deep_audit:
            behavior_flags.extend(['scan', 'reason', 'attack-chain', 'poc', 'verify', 'report'])
        elif red_team:
            behavior_flags.extend(['scan', 'reason', 'attack-chain', 'poc', 'verify'])
        elif bug_bounty:
            behavior_flags.extend(['scan', 'reason', 'poc', 'report'])
        elif compliance:
            behavior_flags.extend(['scan', 'reason', 'report'])
        else:
            # 默认行为
            behavior_flags.extend(['scan', 'report'])
        
        # 执行扫描
        result = asyncio.run(execute_with_unified_engine(
            config=config,
            target=target,
            behavior_flags=behavior_flags,
            mode=mode,
            ask=user_query,
            focus=None
        ))
        
        # 显示结果
        display_unified_result(result, console, quiet=config.quiet)
        
        # 生成报告
        if output:
            _generate_unified_report(result, output, output_format, config)
        
        # 设置退出码
        if not result.success and result.total_findings > 0:
            sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]执行失败: {e}[/bold red]")
        if config.debug:
            import traceback
            traceback.print_exc()
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
        # 跳过 ReportGeneratorAgent，因为它的 findings 是重复的（收集了其他 Agent 的 findings）
        if agent_name in ['report', 'ReportGeneratorAgent']:
            continue
            
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
    engine = UnifiedInteractionEngine(config, session_name=session)
    
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


# 🔥🔥🔥 Phase 2: 增量索引管理命令组（新增）
@cli.group()
def index() -> None:
    """增量索引管理命令
    
    管理项目的增量扫描索引，提高重复扫描效率。
    
    示例：
    \b
    hos-ls index status ./project      查看索引状态
    hos-ls index rebuild ./project     重建索引
    """
    pass


@index.command("status")
@click.argument("target", required=False, default=".")
def index_status(target: str) -> None:
    """显示项目增量索引状态
    
    显示当前项目的文件索引信息，包括：
    - 已索引文件数量
    - 最后更新时间
    - 变更统计（新增/修改/删除）
    - 预计扫描时间节省
    """
    _show_index_status(target, console)


@index.command("rebuild")
@click.argument("target", required=False, default=".")
@click.option("--force", "-f", is_flag=True, help="强制重建，即使索引存在")
def index_rebuild(target: str, force: bool) -> None:
    """重建项目增量索引
    
    重新扫描目标目录并建立/更新增量索引。
    重建后，后续扫描将只分析变更的文件。
    
    使用场景：
    - 索引损坏或数据不一致
    - 项目结构发生重大变化
    - 首次使用增量扫描功能
    """
    from pathlib import Path
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    
    target_path = Path(target).resolve()
    
    if not target_path.exists():
        console.print(f"[bold red]错误: 目标路径不存在: {target}[/bold red]")
        sys.exit(1)
    
    console.print(Panel(
        f"[bold cyan]🔄 重建增量索引[/bold cyan]\n"
        f"目标: {target_path}\n"
        f"模式: {'强制重建' if force else '智能更新'}",
        border_style="cyan"
    ))
    
    try:
        from src.utils.incremental_index import IncrementalIndexManager
        
        with Progress(
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]正在建立索引...", total=None)
            
            index_manager = IncrementalIndexManager()
            
            if force:
                result = index_manager.build_full_index(str(target_path))
            else:
                result = index_manager.update_index(str(target_path))
            
            progress.update(task, completed=True)
        
        # 显示结果
        _display_index_rebuild_result(result, console)
        
    except ImportError:
        console.print("[yellow]警告: 增量索引模块未安装，请确保依赖完整[/yellow]")
        sys.exit(2)
    except Exception as e:
        console.print(f"[bold red]索引重建失败: {e}[/bold red]")
        if config_debug := ctx.obj.get("config"):
            if config_debug.debug:
                import traceback
                traceback.print_exc()
        sys.exit(1)


def _show_index_status(target: str, console: Console) -> None:
    """显示项目索引状态的内部实现"""
    from pathlib import Path
    from rich.table import Table
    
    target_path = Path(target).resolve()
    
    if not target_path.exists():
        console.print(f"[bold red]错误: 目标路径不存在: {target}[/bold red]")
        sys.exit(1)
    
    try:
        from src.utils.incremental_index import IncrementalIndexManager
        
        index_manager = IncrementalIndexManager()
        status = index_manager.get_index_status(str(target_path))
        
        if not status.get('exists', False):
            console.print(Panel(
                "[bold yellow]⚠️ 未找到增量索引[/bold yellow]\n\n"
                "该项目尚未建立增量索引。\n"
                "首次扫描时会自动创建索引。\n\n"
                "[dim]提示: 使用 'hos-ls index rebuild' 手动创建索引[/dim]",
                border_style="yellow"
            ))
            return
        
        # 创建状态表格
        table = Table(title=f"📊 增量索引状态 - {target_path.name}")
        table.add_column("项目", style="cyan")
        table.add_column("值", style="green")
        
        table.add_row("📁 索引路径", str(status.get('index_path', 'N/A')))
        table.add_row("📄 已索引文件数", str(status.get('total_files', 0)))
        table.add_row("🕐 最后更新", str(status.get('last_updated', 'N/A')))
        table.add_row("📦 索引大小", f"{status.get('index_size_bytes', 0) / 1024:.1f} KB")
        
        # 变更统计
        changes = status.get('changes', {})
        if changes:
            table.add_row("➕ 新增文件", str(changes.get('added', 0)))
            table.add_row("✏️ 修改文件", str(changes.get('modified', 0)))
            table.add_row("➖ 删除文件", str(changes.get('deleted', 0)))
        
        console.print(table)
        
        # 显示变更详情
        if changes and any(changes.values()):
            change_table = Table(title="📋 变更文件列表")
            change_table.add_column("类型", style="cyan")
            change_table.add_column("文件路径", style="white")
            
            for change_type, files in changes.items():
                if files and change_type in ['added', 'modified', 'deleted']:
                    type_icon = {"added": "➕", "modified": "✏️", "deleted": "➖"}.get(change_type, "•")
                    for file_path in files[:10]:  # 只显示前10个
                        change_table.add_row(f"{type_icon} {change_type}", file_path)
                    if len(files) > 10:
                        change_table.add_row("...", f"... 还有 {len(files) - 10} 个文件")
            
            if change_table.rows:
                console.print(change_table)
        
        # 性能预估
        if status.get('estimated_time_saving'):
            saving = status['estimated_time_saving']
            console.print(f"\n[bold green]⚡ 预计可节省 ~{saving:.0f}秒 扫描时间[/bold green]")
        
    except ImportError:
        console.print("[yellow]警告: 增量索引模块未安装[/yellow]")
    except Exception as e:
        console.print(f"[bold red]获取索引状态失败: {e}[/bold red]")


def _handle_resume_scan(target: str, checkpoint_id: Optional[str], 
                        config: Config, console: Console) -> None:
    """处理断点续扫请求"""
    from pathlib import Path
    from rich.panel import Panel
    
    target_path = Path(target).resolve()
    
    try:
        from src.core.checkpoint_manager import CheckpointManager
        
        checkpoint_mgr = CheckpointManager(base_dir=str(target_path))
        
        # 获取可用断点
        if checkpoint_id:
            checkpoint = checkpoint_mgr.load_checkpoint(checkpoint_id)
            if not checkpoint:
                console.print(f"[bold red]错误: 未找到断点 ID: {checkpoint_id}[/bold red]")
                sys.exit(1)
        else:
            # 自动查找最新断点
            checkpoint = checkpoint_mgr.get_latest_checkpoint(target=str(target_path))
            if not checkpoint:
                console.print(Panel(
                    "[bold yellow]⚠️ 未找到可恢复的断点[/bold yellow]\n\n"
                    "没有找到可以恢复的扫描断点。\n"
                    "可能的原因：\n"
                    "• 该项目之前从未进行过扫描\n"
                    "• 上次扫描正常完成，已自动清理断点\n"
                    "• 断点文件已被手动删除\n\n"
                    "[dim]建议: 使用普通扫描模式开始新的扫描[/dim]",
                    border_style="yellow"
                ))
                return
        
        # 显示断点信息
        progress = checkpoint.scan_progress
        console.print(Panel(
            f"[bold green]🔄 发现可恢复的断点[/bold green]\n\n"
            f"📝 断点ID: {checkpoint.checkpoint_id[:8]}...\n"
            f"📊 扫描进度: {progress.processed_files}/{progress.total_files} "
            f"({(progress.processed_files/progress.total_files*100):.1f}%)\n"
            f"🐛 已发现问题: {progress.issues_found}\n"
            f"🕐 断点时间: {checkpoint.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"[dim]准备从断点位置继续扫描...[/dim]",
            border_style="green"
        ))
        
        # 执行恢复扫描
        import asyncio
        from src.core.unified_interaction_engine import UnifiedInteractionEngine
        
        engine = UnifiedInteractionEngine(config)
        
        console.print("\n[bold cyan]⚡ 正在恢复扫描...[/bold cyan]")
        
        result = asyncio.run(engine.resume_from_checkpoint(
            target=str(target_path),
            checkpoint=checkpoint,
            config=config
        ))
        
        # 显示结果
        if result.success:
            console.print(f"\n[bold green]✅ 扫描完成！共发现 {result.total_findings} 个问题[/bold green]")
        else:
            console.print(f"\n[yellow]扫描完成，但可能存在部分问题: {result.message}[/yellow]")
        
    except ImportError:
        console.print("[yellow]警告: 断点管理模块未安装[/yellow]")
    except Exception as e:
        console.print(f"[bold red]断点恢复失败: {e}[/bold red]")
        if config.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _display_index_rebuild_result(result: Dict[str, Any], console: Console) -> None:
    """显示索引重建结果"""
    from rich.table import Table
    
    success = result.get('success', False)
    
    if success:
        table = Table(title="✅ 索引重建成功")
        table.add_column("指标", style="cyan")
        table.add_column("值", style="green")
        
        table.add_row("📄 总文件数", str(result.get('total_files', 0)))
        table.add_row("⏱️ 用时", f"{result.get('duration_seconds', 0):.2f}秒")
        table.add_row("📦 索引大小", f"{result.get('index_size_bytes', 0) / 1024:.1f} KB")
        
        console.print(table)
        console.print("\n[bold green]💡 后续扫描将自动使用增量模式，显著提升速度！[/bold green]")
    else:
        console.print(f"[bold red]❌ 索引重建失败: {result.get('error', '未知错误')}[/bold red]")


def main() -> None:
    """主入口"""
    cli()


if __name__ == "__main__":
    main()
