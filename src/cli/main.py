"""CLI 主模块

HOS-LS 的命令行入口。
"""

import sys
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from src import __version__
from src.core.config import Config, ConfigManager
from src.core.scanner import SecurityScanner, create_scanner
from src.integration.nvd_update import run_update
from src.storage.rag_knowledge_base import get_rag_knowledge_base

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
        asyncio.create_task(self._process_queue())
    
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
    banner = f"""
[bold blue] _   _  ___   ___       _     _[/bold blue]
[bold blue]| | | |/ _ \ / __|     | |   | |[/bold blue]
[bold blue]| |_| | | | |\ \  _____| |___| |[/bold blue]
[bold blue]|  _  | |_| | > >|_____|  ___  |[/bold blue]
[bold blue]|_| |_|\___/ |_/       |_|   |_|[/bold blue]
[bold green]AI 生成代码安全扫描工具 v{__version__}[/bold green]
    """
    console.print(banner)


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
@click.option("--ai-provider", help="AI 提供商 (anthropic, openai, deepseek, local)")
@click.option("--incremental", is_flag=True, help="启用增量扫描")
@click.option("--langgraph", is_flag=True, help="使用 LangGraph 流程")
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
    ai_provider: Optional[str],
    incremental: bool,
    langgraph: bool,
) -> None:
    """扫描代码安全漏洞"""
    config: Config = ctx.obj["config"]

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
    if ai_provider:
        config.ai.provider = ai_provider

    # 执行扫描
    try:
        if langgraph:
            # 使用 LangGraph 多Agent流程
            from src.core.langgraph_flow import analyze_code
            import asyncio
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
            scanner = create_scanner(config)
            result = scanner.scan_sync(target)

            # 显示结果
            if not config.quiet:
                _display_result(result)

            # 生成报告
            if output:
                _generate_report(result, output, output_format)

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
@click.option("--zip", "-z", type=click.Path(exists=True), default="nvd-json-data-feeds-main.zip", help="NVD压缩包路径 (默认: nvd-json-data-feeds-main.zip)")
@click.option("--limit", "-l", type=int, default=None, help="限制处理的文件数量 (用于测试)")
@click.option("--no-rag", is_flag=True, help="不导入到RAG库，仅解析")
@click.option("--batch-size", "-b", type=int, default=1000, help="批量处理大小 (默认: 1000)")
@click.option("--resume", type=int, default=0, help="从指定文件开始续传")
@click.pass_context
def update(ctx, zip, limit, no_rag, batch_size, resume) -> None:
    """更新NVD漏洞库，解压并同步到本地RAG库"""
    config: Config = ctx.obj["config"]
    
    zip_path = Path(zip)
    if not zip_path.exists():
        script_dir = Path(__file__).parent.parent.parent
        script_zip = script_dir / zip
        if script_zip.exists():
            zip_path = script_zip
        else:
            console.print(f"[bold red]错误: 找不到压缩包: {zip}[/bold red]")
            console.print(f"请确保文件存在于: {zip_path.absolute()}")
            return
    
    rag_base = None
    if not no_rag:
        try:
            rag_base = get_rag_knowledge_base()
            console.print("[bold green]已连接到RAG知识库[/bold green]")
        except Exception as e:
            console.print(f"[bold yellow]警告: 无法初始化RAG知识库: {e}[/bold yellow]")
            console.print("[bold yellow]将仅解析数据，不导入RAG[/bold yellow]")
    
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
                str(zip_path),
                rag_base=rag_base,
                limit=limit,
                batch_size=batch_size,
                resume_from=resume,
                progress_callback=progress_callback
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


def _display_result(result) -> None:
    """显示扫描结果"""
    from src.core.engine import Severity

    summary = result.to_dict()["summary"]

    # 创建结果表格
    table = Table(title="扫描结果摘要")
    table.add_column("严重级别", style="cyan")
    table.add_column("数量", style="green")

    severity_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
        "info": "grey",
    }

    for severity in ["critical", "high", "medium", "low", "info"]:
        count = summary.get(severity, 0)
        color = severity_colors.get(severity, "white")
        table.add_row(f"[{color}]{severity}[/{color}]", str(count))

    table.add_row("总计", str(summary["total"]), style="bold")

    console.print(table)

    # 显示详细发现
    if result.findings:
        console.print("\n[bold]发现问题:[/bold]")
        for i, finding in enumerate(result.findings[:10], 1):  # 只显示前10个
            severity_color = severity_colors.get(finding.severity.value, "white")
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

    # 显示攻击链分析结果
    if hasattr(result, 'metadata') and 'local_attack_chain' in result.metadata:
        attack_chain_data = result.metadata['local_attack_chain']
        if attack_chain_data.get('critical_chains'):
            console.print("\n[bold]攻击链分析:[/bold]")
            console.print(f"[info]{attack_chain_data.get('summary', '')}[/info]")
            
            for i, chain in enumerate(attack_chain_data['critical_chains'][:3], 1):
                risk_color = "red" if chain['risk_level'] == "high" else "yellow" if chain['risk_level'] == "medium" else "blue"
                console.print(f"\n{i}. [{risk_color}]攻击路径 (风险: {chain['risk_level']})[/{risk_color}]")
                console.print(f"   路径: {chain['description']}")
                console.print("   步骤:")
                for step in chain['steps']:
                    console.print(f"     - {step['description']}")
                console.print(f"   状态: {chain['status']}")


def _generate_report(result, output: str, format: str) -> None:
    """生成报告"""
    from src.reporting.generator import JSONReportGenerator, HTMLReportGenerator, MarkdownReportGenerator, SARIFReportGenerator
    
    # 根据格式选择报告生成器
    generators = {
        "json": JSONReportGenerator,
        "html": HTMLReportGenerator,
        "markdown": MarkdownReportGenerator,
        "sarif": SARIFReportGenerator
    }
    
    generator_class = generators.get(format)
    if not generator_class:
        console.print(f"[bold red]不支持的报告格式: {format}[/bold red]")
        return
    
    try:
        generator = generator_class()
        report_path = generator.generate([result], output)
        console.print(f"[bold green]报告已生成: {report_path}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]报告生成失败: {e}[/bold red]")


def main() -> None:
    """主入口"""
    cli()


if __name__ == "__main__":
    main()
