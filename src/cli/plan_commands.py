"""Plan命令组

提供Plan相关的CLI命令。
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.core.plan_manager import PlanManager
from src.core.plan_dsl import PlanDSLParser
from src.core.config import Config

console = Console()


@click.group()
def plan():
    """Plan管理命令"""
    pass


@plan.command()
@click.argument("description", required=False)
@click.option("--template", "-t", help="使用预设模板")
@click.pass_context
def generate(ctx, description, template):
    """生成执行方案
    
    DESCRIPTION: 自然语言描述任务目标
    """
    config: Config = ctx.obj["config"]
    plan_manager = PlanManager(config)
    
    if config.debug:
        console.print(Panel("[DEBUG] 开始生成方案", border_style="yellow"))
        if description:
            console.print(f"[DEBUG] 输入描述: {description}")
        if template:
            console.print(f"[DEBUG] 使用模板: {template}")
    
    if template:
        try:
            if config.debug:
                console.print("[DEBUG] 从模板生成Plan")
            plan = plan_manager.generate_from_template(template)
        except ValueError as e:
            console.print(f"[bold red]错误: {e}[/bold red]")
            return
    elif description:
        if config.debug:
            console.print("[DEBUG] 从自然语言生成Plan")
        plan = plan_manager.generate_from_natural_language(description)
    else:
        console.print("[bold red]错误: 请提供任务描述或使用模板[/bold red]")
        return
    
    if config.debug:
        console.print("[DEBUG] Plan生成完成")
        console.print("[DEBUG] Plan内容:")
        console.print(PlanDSLParser.to_yaml(plan))
    
    # 显示生成的Plan
    console.print(Panel("生成的执行方案", border_style="cyan"))
    console.print(PlanDSLParser.format_plan_for_display(plan))
    
    # 询问是否保存
    if click.confirm("是否保存此方案？"):
        name = click.prompt("请输入方案名称")
        try:
            if config.debug:
                console.print(f"[DEBUG] 保存Plan到: {name}")
            file_path = plan_manager.save_plan(plan, name)
            console.print(f"[bold green]方案已保存: {file_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]保存失败: {e}[/bold red]")


@plan.command()
@click.argument("name")
@click.option("--file", "-f", help="保存到指定文件")
@click.pass_context
def save(ctx, name, file):
    """保存方案到文件
    
    NAME: 方案名称
    """
    config: Config = ctx.obj["config"]
    plan_manager = PlanManager(config)
    
    try:
        # 加载现有Plan
        plan = plan_manager.load_plan(name)
        
        if file:
            # 保存到指定文件
            PlanDSLParser.save_to_file(plan, file)
            console.print(f"[bold green]方案已保存到: {file}[/bold green]")
        else:
            # 保存到默认位置
            file_path = plan_manager.save_plan(plan, name)
            console.print(f"[bold green]方案已保存: {file_path}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]错误: {e}[/bold red]")


@plan.command()
@click.argument("name")
@click.pass_context
def load(ctx, name):
    """加载方案
    
    NAME: 方案名称
    """
    config: Config = ctx.obj["config"]
    plan_manager = PlanManager(config)
    
    try:
        plan = plan_manager.load_plan(name)
        console.print(Panel(f"加载的方案: {name}", border_style="cyan"))
        console.print(PlanDSLParser.format_plan_for_display(plan))
    except Exception as e:
        console.print(f"[bold red]错误: {e}[/bold red]")


@plan.command()
@click.argument("name")
@click.pass_context
def run(ctx, name):
    """执行方案
    
    NAME: 方案名称
    """
    config: Config = ctx.obj["config"]
    plan_manager = PlanManager(config)
    
    if config.debug:
        console.print(Panel("[DEBUG] 开始执行方案", border_style="yellow"))
        console.print(f"[DEBUG] 方案名称: {name}")
    
    try:
        # 加载Plan
        if config.debug:
            console.print("[DEBUG] 加载Plan")
        plan = plan_manager.load_plan(name)
        
        if config.debug:
            console.print("[DEBUG] Plan加载完成")
            console.print("[DEBUG] Plan内容:")
            console.print(PlanDSLParser.to_yaml(plan))
        
        # 显示执行计划
        console.print(Panel("执行方案", border_style="green"))
        console.print(PlanDSLParser.format_plan_for_display(plan))
        
        # 转换为CLI参数
        if config.debug:
            console.print("[DEBUG] 转换为CLI参数")
        cli_args = _plan_to_cli_args(plan)
        
        if config.debug:
            console.print("[DEBUG] CLI参数:")
            console.print(cli_args)
        
        # 导入扫描函数
        from src.cli.main import scan
        
        # 执行扫描
        if config.debug:
            console.print("[DEBUG] 开始执行扫描")
        ctx.invoke(scan, **cli_args)
        
        if config.debug:
            console.print("[DEBUG] 扫描执行完成")
        
    except Exception as e:
        console.print(f"[bold red]错误: {e}[/bold red]")


@plan.command()
@click.argument("name")
@click.pass_context
def explain(ctx, name):
    """解释方案
    
    NAME: 方案名称
    """
    config: Config = ctx.obj["config"]
    plan_manager = PlanManager(config)
    
    try:
        plan = plan_manager.load_plan(name)
        
        console.print(Panel("方案解释", border_style="blue"))
        console.print(f"[bold]目标:[/bold] {plan.goal}")
        console.print(f"[bold]配置文件:[/bold] {plan.profile.value}")
        console.print("[bold]选择理由:[/bold]")
        
        # 生成解释
        explanations = _generate_plan_explanation(plan)
        for explanation in explanations:
            console.print(f"  - {explanation}")
            
    except Exception as e:
        console.print(f"[bold red]错误: {e}[/bold red]")


@plan.command()
@click.argument("name")
@click.pass_context
def visualize(ctx, name):
    """可视化方案
    
    NAME: 方案名称
    """
    config: Config = ctx.obj["config"]
    plan_manager = PlanManager(config)
    
    try:
        plan = plan_manager.load_plan(name)
        
        console.print(Panel("方案可视化", border_style="magenta"))
        
        # 文本可视化
        console.print("[bold]执行流程:[/bold]")
        steps = [step.type.value for step in plan.steps]
        flow = " → ".join(steps)
        console.print(f"  {flow}")
        
        # 显示详细信息
        console.print("\n[bold]步骤详情:[/bold]")
        for i, step in enumerate(plan.steps, 1):
            console.print(f"{i}. {step.type.value}")
            if step.config:
                for key, value in step.config.items():
                    console.print(f"   - {key}: {value}")
                    
    except Exception as e:
        console.print(f"[bold red]错误: {e}[/bold red]")


@plan.command()
@click.pass_context
def list(ctx):
    """列出保存的方案"""
    config: Config = ctx.obj["config"]
    plan_manager = PlanManager(config)
    
    plans = plan_manager.list_plans()
    
    if not plans:
        console.print("[bold yellow]没有保存的方案[/bold yellow]")
        return
    
    table = Table(title="保存的方案")
    table.add_column("名称", style="cyan")
    table.add_column("操作", style="green")
    
    for plan_name in plans:
        table.add_row(plan_name, f"hos-ls plan run {plan_name}")
    
    console.print(table)


@plan.command()
@click.argument("name")
@click.pass_context
def delete(ctx, name):
    """删除方案
    
    NAME: 方案名称
    """
    config: Config = ctx.obj["config"]
    plan_manager = PlanManager(config)
    
    if plan_manager.delete_plan(name):
        console.print(f"[bold green]方案已删除: {name}[/bold green]")
    else:
        console.print(f"[bold red]方案不存在: {name}[/bold red]")


def _plan_to_cli_args(plan):
    """将Plan转换为CLI参数"""
    args = {
        "target": ".",
        "scan": False,
        "reason": False,
        "attack_chain": False,
        "poc": False,
        "verify": False,
        "fix": False,
        "report": False,
        "pure_ai": False,
        "fast": False,
        "deep": False,
        "stealth": False,
        "output_format": "html",
        "output": None,
        "ruleset": None,
        "diff": False,
        "workers": 4,
        "threads": 4,
        "timeout": None,
        "scope": None,
        "exclude": None,
        "full_audit": False,
        "quick_scan": False,
        "deep_audit": False,
        "red_team": False,
        "bug_bounty": False,
        "compliance": False,
        "explain": False,
        "ask": plan.goal,
        "focus": None,
        "ai": False,
        "pure_ai_fast": False,
        "pure_ai_batch_size": 8,
        "pure_ai_cache_ttl": "7d",
        "pure_ai_provider": None,
        "poc_dir": "./generated_pocs",
        "poc_severity": "high",
        "poc_max": 10,
        "ai_provider": None,
        "incremental": False,
        "langgraph": False,
        "test": 0,
        "cn": False,
        "en": False
    }
    
    # 设置目标路径
    for step in plan.steps:
        if step.type.value == "scan" and "path" in step.config:
            args["target"] = step.config["path"]
            break
    
    # 设置模式
    if plan.profile.value == "fast":
        args["fast"] = True
    elif plan.profile.value == "deep":
        args["deep"] = True
    elif plan.profile.value == "stealth":
        args["stealth"] = True
    
    # 设置步骤
    for step in plan.steps:
        step_type = step.type.value
        if step_type == "scan":
            args["scan"] = True
        elif step_type == "reason":
            args["reason"] = True
            args["ai"] = True
        elif step_type == "attack_chain":
            args["attack_chain"] = True
            args["ai"] = True
        elif step_type == "poc":
            args["poc"] = True
            args["ai"] = True
        elif step_type == "verify":
            args["verify"] = True
        elif step_type == "fix":
            args["fix"] = True
        elif step_type == "report":
            args["report"] = True
            if "format" in step.config:
                args["output_format"] = step.config["format"]
            if "output" in step.config:
                args["output"] = step.config["output"]
    
    # 设置约束
    if plan.constraints.max_workers:
        args["workers"] = plan.constraints.max_workers
    if plan.constraints.timeout:
        args["timeout"] = plan.constraints.timeout
    
    return args


def _generate_plan_explanation(plan):
    """生成Plan解释"""
    explanations = []
    
    # 目标解释
    explanations.append(f"目标: {plan.goal}")
    
    # 配置文件解释
    profile_explanations = {
        "standard": "使用标准配置，平衡扫描深度和速度",
        "full": "使用完整配置，进行深度扫描和分析",
        "fast": "使用快速配置，进行浅层扫描，节省时间",
        "deep": "使用深度配置，进行全面深入的安全分析",
        "stealth": "使用 stealth 模式，减少扫描痕迹"
    }
    explanations.append(f"配置: {profile_explanations.get(plan.profile.value, plan.profile.value)}")
    
    # 步骤解释
    for step in plan.steps:
        step_type = step.type.value
        if step_type == "scan":
            depth = step.config.get("depth", "medium")
            explanations.append(f"扫描: 使用 {depth} 深度扫描代码")
        elif step_type == "auth_analysis":
            detect = step.config.get("detect", [])
            explanations.append(f"认证分析: 检测 {', '.join(detect)} 认证方式")
        elif step_type == "poc":
            generate = step.config.get("generate", False)
            explanations.append(f"POC生成: {'启用' if generate else '禁用'}")
        elif step_type == "attack_chain":
            explanations.append("攻击链分析: 分析潜在的攻击路径")
        elif step_type == "report":
            format = step.config.get("format", "html")
            explanations.append(f"报告生成: 生成 {format} 格式的报告")
    
    # 约束解释
    if plan.constraints.safe_mode:
        explanations.append("安全模式: 启用，避免生成危险的POC")
    if plan.constraints.max_time:
        explanations.append(f"最大时间: {plan.constraints.max_time}")
    
    return explanations
