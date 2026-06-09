"""验证器管理命令"""

import sys
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(emoji=False, force_terminal=True)


@click.group()
def validator() -> None:
    """验证器管理"""
    pass


@validator.command("list")
@click.option("--enabled-only", is_flag=True, help="仅显示已启用的验证器")
@click.pass_context
def list_validators(ctx: click.Context, enabled_only: bool) -> None:
    """列出可用验证器"""
    config = ctx.obj.get("config")
    quiet = getattr(config, "quiet", False) if config else False

    try:
        from src.validators.registry import get_validator_registry

        registry = get_validator_registry()
        validators = registry.get_all()

        table = Table(title="可用验证器")
        table.add_column("名称", style="cyan")
        table.add_column("描述", style="green")
        table.add_column("状态", style="yellow")
        table.add_column("类型", style="blue")

        for name, v in sorted(validators.items()):
            if enabled_only and not getattr(v, "enabled", True):
                continue
            status = "[green]已启用" if getattr(v, "enabled", True) else "[dim]已禁用"
            vtype = getattr(v, "validator_type", "unknown")
            desc = getattr(v, "description", "") or ""
            table.add_row(name, desc[:50], status, vtype)

        console.print(table)
        if not quiet:
            console.print(f"\n[dim]共 {len(validators)} 个验证器[/dim]")
    except ImportError:
        _show_builtin_validators(enabled_only)
    except Exception as e:
        console.print(f"[bold red]获取验证器列表失败: {e}[/bold red]")
        sys.exit(1)


@validator.command()
@click.argument("validator_name")
@click.option("--target", "-t", type=click.Path(exists=True), default=".", help="验证目标路径")
@click.option("--output", "-o", help="输出结果文件")
@click.pass_context
def run(ctx: click.Context, validator_name: str, target: str, output: Optional[str]) -> None:
    """运行指定验证器"""
    config = ctx.obj.get("config")
    quiet = getattr(config, "quiet", False) if config else False

    if not quiet:
        console.print(f"[bold cyan]正在运行验证器: {validator_name}[/bold cyan]")
        console.print(f"  目标: {target}")

    try:
        from src.validators.registry import get_validator_registry

        registry = get_validator_registry()
        v = registry.get(validator_name)
        if v is None:
            console.print(f"[bold red]验证器不存在: {validator_name}[/bold red]")
            console.print("[yellow]使用 hosls validator list 查看可用验证器[/yellow]")
            sys.exit(1)

        result = v.run(target)
        if not quiet:
            console.print(Panel(
                f"[bold]验证结果: {validator_name}[/bold]\n"
                f"状态: [green]完成[/green]\n"
                f"发现: {len(getattr(result, 'findings', []) or [])} 个",
                border_style="cyan",
            ))

        if output:
            _save_result(output, validator_name, result)
            if not quiet:
                console.print(f"[bold green]结果已保存: {output}[/bold green]")
    except ImportError:
        console.print(f"[bold red]验证器模块不可用[/bold red]")
        console.print("[yellow]提示: 验证器功能需要 src.validators 模块支持[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]验证器运行失败: {e}[/bold red]")
        sys.exit(2)


@validator.command()
@click.argument("validator_name")
@click.pass_context
def info(ctx: click.Context, validator_name: str) -> None:
    """显示验证器详情"""
    config = ctx.obj.get("config")
    quiet = getattr(config, "quiet", False) if config else False

    try:
        from src.validators.registry import get_validator_registry

        registry = get_validator_registry()
        v = registry.get(validator_name)
        if v is None:
            console.print(f"[bold red]验证器不存在: {validator_name}[/bold red]")
            console.print("[yellow]使用 hosls validator list 查看可用验证器[/yellow]")
            sys.exit(1)

        table = Table(title=f"验证器详情: {validator_name}")
        table.add_column("属性", style="cyan")
        table.add_column("值", style="green")
        table.add_row("名称", validator_name)
        table.add_row("描述", getattr(v, "description", "") or "无")
        table.add_row("类型", getattr(v, "validator_type", "unknown"))
        table.add_row("状态", "已启用" if getattr(v, "enabled", True) else "已禁用")
        table.add_row("版本", getattr(v, "version", "unknown"))
        console.print(table)
    except ImportError:
        console.print(f"[bold red]验证器模块不可用[/bold red]")
        console.print("[yellow]提示: 验证器功能需要 src.validators 模块支持[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]获取验证器信息失败: {e}[/bold red]")
        sys.exit(1)


def _show_builtin_validators(enabled_only: bool) -> None:
    """显示内置验证器占位信息"""
    table = Table(title="可用验证器 (占位)")
    table.add_column("名称", style="cyan")
    table.add_column("描述", style="green")
    table.add_column("状态", style="yellow")

    builtin = [
        ("dependency-check", "依赖漏洞验证", True),
        ("config-validator", "配置合规验证", True),
        ("secret-scanner", "密钥泄露验证", True),
        ("auth-validator", "认证机制验证", True),
    ]
    for name, desc, enabled in builtin:
        if enabled_only and not enabled:
            continue
        status = "[green]已启用" if enabled else "[dim]已禁用"
        table.add_row(name, desc, status)

    console.print(table)


def _save_result(output: str, name: str, result) -> None:
    """保存验证结果"""
    import json

    data = {
        "validator": name,
        "findings": [
            {
                "rule_id": getattr(f, "rule_id", ""),
                "severity": str(getattr(f, "severity", "")),
                "message": getattr(f, "message", ""),
                "location": {
                    "file": getattr(getattr(f, "location", None), "file", ""),
                    "line": getattr(getattr(f, "location", None), "line", 0),
                },
            }
            for f in (getattr(result, "findings", []) or [])
        ],
    }
    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
