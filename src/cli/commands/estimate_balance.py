"""estimate 和 balance 命令"""

from pathlib import Path
from typing import Optional

import click
from rich.table import Table

from src.core.config import Config


def register_commands(cli: click.Group) -> None:
    """注册 estimate 和 balance 命令到 CLI 组"""

    @cli.command()
    @click.argument("target", required=False, default=".", type=click.Path())
    @click.option("--provider", help="AI 提供商 (deepseek, openai, anthropic, aliyun)")
    @click.option("--model", help="模型名（不指定则用配置/默认）")
    @click.option("--no-balance", is_flag=True, help="跳过余额检查")
    @click.pass_context
    def estimate(
        ctx: click.Context,
        target: str,
        provider: Optional[str],
        model: Optional[str],
        no_balance: bool,
    ) -> None:
        """运行前消费预估：估算目标文件数与预计 token/费用，并查询 API 余额

        示例:
            hos-ls estimate .                 # 预估当前目录（纯 AI 口径）
            hos-ls estimate ./src --provider deepseek --model deepseek-v4-flash
        """
        from rich.console import Console

        console = Console(emoji=False, force_terminal=True)
        config: Config = ctx.obj["config"]

        from src.ai.cost_estimator import get_cost_estimator

        provider = provider or config.ai.get_provider("pure_ai") or config.ai.provider or "deepseek"
        model = model or config.ai.get_model("pure_ai")

        target_path = Path(target)
        file_count = 1
        if target_path.is_dir():
            from src.utils.file_discovery import FileDiscoveryEngine

            engine = FileDiscoveryEngine()
            files = engine.discover_files(str(target_path))
            file_count = len(files)
            console.print(
                f"[bold cyan][ESTIMATE] 目标目录:[/bold cyan] [bold green]{target}[/bold green] "
                f"发现 [bold]{file_count}[/bold] 个文件"
            )
        else:
            console.print(f"[bold cyan][ESTIMATE] 目标文件:[/bold cyan] [bold green]{target}[/bold green]")

        est = get_cost_estimator().estimate(file_count, provider, model)
        table = Table(title="运行前消费预估", show_header=True)
        table.add_column("项", style="cyan")
        table.add_column("值", style="green")
        table.add_row("provider / model", f"{provider} / {est.model}")
        table.add_row("文件数", f"{est.file_count:,}")
        table.add_row("每文件 token（历史校准）", f"{est.avg_tokens_per_file:,}")
        table.add_row("预估总 token", f"{est.estimated_total_tokens:,}")
        table.add_row("预估输入 token", f"{est.estimated_prompt_tokens:,} ({est.estimated_prompt_tokens / est.estimated_total_tokens * 100 if est.estimated_total_tokens else 0:.0f}%)")
        table.add_row("预估输出 token", f"{est.estimated_completion_tokens:,} ({est.estimated_completion_tokens / est.estimated_total_tokens * 100 if est.estimated_total_tokens else 0:.0f}%)")
        table.add_row("预估费用 (USD)", f"${est.estimated_total_cost_usd:.4f}")
        table.add_row("预估费用 (CNY)", f"¥{est.estimated_cost_cny:.2f}")
        table.add_row("定价来源", est.pricing_source)
        console.print(table)

        if not no_balance:
            from src.ai.balance import check_balance

            console.print("[bold]API 余额:[/bold]")
            check_balance(config, provider=provider)

        if est.file_count > 100:
            console.print(
                f"[bold yellow]\u26a0 文件数 {est.file_count} 超过 100，纯 AI 扫描将触发逐文件深度分析，"
                f"预估费用 \u00a5{est.estimated_cost_cny:.2f}（仅供参考）[/bold yellow]"
            )

    @cli.command()
    @click.option("--provider", help="AI 提供商 (deepseek, openai, anthropic, aliyun)")
    @click.pass_context
    def balance(ctx: click.Context, provider: Optional[str]) -> None:
        """自动查询 AI API 账户余额

        示例:
            hos-ls balance                       # 查询当前配置 provider 余额
            hos-ls balance --provider deepseek   # 指定 provider
        """
        from rich.console import Console

        console = Console(emoji=False, force_terminal=True)
        config: Config = ctx.obj["config"]

        from src.ai.balance import check_balance

        provider = provider or config.ai.get_provider("pure_ai") or config.ai.provider or "deepseek"
        console.print(f"[bold cyan][BALANCE] 查询 {provider} 账户余额...[/bold cyan]")
        check_balance(config, provider=provider)