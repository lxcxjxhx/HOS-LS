"""CLI 主入口

HOS-LS 的命令行入口。
"""

import sys
import warnings
from typing import Optional

import click

warnings.filterwarnings("ignore", message="Failed to find CUDA.")
warnings.filterwarnings("ignore", category=RuntimeWarning, message="Redirects are currently not supported in Windows or MacOs.")
warnings.filterwarnings("ignore", category=RuntimeWarning, message="'src.cli.main' found in sys.modules after import of package 'src.cli'")
warnings.filterwarnings("ignore", message=".*cpp extensions.*")
warnings.filterwarnings("ignore", message="Skipping import of cpp extensions.*")

from src import __version__
from src.core.config import ConfigManager

from src.cli.commands.scan import scan
from src.cli.commands.config import config, test_api
from src.cli.commands.nvd import nvd
from src.cli.commands.data_preload import data_preload
from src.cli.commands.index import index
from src.cli.commands.model import model
from src.cli.commands.misc import panel, serial, chat, rules, init as init_cmd, import_scan, replay
from src.cli.commands.verify import verify
from src.cli.commands.plugin import plugin
from src.cli.commands.interactive import interactive
from src.cli.commands.live_scan import live_scan
from src.cli.commands.report import report
from src.cli.commands.validator import validator
from src.cli.commands.sessions import sessions
from src.cli.commands.pentest import pentest
from src.cli.commands.pentest_bench import pentest_bench
from src.cli.commands.recon import recon
from src.cli.commands.web import web
from src.cli.commands.audit import ai_audit as audit


@click.group()
@click.version_option(version=__version__, prog_name="hos-ls")
@click.option("--config", "-c", type=click.Path(), help="配置文件路径")
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
@click.option("--quiet", "-q", is_flag=True, help="静默模式")
@click.option("--debug", "-d", is_flag=True, help="调试模式")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool, quiet: bool, debug: bool) -> None:
    """HOS-LS: AI 生成代码安全扫描工具"""
    ctx.ensure_object(dict)

    config_manager = ConfigManager()
    if config:
        cfg = config_manager.load_from_file(config)
    else:
        cfg = config_manager.auto_load()

    cfg.verbose = verbose
    cfg.quiet = quiet
    cfg.debug = debug

    ctx.obj["config"] = cfg


# Create deprecated alias for backward compatibility
@click.command("ai-audit")
@click.argument("target")
@click.option("--mode", type=click.Choice(["quick", "standard", "deep"], case_sensitive=False),
              default="standard", help="审计模式 (quick=快速扫描, standard=标准审计, deep=深度分析)")
@click.option("--output", "-o", default=None, help="报告输出路径")
@click.option("--format", "report_format", type=click.Choice(["json", "markdown", "html"]),
              default="markdown", help="报告格式")
@click.option("--ai-provider", type=str, default=None,
              help="指定 AI 提供商 (anthropic, openai, deepseek, aliyun, local)")
@click.option("--workers", "-w", type=int, default=4, help="并发工作线程数 (默认: 4)")
@click.option("--debug", "-d", is_flag=True, help="启用详细调试日志")
@click.pass_context
def ai_audit_alias(ctx, **kwargs):
    """⚠️  Deprecated: Use 'audit' command instead"""
    click.echo("⚠️  WARNING: 'ai-audit' command is deprecated, use 'audit' instead", err=True)
    ctx.invoke(audit, **kwargs)


cli.add_command(scan)
cli.add_command(config)
cli.add_command(nvd)
cli.add_command(data_preload)
cli.add_command(index)
cli.add_command(model)
cli.add_command(panel)
cli.add_command(serial)
cli.add_command(chat)
cli.add_command(rules)
cli.add_command(init_cmd)
cli.add_command(import_scan)
cli.add_command(replay)
cli.add_command(verify)
cli.add_command(plugin)
cli.add_command(interactive)
cli.add_command(live_scan)
cli.add_command(report)
cli.add_command(validator)
cli.add_command(sessions)
cli.add_command(test_api)
cli.add_command(pentest)
cli.add_command(pentest_bench)
cli.add_command(recon)
cli.add_command(web)
cli.add_command(audit)
cli.add_command(ai_audit_alias)  # Deprecated alias for backward compatibility


def main() -> None:
    """主入口"""
    cli()


if __name__ == "__main__":
    main()
