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
from src.cli.commands.config import config
from src.cli.commands.nvd import nvd
from src.cli.commands.data_preload import data_preload
from src.cli.commands.index import index
from src.cli.commands.model import model
from src.cli.commands.misc import panel, serial, chat, rules, init as init_cmd, import_scan, replay


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


def main() -> None:
    """主入口"""
    cli()


if __name__ == "__main__":
    main()
