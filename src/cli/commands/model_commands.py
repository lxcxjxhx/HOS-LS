"""模型管理命令

AI 模型下载和管理命令。
"""

from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console

from src.cli.main import cli, console
from src.core.config import Config, ConfigManager


@cli.group()
def model() -> None:
    """AI 模型管理"""


@model.command()
@click.option(
    "--model", "-m", "model_name", type=click.Choice(["deepseek", "codebert", "graphcodebert"]),
    default="deepseek", help="要下载的模型 (默认: deepseek)"
)
@click.option("--output", "-o", type=click.Path(), help="输出目录")
@click.option("--force", is_flag=True, help="强制覆盖现有模型")
@click.option("--token", "-t", required=True, help="Hugging Face 登录 token")
@click.pass_context
def download(ctx, model_name, output, force, token) -> None:
    """下载 AI 模型"""
    config = ConfigManager.load()
    from src.ai.model_downloader import ModelDownloader

    downloader = ModelDownloader(config=config)
    downloader.download(model_name, output_dir=output, force=force, token=token)