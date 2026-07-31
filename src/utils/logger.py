"""日志模块

提供统一的日志记录功能。
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    use_rich: bool = True,
) -> logging.Logger:
    """设置日志

    Args:
        level: 日志级别
        log_file: 日志文件路径（显式指定时优先使用）
        use_rich: 是否使用 Rich 处理程序

    Returns:
        日志记录器

    文件日志控制:
        - 通过 log_file 参数显式指定日志文件路径
        - 通过环境变量 HOS_LS_LOG_FILE 启用（值为日志文件名，默认 "hos-ls.log"）
        - 通过环境变量 HOS_LS_LOG_DIR 指定日志目录（默认 "./logs"）
        - 未设置任何参数时，文件日志默认关闭
    """
    # 创建日志记录器
    logger = logging.getLogger("hos-ls")
    logger.setLevel(getattr(logging, level.upper()))

    # 清除现有处理程序
    logger.handlers.clear()

    # 创建格式化器
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 控制台处理程序
    if use_rich:
        rich_handler = RichHandler(
            console=Console(stderr=True),
            show_time=False,
            show_path=False,
        )
        rich_handler.setLevel(getattr(logging, level.upper()))
        logger.addHandler(rich_handler)
    else:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(getattr(logging, level.upper()))
        logger.addHandler(stream_handler)

    # 文件处理程序（使用 RotatingFileHandler）
    resolved_log_file = log_file
    if not resolved_log_file:
        # 通过环境变量启用文件日志
        env_log_file = os.getenv("HOS_LS_LOG_FILE")
        if env_log_file:
            log_dir = os.getenv("HOS_LS_LOG_DIR", "./logs")
            os.makedirs(log_dir, exist_ok=True)
            resolved_log_file = os.path.join(log_dir, env_log_file)

    if resolved_log_file:
        log_path = Path(resolved_log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            resolved_log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "hos-ls") -> logging.Logger:
    """获取日志记录器

    Args:
        name: 日志记录器名称

    Returns:
        日志记录器
    """
    return logging.getLogger(name)
