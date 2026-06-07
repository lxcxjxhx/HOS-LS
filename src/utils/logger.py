"""日志模块

提供统一的日志记录功能。
"""

import logging
import sys
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
        log_file: 日志文件路径
        use_rich: 是否使用 Rich 处理程序

    Returns:
        日志记录器
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
        console_handler = RichHandler(
            console=Console(stderr=True),
            show_time=False,
            show_path=False,
        )
        console_handler.setLevel(getattr(logging, level.upper()))
        logger.addHandler(console_handler)
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(getattr(logging, level.upper()))
        logger.addHandler(console_handler)

    # 文件处理程序
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
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
