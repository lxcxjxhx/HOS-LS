"""扫描运行器

从 SecurityScanner 中提取的 scan 主方法。
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from src.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


async def scan(scanner, target):
    """执行安全扫描（委托给 SecurityScanner.scan）
    
    Args:
        scanner: SecurityScanner 实例
        target: 扫描目标
    """
    return await scanner.scan(target)


def scan_sync(scanner, target):
    """同步扫描（委托给 SecurityScanner.scan_sync）"""
    return scanner.scan_sync(target)


def pre_scan_cost_check(scanner, target):
    """预扫描成本检查（委托给 SecurityScanner._pre_scan_cost_check）"""
    scanner._pre_scan_cost_check(target)


def discover_files(scanner, target):
    """发现文件（委托给 SecurityScanner._discover_files）"""
    return scanner._discover_files(target)


def get_location(obj, default_file="unknown"):
    """获取位置（委托给 SecurityScanner._get_location）"""
    from src.core.scanner import SecurityScanner
    return SecurityScanner._get_location(obj, default_file)