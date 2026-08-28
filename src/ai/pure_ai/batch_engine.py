"""批量分析引擎

从 PureAIAnalyzer 中提取的批量分析方法。
"""

import asyncio
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


async def analyze_batch(analyzer, file_infos, config=None, progress_callback=None):
    """批量分析文件（委托给 PureAIAnalyzer.analyze_batch）"""
    return await analyzer.analyze_batch(file_infos, config=config, progress_callback=progress_callback)


async def resume(analyzer, checkpoint_data):
    """从断点恢复（委托给 PureAIAnalyzer.resume）"""
    return await analyzer.resume(checkpoint_data)


async def incremental_scan(analyzer, file_path, previous_results):
    """增量扫描（委托给 PureAIAnalyzer.incremental_scan）"""
    return await analyzer.incremental_scan(file_path, previous_results)