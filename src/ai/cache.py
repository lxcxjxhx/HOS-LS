"""AI 分析缓存模块

提供分析结果缓存功能，减少重复的 API 调用，提高性能。
"""

import hashlib
import json
from dataclasses import asdict
from typing import Dict, Optional, Any, List

from src.ai.models import SecurityAnalysisResult
from src.ai.analyzer import AnalysisContext
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisCache:
    """分析缓存"""

    def __init__(self, max_size: int = 1000):
        """初始化分析缓存

        Args:
            max_size: 缓存最大容量
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._max_size = max_size
        self._access_order: List[str] = []  # LRU 缓存，记录访问顺序

    def _generate_key(self, context: AnalysisContext) -> str:
        """生成缓存键

        Args:
            context: 分析上下文

        Returns:
            str: 缓存键
        """
        # 基于文件路径、代码内容、语言和分析级别生成唯一键
        key_data = {
            "file_path": context.file_path,
            "code_content": context.code_content,
            "language": context.language,
            "analysis_level": context.analysis_level.value,
            "function_name": context.function_name,
            "class_name": context.class_name
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, context: AnalysisContext) -> Optional[SecurityAnalysisResult]:
        """获取缓存的分析结果

        Args:
            context: 分析上下文

        Returns:
            Optional[SecurityAnalysisResult]: 缓存的分析结果
        """
        key = self._generate_key(context)
        if key in self._cache:
            # 更新访问顺序（LRU）
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
            
            logger.debug(f"Cache hit for {context.file_path}")
            return self._deserialize_result(self._cache[key])
        logger.debug(f"Cache miss for {context.file_path}")
        return None

    def set(self, context: AnalysisContext, result: SecurityAnalysisResult) -> None:
        """设置缓存的分析结果

        Args:
            context: 分析上下文
            result: 分析结果
        """
        key = self._generate_key(context)
        
        # 如果缓存已满，移除最久未使用的项（LRU）
        if len(self._cache) >= self._max_size:
            oldest_key = self._access_order.pop(0)
            del self._cache[oldest_key]
            logger.debug(f"Cache evicted: {oldest_key}")
        
        # 序列化结果并存储
        self._cache[key] = self._serialize_result(result)
        
        # 更新访问顺序
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
        
        logger.debug(f"Cache set for {context.file_path}")

    def _serialize_result(self, result: SecurityAnalysisResult) -> Dict[str, Any]:
        """序列化分析结果

        Args:
            result: 分析结果

        Returns:
            Dict[str, Any]: 序列化后的结果
        """
        result_dict = asdict(result)
        # 序列化 findings
        if hasattr(result, 'findings') and result.findings:
            result_dict['findings'] = [asdict(finding) for finding in result.findings]
        return result_dict

    def _deserialize_result(self, data: Dict[str, Any]) -> SecurityAnalysisResult:
        """反序列化分析结果

        Args:
            data: 序列化后的数据

        Returns:
            SecurityAnalysisResult: 反序列化后的分析结果
        """
        from src.ai.models import VulnerabilityFinding
        
        # 反序列化 findings
        if 'findings' in data and data['findings']:
            findings = []
            for finding_data in data['findings']:
                finding = VulnerabilityFinding(**finding_data)
                findings.append(finding)
            data['findings'] = findings
        
        return SecurityAnalysisResult(**data)

    def clear(self) -> None:
        """清除缓存"""
        self._cache.clear()
        self._access_order.clear()
        logger.info("Cache cleared")

    def size(self) -> int:
        """获取缓存大小

        Returns:
            int: 缓存大小
        """
        return len(self._cache)


# 全局缓存实例
_analysis_cache: Optional[AnalysisCache] = None


def get_analysis_cache() -> AnalysisCache:
    """获取分析缓存实例

    Returns:
        AnalysisCache: 分析缓存实例
    """
    global _analysis_cache
    if _analysis_cache is None:
        _analysis_cache = AnalysisCache()
    return _analysis_cache
