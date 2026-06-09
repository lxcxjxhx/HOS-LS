"""分析结果智能缓存

缓存各种分析结果，提高扫描效率。
"""

import hashlib
import json
import pickle
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """缓存条目"""
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AnalysisCache:
    """分析结果智能缓存

    支持：
    - TTL过期
    - LRU淘汰
    - 访问统计
    - 批量操作
    """

    DEFAULT_TTL = 3600
    MAX_SIZE = 10000

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        max_size: int = MAX_SIZE,
        default_ttl: float = DEFAULT_TTL,
    ):
        """初始化缓存

        Args:
            cache_dir: 缓存目录
            max_size: 最大缓存条目数
            default_ttl: 默认TTL（秒）
        """
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._memory_cache: Dict[str, CacheEntry] = {}
        self._access_order: List[str] = []
        self._hits = 0
        self._misses = 0

        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _generate_key(self, data: Any) -> str:
        """生成缓存键

        Args:
            data: 输入数据

        Returns:
            缓存键
        """
        if isinstance(data, str):
            content = data
        elif isinstance(data, (dict, list)):
            content = json.dumps(data, sort_keys=True)
        else:
            content = str(data)

        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _is_expired(self, entry: CacheEntry) -> bool:
        """检查是否过期

        Args:
            entry: 缓存条目

        Returns:
            是否过期
        """
        if entry.ttl is None:
            return False

        return time.time() - entry.created_at > entry.ttl

    def get(self, key: str) -> Optional[Any]:
        """获取缓存

        Args:
            key: 缓存键

        Returns:
            缓存值，不存在或过期返回None
        """
        if key not in self._memory_cache:
            self._misses += 1
            return None

        entry = self._memory_cache[key]

        if self._is_expired(entry):
            self._remove(key)
            self._misses += 1
            return None

        entry.last_accessed = time.time()
        entry.access_count += 1
        self._hits += 1

        self._update_access_order(key)

        return entry.value

    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """设置缓存

        Args:
            key: 缓存键
            value: 缓存值
            ttl: TTL（秒）
            metadata: 元数据
        """
        if len(self._memory_cache) >= self.max_size:
            self._evict_lru()

        entry = CacheEntry(
            key=key,
            value=value,
            created_at=time.time(),
            last_accessed=time.time(),
            ttl=ttl or self.default_ttl,
            metadata=metadata or {},
        )

        self._memory_cache[key] = entry
        self._update_access_order(key)

    def _update_access_order(self, key: str) -> None:
        """更新访问顺序"""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

    def _remove(self, key: str) -> None:
        """移除缓存条目

        Args:
            key: 缓存键
        """
        if key in self._memory_cache:
            del self._memory_cache[key]
        if key in self._access_order:
            self._access_order.remove(key)

    def _evict_lru(self) -> None:
        """淘汰最少使用的条目"""
        if not self._access_order:
            return

        oldest_key = self._access_order[0]
        self._remove(oldest_key)
        logger.debug(f"Evicted LRU entry: {oldest_key}")

    def delete(self, key: str) -> bool:
        """删除缓存

        Args:
            key: 缓存键

        Returns:
            是否删除成功
        """
        if key not in self._memory_cache:
            return False

        self._remove(key)
        return True

    def clear(self) -> None:
        """清空缓存"""
        self._memory_cache.clear()
        self._access_order.clear()
        logger.info("Cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计

        Returns:
            缓存统计信息
        """
        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0.0

        return {
            'size': len(self._memory_cache),
            'max_size': self.max_size,
            'hits': self._hits,
            'misses': self._misses,
            'hit_rate': hit_rate,
            'total_requests': total_requests,
        }

    def save_to_disk(self, filename: str) -> bool:
        """保存缓存到磁盘

        Args:
            filename: 文件名

        Returns:
            是否保存成功
        """
        if not self.cache_dir:
            return False

        try:
            filepath = self.cache_dir / filename
            data = {
                'cache': {
                    key: {
                        'key': entry.key,
                        'value': entry.value,
                        'created_at': entry.created_at,
                        'last_accessed': entry.last_accessed,
                        'access_count': entry.access_count,
                        'ttl': entry.ttl,
                        'metadata': entry.metadata,
                    }
                    for key, entry in self._memory_cache.items()
                    if not self._is_expired(entry)
                },
                'saved_at': datetime.now().isoformat(),
            }

            with open(filepath, 'wb') as f:
                pickle.dump(data, f)

            logger.info(f"Cache saved to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
            return False

    def load_from_disk(self, filename: str) -> bool:
        """从磁盘加载缓存

        Args:
            filename: 文件名

        Returns:
            是否加载成功
        """
        if not self.cache_dir:
            return False

        try:
            filepath = self.cache_dir / filename
            if not filepath.exists():
                return False

            with open(filepath, 'rb') as f:
                data = pickle.load(f)

            cache_data = data.get('cache', {})
            for key, entry_data in cache_data.items():
                entry = CacheEntry(**entry_data)
                if not self._is_expired(entry):
                    self._memory_cache[key] = entry
                    self._access_order.append(key)

            logger.info(f"Cache loaded from {filepath}, {len(cache_data)} entries")
            return True
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            return False


class MultiLevelCache:
    """多级缓存

    支持内存缓存 + 磁盘缓存的组合。
    """

    def __init__(self, cache_dir: Optional[str] = None, memory_size: int = 1000):
        """初始化多级缓存

        Args:
            cache_dir: 磁盘缓存目录
            memory_size: 内存缓存大小
        """
        self.memory_cache = AnalysisCache(max_size=memory_size)
        self.disk_cache = AnalysisCache(cache_dir=cache_dir, max_size=10000) if cache_dir else None

    def get(self, key: str) -> Optional[Any]:
        """获取缓存（先检查内存，再检查磁盘）

        Args:
            key: 缓存键

        Returns:
            缓存值
        """
        value = self.memory_cache.get(key)
        if value is not None:
            return value

        if self.disk_cache:
            value = self.disk_cache.get(key)
            if value is not None:
                self.memory_cache.set(key, value)
                return value

        return None

    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
        persist: bool = False,
    ) -> None:
        """设置缓存

        Args:
            key: 缓存键
            value: 缓存值
            ttl: TTL
            persist: 是否持久化到磁盘
        """
        self.memory_cache.set(key, value, ttl)

        if persist and self.disk_cache:
            self.disk_cache.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        """删除缓存

        Args:
            key: 缓存键

        Returns:
            是否删除成功
        """
        memory_deleted = self.memory_cache.delete(key)

        if self.disk_cache:
            disk_deleted = self.disk_cache.delete(key)
            return memory_deleted or disk_deleted

        return memory_deleted

    def clear(self) -> None:
        """清空所有缓存"""
        self.memory_cache.clear()
        if self.disk_cache:
            self.disk_cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'memory': self.memory_cache.get_stats(),
        }

        if self.disk_cache:
            stats['disk'] = self.disk_cache.get_stats()

        return stats


def get_analysis_cache(cache_dir: Optional[str] = None) -> AnalysisCache:
    """获取分析缓存实例

    Args:
        cache_dir: 缓存目录

    Returns:
        分析缓存实例
    """
    return AnalysisCache(cache_dir=cache_dir)
