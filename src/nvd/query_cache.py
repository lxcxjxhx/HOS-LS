"""NVD 查询缓存

缓存常见的 CWE 查询结果，减少数据库访问
"""

import time
from typing import Any, Optional, Dict
from threading import Lock


class NVDQueryCache:
    """NVD 查询缓存

    缓存常见的 CWE 查询结果，减少数据库访问
    支持 LRU 淘汰和 TTL 过期
    """

    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        """初始化缓存

        Args:
            max_size: 最大缓存条目数
            ttl: 缓存过期时间（秒）
        """
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._access_order: Dict[str, int] = {}
        self._access_counter = 0
        self.max_size = max_size
        self.ttl = ttl
        self._lock = Lock()

    def get(self, key: str) -> Optional[Any]:
        """获取缓存值

        Args:
            key: 缓存键

        Returns:
            缓存值，如果不存在或已过期返回 None
        """
        with self._lock:
            if key not in self._cache:
                return None

            if self._is_expired(key):
                self._remove(key)
                return None

            self._access_counter += 1
            self._access_order[key] = self._access_counter
            return self._cache[key]

    def set(self, key: str, value: Any) -> None:
        """设置缓存值

        Args:
            key: 缓存键
            value: 缓存值
        """
        with self._lock:
            if key in self._cache:
                self._cache[key] = value
                self._timestamps[key] = time.time()
                self._access_counter += 1
                self._access_order[key] = self._access_counter
                return

            if len(self._cache) >= self.max_size:
                self._evict_lru()

            self._cache[key] = value
            self._timestamps[key] = time.time()
            self._access_counter += 1
            self._access_order[key] = self._access_counter

    def _is_expired(self, key: str) -> bool:
        """检查缓存是否过期

        Args:
            key: 缓存键

        Returns:
            是否过期
        """
        if key not in self._timestamps:
            return True

        elapsed = time.time() - self._timestamps[key]
        return elapsed > self.ttl

    def _remove(self, key: str) -> None:
        """移除缓存条目

        Args:
            key: 缓存键
        """
        if key in self._cache:
            del self._cache[key]
        if key in self._timestamps:
            del self._timestamps[key]
        if key in self._access_order:
            del self._access_order[key]

    def _evict_lru(self) -> None:
        """淘汰最近最少使用的条目"""
        if not self._access_order:
            return

        lru_key = min(self._access_order.items(), key=lambda x: x[1])[0]
        self._remove(lru_key)

    def clear(self) -> None:
        """清空所有缓存"""
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()
            self._access_order.clear()
            self._access_counter = 0

    def size(self) -> int:
        """获取当前缓存大小

        Returns:
            缓存条目数
        """
        with self._lock:
            return len(self._cache)

    def cleanup_expired(self) -> int:
        """清理所有过期的缓存条目

        Returns:
            清理的条目数
        """
        with self._lock:
            expired_keys = [k for k in self._cache.keys() if self._is_expired(k)]
            for key in expired_keys:
                self._remove(key)
            return len(expired_keys)


_global_cache: Optional[NVDQueryCache] = None
_cache_lock = Lock()


def get_global_cache() -> NVDQueryCache:
    """获取全局缓存实例

    Returns:
        全局 NVDQueryCache 实例
    """
    global _global_cache
    with _cache_lock:
        if _global_cache is None:
            _global_cache = NVDQueryCache(max_size=1000, ttl=3600)
        return _global_cache


def clear_global_cache() -> None:
    """清空全局缓存"""
    global _global_cache
    with _cache_lock:
        if _global_cache is not None:
            _global_cache.clear()