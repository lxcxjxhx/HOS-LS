"""缓存管理器

提供扫描结果的缓存和检索功能。
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

import diskcache

from src.core.config import Config, get_config


class CacheManager:
    """缓存管理器"""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()
        self._cache: Optional[diskcache.Cache] = None
        self._cache_dir = Path(".cache/hos-ls")

    def initialize(self) -> None:
        """初始化缓存"""
        if self.config.scan.cache_enabled:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._cache = diskcache.Cache(str(self._cache_dir))

    def close(self) -> None:
        """关闭缓存"""
        if self._cache:
            self._cache.close()
            self._cache = None

    def get(self, key: str) -> Optional[Any]:
        """获取缓存值

        Args:
            key: 缓存键

        Returns:
            缓存值
        """
        if not self._cache or not self.config.scan.cache_enabled:
            return None
        return self._cache.get(key)

    def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None,
    ) -> None:
        """设置缓存值

        Args:
            key: 缓存键
            value: 缓存值
            expire: 过期时间（秒）
        """
        if not self._cache or not self.config.scan.cache_enabled:
            return
        self._cache.set(key, value, expire=expire)

    def delete(self, key: str) -> None:
        """删除缓存值

        Args:
            key: 缓存键
        """
        if self._cache:
            self._cache.delete(key)

    def clear(self) -> None:
        """清空缓存"""
        if self._cache:
            self._cache.clear()

    def generate_key(
        self,
        file_path: str,
        content: str,
        rule_ids: Optional[list] = None,
    ) -> str:
        """生成缓存键

        Args:
            file_path: 文件路径
            content: 文件内容
            rule_ids: 规则 ID 列表

        Returns:
            缓存键
        """
        # 基于文件内容和规则生成哈希
        key_data = f"{file_path}:{content}"
        if rule_ids:
            key_data += f":{sorted(rule_ids)}"

        return hashlib.sha256(key_data.encode()).hexdigest()

    def get_file_hash(self, file_path: str) -> Optional[str]:
        """获取文件哈希

        Args:
            file_path: 文件路径

        Returns:
            文件哈希
        """
        try:
            content = Path(file_path).read_bytes()
            return hashlib.sha256(content).hexdigest()
        except Exception:
            return None

    def is_cached(self, file_path: str) -> bool:
        """检查文件是否已缓存

        Args:
            file_path: 文件路径

        Returns:
            是否已缓存
        """
        if not self._cache:
            return False

        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return False

        return self._cache.get(f"hash:{file_path}") == file_hash

    def cache_result(
        self,
        file_path: str,
        result: Dict[str, Any],
    ) -> None:
        """缓存扫描结果

        Args:
            file_path: 文件路径
            result: 扫描结果
        """
        if not self._cache:
            return

        file_hash = self.get_file_hash(file_path)
        if file_hash:
            self._cache.set(f"hash:{file_path}", file_hash)
            self._cache.set(f"result:{file_path}", result)

    def get_cached_result(
        self,
        file_path: str,
    ) -> Optional[Dict[str, Any]]:
        """获取缓存的扫描结果

        Args:
            file_path: 文件路径

        Returns:
            扫描结果
        """
        if not self._cache:
            return None

        if self.is_cached(file_path):
            return self._cache.get(f"result:{file_path}")

        return None
