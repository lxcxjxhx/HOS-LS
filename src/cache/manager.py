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


class FunctionCache:
    """Function 级别缓存

    基于函数代码哈希的分析结果缓存。
    预期收益：提速 3~10 倍，避免重复分析。
    """

    def __init__(self, cache_manager: CacheManager) -> None:
        self._cache_manager = cache_manager

    def get_cache_key(self, function_code: str) -> str:
        return f"func:{hashlib.sha256(function_code.encode()).hexdigest()}"

    def get(self, function_code: str) -> Optional[Dict[str, Any]]:
        key = self.get_cache_key(function_code)
        return self._cache_manager.get(key)

    def set(self, function_code: str, result: Dict[str, Any], expire: Optional[int] = 86400) -> None:
        key = self.get_cache_key(function_code)
        self._cache_manager.set(key, result, expire=expire)

    def invalidate(self, function_code: str) -> None:
        key = self.get_cache_key(function_code)
        self._cache_manager.delete(key)


class PathCache:
    """Path 级别缓存

    基于 taint_path 的缓存。
    """

    def __init__(self, cache_manager: CacheManager) -> None:
        self._cache_manager = cache_manager

    def get_cache_key(self, source: str, sink: str, propagation_path: str) -> str:
        path_data = f"{source}:{sink}:{propagation_path}"
        return f"path:{hashlib.sha256(path_data.encode()).hexdigest()}"

    def get(self, source: str, sink: str, propagation_path: str) -> Optional[Dict[str, Any]]:
        key = self.get_cache_key(source, sink, propagation_path)
        return self._cache_manager.get(key)

    def set(
        self,
        source: str,
        sink: str,
        propagation_path: str,
        result: Dict[str, Any],
        expire: Optional[int] = 86400,
    ) -> None:
        key = self.get_cache_key(source, sink, propagation_path)
        self._cache_manager.set(key, result, expire=expire)

    def is_vulnerable(self, source: str, sink: str, propagation_path: str) -> Optional[bool]:
        cached = self.get(source, sink, propagation_path)
        if cached is not None:
            return cached.get("is_vulnerable")
        return None


class PlanCache:
    """Plan 级别缓存

    基于输入生成扫描计划的缓存。
    """

    def __init__(self, cache_manager: CacheManager) -> None:
        self._cache_manager = cache_manager

    def get_cache_key(self, target: str, user_focus: Optional[list] = None) -> str:
        focus_str = ",".join(sorted(user_focus)) if user_focus else ""
        plan_data = f"{target}:{focus_str}"
        return f"plan:{hashlib.sha256(plan_data.encode()).hexdigest()}"

    def get(self, target: str, user_focus: Optional[list] = None) -> Optional[Dict[str, Any]]:
        key = self.get_cache_key(target, user_focus)
        return self._cache_manager.get(key)

    def set(
        self,
        target: str,
        user_focus: Optional[list],
        plan: Dict[str, Any],
        expire: Optional[int] = 3600,
    ) -> None:
        key = self.get_cache_key(target, user_focus)
        self._cache_manager.set(key, plan, expire=expire)


class CacheManagerV2(CacheManager):
    """增强版缓存管理器

    支持 Function Cache、Path Cache、Plan Cache 三种缓存类型。
    预期收益：提速 3~10 倍，避免重复分析。
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(config)
        self._function_cache: Optional[FunctionCache] = None
        self._path_cache: Optional[PathCache] = None
        self._plan_cache: Optional[PlanCache] = None

    def initialize(self) -> None:
        super().initialize()
        if self._cache:
            self._function_cache = FunctionCache(self)
            self._path_cache = PathCache(self)
            self._plan_cache = PlanCache(self)

    @property
    def function_cache(self) -> Optional[FunctionCache]:
        return self._function_cache

    @property
    def path_cache(self) -> Optional[PathCache]:
        return self._path_cache

    @property
    def plan_cache(self) -> Optional[PlanCache]:
        return self._plan_cache

    def invalidate_function(self, function_code: str) -> None:
        if self._function_cache:
            self._function_cache.invalidate(function_code)

    def get_cached_function_result(self, function_code: str) -> Optional[Dict[str, Any]]:
        if self._function_cache:
            return self._function_cache.get(function_code)
        return None

    def cache_function_result(self, function_code: str, result: Dict[str, Any]) -> None:
        if self._function_cache:
            self._function_cache.set(function_code, result)

    def get_cached_path_result(
        self,
        source: str,
        sink: str,
        propagation_path: str,
    ) -> Optional[Dict[str, Any]]:
        if self._path_cache:
            return self._path_cache.get(source, sink, propagation_path)
        return None

    def cache_path_result(
        self,
        source: str,
        sink: str,
        propagation_path: str,
        result: Dict[str, Any],
    ) -> None:
        if self._path_cache:
            self._path_cache.set(source, sink, propagation_path, result)

    def get_cached_plan(
        self,
        target: str,
        user_focus: Optional[list] = None,
    ) -> Optional[Dict[str, Any]]:
        if self._plan_cache:
            return self._plan_cache.get(target, user_focus)
        return None

    def cache_plan(
        self,
        target: str,
        user_focus: Optional[list],
        plan: Dict[str, Any],
    ) -> None:
        if self._plan_cache:
            self._plan_cache.set(target, user_focus, plan)
