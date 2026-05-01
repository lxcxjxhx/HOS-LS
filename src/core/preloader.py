"""模块预加载器模块

预加载和预热常用模块，提高系统启动速度和响应性能。
"""

import importlib
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type, TypeVar

T = TypeVar("T")


class ModuleStatus(Enum):
    """模块状态"""

    NOT_LOADED = "not_loaded"
    LOADING = "loading"
    LOADED = "loaded"
    WARMED_UP = "warmed_up"
    ERROR = "error"


class LoadPriority(Enum):
    """加载优先级"""

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    DEFERRED = 4


@dataclass
class ModuleInfo:
    """模块信息"""

    name: str
    module_path: str
    status: ModuleStatus = ModuleStatus.NOT_LOADED
    priority: LoadPriority = LoadPriority.NORMAL
    dependencies: List[str] = field(default_factory=list)
    load_time: float = 0.0
    warmup_time: float = 0.0
    error_message: Optional[str] = None
    instance: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "module_path": self.module_path,
            "status": self.status.value,
            "priority": self.priority.value,
            "dependencies": self.dependencies,
            "load_time": self.load_time,
            "warmup_time": self.warmup_time,
            "error_message": self.error_message,
        }


@dataclass
class PreloadConfig:
    """预加载配置"""

    max_workers: int = 4
    enable_parallel: bool = True
    enable_lazy_loading: bool = True
    warmup_timeout: int = 30
    load_timeout: int = 60
    retry_count: int = 3
    retry_delay: float = 1.0


class ModulePreloader:
    """模块预加载器

    预加载和预热常用模块，支持并行加载、懒加载和依赖管理。
    """

    DEFAULT_MODULES: Dict[str, ModuleInfo] = {
        "core.config": ModuleInfo(
            name="core.config",
            module_path="src.core.config",
            priority=LoadPriority.CRITICAL,
        ),
        "core.registry": ModuleInfo(
            name="core.registry",
            module_path="src.core.registry",
            priority=LoadPriority.CRITICAL,
        ),
        "core.engine": ModuleInfo(
            name="core.engine",
            module_path="src.core.engine",
            priority=LoadPriority.HIGH,
            dependencies=["core.config", "core.registry"],
        ),
        "analyzers.base": ModuleInfo(
            name="analyzers.base",
            module_path="src.analyzers.base",
            priority=LoadPriority.HIGH,
        ),
        "analyzers.ast_analyzer": ModuleInfo(
            name="analyzers.ast_analyzer",
            module_path="src.analyzers.ast_analyzer",
            priority=LoadPriority.NORMAL,
            dependencies=["analyzers.base"],
        ),
        "analyzers.cst_analyzer": ModuleInfo(
            name="analyzers.cst_analyzer",
            module_path="src.analyzers.cst_analyzer",
            priority=LoadPriority.NORMAL,
            dependencies=["analyzers.base"],
        ),
        "rules.base": ModuleInfo(
            name="rules.base",
            module_path="src.rules.base",
            priority=LoadPriority.HIGH,
        ),
        "rules.registry": ModuleInfo(
            name="rules.registry",
            module_path="src.rules.registry",
            priority=LoadPriority.HIGH,
            dependencies=["rules.base"],
        ),
        "ai.client": ModuleInfo(
            name="ai.client",
            module_path="src.ai.client",
            priority=LoadPriority.NORMAL,
            dependencies=["core.config"],
        ),
        "ai.analyzer": ModuleInfo(
            name="ai.analyzer",
            module_path="src.ai.analyzer",
            priority=LoadPriority.NORMAL,
            dependencies=["ai.client", "analyzers.base"],
        ),
        "cache.manager": ModuleInfo(
            name="cache.manager",
            module_path="src.cache.manager",
            priority=LoadPriority.HIGH,
            dependencies=["core.config"],
        ),
        "reporting.generator": ModuleInfo(
            name="reporting.generator",
            module_path="src.reporting.generator",
            priority=LoadPriority.LOW,
        ),
        "attack.graph_engine": ModuleInfo(
            name="attack.graph_engine",
            module_path="src.attack.graph_engine",
            priority=LoadPriority.LOW,
        ),
        "attack.validator": ModuleInfo(
            name="attack.validator",
            module_path="src.attack.validator",
            priority=LoadPriority.LOW,
        ),
        "utils.logger": ModuleInfo(
            name="utils.logger",
            module_path="src.utils.logger",
            priority=LoadPriority.CRITICAL,
        ),
        "utils.file_discovery": ModuleInfo(
            name="utils.file_discovery",
            module_path="src.utils.file_discovery",
            priority=LoadPriority.NORMAL,
        ),
        "utils.priority_engine": ModuleInfo(
            name="utils.priority_engine",
            module_path="src.utils.priority_engine",
            priority=LoadPriority.NORMAL,
            dependencies=["utils.file_discovery"],
        ),
    }

    def __init__(self, config: Optional[PreloadConfig] = None):
        """初始化模块预加载器

        Args:
            config: 预加载配置
        """
        self.config = config or PreloadConfig()
        self._modules: Dict[str, ModuleInfo] = {}
        self._loaded_modules: Set[str] = set()
        self._lock = threading.RLock()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._futures: Dict[str, Future] = {}

        for name, info in self.DEFAULT_MODULES.items():
            self._modules[name] = ModuleInfo(
                name=info.name,
                module_path=info.module_path,
                priority=info.priority,
                dependencies=info.dependencies.copy(),
            )

    def register_module(
        self,
        name: str,
        module_path: str,
        priority: LoadPriority = LoadPriority.NORMAL,
        dependencies: Optional[List[str]] = None,
        warmup_func: Optional[Callable] = None,
    ) -> None:
        """注册模块

        Args:
            name: 模块名称
            module_path: 模块路径
            priority: 加载优先级
            dependencies: 依赖模块列表
            warmup_func: 预热函数
        """
        with self._lock:
            self._modules[name] = ModuleInfo(
                name=name,
                module_path=module_path,
                priority=priority,
                dependencies=dependencies or [],
                metadata={"warmup_func": warmup_func},
            )

    def preload_modules(
        self,
        module_names: Optional[List[str]] = None,
        parallel: Optional[bool] = None,
    ) -> Dict[str, bool]:
        """预加载模块

        Args:
            module_names: 要加载的模块名称列表，如果为 None 则加载所有已注册模块
            parallel: 是否并行加载

        Returns:
            加载结果字典 {模块名: 是否成功}
        """
        if module_names is None:
            module_names = list(self._modules.keys())

        use_parallel = parallel if parallel is not None else self.config.enable_parallel

        if use_parallel and len(module_names) > 1:
            return self._preload_parallel(module_names)
        else:
            return self._preload_sequential(module_names)

    def warm_up(self, module_name: str) -> bool:
        """预热模块

        Args:
            module_name: 模块名称

        Returns:
            是否成功
        """
        with self._lock:
            if module_name not in self._modules:
                return False

            info = self._modules[module_name]

            if info.status != ModuleStatus.LOADED:
                if not self._load_module(module_name):
                    return False

            if info.status == ModuleStatus.WARMED_UP:
                return True

            start_time = time.time()

            try:
                warmup_func = info.metadata.get("warmup_func")
                if warmup_func:
                    warmup_func()

                if info.instance and hasattr(info.instance, "warmup"):
                    info.instance.warmup()

                info.warmup_time = time.time() - start_time
                info.status = ModuleStatus.WARMED_UP
                return True

            except Exception as e:
                info.error_message = str(e)
                info.status = ModuleStatus.ERROR
                return False

    def get_module_status(self, module_name: str) -> ModuleStatus:
        """获取模块状态

        Args:
            module_name: 模块名称

        Returns:
            模块状态
        """
        with self._lock:
            if module_name not in self._modules:
                return ModuleStatus.NOT_LOADED
            return self._modules[module_name].status

    def get_module(self, module_name: str) -> Optional[Any]:
        """获取模块实例

        Args:
            module_name: 模块名称

        Returns:
            模块实例
        """
        with self._lock:
            if module_name not in self._modules:
                return None

            info = self._modules[module_name]

            if info.status == ModuleStatus.NOT_LOADED:
                if not self._load_module(module_name):
                    return None

            return info.instance

    def get_loaded_modules(self) -> List[str]:
        """获取已加载的模块列表

        Returns:
            已加载的模块名称列表
        """
        with self._lock:
            return [
                name
                for name, info in self._modules.items()
                if info.status in [ModuleStatus.LOADED, ModuleStatus.WARMED_UP]
            ]

    def get_module_info(self, module_name: str) -> Optional[ModuleInfo]:
        """获取模块信息

        Args:
            module_name: 模块名称

        Returns:
            模块信息
        """
        with self._lock:
            return self._modules.get(module_name)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            total = len(self._modules)
            loaded = sum(
                1
                for info in self._modules.values()
                if info.status == ModuleStatus.LOADED
            )
            warmed_up = sum(
                1
                for info in self._modules.values()
                if info.status == ModuleStatus.WARMED_UP
            )
            errors = sum(
                1
                for info in self._modules.values()
                if info.status == ModuleStatus.ERROR
            )

            total_load_time = sum(info.load_time for info in self._modules.values())
            total_warmup_time = sum(info.warmup_time for info in self._modules.values())

            return {
                "total_modules": total,
                "loaded_modules": loaded,
                "warmed_up_modules": warmed_up,
                "error_modules": errors,
                "total_load_time": total_load_time,
                "total_warmup_time": total_warmup_time,
                "avg_load_time": total_load_time / max(loaded + warmed_up, 1),
                "avg_warmup_time": total_warmup_time / max(warmed_up, 1),
            }

    def clear(self) -> None:
        """清除所有已加载的模块"""
        with self._lock:
            for name in list(self._modules.keys()):
                info = self._modules[name]
                info.status = ModuleStatus.NOT_LOADED
                info.instance = None
                info.error_message = None

            self._loaded_modules.clear()

            if self._executor:
                self._executor.shutdown(wait=False)
                self._executor = None

    def shutdown(self) -> None:
        """关闭预加载器"""
        with self._lock:
            if self._executor:
                self._executor.shutdown(wait=True)
                self._executor = None

            self._futures.clear()

    def _load_module(self, module_name: str) -> bool:
        """加载单个模块

        Args:
            module_name: 模块名称

        Returns:
            是否成功
        """
        with self._lock:
            if module_name not in self._modules:
                return False

            info = self._modules[module_name]

            if info.status in [ModuleStatus.LOADED, ModuleStatus.WARMED_UP]:
                return True

            if info.status == ModuleStatus.LOADING:
                return False

            for dep in info.dependencies:
                if dep not in self._loaded_modules:
                    if not self._load_module(dep):
                        info.error_message = f"依赖模块 {dep} 加载失败"
                        info.status = ModuleStatus.ERROR
                        return False

            info.status = ModuleStatus.LOADING
            start_time = time.time()

            for attempt in range(self.config.retry_count):
                try:
                    module = importlib.import_module(info.module_path)
                    info.instance = module
                    info.load_time = time.time() - start_time
                    info.status = ModuleStatus.LOADED
                    self._loaded_modules.add(module_name)
                    return True

                except Exception as e:
                    if attempt < self.config.retry_count - 1:
                        time.sleep(self.config.retry_delay)
                    else:
                        info.error_message = str(e)
                        info.status = ModuleStatus.ERROR
                        return False

            return False

    def _preload_sequential(self, module_names: List[str]) -> Dict[str, bool]:
        """顺序预加载模块

        Args:
            module_names: 模块名称列表

        Returns:
            加载结果字典
        """
        results: Dict[str, bool] = {}

        sorted_modules = self._sort_by_priority(module_names)

        for name in sorted_modules:
            results[name] = self._load_module(name)

        return results

    def _preload_parallel(self, module_names: List[str]) -> Dict[str, bool]:
        """并行预加载模块

        Args:
            module_names: 模块名称列表

        Returns:
            加载结果字典
        """
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self.config.max_workers)

        results: Dict[str, bool] = {}
        sorted_modules = self._sort_by_priority(module_names)

        loaded: Set[str] = set()
        pending: List[str] = sorted_modules.copy()

        while pending:
            ready_to_load: List[str] = []
            still_pending: List[str] = []

            for name in pending:
                info = self._modules.get(name)
                if not info:
                    results[name] = False
                    continue

                if all(dep in loaded for dep in info.dependencies):
                    ready_to_load.append(name)
                else:
                    still_pending.append(name)

            pending = still_pending

            if ready_to_load:
                futures: Dict[str, Future] = {}
                for name in ready_to_load:
                    future = self._executor.submit(self._load_module, name)
                    futures[name] = future

                for name, future in futures.items():
                    try:
                        results[name] = future.result(timeout=self.config.load_timeout)
                        if results[name]:
                            loaded.add(name)
                    except Exception:
                        results[name] = False

            elif pending:
                for name in pending:
                    results[name] = False
                break

        return results

    def _sort_by_priority(self, module_names: List[str]) -> List[str]:
        """按优先级排序模块

        Args:
            module_names: 模块名称列表

        Returns:
            排序后的模块名称列表
        """
        def get_priority(name: str) -> int:
            info = self._modules.get(name)
            return info.priority.value if info else LoadPriority.NORMAL.value

        return sorted(module_names, key=get_priority)


_preloader: Optional[ModulePreloader] = None


def get_preloader() -> ModulePreloader:
    """获取全局预加载器实例

    Returns:
        模块预加载器实例
    """
    global _preloader
    if _preloader is None:
        _preloader = ModulePreloader()
    return _preloader


def preload(module_names: Optional[List[str]] = None) -> Dict[str, bool]:
    """预加载模块

    Args:
        module_names: 模块名称列表

    Returns:
        加载结果字典
    """
    return get_preloader().preload_modules(module_names)


def get_module(module_name: str) -> Optional[Any]:
    """获取模块实例

    Args:
        module_name: 模块名称

    Returns:
        模块实例
    """
    return get_preloader().get_module(module_name)
