"""模块注册表和依赖注入系统

提供模块的注册、发现和依赖注入功能，实现松耦合的架构设计。
"""

import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, get_type_hints

T = TypeVar("T")


@dataclass
class ModuleInfo:
    """模块信息"""

    name: str
    module_class: Type[Any]
    instance: Optional[Any] = None
    dependencies: List[str] = field(default_factory=list)
    priority: int = 0
    singleton: bool = True


class ModuleRegistry:
    """模块注册表

    提供模块的注册、发现和生命周期管理功能。
    """

    _instance: Optional["ModuleRegistry"] = None
    _modules: Dict[str, ModuleInfo] = {}
    _initialized: bool = False

    def __new__(cls) -> "ModuleRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self._modules = {}
            self._initialized = True

    def register(
        self,
        name: str,
        module_class: Type[T],
        dependencies: Optional[List[str]] = None,
        priority: int = 0,
        singleton: bool = True,
    ) -> Type[T]:
        """注册模块

        Args:
            name: 模块名称
            module_class: 模块类
            dependencies: 依赖模块列表
            priority: 优先级（数字越小优先级越高）
            singleton: 是否为单例

        Returns:
            注册的模块类（用于装饰器模式）
        """
        if name in self._modules:
            raise ValueError(f"模块 '{name}' 已注册")

        self._modules[name] = ModuleInfo(
            name=name,
            module_class=module_class,
            dependencies=dependencies or [],
            priority=priority,
            singleton=singleton,
        )

        return module_class

    def unregister(self, name: str) -> None:
        """注销模块

        Args:
            name: 模块名称
        """
        if name in self._modules:
            del self._modules[name]

    def get(self, name: str) -> Optional[Any]:
        """获取模块实例

        Args:
            name: 模块名称

        Returns:
            模块实例，如果未找到则返回 None
        """
        if name not in self._modules:
            return None

        module_info = self._modules[name]

        # 如果是单例且已有实例，直接返回
        if module_info.singleton and module_info.instance is not None:
            return module_info.instance

        # 创建实例
        instance = self._create_instance(module_info)

        # 如果是单例，保存实例
        if module_info.singleton:
            module_info.instance = instance

        return instance

    def get_class(self, name: str) -> Optional[Type[Any]]:
        """获取模块类

        Args:
            name: 模块名称

        Returns:
            模块类，如果未找到则返回 None
        """
        if name not in self._modules:
            return None
        return self._modules[name].module_class

    def has(self, name: str) -> bool:
        """检查模块是否已注册

        Args:
            name: 模块名称

        Returns:
            是否已注册
        """
        return name in self._modules

    def list_modules(self) -> List[str]:
        """获取所有已注册的模块名称

        Returns:
            模块名称列表
        """
        return list(self._modules.keys())

    def get_modules_by_priority(self) -> List[ModuleInfo]:
        """按优先级获取模块列表

        Returns:
            按优先级排序的模块信息列表
        """
        return sorted(self._modules.values(), key=lambda m: m.priority)

    def clear(self) -> None:
        """清空所有注册的模块"""
        self._modules.clear()

    def _create_instance(self, module_info: ModuleInfo) -> Any:
        """创建模块实例

        Args:
            module_info: 模块信息

        Returns:
            模块实例
        """
        # 获取构造函数参数
        init_signature = inspect.signature(module_info.module_class.__init__)
        type_hints = get_type_hints(module_info.module_class.__init__)

        # 准备构造函数参数
        kwargs = {}
        for param_name, param in init_signature.parameters.items():
            if param_name == "self":
                continue

            # 检查是否是依赖模块
            if param_name in self._modules:
                kwargs[param_name] = self.get(param_name)
            elif param.default != inspect.Parameter.empty:
                # 使用默认值
                continue
            else:
                # 尝试从依赖注入器获取
                injector = DependencyInjector()
                value = injector.resolve(param_name, type_hints.get(param_name))
                if value is not None:
                    kwargs[param_name] = value

        return module_info.module_class(**kwargs)

    def decorator(
        self,
        name: Optional[str] = None,
        dependencies: Optional[List[str]] = None,
        priority: int = 0,
        singleton: bool = True,
    ) -> Callable[[Type[T]], Type[T]]:
        """装饰器模式注册模块

        Args:
            name: 模块名称（默认为类名）
            dependencies: 依赖模块列表
            priority: 优先级
            singleton: 是否为单例

        Returns:
            装饰器函数
        """

        def decorator(cls: Type[T]) -> Type[T]:
            module_name = name or cls.__name__
            self.register(module_name, cls, dependencies, priority, singleton)
            return cls

        return decorator


class DependencyInjector:
    """依赖注入器

    提供依赖的注册和解析功能。
    """

    _instance: Optional["DependencyInjector"] = None
    _dependencies: Dict[str, Any] = {}
    _factories: Dict[str, Callable[[], Any]] = {}
    _initialized: bool = False

    def __new__(cls) -> "DependencyInjector":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self._dependencies = {}
            self._factories = {}
            self._initialized = True

    def register(self, name: str, value: Any) -> None:
        """注册依赖

        Args:
            name: 依赖名称
            value: 依赖值
        """
        self._dependencies[name] = value

    def register_factory(self, name: str, factory: Callable[[], Any]) -> None:
        """注册工厂函数

        Args:
            name: 依赖名称
            factory: 工厂函数
        """
        self._factories[name] = factory

    def resolve(self, name: str, expected_type: Optional[Type[T]] = None) -> Optional[T]:
        """解析依赖

        Args:
            name: 依赖名称
            expected_type: 期望的类型

        Returns:
            依赖值，如果未找到则返回 None
        """
        # 首先尝试直接获取
        if name in self._dependencies:
            value = self._dependencies[name]
            if expected_type is not None and not isinstance(value, expected_type):
                raise TypeError(f"依赖 '{name}' 的类型不匹配")
            return value

        # 然后尝试工厂函数
        if name in self._factories:
            value = self._factories[name]()
            if expected_type is not None and not isinstance(value, expected_type):
                raise TypeError(f"依赖 '{name}' 的类型不匹配")
            return value

        return None

    def inject(self, func: Callable) -> Callable:
        """注入装饰器

        自动为函数参数注入依赖。

        Args:
            func: 目标函数

        Returns:
            包装后的函数
        """

        def wrapper(*args, **kwargs):
            signature = inspect.signature(func)
            type_hints = get_type_hints(func)

            for param_name, param in signature.parameters.items():
                if param_name in kwargs or param.default != inspect.Parameter.empty:
                    continue

                value = self.resolve(param_name, type_hints.get(param_name))
                if value is not None:
                    kwargs[param_name] = value

            return func(*args, **kwargs)

        return wrapper

    def clear(self) -> None:
        """清空所有注册的依赖"""
        self._dependencies.clear()
        self._factories.clear()


class BaseModule(ABC):
    """模块基类

    所有模块都应继承此类。
    """

    def __init__(self) -> None:
        self._initialized = False

    @abstractmethod
    def initialize(self) -> None:
        """初始化模块"""
        self._initialized = True

    @abstractmethod
    def shutdown(self) -> None:
        """关闭模块"""
        self._initialized = False

    @property
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized


# 全局实例
_registry: Optional[ModuleRegistry] = None
_injector: Optional[DependencyInjector] = None


def get_registry() -> ModuleRegistry:
    """获取全局模块注册表实例

    Returns:
        模块注册表实例
    """
    global _registry
    if _registry is None:
        _registry = ModuleRegistry()
    return _registry


def get_injector() -> DependencyInjector:
    """获取全局依赖注入器实例

    Returns:
        依赖注入器实例
    """
    global _injector
    if _injector is None:
        _injector = DependencyInjector()
    return _injector


def register_module(
    name: Optional[str] = None,
    dependencies: Optional[List[str]] = None,
    priority: int = 0,
    singleton: bool = True,
) -> Callable[[Type[T]], Type[T]]:
    """模块注册装饰器

    Args:
        name: 模块名称
        dependencies: 依赖模块列表
        priority: 优先级
        singleton: 是否为单例

    Returns:
        装饰器函数
    """
    return get_registry().decorator(name, dependencies, priority, singleton)
