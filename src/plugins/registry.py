"""插件注册表模块

管理插件的注册、加载和查询。
"""

import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from .base import Plugin, ScanPlugin


class PluginRegistry:
    """插件注册表

    统一管理所有插件的注册、加载和查询。
    """

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """初始化插件注册表

        Args:
            plugin_dirs: 插件搜索目录列表
        """
        self._plugins: Dict[str, Plugin] = {}
        self._plugin_dirs: List[Path] = [
            Path(d) for d in (plugin_dirs or [])
        ]

    def register(self, plugin: Plugin) -> None:
        """注册插件

        Args:
            plugin: 插件实例
        """
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin already registered: {plugin.name}")
        self._plugins[plugin.name] = plugin

    def unregister(self, name: str) -> None:
        """注销插件

        Args:
            name: 插件名称
        """
        if name in self._plugins:
            del self._plugins[name]

    def get_all_plugins(self) -> List[Plugin]:
        """获取所有已注册的插件

        Returns:
            插件列表
        """
        return list(self._plugins.values())

    def get_by_type(self, plugin_type: Type[Plugin]) -> List[Plugin]:
        """按类型获取插件

        Args:
            plugin_type: 插件类型

        Returns:
            符合类型的插件列表
        """
        return [
            plugin for plugin in self._plugins.values()
            if isinstance(plugin, plugin_type)
        ]

    def load_from_directory(self, directory: str) -> List[str]:
        """从目录动态加载插件

        Args:
            directory: 插件目录路径

        Returns:
            加载的插件名称列表
        """
        loaded_plugins: List[str] = []
        plugin_dir = Path(directory)

        if not plugin_dir.exists() or not plugin_dir.is_dir():
            return loaded_plugins

        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            try:
                module_name = py_file.stem
                spec = importlib.util.spec_from_file_location(
                    module_name, py_file
                )
                if spec is None or spec.loader is None:
                    continue

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, Plugin)
                        and attr is not Plugin
                        and attr is not ScanPlugin
                    ):
                        plugin_instance = attr()
                        self.register(plugin_instance)
                        loaded_plugins.append(plugin_instance.name)

            except Exception:
                continue

        return loaded_plugins

    def load_configs(self, configs: List[Any]) -> None:
        """加载插件配置

        Args:
            configs: 插件配置列表
        """
        for config in configs:
            plugin_name = config.name if hasattr(config, 'name') else config.get('name')
            enabled = config.enabled if hasattr(config, 'enabled') else config.get('enabled', True)

            if plugin_name in self._plugins:
                plugin = self._plugins[plugin_name]
                if hasattr(plugin.metadata, 'enabled'):
                    plugin.metadata.enabled = enabled

                if hasattr(config, 'config'):
                    plugin.config.update(config.config)
                elif hasattr(config, 'get'):
                    plugin.config.update(config.get('config', {}))
