"""插件管理器模块

提供插件管理功能。
"""

from pathlib import Path
from typing import Any, Dict, Optional

from src.plugins.base import PluginManager
from src.plugins.registry import PluginRegistry
from src.plugins.config_loader import PluginConfigLoader


# 全局插件管理器实例
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager(config: Dict[str, Any] = None) -> PluginManager:
    """获取插件管理器实例

    Args:
        config: hos-ls.yaml 配置

    Returns:
        配置好的插件管理器实例
    """
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
        _register_builtin_plugins(_plugin_manager)

        if config is not None:
            config_loader = PluginConfigLoader()
            registry = PluginRegistry(_plugin_manager)
            loaded_plugins = registry.load_plugins(config_loader.load_from_config(config))
            for plugin in loaded_plugins:
                _plugin_manager.register(plugin)

    return _plugin_manager


def _register_builtin_plugins(manager: PluginManager) -> None:
    """注册内置插件
    
    Args:
        manager: 插件管理器
    """
    # 导入内置插件
    try:
        from src.plugins.builtin.regex_rules_plugin import RegexRulesPlugin
        from src.plugins.builtin.ast_analysis_plugin import ASTAnalysisPlugin
        from src.plugins.builtin.semantic_analysis_plugin import SemanticAnalysisPlugin
        
        # 注册插件
        manager.register(RegexRulesPlugin())
        manager.register(ASTAnalysisPlugin())
        manager.register(SemanticAnalysisPlugin())
        
    except ImportError as e:
        # 插件可能尚未创建，忽略错误
        pass
