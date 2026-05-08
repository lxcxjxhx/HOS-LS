"""插件系统模块

提供可扩展的插件架构，支持异步扫描。
"""

from src.plugins.base import (
    Plugin,
    PluginManager,
    ScanPlugin,
    MCPToolPlugin,
    SkillPlugin,
    ToolResult,
    SkillResult,
    SkillPrompt,
    PluginPriority,
    PluginMetadata,
)
from src.plugins.manager import get_plugin_manager

__all__ = [
    "Plugin",
    "ScanPlugin",
    "MCPToolPlugin",
    "SkillPlugin",
    "PluginManager",
    "get_plugin_manager",
    "ToolResult",
    "SkillResult",
    "SkillPrompt",
    "PluginPriority",
    "PluginMetadata",
]
