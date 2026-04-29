"""插件配置加载器模块

从 YAML 配置加载插件配置。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PluginConfig:
    """插件配置数据类"""
    name: str
    plugin_type: str
    enabled: bool = True
    path: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)


class PluginConfigLoader:
    """插件配置加载器

    从 hos-ls.yaml 加载插件配置。
    """

    def load_from_config(self, config: Dict[str, Any]) -> List[PluginConfig]:
        """从配置加载插件配置

        Args:
            config: hos-ls.yaml 配置

        Returns:
            插件配置列表
        """
        plugin_configs = []
        plugins_section = config.get("plugins", {})

        for mcp_config in plugins_section.get("mcp", []):
            plugin_configs.append(PluginConfig(
                name=mcp_config["name"],
                plugin_type="mcp",
                enabled=mcp_config.get("enabled", True),
                path=mcp_config.get("path"),
                config=mcp_config.get("config", {}),
            ))

        for skill_config in plugins_section.get("skills", []):
            plugin_configs.append(PluginConfig(
                name=skill_config["name"],
                plugin_type="skill",
                enabled=skill_config.get("enabled", True),
                path=skill_config.get("path"),
                config=skill_config.get("config", {}),
            ))

        for functional_config in plugins_section.get("functional", []):
            plugin_configs.append(PluginConfig(
                name=functional_config["name"],
                plugin_type="functional",
                enabled=functional_config.get("enabled", True),
                path=functional_config.get("path"),
                config=functional_config.get("config", {}),
            ))

        return plugin_configs
