"""交互式面板模块

提供交互式配置面板和主菜单功能。
"""

from typing import Optional

from .base import InteractivePanel, PanelItem, Key, clear_screen, print_divider
from .config_panel import ConfigPanel
from .main_menu import MainMenuPanel, CategoryPanel

__all__ = [
    "InteractivePanel",
    "PanelItem",
    "Key",
    "clear_screen",
    "print_divider",
    "ConfigPanel",
    "MainMenuPanel",
    "CategoryPanel",
]


def run_config_panel(config_dict: dict = None) -> Optional[dict]:
    """运行配置面板

    Args:
        config_dict: 初始配置字典

    Returns:
        修改后的配置字典，如果用户放弃则返回None
    """
    panel = ConfigPanel(config_dict)
    result = panel.run()
    if panel.is_modified():
        return panel.get_config()
    return None


def run_main_menu() -> Optional[str]:
    """运行主菜单

    Returns:
        用户选择的菜单项值
    """
    panel = MainMenuPanel()
    return panel.run()
