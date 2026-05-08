"""主菜单面板

提供主菜单导航功能。
"""

from typing import Optional
from .base import InteractivePanel, PanelItem, clear_screen, print_divider


class MainMenuPanel(InteractivePanel):
    """主菜单面板

    提供配置分类导航。
    """

    def __init__(self, parent: Optional["InteractivePanel"] = None):
        super().__init__("HOS-LS 主菜单")
        self.parent = parent
        self._build_items()

    def _build_items(self) -> None:
        """构建菜单项"""
        self.clear_items()

        self.add_item(PanelItem(
            label="AI 配置",
            value="ai",
            description="配置AI提供商、模型、API Key等"
        ))

        self.add_item(PanelItem(
            label="扫描配置",
            value="scan",
            description="配置扫描线程数、增量扫描等"
        ))

        self.add_item(PanelItem(
            label="规则配置",
            value="rules",
            description="配置规则集、自定义规则等"
        ))

        self.add_item(PanelItem(
            label="报告配置",
            value="report",
            description="配置报告格式、输出路径等"
        ))

        self.add_item(PanelItem(
            label="工具配置",
            value="tools",
            description="配置工具链、Semgrep、Trivy等"
        ))

        self.add_item(PanelItem(
            label="验证配置",
            value="validation",
            description="配置置信度阈值、行号容忍度等"
        ))

        self.add_item(PanelItem(
            label="i18n 配置",
            value="i18n",
            description="配置界面语言"
        ))

        self.add_item(PanelItem(
            label="沙盒配置",
            value="sandbox",
            description="配置沙盒动态验证"
        ))

        self.add_item(PanelItem(
            label="远程扫描配置",
            value="remote",
            description="配置远程扫描连接"
        ))

        self.add_item(PanelItem(
            label="保存并退出",
            value="save",
            description="保存配置并退出"
        ))

        self.add_item(PanelItem(
            label="放弃修改并退出",
            value="quit",
            description="不保存配置并退出"
        ))

    def render(self) -> None:
        """渲染主菜单"""
        clear_screen()
        print_divider("─", 80)
        print(" HOS-LS 交互式配置面板 ".center(78, "─"))
        print_divider("─", 80)
        print()
        print("  方向键导航 | Enter 进入子菜单 | Q 退出")
        print()
        print_divider("─", 80)

        for i, item in enumerate(self.items):
            prefix = " ▶ " if i == self.current_index else "   "
            print(f"{prefix}[{i:02d}] {item.label}")
            if i == self.current_index and item.description:
                print(f"      {item.description}")

        print_divider("─", 80)

    def handle_enter(self) -> Optional["InteractivePanel"]:
        """处理回车键"""
        current = self.get_current_item()
        if current:
            return current.value
        return None

    def handle_escape(self) -> Optional["InteractivePanel"]:
        """处理ESC键"""
        return None


class CategoryPanel(InteractivePanel):
    """分类配置面板

    显示特定分类的配置项。
    """

    def __init__(self, category: str, config_data: dict, parent: Optional["InteractivePanel"] = None):
        super().__init__(f"配置 - {category}")
        self.category = category
        self.config_data = config_data
        self.parent = parent
        self._build_items()

    def _build_items(self) -> None:
        """构建配置项"""
        self.clear_items()

        category_config = self.config_data.get(self.category, {})

        if isinstance(category_config, dict):
            for key, value in category_config.items():
                self.add_item(PanelItem(
                    label=f"{key}",
                    value=value,
                    description=f"{self.category}.{key}"
                ))
        else:
            self.add_item(PanelItem(
                label="value",
                value=category_config,
                description=f"{self.category}"
            ))

    def render(self) -> None:
        """渲染分类面板"""
        clear_screen()
        print_divider("─", 80)
        print(f" 配置 - {self.category} ".center(78, "─"))
        print_divider("─", 80)
        print()
        print("  方向键导航 | Space 切换值 | Q 返回上级菜单")
        print()
        print_divider("─", 80)

        for i, item in enumerate(self.items):
            prefix = " ▶ " if i == self.current_index else "   "
            if item.options:
                value_str = f"[{item.value}]"
            else:
                value_str = f"{item.value}"

            print(f"{prefix}[{i:02d}] {item.label}: {value_str}")

            if i == self.current_index and item.description:
                print(f"      路径: {item.description}")

        print_divider("─", 80)

    def handle_escape(self) -> Optional["InteractivePanel"]:
        """处理ESC键"""
        return self.parent
