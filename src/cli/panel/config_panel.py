"""配置面板

提供交互式配置面板功能。
"""

from typing import Optional, Any
from .base import InteractivePanel, PanelItem, clear_screen, print_divider, Key


class ConfigPanel(InteractivePanel):
    """配置面板

    提供交互式配置修改功能。
    """

    def __init__(self, config_dict: dict = None, parent: Optional[InteractivePanel] = None):
        super().__init__("HOS-LS 配置面板")
        self.config_dict = config_dict or {}
        self.parent_panel = parent
        self.modified = False
        self._build_items()

    def _build_items(self) -> None:
        """构建配置项"""
        self.clear_items()

        self.add_item(PanelItem(
            label="调试模式 (debug)",
            value=self.config_dict.get("debug", False),
            default=False,
            description="启用调试输出",
            type="bool"
        ))

        self.add_item(PanelItem(
            label="详细输出 (verbose)",
            value=self.config_dict.get("verbose", False),
            default=False,
            description="显示详细日志",
            type="bool"
        ))

        self.add_item(PanelItem(
            label="界面语言 (language)",
            value=self.config_dict.get("language", "zh"),
            default="zh",
            description="zh=中文, en=英文",
            options=["zh", "en"]
        ))

        self.add_item(PanelItem(
            label="测试模式 (test_mode)",
            value=self.config_dict.get("test_mode", False),
            default=False,
            description="测试模式",
            type="bool"
        ))

        self.add_item(PanelItem(
            label="过滤幻觉 (filter_hallucinations)",
            value=self.config_dict.get("filter_hallucinations", True),
            default=True,
            description="过滤AI幻觉发现",
            type="bool"
        ))

        self.add_item(PanelItem(
            label="AI 提供商 (provider)",
            value=self.config_dict.get("ai", {}).get("provider", "deepseek"),
            default="deepseek",
            description="AI服务提供商",
            options=["deepseek", "aliyun", "anthropic", "openai"]
        ))

        self.add_item(PanelItem(
            label="AI 模型 (model)",
            value=self.config_dict.get("ai", {}).get("model", "deepseek-chat"),
            default="deepseek-chat",
            description="AI模型"
        ))

        self.add_item(PanelItem(
            label="最大Token (max_tokens)",
            value=self.config_dict.get("ai", {}).get("max_tokens", 4096),
            default=4096,
            description="单次请求最大Token数",
            type="int"
        ))

        self.add_item(PanelItem(
            label="扫描线程数 (max_workers)",
            value=self.config_dict.get("scan", {}).get("max_workers", 4),
            default=4,
            description="并行扫描线程数",
            type="int"
        ))

        self.add_item(PanelItem(
            label="增量扫描 (incremental)",
            value=self.config_dict.get("scan", {}).get("incremental", True),
            default=True,
            description="启用增量扫描",
            type="bool"
        ))

        self.add_item(PanelItem(
            label="缓存启用 (cache_enabled)",
            value=self.config_dict.get("scan", {}).get("cache_enabled", True),
            default=True,
            description="启用扫描缓存",
            type="bool"
        ))

        self.add_item(PanelItem(
            label="行号偏差容忍度",
            value=self.config_dict.get("validation", {}).get("line_number_tolerance", 5),
            default=5,
            description="行号偏差容忍行数",
            type="int"
        ))

        self.add_item(PanelItem(
            label="最小置信度阈值",
            value=self.config_dict.get("validation", {}).get("min_confidence_threshold", 0.7),
            default=0.7,
            description="置信度阈值",
            type="float"
        ))

    def render(self) -> None:
        """渲染配置面板"""
        clear_screen()
        print_divider("─", 80)
        print(" HOS-LS 配置面板 ".center(78, "─"))
        print_divider("─", 80)
        print()
        print("  方向键导航 | Space/Tab 切换选项 | Enter 确认 | Q 返回")
        print()
        print_divider("─", 80)

        for i, item in enumerate(self.items):
            prefix = " ▶ " if i == self.current_index else "   "
            if item.type == "bool":
                value_str = "✓ 是" if item.value else "✗ 否"
            elif item.options:
                value_str = str(item.value)
            else:
                value_str = str(item.value)

            if item.description:
                print(f"{prefix}[{i:02d}] {item.label}")
                if i == self.current_index:
                    print(f"      当前值: {value_str}")
                    print(f"      默认值: {item.default}")
                    print(f"      说明: {item.description}")
                    if item.options:
                        print(f"      选项: {', '.join(str(o) for o in item.options)}")
            else:
                print(f"{prefix}[{i:02d}] {item.label}: {value_str}")

        print_divider("─", 80)
        if self.modified:
            print(" [已修改] 按 Enter 保存更改 ".center(78, "─"))
        else:
            print(" [未修改] 按 Q 返回上级菜单 ".center(78, "─"))

    def handle_space(self) -> None:
        """处理空格键"""
        current = self.get_current_item()
        if current:
            if current.type == "bool":
                current.value = not current.value
                self.modified = True
            elif current.options:
                idx = current.options.index(current.value) if current.value in current.options else -1
                current.value = current.options[(idx + 1) % len(current.options)]
                self.modified = True

    def handle_tab(self) -> None:
        """处理Tab键"""
        self.handle_space()

    def handle_enter(self) -> Optional["InteractivePanel"]:
        """处理回车键"""
        current = self.get_current_item()
        if current:
            self.modified = True
        return None

    def handle_escape(self) -> Optional["InteractivePanel"]:
        """处理ESC键"""
        return self.parent_panel

    def get_config(self) -> dict:
        """获取修改后的配置"""
        config = {}
        for item in self.items:
            keys = item.label.split(" (")[0].split(" (")
            if len(keys) > 1:
                section = keys[0]
                key = keys[1].rstrip(")")

                if section not in config:
                    config[section] = {}

                config[section][key] = item.value
            else:
                config[item.label] = item.value
        return config

    def is_modified(self) -> bool:
        """检查是否有修改"""
        return self.modified
