"""交互式面板基类

提供交互式面板的基类定义和通用功能。
"""

import sys
import os
from typing import Callable, List, Optional, Any, Dict
from dataclasses import dataclass
from enum import Enum


class Key(Enum):
    """键盘按键枚举"""
    UP = "up"
    DOWN = "down"
    LEFT = "left"
    RIGHT = "right"
    ENTER = "enter"
    ESC = "esc"
    SPACE = "space"
    BACKSPACE = "backspace"
    TAB = "tab"
    Q = "q"
    UNKNOWN = "unknown"


@dataclass
class PanelItem:
    """面板项数据结构"""
    label: str
    value: Any
    default: Any = None
    description: str = ""
    options: List[Any] = None
    type: str = "string"
    on_change: Callable[[Any], None] = None

    def __post_init__(self):
        if self.options is None:
            self.options = []


class InteractivePanel:
    """交互式面板基类

    提供交互式面板的通用功能，包括：
    - 面板渲染
    - 键盘事件处理
    - 项目导航
    """

    def __init__(self, title: str = "HOS-LS Panel"):
        self.title = title
        self.items: List[PanelItem] = []
        self.current_index = 0
        self.parent: Optional["InteractivePanel"] = None
        self.is_running = False
        self._input_buffer = ""

    def add_item(self, item: PanelItem) -> "InteractivePanel":
        """添加面板项"""
        self.items.append(item)
        return self

    def add_items(self, items: List[PanelItem]) -> "InteractivePanel":
        """批量添加面板项"""
        self.items.extend(items)
        return self

    def clear_items(self) -> "InteractivePanel":
        """清空面板项"""
        self.items.clear()
        self.current_index = 0
        return self

    def get_current_item(self) -> Optional[PanelItem]:
        """获取当前面板项"""
        if 0 <= self.current_index < len(self.items):
            return self.items[self.current_index]
        return None

    def navigate_up(self) -> None:
        """向上导航"""
        if self.items:
            self.current_index = (self.current_index - 1) % len(self.items)

    def navigate_down(self) -> None:
        """向下导航"""
        if self.items:
            self.current_index = (self.current_index + 1) % len(self.items)

    def navigate_left(self) -> None:
        """向左导航（子类可重写）"""
        pass

    def navigate_right(self) -> None:
        """向右导航（子类可重写）"""
        pass

    def handle_enter(self) -> Optional["InteractivePanel"]:
        """处理回车键（子类可重写）"""
        return None

    def handle_escape(self) -> Optional["InteractivePanel"]:
        """处理ESC键"""
        return self.parent

    def handle_space(self) -> None:
        """处理空格键（子类可重写）"""
        current = self.get_current_item()
        if current and current.options:
            current.value = not current.value if isinstance(current.value, bool) else current.value

    def handle_backspace(self) -> None:
        """处理退格键"""
        if self._input_buffer:
            self._input_buffer = self._input_buffer[:-1]

    def handle_tab(self) -> None:
        """处理Tab键"""
        current = self.get_current_item()
        if current and current.options:
            if isinstance(current.value, bool):
                current.value = not current.value
            elif current.options:
                idx = current.options.index(current.value) if current.value in current.options else -1
                current.value = current.options[(idx + 1) % len(current.options)]

    def handle_character(self, char: str) -> None:
        """处理普通字符输入"""
        self._input_buffer += char

    def render(self) -> None:
        """渲染面板（子类必须实现）"""
        raise NotImplementedError

    def get_key(self) -> Key:
        """获取键盘按键（跨平台实现）"""
        if os.name == 'nt':
            return self._get_key_windows()
        else:
            return self._get_key_unix()

    def _get_key_windows(self) -> Key:
        """Windows平台获取按键"""
        import msvcrt
        char = msvcrt.getch()
        if char == b'\xe0':
            char = msvcrt.getch()
            if char == b'H':
                return Key.UP
            elif char == b'P':
                return Key.DOWN
            elif char == b'M':
                return Key.RIGHT
            elif char == b'K':
                return Key.LEFT
        elif char == b'\r':
            return Key.ENTER
        elif char == b' ':
            return Key.SPACE
        elif char == b'\x08':
            return Key.BACKSPACE
        elif char == b'\x1b':
            return Key.ESC
        elif char == b'\t':
            return Key.TAB
        elif char in (b'q', b'Q'):
            return Key.Q
        else:
            try:
                return Key(char.decode('utf-8'))
            except:
                return Key.UNKNOWN

    def _get_key_unix(self) -> Key:
        """Unix平台获取按键"""
        import tty
        import termios
        import sys as _sys

        fd = _sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            char = _sys.stdin.read(1)
            if char == '\x1b':
                next_char = _sys.stdin.read(1)
                if next_char == '[':
                    third_char = _sys.stdin.read(1)
                    if third_char == 'A':
                        return Key.UP
                    elif third_char == 'B':
                        return Key.DOWN
                    elif third_char == 'C':
                        return Key.RIGHT
                    elif third_char == 'D':
                        return Key.LEFT
            elif char == '\r' or char == '\n':
                return Key.ENTER
            elif char == ' ':
                return Key.SPACE
            elif char == '\x7f':
                return Key.BACKSPACE
            elif char == '\t':
                return Key.TAB
            elif char.lower() == 'q':
                return Key.Q
            else:
                return Key.UNKNOWN
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def run(self) -> Optional["InteractivePanel"]:
        """运行面板主循环"""
        self.is_running = True
        result_panel = None

        while self.is_running:
            self.render()

            key = self.get_key()

            if key == Key.UP:
                self.navigate_up()
            elif key == Key.DOWN:
                self.navigate_down()
            elif key == Key.LEFT:
                self.navigate_left()
            elif key == Key.RIGHT:
                self.navigate_right()
            elif key == Key.ENTER:
                result_panel = self.handle_enter()
                if result_panel is not None and result_panel != self:
                    self.is_running = False
            elif key == Key.ESC:
                result_panel = self.handle_escape()
                if result_panel is not None and result_panel != self:
                    self.is_running = False
            elif key == Key.SPACE:
                self.handle_space()
            elif key == Key.BACKSPACE:
                self.handle_backspace()
            elif key == Key.TAB:
                self.handle_tab()
            elif key == Key.Q:
                self.is_running = False
                result_panel = None
            elif key != Key.UNKNOWN:
                self.handle_character(str(key.value) if hasattr(key.value, 'value') else key.name.lower())

        return result_panel


def clear_screen() -> None:
    """清除屏幕"""
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def print_centered(text: str, width: int = 80) -> None:
    """居中打印文本"""
    print(text.center(width))


def print_divider(char: str = "─", width: int = 80) -> None:
    """打印分隔线"""
    print(char * width)
