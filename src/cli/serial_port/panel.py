"""串口工具面板

提供交互式串口工具界面。
"""

import os
import time
from typing import Optional, List
from datetime import datetime
from .manager import (
    SerialManager, SerialConfig, SerialPortInfo,
    Parity, StopBits, hex_encode, hex_decode, ascii_encode, is_hex_string
)
from ..panel.base import InteractivePanel, PanelItem, clear_screen, print_divider


class SerialPortPanel(InteractivePanel):
    """串口工具面板

    提供交互式串口工具界面。
    """

    BAUDRATES = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
    DATASIZES = [5, 6, 7, 8]
    PARITIES = ["N", "O", "E", "M", "S"]
    STOPBITS = [1.0, 1.5, 2.0]

    def __init__(self, parent: Optional["InteractivePanel"] = None):
        super().__init__("HOS-LS 串口工具")
        self.parent_panel = parent
        self.manager = SerialManager()
        self.ports: List[SerialPortInfo] = []
        self.receive_buffer: List[str] = []
        self.send_history: List[str] = []
        self.send_index = -1

        self.selected_port_index = 0
        self.selected_baudrate_index = 4
        self.selected_datasize_index = 3
        self.selected_parity_index = 0
        self.selected_stopbits_index = 0

        self.hex_mode = False
        self.auto_scroll = True
        self.add_newline = True
        self.show_timestamp = True
        self.show_hex = True

        self.current_field = "port"
        self.input_buffer = ""
        self.send_input_buffer = ""

        self._scan_ports()

    def _scan_ports(self) -> None:
        """扫描可用串口"""
        self.ports = SerialManager.list_ports()
        if self.ports and self.selected_port_index >= len(self.ports):
            self.selected_port_index = 0

    def _get_current_config(self) -> SerialConfig:
        """获取当前配置"""
        return SerialConfig(
            port=self.ports[self.selected_port_index].device if self.ports else "COM1",
            baudrate=self.BAUDRATES[self.selected_baudrate_index],
            bytesize=self.DATASIZES[self.selected_datasize_index],
            parity=self.PARITIES[self.selected_parity_index],
            stopbits=self.STOPBITS[self.selected_stopbits_index],
        )

    def render(self) -> None:
        """渲染串口工具面板"""
        clear_screen()
        print_divider("─", 80)
        print(" HOS-LS 串口工具 ".center(78, "─"))
        print_divider("─", 80)

        connected = self.manager.is_connected()
        status = "已连接" if connected else "未连接"
        status_style = "[green]" if connected else "[red]"
        print(f"  状态: {status_style}{status}[/] | 按 Q 退出")

        print()
        print_divider("─", 80)
        print("  串口参数配置")
        print_divider("─", 80)

        port_name = self.ports[self.selected_port_index].device if self.ports else "(无可用串口)"
        port_desc = self.ports[self.selected_port_index].description if self.ports else ""

        print(f"  串口: [{self.selected_port_index}] {port_name}  {port_desc}")
        print(f"  波特率: [{self.selected_baudrate_index}] {self.BAUDRATES[self.selected_baudrate_index]}")
        print(f"  数据位: [{self.selected_datasize_index}] {self.DATASIZES[self.selected_datasize_index]}")
        print(f"  校验位: [{self.selected_parity_index}] {self.PARITIES[self.selected_parity_index]} "
              f"({'无' if self.PARITIES[self.selected_parity_index] == 'N' else '奇' if self.PARITIES[self.selected_parity_index] == 'O' else '偶' if self.PARITIES[self.selected_parity_index] == 'E' else '其他'})")
        print(f"  停止位: [{self.selected_stopbits_index}] {self.STOPBITS[self.selected_stopbits_index]}")

        print()
        print_divider("─", 80)
        print("  操作说明: 方向键修改参数 | C 连接/D 断开 | S 扫描串口 | T 切换模式 | R 清除接收")
        print()
        print_divider("─", 80)
        print("  接收区 (按 T 切换 HEX/ASCII 显示)")
        print_divider("─", 80)

        if self.receive_buffer:
            display_buffer = self.receive_buffer[-50:] if len(self.receive_buffer) > 50 else self.receive_buffer
            for line in display_buffer:
                print(f"  {line}")
        else:
            print("  (无数据)")

        print()
        print_divider("─", 80)
        print("  发送区")
        print_divider("─", 80)

        mode_str = "HEX" if self.hex_mode else "ASCII"
        newline_str = "是" if self.add_newline else "否"
        print(f"  模式: {mode_str} | 追加换行: {newline_str}")
        print()

        prompt = "> " if not self.send_input_buffer else self.send_input_buffer
        print(f"  {prompt}_")

        if self.send_history:
            print(f"  历史: {len(self.send_history)} 条 | 上/下箭头选择")

        print()
        print_divider("─", 80)

    def _add_receive_line(self, data: bytes) -> None:
        """添加接收数据行"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3] if self.show_timestamp else ""

        if self.show_hex:
            hex_str = hex_encode(data)
            line = f"[{timestamp}] RX: {hex_str}" if timestamp else f"RX: {hex_str}"
        else:
            ascii_str = ascii_encode(data)
            line = f"[{timestamp}] RX: {ascii_str}" if timestamp else f"RX: {ascii_str}"

        self.receive_buffer.append(line)

    def _handle_connect(self) -> None:
        """处理连接"""
        if self.manager.is_connected():
            self.manager.disconnect()
        else:
            if not self.ports:
                self._scan_ports()
            if self.ports:
                config = self._get_current_config()
                if self.manager.connect(config):
                    self.manager.set_receive_callback(self._add_receive_line)

    def _handle_send(self) -> None:
        """处理发送"""
        if not self.send_input_buffer.strip():
            return

        data = self.send_input_buffer

        if self.hex_mode:
            data = hex_decode(data)
        else:
            data = data.encode('utf-8')
            if self.add_newline:
                data += b'\r\n'

        if data:
            self.manager.send(data)
            self.send_history.append(self.send_input_buffer)
            self.send_input_buffer = ""
            self.send_index = -1

            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3] if self.show_timestamp else ""
            tx_line = f"[{timestamp}] TX: {self.send_input_buffer}" if timestamp else f"TX: {self.send_input_buffer}"
            self.receive_buffer.append(tx_line)

    def handle_key(self, key) -> None:
        """处理按键"""
        from ..panel.base import Key

        if key == Key.UP:
            if self.send_history:
                if self.send_index < len(self.send_history) - 1:
                    self.send_index += 1
                    self.send_input_buffer = self.send_history[-(self.send_index + 1)]
        elif key == Key.DOWN:
            if self.send_index > 0:
                self.send_index -= 1
                self.send_input_buffer = self.send_history[-(self.send_index + 1)]
            elif self.send_index == 0:
                self.send_index = -1
                self.send_input_buffer = ""
        elif key == Key.LEFT:
            if self.current_field == "baudrate":
                self.selected_baudrate_index = (self.selected_baudrate_index - 1) % len(self.BAUDRATES)
            elif self.current_field == "datasize":
                self.selected_datasize_index = (self.selected_datasize_index - 1) % len(self.DATASIZES)
            elif self.current_field == "parity":
                self.selected_parity_index = (self.selected_parity_index - 1) % len(self.PARITIES)
            elif self.current_field == "stopbits":
                self.selected_stopbits_index = (self.selected_stopbits_index - 1) % len(self.STOPBITS)
            elif self.current_field == "port":
                self.selected_port_index = (self.selected_port_index - 1) % max(len(self.ports), 1)
        elif key == Key.RIGHT:
            if self.current_field == "baudrate":
                self.selected_baudrate_index = (self.selected_baudrate_index + 1) % len(self.BAUDRATES)
            elif self.current_field == "datasize":
                self.selected_datasize_index = (self.selected_datasize_index + 1) % len(self.DATASIZES)
            elif self.current_field == "parity":
                self.selected_parity_index = (self.selected_parity_index + 1) % len(self.PARITIES)
            elif self.current_field == "stopbits":
                self.selected_stopbits_index = (self.selected_stopbits_index + 1) % len(self.STOPBITS)
            elif self.current_field == "port":
                self.selected_port_index = (self.selected_port_index + 1) % max(len(self.ports), 1)
        elif key == Key.SPACE:
            self.hex_mode = not self.hex_mode
        elif key == Key.ENTER:
            self._handle_send()
        elif key == Key.BACKSPACE:
            if self.send_input_buffer:
                self.send_input_buffer = self.send_input_buffer[:-1]
                self.send_index = -1
        elif key == Key.TAB:
            self.add_newline = not self.add_newline
        elif key == Key.ESC:
            pass
        elif hasattr(key, 'value') and isinstance(key.value, str):
            char = key.value
            if len(char) == 1:
                self.send_input_buffer += char
                self.send_index = -1

    def run(self) -> Optional["InteractivePanel"]:
        """运行面板"""
        self.is_running = True
        result_panel = None

        while self.is_running:
            self.render()

            key = self.get_key()

            if key.value in ('q', 'Q'):
                self.is_running = False
                result_panel = self.parent_panel
            elif key.value in ('c', 'C'):
                self._handle_connect()
            elif key.value in ('d', 'D'):
                if self.manager.is_connected():
                    self.manager.disconnect()
            elif key.value in ('s', 'S'):
                self._scan_ports()
            elif key.value in ('t', 'T'):
                self.show_hex = not self.show_hex
            elif key.value in ('r', 'R'):
                self.receive_buffer.clear()
            elif key.value in ('n', 'N'):
                self.add_newline = not self.add_newline
            else:
                self.handle_key(key)

        if self.manager.is_connected():
            self.manager.disconnect()

        return result_panel
