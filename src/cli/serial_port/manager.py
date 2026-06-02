"""串口通信模块

提供串口扫描、连接、数据收发功能。
"""

import threading
import time
from typing import Optional, Callable, List, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    import serial
    import serial.tools.list_ports
    PYSERIAL_AVAILABLE = True
except ImportError:
    PYSERIAL_AVAILABLE = False
    serial = None


class Parity(Enum):
    """校验位"""
    NONE = "N"
    ODD = "O"
    EVEN = "E"
    MARK = "M"
    SPACE = "S"


class StopBits(Enum):
    """停止位"""
    ONE = 1
    ONE_POINT_FIVE = 1.5
    TWO = 2


@dataclass
class SerialPortInfo:
    """串口信息"""
    device: str
    description: str
    hwid: str


@dataclass
class SerialConfig:
    """串口配置"""
    port: str = "COM1"
    baudrate: int = 115200
    bytesize: int = 8
    parity: str = "N"
    stopbits: float = 1.0
    timeout: float = 1.0
    xonxoff: bool = False
    rtscts: bool = False


class SerialManager:
    """串口管理器

    提供串口扫描、连接、数据收发功能。
    """

    def __init__(self):
        self.serial_obj: Optional[serial.Serial] = None
        self.config = SerialConfig()
        self._receive_thread: Optional[threading.Thread] = None
        self._running = False
        self._receive_callback: Optional[Callable[[bytes], None]] = None
        self._log: List[Tuple[str, bytes]] = []

    @staticmethod
    def is_available() -> bool:
        """检查pyserial是否可用"""
        return PYSERIAL_AVAILABLE

    @staticmethod
    def list_ports() -> List[SerialPortInfo]:
        """列出所有可用串口

        Returns:
            串口信息列表
        """
        if not PYSERIAL_AVAILABLE:
            return []

        ports = serial.tools.list_ports.comports()
        return [
            SerialPortInfo(
                device=p.device,
                description=p.description or "未知设备",
                hwid=p.hwid or "未知"
            )
            for p in ports
        ]

    def connect(self, config: SerialConfig) -> bool:
        """连接串口

        Args:
            config: 串口配置

        Returns:
            是否连接成功
        """
        if not PYSERIAL_AVAILABLE:
            return False

        try:
            self.disconnect()
            self.config = config

            self.serial_obj = serial.Serial(
                port=config.port,
                baudrate=config.baudrate,
                bytesize=config.bytesize,
                parity=config.parity,
                stopbits=config.stopbits,
                timeout=config.timeout,
                xonxoff=config.xonxoff,
                rtscts=config.rtscts,
            )

            self._running = True
            self._receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self._receive_thread.start()

            return True
        except Exception as e:
            print(f"连接串口失败: {e}")
            return False

    def disconnect(self) -> None:
        """断开串口连接"""
        self._running = False

        if self._receive_thread and self._receive_thread.is_alive():
            self._receive_thread.join(timeout=1.0)

        if self.serial_obj and self.serial_obj.is_open:
            self.serial_obj.close()
            self.serial_obj = None

    def is_connected(self) -> bool:
        """检查是否已连接"""
        return self.serial_obj is not None and self.serial_obj.is_open

    def send(self, data: bytes) -> int:
        """发送数据

        Args:
            data: 要发送的数据

        Returns:
            发送的字节数
        """
        if not self.is_connected():
            return 0

        try:
            self._log.append(("TX", data))
            return self.serial_obj.write(data)
        except Exception as e:
            print(f"发送数据失败: {e}")
            return 0

    def receive(self, timeout: float = 0.1) -> bytes:
        """接收数据

        Args:
            timeout: 超时时间（秒）

        Returns:
            接收到的数据
        """
        if not self.is_connected():
            return b""

        try:
            self.serial_obj.timeout = timeout
            data = self.serial_obj.read(1024)
            if data:
                self._log.append(("RX", data))
            return data
        except Exception as e:
            print(f"接收数据失败: {e}")
            return b""

    def set_receive_callback(self, callback: Callable[[bytes], None]) -> None:
        """设置接收回调函数

        Args:
            callback: 回调函数，接收bytes参数
        """
        self._receive_callback = callback

    def _receive_loop(self) -> None:
        """接收线程循环"""
        while self._running and self.is_connected():
            try:
                if self.serial_obj.in_waiting > 0:
                    data = self.serial_obj.read(self.serial_obj.in_waiting)
                    if data:
                        self._log.append(("RX", data))
                        if self._receive_callback:
                            self._receive_callback(data)
                time.sleep(0.01)
            except Exception:
                break

    def get_log(self) -> List[Tuple[str, bytes]]:
        """获取通信日志

        Returns:
            日志列表，每项为 (方向, 数据)
        """
        return self._log.copy()

    def clear_log(self) -> None:
        """清空通信日志"""
        self._log.clear()


def hex_encode(data: bytes) -> str:
    """将字节转换为HEX字符串

    Args:
        data: 字节数据

    Returns:
        HEX字符串（如 "01 02 03 04"）
    """
    return " ".join(f"{b:02X}" for b in data)


def hex_decode(hex_str: str) -> bytes:
    """将HEX字符串转换为字节

    Args:
        hex_str: HEX字符串（如 "01 02 03 04"）

    Returns:
        字节数据
    """
    hex_str = hex_str.replace(" ", "").replace("\n", "").replace("\r", "")
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return b""


def ascii_encode(data: bytes) -> str:
    """将字节转换为ASCII字符串

    Args:
        data: 字节数据

    Returns:
        ASCII字符串
    """
    result = []
    for b in data:
        if 32 <= b < 127:
            result.append(chr(b))
        else:
            result.append(f"\\x{b:02X}")
    return "".join(result)


def is_hex_string(s: str) -> bool:
    """检查字符串是否为HEX格式

    Args:
        s: 输入字符串

    Returns:
        是否为HEX格式
    """
    s = s.replace(" ", "").replace("\n", "").replace("\r", "")
    if not s:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False
