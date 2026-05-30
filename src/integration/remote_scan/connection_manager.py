"""Connection Manager

管理远程连接，包括网络连接和串口连接。
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum


class ConnectionState(Enum):
    """连接状态"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class NetworkConnection:
    """网络连接配置"""
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    key_path: Optional[str] = None


@dataclass
class SerialConnection:
    """串口连接配置"""
    port: str
    baudrate: int = 115200
    bytesize: int = 8
    parity: str = "N"
    stopbits: int = 1


class ConnectionManager(ABC):
    """连接管理器基类"""

    def __init__(self):
        self._state = ConnectionState.DISCONNECTED
        self._connection: Optional[Any] = None

    @property
    def state(self) -> ConnectionState:
        """获取连接状态"""
        return self._state

    @abstractmethod
    def connect(self) -> bool:
        """建立连接"""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """断开连接"""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """检查连接状态"""
        pass

    @abstractmethod
    def send(self, data: bytes) -> int:
        """发送数据"""
        pass

    @abstractmethod
    def recv(self, size: int) -> bytes:
        """接收数据"""
        pass