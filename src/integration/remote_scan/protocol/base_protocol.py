"""Base Protocol

协议基类定义。
"""

from abc import ABC, abstractmethod
from typing import Optional, Any


class BaseProtocol(ABC):
    """协议基类"""

    def __init__(self):
        self._connected: bool = False

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