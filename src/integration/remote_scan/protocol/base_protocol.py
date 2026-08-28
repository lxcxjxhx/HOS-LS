"""Base Protocol

协议基类定义。
"""

from abc import ABC, abstractmethod


class BaseProtocol(ABC):
    """协议基类"""

    def __init__(self):
        self._connected: bool = False

    @abstractmethod
    def connect(self) -> bool:
        """建立连接"""

    @abstractmethod
    def disconnect(self) -> None:
        """断开连接"""

    @abstractmethod
    def is_connected(self) -> bool:
        """检查连接状态"""

    @abstractmethod
    def send(self, data: bytes) -> int:
        """发送数据"""

    @abstractmethod
    def recv(self, size: int) -> bytes:
        """接收数据"""
