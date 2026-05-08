"""Base Remote Scanner

定义远程扫描器的基础抽象类。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum


class ScannerType(Enum):
    """扫描器类型"""
    NETWORK = "network"
    SERIAL = "serial"


@dataclass
class RemoteFile:
    """远程文件"""
    path: str
    size: int
    modified_time: float
    permissions: str
    owner: Optional[str] = None
    group: Optional[str] = None


@dataclass
class ScanResult:
    """扫描结果"""
    files: List[RemoteFile]
    target: str
    scanner_type: ScannerType
    metadata: Dict[str, Any]


class BaseRemoteScanner(ABC):
    """远程扫描器基类"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

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
    def discover_files(self, remote_path: str) -> List[RemoteFile]:
        """发现远程文件"""
        pass

    @abstractmethod
    def read_file(self, remote_path: str) -> bytes:
        """读取远程文件内容"""
        pass

    @abstractmethod
    def execute_command(self, command: str) -> Dict[str, Any]:
        """执行远程命令"""
        pass

    @property
    @abstractmethod
    def scanner_type(self) -> ScannerType:
        """获取扫描器类型"""
        pass