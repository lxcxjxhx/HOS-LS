"""Remote Scan Module

支持远程设备扫描功能，包括网络扫描和串口扫描。
"""

from .base_scanner import BaseRemoteScanner
from .connection_manager import ConnectionManager, NetworkConnection, SerialConnection
from .config import RemoteScanConfig
from .exceptions import (
    RemoteScanError,
    ConnectionError,
    AuthenticationError,
    TimeoutError,
)

__all__ = [
    "BaseRemoteScanner",
    "ConnectionManager",
    "NetworkConnection",
    "SerialConnection",
    "RemoteScanConfig",
    "RemoteScanError",
    "ConnectionError",
    "AuthenticationError",
    "TimeoutError",
]