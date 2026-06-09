"""串口工具模块

提供串口通信和交互式串口工具面板功能。
"""

from .manager import (
    SerialManager,
    SerialConfig,
    SerialPortInfo,
    Parity,
    StopBits,
    hex_encode,
    hex_decode,
    ascii_encode,
    is_hex_string,
)
from .panel import SerialPortPanel

__all__ = [
    "SerialManager",
    "SerialConfig",
    "SerialPortInfo",
    "Parity",
    "StopBits",
    "hex_encode",
    "hex_decode",
    "ascii_encode",
    "is_hex_string",
    "SerialPortPanel",
]
