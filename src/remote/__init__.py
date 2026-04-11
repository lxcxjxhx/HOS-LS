"""
HOS-LS 远程扫描模块

提供远程服务器、网站和物理设备的统一扫描能力。
"""

from .target import (
    BaseTarget,
    TargetInfo,
    LocalTarget,
    RemoteServerTarget,
    WebTarget,
    DirectConnectTarget,
    TargetFactory
)

__all__ = [
    'BaseTarget',
    'TargetInfo',
    'LocalTarget',
    'RemoteServerTarget',
    'WebTarget',
    'DirectConnectTarget',
    'TargetFactory'
]

__version__ = '1.0.0'
