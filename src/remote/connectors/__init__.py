"""
连接器模块

提供各种远程连接的插件式连接器。
"""

from .base_connector import BaseConnector, ConnectionResult, ConnectionStatus
from .registry import ConnectorRegistry, get_registry

__all__ = [
    'BaseConnector',
    'ConnectionResult',
    'ConnectionStatus',
    'ConnectorRegistry',
    'get_registry'
]
