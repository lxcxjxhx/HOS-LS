"""
网线直连连接器

基于 raw socket/scapy 的网络接口直接连接。
"""

from .base_connector import BaseConnector, ConnectionResult, ConnectionStatus, ConnectionConfig
from .serial_connector import DirectEthernetConnector

__all__ = ['DirectEthernetConnector']
