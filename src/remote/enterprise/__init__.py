"""
企业内网与VPN连接模块

支持复杂网络环境下的安全扫描：
- 企业VPN连接（OpenVPN/WireGuard/IPSec）
- 代理链与跳板机（SSH Tunneling/SOCKS5）
- 内网子网发现与扫描
"""

from .vpn_connector import (
    VPNConnector,
    OpenVPNConnector,
    WireGuardConnector,
    IPSecConnector,
    VPNConfig,
    VPNStatus
)
from .proxy_tunnel import (
    ProxyChain,
    SSHTunnel,
    SOCKS5Proxy,
    JumpHostManager,
    ProxyTunnel
)
from .internal_network_scanner import (
    InternalNetworkScanner,
    SubnetDiscovery,
    PortScanner,
    ServiceIdentifier,
    NetworkHost
)

__all__ = [
    'VPNConnector',
    'OpenVPNConnector',
    'WireGuardConnector',
    'IPSecConnector',
    'VPNConfig',
    'VPNStatus',
    'ProxyChain',
    'SSHTunnel',
    'SOCKS5Proxy',
    'JumpHostManager',
    'ProxyTunnel',
    'InternalNetworkScanner',
    'SubnetDiscovery',
    'PortScanner',
    'ServiceIdentifier',
    'NetworkHost'
]

__version__ = '1.0.0'
