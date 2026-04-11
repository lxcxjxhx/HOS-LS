"""
企业内网/VPN模块单元测试

覆盖VPN连接器、代理链、内网扫描等核心功能。
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from src.remote.enterprise.vpn_connector import (
    VPNConfig,
    VPNStatus,
    VPNConnectionInfo,
    VPNConnector,
    OpenVPNConnector,
    WireGuardConnector
)
from src.remote.enterprise.proxy_tunnel import (
    ProxyType,
    ProxyConfig,
    SSHTunnel,
    JumpHostManager,
    _parse_jump_host
)
from src.remote.enterprise.internal_network_scanner import (
    NetworkHost,
    SubnetInfo,
    SubnetDiscovery,
    PortScanner,
    InternalNetworkScanner
)


class TestVPNConfig:
    """测试VPN配置"""
    
    def test_create_vpn_config(self):
        config = VPNConfig(
            vpn_type='openvpn',
            server_address='vpn.example.com',
            port=1194,
            username='testuser'
        )
        
        assert config.vpn_type == 'openvpn'
        assert config.server_address == 'vpn.example.com'
        assert config.port == 1194
    
    def test_vpn_config_to_dict(self):
        config = VPNConfig(
            vpn_type='wireguard',
            server_address='10.0.0.1',
            username='admin',
            password='secret'
        )
        
        data = config.to_dict()
        
        assert data['vpn_type'] == 'wireguard'
        assert data['server'] == '10.0.0.1'
        assert data['has_auth'] is True


class TestVPNConnectionInfo:
    """测试VPN连接信息"""
    
    def test_create_connection_info(self):
        info = VPNConnectionInfo(
            local_ip='10.8.0.2',
            remote_ip='10.8.0.1',
            tunnel_interface='tun0',
            connected_since=datetime.now()
        )
        
        assert info.local_ip == '10.8.0.2'
        assert info.tunnel_interface == 'tun0'
        assert info.connected_since is not None


class TestOpenVPNConnector:
    """测试OpenVPN连接器"""
    
    def test_create_connector_with_config(self):
        config = VPNConfig(
            server_address='vpn.test.com',
            config_file='/tmp/test.ovpn',
            username='user'
        )
        
        connector = OpenVPNConnector(config=config)
        
        assert connector.vpn_config.server_address == 'vpn.test.com'
        assert connector.connector_type == 'openvpn'


class TestWireGuardConnector:
    """测试WireGuard连接器"""
    
    def test_create_connector(self):
        config = VPNConfig(config_file='/etc/wireguard/wg0.conf')
        connector = WireGuardConnector(config=config, interface_name='wg-test')
        
        assert connector.interface_name == 'wg-test'
        assert connector.connector_type == 'wireguard'


class TestProxyConfig:
    """测试代理配置"""
    
    def test_ssh_tunnel_config(self):
        config = ProxyConfig(
            proxy_type=ProxyType.SSH_TUNNEL,
            host='bastion.com',
            port=22,
            username='admin'
        )
        
        data = config.to_dict()
        
        assert data['type'] == 'ssh_tunnel'
        assert data['host'] == 'bastion.com'
    
    def test_socks5_proxy_config(self):
        config = ProxyConfig(
            proxy_type=ProxyType.SOCKS5,
            host='127.0.0.1',
            port=1080
        )
        
        assert config.proxy_type == ProxyType.SOCKS5


class TestSSHTunnel:
    """测试SSH隧道"""
    
    @pytest.mark.asyncio
    async def test_ssh_tunnel_creation(self):
        tunnel = SSHTunnel(
            ssh_host='localhost',
            ssh_port=22,
            username='test'
        )
        
        assert tunnel.ssh_host == 'localhost'
        assert tunnel.username == 'test'
        assert not tunnel.is_connected


class TestJumpHostManager:
    """测试跳板机管理器"""
    
    def test_create_manager(self):
        chain_config = [
            {'ssh_host': 'hop1', 'username': 'user1'},
            {'ssh_host': 'hop2', 'username': 'user2'}
        ]
        
        manager = JumpHostManager(chain_config)
        
        assert manager.chain_length == 2
        assert not manager.is_connected


class TestNetworkHost:
    """测试网络主机信息"""
    
    def test_create_host(self):
        host = NetworkHost(
            ip_address='192.168.1.100',
            hostname='web-server-01',
            status='up',
            open_ports=[22, 80, 443]
        )
        
        assert host.ip_address == '192.168.1.100'
        assert host.is_alive
        assert len(host.open_ports) == 3
    
    def test_risk_score_calculation(self):
        # 高风险主机（开放了数据库端口）
        high_risk_host = NetworkHost(
            ip_address='192.168.1.200',
            open_ports=[22, 80, 3306, 6379]
        )
        
        # 低风险主机（只开放Web端口）
        low_risk_host = NetworkHost(
            ip_address='192.168.1.201',
            open_ports=[80, 443]
        )
        
        assert high_risk_host.risk_score > low_risk_host.risk_score
    
    def test_to_dict_conversion(self):
        host = NetworkHost(
            ip_address='10.0.0.50',
            hostname='db-master',
            os_guess='Ubuntu 20.04',
            services={3306: 'MySQL', 22: 'SSH'}
        )
        
        data = host.to_dict()
        
        assert data['ip'] == '10.0.0.50'
        assert data['hostname'] == 'db-master'
        assert 'MySQL' in data['services'].values()


class TestSubnetDiscovery:
    """测试子网发现"""
    
    def test_create_discovery(self):
        discovery = SubnetDiscovery()
        
        assert discovery.timeout > 0
        assert discovery.max_concurrent > 0


class TestPortScanner:
    """测试端口扫描器"""
    
    def test_common_ports_defined(self):
        scanner = PortScanner()
        
        assert len(scanner.COMMON_PORTS) > 30
        assert 22 in scanner.COMMON_PORTS  # SSH
        assert 80 in scanner.COMMON_PORTS  # HTTP
        assert 443 in scanner.COMMON_PORTS  # HTTPS
        assert 3306 in scanner.COMMON_PORTS  # MySQL
    
    def test_create_scanner_with_custom_config(self):
        scanner = PortScanner(timeout=5.0, max_concurrent=200)
        
        assert scanner.timeout == 5.0
        assert scanner.max_concurrent == 200


class TestInternalNetworkScanner:
    """测试内网扫描器"""
    
    def test_create_scanner(self):
        scanner = InternalNetworkScanner()
        
        assert scanner.subnet_discovery is not None
        assert scanner.port_scanner is not None
        assert scanner.service_identifier is not None


class TestJumpHostParsing:
    """测试跳板机地址解析"""
    
    def test_parse_user_host_port(self):
        result = _parse_jump_host('admin@server:2222')
        
        assert result['host'] == 'server'
        assert result['port'] == 2222
        assert result['username'] == 'admin'
    
    def test_parse_host_port(self):
        result = _parse_jump_host('db-server:3306')
        
        assert result['host'] == 'db-server'
        assert result['port'] == 3306
        assert result['username'] is None
    
    def test_parse_user_host(self):
        result = _parse_jump_host('deploy@ci-server')
        
        assert result['host'] == 'ci-server'
        assert result['port'] == 22  # 默认端口
        assert result['username'] == 'deploy'
    
    def test_parse_simple_host(self):
        result = _parse_jump_host('web-server')
        
        assert result['host'] == 'web-server'
        assert result['port'] == 22
        assert result['username'] is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
