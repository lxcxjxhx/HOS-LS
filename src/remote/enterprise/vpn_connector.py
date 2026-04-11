"""
VPN 连接器

支持企业VPN连接，包括 OpenVPN、WireGuard 和 IPSec。
提供统一的VPN接口用于内网安全扫描。
"""

import asyncio
import subprocess
import os
import socket
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..connectors.base_connector import (
    BaseConnector,
    ConnectionResult,
    ConnectionStatus,
    ConnectionConfig
)

from rich.console import Console

console = Console()


class VPNStatus(Enum):
    """VPN连接状态"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


@dataclass
class VPNConfig:
    """VPN配置数据类"""
    vpn_type: str = "openvpn"  # openvpn, wireguard, ipsec
    config_file: str = None  # VPN配置文件路径
    auth_file: str = None  # 认证文件（用户名/密码）
    cert_file: str = None  # 客户端证书
    key_file: str = None  # 私钥文件
    ca_file: str = None  # CA证书
    username: str = None  # 用户名
    password: str = None  # 密码
    server_address: str = None  # VPN服务器地址
    server_port: int = 1194  # VPN端口
    protocol: str = "udp"  # 协议 (tcp/udp)
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])
    search_domains: List[str] = field(default_factory=list)
    routes: List[str] = field(default_factory=list)  # 路由配置
    script_security: int = 2  # 安全级别
    log_level: int = 3  # 日志级别
    timeout: int = 30  # 连接超时
    reconnect: bool = True  # 自动重连
    keepalive: int = 10  # 心跳间隔
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vpn_type': self.vpn_type,
            'server': self.server_address,
            'port': self.server_port,
            'protocol': self.protocol,
            'has_auth': bool(self.username and self.password),
            'has_cert': bool(self.cert_file)
        }


@dataclass
class VPNConnectionInfo:
    """VPN连接信息"""
    local_ip: str = ""
    remote_ip: str = ""
    tunnel_interface: str = ""  # tun0, wg0等
    dns_servers: List[str] = field(default_factory=list)
    routes: List[str] = field(default_factory=list)
    connected_since: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0


class VPNConnector(BaseConnector):
    """
    VPN连接器基类
    
    提供统一的VPN连接管理接口。
    支持多种VPN协议的抽象实现。
    """
    
    connector_type = "vpn"
    
    def __init__(self, config: VPNConfig = None, **kwargs):
        super().__init__(
            config=ConnectionConfig(
                timeout=config.timeout if config else 30
            ) if config else ConnectionConfig(),
            **kwargs
        )
        
        self.vpn_config = config or VPNConfig()
        self._vpn_status = VPNStatus.DISCONNECTED
        self._connection_info: Optional[VPNConnectionInfo] = None
        self._process: Optional[subprocess.Popen] = None
        
        if not self.vpn_config.server_address:
            raise ValueError("必须指定VPN服务器地址 (server_address)")
    
    @property
    def status(self) -> VPNStatus:
        return self._vpn_status
    
    @property
    def is_connected(self) -> bool:
        return self._vpn_status == VPNStatus.CONNECTED
    
    @property
    def connection_info(self) -> Optional[VPNConnectionInfo]:
        return self._connection_info
    
    async def _do_connect(self) -> ConnectionResult:
        """建立VPN连接（子类实现）"""
        raise NotImplementedError("子类必须实现 _do_connect 方法")
    
    async def _do_disconnect(self) -> None:
        """断开VPN连接（子类实现）"""
        raise NotImplementedError("子类必须实现 _do_disconnect 方法")
    
    async def check_connection(self) -> bool:
        """检查VPN连接是否仍然活跃"""
        if not self.is_connected:
            return False
            
        try:
            result = await asyncio.create_subprocess_shell(
                f"ping -c 1 -W 2 {self.vpn_config.dns_servers[0]}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(result.communicate(), timeout=5)
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    async def get_network_info(self) -> Dict[str, Any]:
        """获取VPN网络信息"""
        info = {
            'status': self._vpn_status.value,
            'config': self.vpn_config.to_dict(),
            'connection': {}
        }
        
        if self._connection_info:
            info['connection'] = {
                'local_ip': self._connection_info.local_ip,
                'remote_ip': self._connection_info.remote_ip,
                'interface': self._connection_info.tunnel_interface,
                'dns': self._connection_info.dns_servers,
                'routes': self._connection_info.routes,
                'uptime': (
                    (datetime.now() - self._connection_info.connected_since).total_seconds()
                    if self._connection_info.connected_since else 0
                ),
                'bytes_sent': self._connection_info.bytes_sent,
                'bytes_received': self._connection_info.bytes_received
            }
        
        return info


class OpenVPNConnector(VPNConnector):
    """
    OpenVPN 连接器
    
    通过 openvpn 命令行工具或管理接口连接 OpenVPN 服务器。
    支持配置文件驱动和参数化连接方式。
    """
    
    connector_type = "openvpn"
    
    def __init__(self, config: VPNConfig = None, **kwargs):
        super().__init__(config=config, **kwargs)
        
        self.management_interface: Optional[str] = kwargs.get('management_interface')
        self._management_socket: Optional[socket.socket] = None
    
    async def _do_connect(self) -> ConnectionResult:
        """建立OpenVPN连接"""
        self._vpn_status = VPNStatus.CONNECTING
        
        try:
            if not self.vpn_config.config_file:
                return ConnectionResult(
                    success=False,
                    status=ConnectionStatus.ERROR,
                    message="未指定OpenVPN配置文件",
                    error=ValueError("Missing OpenVPN config file")
                )
            
            cmd = [
                'openvpn',
                '--config', self.vpn_config.config_file,
                '--daemon',  # 后台运行
                '--log', '/tmp/hos-ls-openvpn.log',
                '--verb', str(self.vpn_config.log_level),
                '--script-security', str(self.vpn_config.script_security),
                '--persist-tun',
                '--persist-key'
            ]
            
            if self.vpn_config.auth_file:
                cmd.extend(['--auth-user-pass', self.vpn_config.auth_file])
            
            if self.vpn_config.server_address:
                cmd.extend(['--remote', self.vpn_config.server_address])
                
            if self.vpn_config.server_port != 1194:
                cmd.extend(['--rport', str(self.vpn_config.server_port)])
            
            if self.vpn_config.protocol == 'tcp':
                cmd.append('--proto-tcp')
            
            console.print(f"[cyan]正在启动OpenVPN: {' '.join(cmd[:5])}...[/cyan]")
            
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.sleep(3)
            
            if self._process.returncode is not None:
                stderr = await self._process.stderr.read()
                return ConnectionResult(
                    success=False,
                    status=ConnectionStatus.ERROR,
                    message=f"OpenVPN启动失败: {stderr.decode()[:200]}",
                    error=RuntimeError("OpenVPN process exited")
                )
            
            await asyncio.wait_for(
                self._wait_for_connection(),
                timeout=self.vpn_config.timeout
            )
            
            connection_info = await self._extract_connection_info()
            self._connection_info = connection_info
            self._vpn_status = VPNStatus.CONNECTED
            
            return ConnectionResult(
                success=True,
                status=ConnectionStatus.CONNECTED,
                message=f"已成功连接到OpenVPN服务器 {self.vpn_config.server_address}",
                metadata={
                    'server': self.vpn_config.server_address,
                    'interface': connection_info.tunnel_interface,
                    'local_ip': connection_info.local_ip
                }
            )
            
        except asyncio.TimeoutError:
            self._terminate_process()
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=f"VPN连接超时 ({self.vpn_config.timeout}s)",
                error=TimeoutError("VPN connection timeout")
            )
        except Exception as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=str(e),
                error=e
            )
    
    async def _wait_for_connection(self):
        """等待VPN隧道建立"""
        max_attempts = 30
        attempt = 0
        
        while attempt < max_attempts:
            if await self._check_tunnel_exists():
                return True
                
            await asyncio.sleep(1)
            attempt += 1
            
        raise TimeoutError("VPN tunnel establishment timeout")
    
    async def _check_tunnel_exists(self) -> bool:
        """检查VPN隧道接口是否存在"""
        try:
            process = await asyncio.create_subprocess_shell(
                "ip link show type tun | grep -q 'tun'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.wait()
            return process.returncode == 0
            
        except Exception:
            return False
    
    async def _extract_connection_info(self) -> VPNConnectionInfo:
        """提取VPN连接信息"""
        info = VPNConnectionInfo()
        info.connected_since = datetime.now()
        
        try:
            process = await asyncio.create_subprocess_shell(
                "ip addr show tun0 | grep inet | awk '{print $2}' | cut -d/ -f1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            if stdout.strip():
                info.local_ip = stdout.decode().strip()
                info.tunnel_interface = "tun0"
            
            process = await asyncio.create_subprocess_shell(
                "ip route show dev tun0 | grep default | awk '{print $3}'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            if stdout.strip():
                info.remote_ip = stdout.decode().strip()
                
        except Exception as e:
            console.print(f"[yellow]警告: 无法提取VPN信息: {e}[/yellow]")
        
        return info
    
    async def _do_disconnect(self) -> None:
        """断开OpenVPN连接"""
        self._terminate_process()
        self._vpn_status = VPNStatus.DISCONNECTED
        self._connection_info = None
        
        console.print("[dim]OpenVPN连接已关闭[/dim]")
    
    def _terminate_process(self):
        """终止OpenVPN进程"""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            finally:
                self._process = None


class WireGuardConnector(VPNConnector):
    """
    WireGuard VPN 连接器
    
    现代高性能VPN协议，内核空间实现。
    配置简单，性能优异。
    """
    
    connector_type = "wireguard"
    
    def __init__(self, config: VPNConfig = None, **kwargs):
        super().__init__(config=config, **kwargs)
        self.interface_name = kwargs.get('interface_name', 'wg0')
    
    async def _do_connect(self) -> ConnectionResult:
        """建立WireGuard连接"""
        self._vpn_status = VPNStatus.CONNECTING
        
        try:
            if not self.vpn_config.config_file:
                return ConnectionResult(
                    success=False,
                    status=ConnectionStatus.ERROR,
                    message="未指定WireGuard配置文件 (.conf)"
                )
            
            console.print(f"[cyan]正在启动WireGuard ({self.interface_name})...[/cyan]")
            
            up_cmd = f'wg-quick up {self.vpn_config.config_file}'
            
            process = await asyncio.create_subprocess_shell(
                up_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            _, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.vpn_config.timeout
            )
            
            if process.returncode != 0:
                return ConnectionResult(
                    success=False,
                    status=ConnectionStatus.ERROR,
                    message=f"WireGuard启动失败: {stderr.decode()[:200]}"
                )
            
            connection_info = await self._extract_wg_info()
            self._connection_info = connection_info
            self._vpn_status = VPNStatus.CONNECTED
            
            return ConnectionResult(
                success=True,
                status=ConnectionStatus.CONNECTED,
                message=f"已成功连接到WireGuard VPN ({self.interface_name})",
                metadata={
                    'interface': self.interface_name,
                    'local_ip': connection_info.local_ip
                }
            )
            
        except asyncio.TimeoutError:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message="WireGuard连接超时"
            )
        except Exception as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=str(e),
                error=e
            )
    
    async def _extract_wg_info(self) -> VPNConnectionInfo:
        """提取WireGuard连接信息"""
        info = VPNConnectionInfo()
        info.connected_since = datetime.now()
        info.tunnel_interface = self.interface_name
        
        try:
            show_cmd = f'wg show {self.interface_name}'
            process = await asyncio.create_subprocess_shell(
                show_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            output = stdout.decode()
            
            for line in output.split('\n'):
                if 'allowed ips' in line.lower():
                    parts = line.split()
                    for part in parts:
                        if '/' in part and part != 'allowed':
                            ip = part.split('/')[0]
                            if '.' in ip:
                                info.local_ip = ip
                            break
                            
        except Exception as e:
            console.print(f"[yellow]警告: 无法获取WireGuard信息: {e}[/yellow]")
        
        return info
    
    async def _do_disconnect(self) -> None:
        """断开WireGuard连接"""
        try:
            down_cmd = f'wg-quick down {self.interface_name}'
            await asyncio.create_subprocess_shell(down_cmd)
        except Exception as e:
            console.print(f"[yellow]关闭WireGuard时出错: {e}[/yellow]")
        
        self._vpn_status = VPNStatus.DISCONNECTED
        self._connection_info = None


class IPSecConnector(VPNConnector):
    """
    IPSec VPN 连接器
    
    支持 StrongSwan/Libreswan 的IKEv2/IPSec连接。
    企业级VPN标准协议。
    """
    
    connector_type = "ipsec"
    
    def __init__(self, config: VPNConfig = None, **kwargs):
        super().__init__(config=config, **kwargs)
        self.connection_name = kwargs.get('connection_name', 'hos-ls-vpn')
    
    async def _do_connect(self) -> ConnectionResult:
        """建立IPSec连接"""
        self._vpn_status = VPNStatus.CONNECTING
        
        try:
            console.print("[cyan]正在启动IPSec VPN...[/cyan]")
            
            up_cmd = f'ipsec up {self.connection_name}'
            
            process = await asyncio.create_subprocess_shell(
                up_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            _, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.vpn_config.timeout
            )
            
            if process.returncode != 0:
                return ConnectionResult(
                    success=False,
                    status=ConnectionStatus.ERROR,
                    message=f"IPSec连接失败: {stderr.decode()[:200]}"
                )
            
            self._vpn_status = VPNStatus.CONNECTED
            self._connection_info = VPNConnectionInfo(
                connected_since=datetime.now(),
                tunnel_interface="ipsec0"
            )
            
            return ConnectionResult(
                success=True,
                status=ConnectionStatus.CONNECTED,
                message=f"已成功连接到IPSec VPN ({self.connection_name})"
            )
            
        except asyncio.TimeoutError:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message="IPSec连接超时"
            )
        except Exception as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=str(e),
                error=e
            )
    
    async def _do_disconnect(self) -> None:
        """断开IPSec连接"""
        try:
            down_cmd = f'ipsec down {self.connection_name}'
            await asyncio.create_subprocess_shell(down_cmd)
        except Exception as e:
            console.print(f"[yellow]关闭IPSec时出错: {e}[/yellow]")
        
        self._vpn_status = VPNStatus.DISCONNECTED
        self._connection_info = None


def create_vpn_connector(vpn_type: str, config: VPNConfig = None, **kwargs) -> VPNConnector:
    """
    工厂函数：创建适当类型的VPN连接器
    
    Args:
        vpn_type: VPN类型 (openvpn, wireguard, ipsec)
        config: VPN配置
        **kwargs: 额外参数
        
    Returns:
        VPN连接器实例
    """
    vpn_type = vpn_type.lower().strip()
    
    if vpn_type == 'openvpn':
        return OpenVPNConnector(config=config, **kwargs)
    elif vpn_type == 'wireguard':
        return WireGuardConnector(config=config, **kwargs)
    elif vpn_type in ('ipsec', 'ikev2', 'strongswan'):
        return IPSecConnector(config=config, **kwargs)
    else:
        raise ValueError(f"不支持的VPN类型: {vpn_type}. 支持: openvpn, wireguard, ipsec")


async def test_vpn_connectivity(vpn_connector: VPNConnector) -> bool:
    """
    测试VPN连接的可用性
    
    Args:
        vpn_connector: VPN连接器实例
        
    Returns:
        是否可正常通信
    """
    if not vpn_connector.is_connected:
        return False
        
    try:
        result = await vpn_connector.check_connection()
        return result
    except Exception:
        return False
