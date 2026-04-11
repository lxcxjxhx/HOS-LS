"""
代理与跳板机模块

支持复杂的网络访问场景：
- SSH隧道（端口转发）
- SOCKS5代理链
- 跳板机（Jump Host）多跳连接
- HTTP/HTTPS代理
"""

import asyncio
import socket
import subprocess
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from rich.console import Console

console = Console()


class ProxyType(Enum):
    """代理类型枚举"""
    SSH_TUNNEL = "ssh_tunnel"
    SOCKS5 = "socks5"
    HTTP_PROXY = "http"
    HTTPS_PROXY = "https"
    JUMP_HOST = "jump_host"


@dataclass
class ProxyConfig:
    """代理配置数据类"""
    proxy_type: ProxyType
    host: str
    port: int = None
    username: str = None
    password: str = None
    key_file: str = None  # SSH密钥文件
    local_port: int = None  # 本地监听端口
    remote_host: str = None  # 远程目标主机
    remote_port: int = None  # 远程目标端口
    bind_address: str = "127.0.0.1"  # 绑定地址
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.proxy_type.value,
            'host': self.host,
            'port': self.port,
            'has_auth': bool(self.username and self.password)
        }


@dataclass
class ProxyTunnelInfo:
    """代理隧道信息"""
    local_address: str = ""
    local_port: int = 0
    remote_address: str = ""
    remote_port: int = 0
    established_at: Optional[datetime] = None
    bytes_transferred: int = 0


class SSHTunnel:
    """
    SSH隧道管理器
    
    通过SSH建立本地端口转发，用于访问内网资源。
    支持本地转发（Local Forward）和远程转发（Remote Forward）。
    
    使用场景：
    - 访问内网数据库：local -> jump host -> internal-db:3306
    - 访问内网Web服务：local -> jump host -> internal-web:8080
    """
    
    def __init__(
        self,
        ssh_host: str,
        ssh_port: int = 22,
        username: str = None,
        password: str = None,
        key_file: str = None,
        **kwargs
    ):
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.username = username
        self.password = password
        self.key_file = key_file
        
        self._ssh_conn: Optional[Any] = None
        self._tunnels: Dict[int, ProxyTunnelInfo] = {}
        
        if not ASYNCSSH_AVAILABLE:
            raise ImportError("请安装 asyncssh 库: pip install asyncssh")
    
    async def connect(self) -> bool:
        """建立SSH连接到跳板机"""
        try:
            connect_kwargs = {
                'host': self.ssh_host,
                'port': self.ssh_port,
                'known_hosts': None
            }
            
            if self.username:
                connect_kwargs['username'] = self.username
            
            if self.password:
                connect_kwargs['password'] = self.password
            elif self.key_file:
                connect_kwargs['client_keys'] = self.key_file
                
            self._ssh_conn = await asyncssh.connect(**connect_kwargs)
            
            console.print(
                f"[green]✓ 已连接到SSH跳板机: "
                f"{self.username}@{self.ssh_host}:{self.ssh_port}[/green]"
            )
            
            return True
            
        except Exception as e:
            console.print(f"[red]SSH连接失败: {e}[/red]")
            return False
    
    async def create_local_forward(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        bind_address: str = "127.0.0.1"
    ) -> ProxyTunnelInfo:
        """
        创建本地端口转发
        
        将本地端口映射到通过SSH隧道访问的远程主机端口。
        
        Args:
            local_port: 本地监听端口
            remote_host: 远程目标主机（相对于跳板机）
            remote_port: 远程目标端口
            bind_address: 绑定地址
            
        Returns:
            隧道信息
        """
        if not self._ssh_conn:
            raise RuntimeError("未连接到SSH跳板机")
        
        try:
            listener = await self._ssh_conn.forward_local(
                f'{bind_address}:{local_port}',
                remote_host,
                remote_port
            )
            
            tunnel_info = ProxyTunnelInfo(
                local_address=bind_address,
                local_port=local_port,
                remote_address=remote_host,
                remote_port=remote_port,
                established_at=datetime.now()
            )
            
            self._tunnels[local_port] = tunnel_info
            
            console.print(
                f"[green]✓ SSH隧道已建立: "
                f"{bind_address}:{local_port} -> {remote_host}:{remote_port}[/green]"
            )
            
            return tunnel_info
            
        except Exception as e:
            console.print(f"[red]创建隧道失败: {e}[/red]")
            raise
    
    async def create_dynamic_forward(
        self,
        local_port: int,
        bind_address: str = "127.0.0.1"
    ) -> ProxyTunnelInfo:
        """
        创建动态端口转发（SOCKS代理）
        
        创建一个SOCKS4/SOCKS5代理，所有通过此端口的流量都会经过SSH隧道。
        
        Args:
            local_port: 本地SOCKS代理端口
            bind_address: 绑定地址
            
        Returns:
            隧道信息
        """
        if not self._ssh_conn:
            raise RuntimeError("未连接到SSH跳板机")
        
        try:
            listener = await self._ssh_conn.forward_local(
                f'{bind_address}:{local_port}',
                socks=True  # 启用SOCKS代理
            )
            
            tunnel_info = ProxyTunnelInfo(
                local_address=bind_address,
                local_port=local_port,
                remote_address="SOCKS Proxy",
                remote_port=0,
                established_at=datetime.now()
            )
            
            self._tunnels[local_port] = tunnel_info
            
            console.print(
                f"[green]✓ SOCKS代理已建立: "
                f"socks5://{bind_address}:{local_port}[/green]"
            )
            
            return tunnel_info
            
        except Exception as e:
            console.print(f"[red]创建SOCKS代理失败: {e}[/red]")
            raise
    
    async def close_tunnel(self, local_port: int) -> bool:
        """关闭指定隧道"""
        if local_port in self._tunnels:
            del self._tunnels[local_port]
            console.print(f"[dim]隧道已关闭: 端口 {local_port}[/dim]")
            return True
        return False
    
    async def close_all(self):
        """关闭所有隧道并断开SSH连接"""
        self._tunnels.clear()
        
        if self._ssh_conn:
            self._ssh_conn.close()
            await self._ssh_conn.wait_closed()
            self._ssh_conn = None
            
        console.print("[dim]所有SSH隧道和连接已关闭[/dim]")
    
    @property
    def active_tunnels(self) -> List[ProxyTunnelInfo]:
        return list(self._tunnels.values())
    
    @property
    def is_connected(self) -> bool:
        return self._ssh_conn is not None


class SOCKS5Proxy:
    """
    SOCKS5代理客户端
    
    用于通过SOCKS5代理发送请求。
    支持HTTP/HTTPS和其他TCP流量。
    """
    
    def __init__(
        self,
        proxy_host: str,
        proxy_port: int,
        username: str = None,
        password: str = None,
        **kwargs
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        
        self._client: Optional[Any] = None
        
        if not HTTPX_AVAILABLE:
            raise ImportError("请安装 httpx 库: pip install httpx")
    
    async def create_client(self):
        """创建带SOCKS代理的HTTP客户端"""
        proxy_url = f"socks5://"
        
        if self.username and self.password:
            from urllib.parse import quote
            proxy_url += f"{quote(self.username)}:{quote(self.password)}@"
        
        proxy_url += f"{self.proxy_host}:{self.proxy_port}"
        
        self._client = httpx.AsyncClient(proxy=proxy_url)
        
        console.print(f"[green]✓ SOCKS5代理客户端已创建: {proxy_url}[/green]")
        
        return self._client
    
    async def fetch(self, url: str, **kwargs) -> Any:
        """通过代理获取URL内容"""
        if not self._client:
            await self.create_client()
        
        response = await self._client.get(url, **kwargs)
        return response
    
    async def close(self):
        """关闭代理客户端"""
        if self._client:
            await self._client.aclose()
            self._client = None


class JumpHostManager:
    """
    跳板机（Jump Host）管理器
    
    管理多跳SSH连接链：
    Local -> Jump Host 1 -> Jump Host 2 -> Target
    
    企业环境中常见的安全架构。
    """
    
    def __init__(self, chain_config: List[Dict[str, Any]] = None):
        """
        初始化跳板机管理器
        
        Args:
            chain_config: 跳板机配置链
                [
                    {'host': 'jump1.example.com', 'username': 'user1', ...},
                    {'host': 'jump2.internal', 'username': 'user2', ...},
                    ...
                ]
        """
        self.chain_config = chain_config or []
        self._connections: List[SSHTunnel] = []
        self._current_chain_index = 0
    
    async def establish_chain(self) -> bool:
        """建立完整的跳板机连接链"""
        for i, hop_config in enumerate(self.chain_config):
            console.print(f"\n[cyan]正在连接第 {i+1}/{len(self.chain_config)} 个跳板机...[/cyan]")
            
            tunnel = SSHTunnel(**hop_config)
            success = await tunnel.connect()
            
            if not success:
                console.print(f"[red]无法连接到跳板机 {hop_config.get('host')}[/red]")
                await self.close_all()
                return False
            
            self._connections.append(tunnel)
            self._current_chain_index = i + 1
        
        console.print(f"\n[bold green]✅ 成功建立包含 {len(self.chain_config)} 个跳板的连接链[/bold green]\n")
        return True
    
    async def create_final_hop(
        self,
        local_port: int,
        target_host: str,
        target_port: int
    ) -> ProxyTunnelInfo:
        """
        在最后一个跳板机上创建到最终目标的隧道
        
        Args:
            local_port: 本地端口
            target_host: 最终目标主机
            target_port: 最终目标端口
            
        Returns:
            隧道信息
        """
        if not self._connections:
            raise RuntimeError("未建立任何跳板机连接")
        
        last_jump = self._connections[-1]
        
        return await last_jump.create_local_forward(
            local_port=local_port,
            remote_host=target_host,
            remote_port=target_port
        )
    
    async def close_all(self):
        """关闭整个连接链"""
        for connection in reversed(self._connections):
            await connection.close_all()
        
        self._connections.clear()
        self._current_chain_index = 0
        
        console.print("[dim]跳板机连接链已完全关闭[/dim]")
    
    @property
    def is_connected(self) -> bool:
        return len(self._connections) > 0
    
    @property
    def chain_length(self) -> int:
        return len(self._connections)


class ProxyChain:
    """
    代理链管理器
    
    组合多种代理方式形成复杂访问路径：
    VPN + SSH Tunnel + SOCKS5 Proxy
    
    示例场景：
    1. 连接企业VPN
    2. 通过VPN访问跳板机
    3. 通过跳板机访问内网数据库
    """
    
    def __init__(self):
        self.vpn_connector: Optional[Any] = None
        self.jump_hosts: Optional[JumpHostManager] = None
        self.socks_proxies: List[SOCKS5Proxy] = []
        self.http_proxy: Optional[SOCKS5Proxy] = None
    
    async def add_vpn(self, vpn_type: str, config: Dict[str, Any]) -> bool:
        """添加VPN连接"""
        from .vpn_connector import VPNConfig, create_vpn_connector
        
        vpn_config = VPNConfig(**config)
        self.vpn_connector = create_vpn_connector(vpn_type, vpn_config)
        
        result = await self.vpn_connector.connect()
        return result.success
    
    async def add_jump_hosts(self, chain_config: List[Dict]) -> bool:
        """添加跳板机链"""
        self.jump_hosts = JumpHostManager(chain_config)
        return await self.jump_hosts.establish_chain()
    
    async def add_socks_proxy(self, host: str, port: int, **kwargs) -> SOCKS5Proxy:
        """添加SOCKS5代理"""
        proxy = SOCKS5Proxy(host, port, **kwargs)
        await proxy.create_client()
        self.socks_proxies.append(proxy)
        return proxy
    
    async def get_target_connection(
        self,
        target_host: str,
        target_port: int,
        local_port: int = None
    ) -> Dict[str, Any]:
        """
        获取到最终目标的完整连接信息
        
        返回可用于扫描的连接配置
        """
        connection_info = {
            'target_host': target_host,
            'target_port': target_port,
            'chain': [],
            'is_reachable': False
        }
        
        if self.vpn_connector and self.vpn_connector.is_connected:
            connection_info['chain'].append({
                'type': 'vpn',
                'info': self.vpn_connector.connection_info.to_dict() if self.vpn_connector.connection_info else {}
            })
        
        if self.jump_hosts and self.jump_hosts.is_connected:
            if local_port:
                tunnel = await self.jump_hosts.create_final_hop(
                    local_port=local_port,
                    target_host=target_host,
                    target_port=target_port
                )
                
                connection_info['chain'].append({
                    'type': 'ssh_jump',
                    'local_endpoint': f"127.0.0.1:{local_port}",
                    'tunnel_info': tunnel.to_dict() if hasattr(tunnel, 'to_dict') else {}
                })
                
                connection_info['proxy_url'] = f"http://127.0.0.1:{local_port}"
                connection_info['is_reachable'] = True
        
        if self.socks_proxies:
            for i, proxy in enumerate(self.socks_proxies):
                connection_info['chain'].append({
                    'type': f'socks5_proxy_{i}',
                    'endpoint': f"{proxy.proxy_host}:{proxy.proxy_port}"
                })
                
                if not connection_info.get('is_reachable'):
                    connection_info['proxy_url'] = (
                        f"socks5://{proxy.proxy_host}:{proxy.proxy_port}"
                    )
                    connection_info['is_reachable'] = True
        
        return connection_info
    
    async def teardown(self):
        """拆除整个代理链"""
        tasks = []
        
        for proxy in self.socks_proxies:
            tasks.append(proxy.close())
        
        if self.jump_hosts:
            tasks.append(self.jump_hosts.close_all())
        
        if self.vpn_connector:
            tasks.append(self.vpn_connector.disconnect())
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        console.print("[bold green]✅ 代理链已完全拆除[/bold green]")


async def create_simple_ssh_tunnel(
    jump_host: str,
    username: str,
    password: str = None,
    target_host: str = None,
    target_port: int = 22,
    local_port: int = 2222
) -> SSHTunnel:
    """
    快速创建简单SSH隧道
    
    Args:
        jump_host: 跳板机地址
        username: 用户名
        password: 密码
        target_host: 目标主机（可选）
        target_port: 目标端口
        local_port: 本地映射端口
        
    Returns:
        SSH隧道实例
    """
    tunnel = SSHTunnel(
        ssh_host=jump_host,
        username=username,
        password=password
    )
    
    await tunnel.connect()
    
    if target_host:
        await tunnel.create_local_forward(
            local_port=local_port,
            remote_host=target_host,
            remote_port=target_port
        )
    
    return tunnel


def parse_proxy_chain_config(config_file: str) -> Dict[str, Any]:
    """
    解析代理链配置文件
    
    配置文件示例 (YAML):
    ```yaml
    vpn:
      type: openvpn
      config_file: /path/to/client.ovpn
      
    jump_hosts:
      - host: bastion.company.com
        username: deploy
        key_file: ~/.ssh/id_rsa
      - host: db-master.internal
        username: dbadmin
        
    proxies:
      - type: socks5
        host: 127.0.0.1
        port: 1080
      - type: http
        host: proxy.company.com
        port: 8080
    ```
    """
    import yaml
    
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    return config or {}


async def test_connectivity_via_chain(
    target_host: str,
    target_port: int,
    chain: ProxyChain,
    timeout: int = 10
) -> bool:
    """
    测试通过代理链的连通性
    
    Args:
        target_host: 目标主机
        target_port: 目标端口
        chain: 代理链实例
        timeout: 超时时间
        
    Returns:
        是否可连通
    """
    conn_info = await chain.get_target_connection(target_host, target_port)
    
    if not conn_info.get('is_reachable'):
        return False
    
    proxy_url = conn_info.get('proxy_url')
    
    if proxy_url:
        try:
            client = httpx.AsyncClient(proxy=proxy_url, timeout=timeout)
            
            if target_port in [80, 443, 8080, 3000, 5000, 8000, 9000]:
                url = f"{'https' if target_port == 443 else 'http'}://{target_host}:{target_port}"
            else:
                url = f"http://{target_host}:{target_port}"
            
            response = await client.get(url)
            success = response.status_code < 500
            
            await client.aclose()
            
            return success
            
        except Exception:
            return False
    
    return False
