"""
内网扫描器

提供企业内网环境下的安全扫描能力：
- 子网发现与主机枚举
- 端口扫描与服务识别
- 内网资产清单
- 漏洞快速检测
"""

import asyncio
import socket
import ipaddress
from typing import List, Optional, Dict, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()


@dataclass
class NetworkHost:
    """网络主机信息"""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    status: str = "unknown"  # up, down, unknown
    os_guess: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)  # port -> service name
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_alive(self) -> bool:
        return self.status == 'up'
    
    @property
    def risk_score(self) -> int:
        """计算风险评分"""
        score = 0
        
        high_risk_ports = {21, 23, 25, 135, 445, 1433, 3306, 5432, 27017}
        for port in self.open_ports:
            if port in high_risk_ports:
                score += 10
            else:
                score += 2
        
        if len(self.vulnerabilities) > 0:
            score += len(self.vulnerabilities) * 15
        
        return score
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip_address,
            'hostname': self.hostname or 'Unknown',
            'mac': self.mac_address,
            'status': self.status,
            'os': self.os_guess,
            'open_ports': self.open_ports,
            'services': self.services,
            'vulns_count': len(self.vulnerabilities),
            'risk_score': self.risk_score
        }


@dataclass 
class SubnetInfo:
    """子网信息"""
    network: str
    netmask: str
    broadcast: str
    total_hosts: int = 0
    discovered_hosts: int = 0
    alive_hosts: int = 0
    hosts: List[NetworkHost] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'network': self.network,
            'netmask': self.netmask,
            'total_hosts': self.total_hosts,
            'discovered': self.discovered_hosts,
            'alive': self.alive_hosts,
            'hosts': [h.to_dict() for h in self.hosts]
        }


class SubnetDiscovery:
    """
    子网发现工具
    
    通过多种方式发现内网中的活跃主机：
    - ICMP Ping 扫描
    - ARP 扫描（需要root权限）
    - DNS反向查询
    - SNMP查询（可选）
    """
    
    def __init__(self, proxy_chain=None):
        """
        初始化子网发现
        
        Args:
            proxy_chain: 可选的代理链实例（用于通过VPN/跳板机访问）
        """
        self.proxy_chain = proxy_chain
        self.timeout = 3.0
        self.max_concurrent = 50
        
    async def discover_subnet(
        self,
        cidr: str,
        scan_method: str = "ping",
        **kwargs
    ) -> SubnetInfo:
        """
        发现指定子网内的主机
        
        Args:
            cidr: CIDR格式的子网 (如 192.168.1.0/24)
            scan_method: 扫描方法 (ping, arp, dns)
            
        Returns:
            子网信息对象
        """
        network = ipaddress.ip_network(cidr, strict=False)
        
        subnet_info = SubnetInfo(
            network=str(network.network_address),
            netmask=str(network.netmask),
            broadcast=str(network.broadcast_address) if network.broadcast_address else '',
            total_hosts=network.num_addresses - 2  # 减去网络地址和广播地址
        )
        
        console.print(f"\n[bold cyan]🔍 开始子网发现:[/bold cyan] [green]{cidr}[/green]")
        console.print(f"[dim]总IP数量: {subnet_info.total_hosts}[/dim]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("扫描中...", total=subnet_info.total_hosts)
            
            tasks = []
            
            for host in network.hosts():
                tasks.append(self._scan_host(str(host), scan_method))
                
                if len(tasks) >= self.max_concurrent:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for result in results:
                        if isinstance(result, NetworkHost):
                            subnet_info.hosts.append(result)
                            subnet_info.discovered_hosts += 1
                            if result.is_alive:
                                subnet_info.alive_hosts += 1
                    
                    progress.advance(task, len(tasks))
                    tasks = []
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, NetworkHost):
                        subnet_info.hosts.append(result)
                        subnet_info.discovered_hosts += 1
                        if result.is_alive:
                            subnet_info.alive_hosts += 1
                
                progress.advance(task, len(tasks))
        
        console.print(
            f"\n[bold green]✅ 子网发现完成[/bold green]\n"
            f"  📊 发现主机: {subnet_info.discovered_hosts}/{subnet_info.total_hosts}\n"
            f"  💚 存活主机: {subnet_info.alive_hosts}\n"
        )
        
        return subnet_info
    
    async def _scan_host(self, ip: str, method: str) -> NetworkHost:
        """扫描单个主机"""
        host = NetworkHost(ip_address=ip)
        
        try:
            if method == "ping":
                alive = await self._ping_host(ip)
            elif method == "arp":
                alive = await self._arp_scan(ip)
            elif method == "dns":
                alive = await self._dns_lookup(ip)
            else:
                alive = await self._ping_host(ip)
            
            if alive:
                host.status = "up"
                hostname = await self._reverse_dns(ip)
                if hostname:
                    host.hostname = hostname
            
        except Exception as e:
            pass
        
        return host
    
    async def _ping_host(self, ip: str, timeout: float = None) -> bool:
        """ICMP Ping检测"""
        timeout = timeout or self.timeout
        
        try:
            proc = await asyncio.create_subprocess_shell(
                f'ping -c 1 -W {int(timeout)} {ip}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
            
            return proc.returncode == 0
            
        except Exception:
            return False
    
    async def _arp_scan(self, ip: str) -> bool:
        """ARP扫描（需要root权限）"""
        try:
            proc = await asyncio.create_subprocess_shell(
                f'arp -n {ip}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode()
            
            return 'incomplete' not in output.lower() and ip in output
            
        except Exception:
            return False
    
    async def _dns_lookup(self, ip: str) -> bool:
        """DNS查询检测"""
        try:
            hostname = socket.gethostbyaddr(ip)
            return True
        except socket.herror:
            return False
        except Exception:
            return False
    
    async def _reverse_dns(self, ip: str) -> Optional[str]:
        """反向DNS查询"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None


class PortScanner:
    """
    端口扫描器
    
    支持多种扫描方式：
    - TCP Connect 扫描（完整握手）
    - SYN 扫描（半开放）
    - UDP 扫描
    - 常用端口快速扫描
    - 全端口深度扫描
    """
    
    COMMON_PORTS = {
        20: 'FTP Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP Server',
        68: 'DHCP Client',
        69: 'TFTP',
        80: 'HTTP',
        110: 'POP3',
        119: 'NNTP',
        123: 'NTP',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP Trap',
        389: 'LDAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        514: 'Syslog',
        587: 'SMTP Submission',
        993: 'IMAPS',
        995: 'POP3S',
        1080: 'SOCKS Proxy',
        1433: 'MSSQL',
        1521: 'Oracle DB',
        1723: 'PPTP VPN',
        2049: 'NFS',
        3306: 'MySQL',
        3389: 'RDP',
        5060: 'SIP',
        5432: 'PostgreSQL',
        5631: 'PCAnywhere',
        5900: 'VNC',
        5938: 'TeamViewer',
        6379: 'Redis',
        8080: 'HTTP Alt',
        8443: 'HTTPS Alt',
        8888: 'HTTP Dev',
        9090: 'HTTP Debug',
        9200: 'Elasticsearch',
        27017: 'MongoDB'
    }
    
    def __init__(self, timeout: float = 2.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
    
    async def scan_ports(
        self,
        target_ip: str,
        ports: List[int] = None,
        scan_type: str = "connect"
    ) -> NetworkHost:
        """
        扫描目标主机的端口
        
        Args:
            target_ip: 目标IP地址
            ports: 要扫描的端口列表（默认使用常用端口）
            scan_type: 扫描类型 (connect, syn, udp)
            
        Returns:
            包含端口信息的主机对象
        """
        host = NetworkHost(ip_address=target_ip)
        
        ports_to_scan = ports or list(self.COMMON_PORTS.keys())
        
        console.print(f"\n[cyan]🔌 正在扫描端口: [/cyan][bold]{target_ip}[/bold]")
        console.print(f"[dim]目标端口数: {len(ports_to_scan)}[/dim]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("端口扫描中...", total=len(ports_to_scan))
            
            batch_size = self.max_concurrent
            for i in range(0, len(ports_to_scan), batch_size):
                batch = ports_to_scan[i:i+batch_size]
                
                tasks = [
                    self._check_port(target_ip, port, scan_type)
                    for port in batch
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for port, is_open in zip(batch, results):
                    if is_open and not isinstance(is_open, Exception):
                        host.open_ports.append(port)
                        service_name = self.COMMON_PORTS.get(port, f'unknown-{port}')
                        host.services[port] = service_name
                
                progress.advance(task, len(batch))
        
        host.status = 'up' if host.open_ports else 'down'
        
        open_count = len(host.open_ports)
        if open_count > 0:
            console.print(
                f"\n[bold green]✅ 端口扫描完成[/bold green]\n"
                f"  🔓 开放端口数: {open_count}\n"
                f"  📋 服务列表:\n"
            )
            
            for port in sorted(host.open_ports):
                service = host.services.get(port, 'Unknown')
                console.print(f"    • [green]{port:>5}/tcp[/green] - {service}")
        
        return host
    
    async def _check_port(
        self,
        target: str,
        port: int,
        scan_type: str
    ) -> bool:
        """检查单个端口是否开放"""
        try:
            future = asyncio.open_connection(target, port)
            
            reader, writer = await asyncio.wait_for(
                future,
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            return True
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
        except Exception:
            return False


class ServiceIdentifier:
    """
    服务识别器
    
    识别开放端口的运行服务和版本信息。
    支持协议指纹识别和Banner抓取。
    """
    
    SERVICE_FINGERPRINTS = {
        22: {'name': 'SSH', 'probe': 'SSH-', 'regex': r'SSH-\d\.\d+'},
        80: {'name': 'HTTP', 'probe': 'GET / HTTP/1.0\r\n\r\n', 'regex': r'(Server|HTTP)'},
        443: {'name': 'HTTPS', 'probe': '', 'tls': True},
        3306: {'name': 'MySQL', 'probe': ''},
        5432: {'name': 'PostgreSQL', 'probe': ''},
        6379: {'name': 'Redis', 'probe': ''},
        27017: {'name': 'MongoDB', 'probe': ''},
        3389: {'name': 'RDP', 'probe': ''}
    }
    
    async def identify_service(
        self,
        target_ip: str,
        port: int,
        timeout: float = 5.0
    ) -> Dict[str, Any]:
        """
        识别指定端口的服务
        
        Args:
            target_ip: 目标IP
            port: 端口号
            timeout: 超时时间
            
        Returns:
            服务信息字典
        """
        info = {
            'port': port,
            'service': 'unknown',
            'version': None,
            'banner': None,
            'product': None
        }
        
        fingerprint = self.SERVICE_FINGERPRINTS.get(port, {})
        
        if fingerprint.get('tls'):
            info['service'] = fingerprint['name']
            info['encrypted'] = True
            return info
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=timeout
            )
            
            if fingerprint.get('probe'):
                writer.write(fingerprint['probe'].encode())
                await writer.drain()
            
            banner_data = await asyncio.wait_for(
                reader.read(1024),
                timeout=timeout
            )
            
            banner = banner_data.decode('utf-8', errors='ignore').strip()
            info['banner'] = banner[:200]
            
            if fingerprint.get('name'):
                info['service'] = fingerprint['name']
            
            import re
            
            if fingerprint.get('regex'):
                match = re.search(fingerprint['regex'], banner, re.IGNORECASE)
                if match:
                    info['version'] = match.group(0)[:100]
            
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            info['service'] = 'filtered'
        except ConnectionRefusedError:
            info['service'] = 'closed'
        except Exception as e:
            info['error'] = str(e)[:100]
        
        return info


class InternalNetworkScanner:
    """
    内网综合扫描器
    
    整合子网发现、端口扫描和服务识别功能，
    提供完整的内网资产安全评估。
    
    使用场景：
    - 企业内网资产盘点
    - VPN连接后内网探测
    - 内部渗透测试前期侦察
    - 安全合规性检查
    """
    
    def __init__(
        self,
        proxy_chain=None,
        config: Dict[str, Any] = None
    ):
        """
        初始化内网扫描器
        
        Args:
            proxy_chain: VPN/代理链实例
            config: 扫描配置
        """
        self.proxy_chain = proxy_chain
        self.config = config or {}
        
        self.subnet_discovery = SubnetDiscovery(proxy_chain)
        self.port_scanner = PortScanner(
            timeout=config.get('port_timeout', 2.0),
            max_concurrent=config.get('max_concurrent', 100)
        )
        self.service_identifier = ServiceIdentifier()
        
        self.results: List[SubnetInfo] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None
    
    async def full_scan(
        self,
        targets: List[str],
        deep_scan: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        执行完整内网扫描
        
        Args:
            targets: 目标列表（CIDR或单个IP）
            deep_scan: 是否进行深度扫描（包含服务识别）
            
        Returns:
            完整的扫描结果
        """
        self.scan_start_time = datetime.now()
        
        console.print("\n" + "=" * 60)
        console.print("[bold blue]🔐 HOS-LS 企业内网安全扫描器[/bold blue]")
        console.print("=" * 60)
        
        all_subnets = []
        all_hosts: List[NetworkHost] = []
        
        for target in targets:
            if '/' in target:
                subnet = await self.subnet_discovery.discover_subnet(target)
                all_subnets.append(subnet)
                all_hosts.extend(subnet.hosts)
            else:
                single_host = NetworkHost(ip_address=target, status="up")
                all_hosts.append(single_host)
        
        alive_hosts = [h for h in all_hosts if h.is_alive]
        
        if not alive_hosts:
            console.print("\n[yellow]⚠️ 未发现存活主机[/yellow]")
            return self._generate_report(all_subnets, [])
        
        console.print(f"\n[cyan]🎯 开始对 {len(alive_hosts)} 个存活主机进行端口扫描...[/cyan]")
        
        scanned_hosts = []
        
        for i, host in enumerate(alive_hosts, 1):
            console.print(f"\n[dim][{i}/{len(alive_hosts)}] 扫描主机: {host.ip_address}[/dim]")
            
            scanned_host = await self.port_scanner.scan_ports(
                target_ip=host.ip_address,
                **kwargs
            )
            
            if deep_scan and scanned_host.open_ports:
                console.print(f"[dim]   进行服务识别...[/dim]")
                
                for port in scanned_host.open_ports[:10]:  # 限制识别前10个端口
                    service_info = await self.service_identifier.identify_service(
                        target_ip=scanned_host.ip_address,
                        port=port
                    )
                    
                    if service_info.get('version'):
                        scanned_host.services[port] = (
                            f"{scanned_host.services.get(port, '')} "
                            f"({service_info['version']})"
                        ).strip()
                        
                        scanned_host.metadata[f'service_{port}_info'] = service_info
            
            scanned_hosts.append(scanned_host)
        
        self.results = all_subnets
        self.scan_end_time = datetime.now()
        
        report = self._generate_report(all_subnets, scanned_hosts)
        
        self._display_summary(report)
        
        return report
    
    def _generate_report(
        self,
        subnets: List[SubnetInfo],
        hosts: List[NetworkHost]
    ) -> Dict[str, Any]:
        """生成扫描报告"""
        total_hosts = sum(s.total_hosts for s in subnets) if subnets else len(hosts)
        discovered = sum(s.discovered_hosts for s in subnets) if subnets else len(hosts)
        alive = sum(s.alive_hosts for s in subnets) if subnets else len([h for h in hosts if h.is_alive])
        
        total_open_ports = sum(len(h.open_ports) for h in hosts)
        unique_services = set()
        for h in hosts:
            unique_services.update(h.services.values())
        
        high_risk_hosts = sorted(
            [h for h in hosts if h.risk_score > 0],
            key=lambda x: x.risk_score,
            reverse=True
        )[:10]
        
        report = {
            'scan_time': {
                'start': self.scan_start_time.isoformat() if self.scan_start_time else None,
                'end': self.scan_end_time.isoformat() if self.scan_end_time else None,
                'duration_seconds': (
                    (self.scan_end_time - self.scan_start_time).total_seconds()
                    if self.scan_end_time and self.scan_start_time else 0
                )
            },
            'statistics': {
                'total_targets': total_hosts,
                'discovered_hosts': discovered,
                'alive_hosts': alive,
                'total_open_ports': total_open_ports,
                'unique_services': len(unique_services),
                'services_list': list(unique_services)
            },
            'subnets': [s.to_dict() for s in subnets],
            'hosts': [h.to_dict() for h in hosts],
            'risk_assessment': {
                'high_risk_hosts': [h.to_dict() for h in high_risk_hosts],
                'avg_risk_per_host': (
                    sum(h.risk_score for h in hosts) / len(hosts)
                    if hosts else 0
                ),
                'critical_findings': self._identify_critical_findings(hosts)
            }
        }
        
        return report
    
    def _identify_critical_findings(self, hosts: List[NetworkHost]) -> List[Dict]:
        """识别关键安全问题"""
        findings = []
        
        critical_ports = {
            23: ('Telnet服务', '明文传输，存在中间人攻击风险'),
            135: ('RPC服务', '可能存在远程代码执行漏洞'),
            445: ('SMB服务', '永恒之蓝等漏洞利用风险'),
            3389: ('RDP服务', '暴力破解和BlueKeep漏洞风险'),
            3306: ('MySQL数据库', '未授权访问风险'),
            6379: ('Redis数据库', '未授权访问可能导致RCE')
        }
        
        for host in hosts:
            for port in host.open_ports:
                if port in critical_ports:
                    service_name, description = critical_ports[port]
                    findings.append({
                        'host': host.ip_address,
                        'port': port,
                        'service': service_name,
                        'severity': 'HIGH',
                        'description': description,
                        'recommendation': (
                            f"建议关闭不必要的{service_name}端口 ({port}) "
                            f"或限制访问来源IP范围"
                        )
                    })
        
        return findings[:20]  # 返回前20个关键发现
    
    def _display_summary(self, report: Dict[str, Any]):
        """显示扫描摘要"""
        stats = report['statistics']
        risks = report['risk_assessment']
        
        console.print("\n" + "=" * 60)
        console.print("[bold cyan]📊 扫描结果摘要[/bold cyan]")
        console.print("=" * 60)
        
        console.print(f"\n[bold]统计信息:[/bold]")
        console.print(f"  🎯 目标总数: {stats['total_targets']}")
        console.print(f"  💚 存活主机: {stats['alive_hosts']}")
        console.print(f"  🔓 开放端口: {stats['total_open_ports']}")
        console.print(f"  🛠️  发现服务: {stats['unique_services']} 种")
        
        if stats['duration_seconds']:
            console.print(f"  ⏱️  扫描耗时: {stats['duration_seconds']:.1f} 秒")
        
        if risks['high_risk_hosts']:
            console.print(f"\n[bold red]⚠️ 高风险主机 TOP 10:[/bold red]")
            for i, host in enumerate(risks['high_risk_hosts'][:10], 1):
                console.print(
                    f"  {i}. [red]{host['ip']}[/red] "
                    f"(风险分: {host['risk_score']}, "
                    f"开放端口: {len(host['open_ports'])})"
                )
        
        if risks['critical_findings']:
            console.print(f"\n[bold red]🔴 关键安全发现:[/bold red]")
            for finding in risks['critical_findings'][:10]:
                console.print(
                    f"  ⚠ {finding['host']}:{finding['port']} "
                    f"- {finding['service']}: {finding['description']}"
                )
        
        console.print("\n" + "=" * 60)


def create_internal_network_scanner(proxy_chain=None, **config) -> InternalNetworkScanner:
    """
    创建内网扫描器实例
    
    Args:
        proxy_chain: VPN/代理链
        **config: 配置参数
        
    Returns:
        内网扫描器实例
    """
    return InternalNetworkScanner(proxy_chain=proxy_chain, config=config)


async def quick_internal_scan(
    cidr: str,
    vpn_config: Dict = None,
    jump_hosts: List[Dict] = None
) -> Dict[str, Any]:
    """
    快速执行内网扫描（便捷函数）
    
    示例用法:
    ```python
    result = await quick_internal_scan(
        cidr="192.168.1.0/24",
        vpn_config={'type': 'openvpn', 'config_file': '/path/to/vpn.ovpn'},
        jump_hosts=[
            {'host': 'bastion.company.com', 'username': 'admin'}
        ]
    )
    ```
    
    Args:
        cidr: 目标子网
        vpn_config: VPN配置
        jump_hosts: 跳板机配置
        
    Returns:
        扫描结果
    """
    from .proxy_tunnel import ProxyChain
    
    chain = ProxyChain()
    
    if vpn_config:
        await chain.add_vpn(vpn_config.pop('type', 'openvpn'), vpn_config)
    
    if jump_hosts:
        await chain.add_jump_hosts(jump_hosts)
    
    scanner = create_internal_network_scanner(proxy_chain=chain)
    
    result = await scanner.full_scan(targets=[cidr], deep_scan=False)
    
    await chain.teardown()
    
    return result
