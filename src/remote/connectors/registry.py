"""
连接器注册表

提供插件式的连接器管理，支持动态注册和发现。
"""

import importlib
from typing import Dict, Type, Optional, List, Any
from dataclasses import dataclass

from .base_connector import BaseConnector, ConnectionConfig

@dataclass
class ConnectorInfo:
    """连接器信息"""
    name: str
    connector_class: Type[BaseConnector]
    description: str = ""
    supported_protocols: List[str] = None
    config_schema: Dict[str, Any] = None
    version: str = "1.0.0"
    
    def __post_init__(self):
        if self.supported_protocols is None:
            self.supported_protocols = []
        if self.config_schema is None:
            self.config_schema = {}


class ConnectorRegistry:
    """
    连接器注册表（单例模式）
    
    管理所有可用的连接器，支持：
    - 动态注册新连接器
    - 按协议/类型查找连接器
    - 自动发现内置连接器
    """
    
    _instance: Optional['ConnectorRegistry'] = None
    _connectors: Dict[str, ConnectorInfo] = {}
    _protocol_map: Dict[str, str] = {}  # protocol -> connector_name
    
    def __new__(cls) -> 'ConnectorRegistry':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """初始化注册表"""
        self._connectors = {}
        self._protocol_map = {}
        
    def register(
        self,
        name: str,
        connector_class: Type[BaseConnector],
        description: str = "",
        supported_protocols: List[str] = None,
        config_schema: Dict[str, Any] = None,
        version: str = "1.0.0",
        overwrite: bool = False
    ) -> None:
        """
        注册连接器
        
        Args:
            name: 连接器名称（唯一标识）
            connector_class: 连接器类
            description: 描述信息
            supported_protocols: 支持的协议列表
            config_schema: 配置模式（用于验证配置）
            version: 版本号
            overwrite: 是否覆盖已存在的连接器
        """
        if not overwrite and name in self._connectors:
            raise ValueError(f"连接器 '{name}' 已存在")
            
        info = ConnectorInfo(
            name=name,
            connector_class=connector_class,
            description=description,
            supported_protocols=supported_protocols or [],
            config_schema=config_schema or {},
            version=version
        )
        
        self._connectors[name] = info
        
        for protocol in info.supported_protocols:
            self._protocol_map[protocol.lower()] = name
            
    def unregister(self, name: str) -> bool:
        """
        注销连接器
        
        Args:
            name: 连接器名称
            
        Returns:
            是否成功注销
        """
        if name in self._connectors:
            info = self._connectors.pop(name)
            
            for protocol in info.supported_protocols:
                if self._protocol_map.get(protocol) == name:
                    del self._protocol_map[protocol]
                    
            return True
            
        return False
    
    def get(self, name: str) -> Optional[ConnectorInfo]:
        """
        获取连接器信息
        
        Args:
            name: 连接器名称或协议名
            
        Returns:
            连接器信息，如果不存在则返回None
        """
        if name in self._connectors:
            return self._connectors[name]
            
        if name.lower() in self._protocol_map:
            connector_name = self._protocol_map[name.lower()]
            return self._connectors.get(connector_name)
            
        return None
    
    def get_connector_class(self, name: str) -> Optional[Type[BaseConnector]]:
        """
        获取连接器类
        
        Args:
            name: 连接器名称或协议名
            
        Returns:
            连接器类
        """
        info = self.get(name)
        return info.connector_class if info else None
    
    def create_connector(
        self, 
        name: str, 
        config: ConnectionConfig = None,
        **kwargs
    ) -> BaseConnector:
        """
        创建连接器实例
        
        Args:
            name: 连接器名称或协议名
            config: 连接配置
            **kwargs: 额外参数
            
        Returns:
            连接器实例
            
        Raises:
            ValueError: 连接器不存在
        """
        connector_class = self.get_connector_class(name)
        
        if not connector_class:
            raise ValueError(f"未找到连接器: {name}")
            
        return connector_class(config=config, **kwargs)
    
    def list_connectors(self) -> List[ConnectorInfo]:
        """
        列出所有已注册的连接器
        
        Returns:
            连接器信息列表
        """
        return list(self._connectors.values())
    
    def list_by_protocol(self, protocol: str) -> List[ConnectorInfo]:
        """
        按协议列出支持该协议的所有连接器
        
        Args:
            protocol: 协议名称
            
        Returns:
            支持该协议的连接器列表
        """
        results = []
        for info in self._connectors.values():
            if protocol.lower() in [p.lower() for p in info.supported_protocols]:
                results.append(info)
                
        return results
    
    def find_by_uri(self, uri: str) -> Optional[ConnectorInfo]:
        """
        根据URI自动查找合适的连接器
        
        Args:
            uri: 目标URI
            
        Returns:
            匹配的连接器信息
        """
        uri_lower = uri.lower().strip()
        
        if uri_lower.startswith(('ssh://', 'sftp://')):
            return self.get('ssh')
        elif uri_lower.startswith(('https://', 'http://')):
            return self.get('http')
        elif uri_lower.startswith('serial://'):
            return self.get('serial')
        elif uri_lower.startswith('direct://'):
            return self.get('direct')
        elif uri_lower.startswith(('file:///', './', '/', '.')):
            return self.get('local')
            
        return None
    
    def discover_builtin_connectors(self) -> int:
        """
        自动发现并注册内置连接器
        
        Returns:
            注册的连接器数量
        """
        builtin_connectors = [
            {
                'module': 'src.remote.connectors.ssh_connector',
                'class': 'SSHConnector',
                'name': 'ssh',
                'protocols': ['ssh', 'sftp'],
                'description': 'SSH/SFTP 远程服务器连接器'
            },
            {
                'module': 'src.remote.connectors.http_connector',
                'class': 'HTTPConnector',
                'name': 'http',
                'protocols': ['http', 'https'],
                'description': 'HTTP/HTTPS 网站连接器'
            },
            {
                'module': 'src.remote.connectors.serial_connector',
                'class': 'SerialConnector',
                'name': 'serial',
                'protocols': ['serial'],
                'description': '串口设备连接器'
            },
            {
                'module': 'src.remote.connectors.direct_connector',
                'class': 'DirectEthernetConnector',
                'name': 'direct',
                'protocols': ['direct-ethernet', 'raw'],
                'description': '网线直连连接器'
            }
        ]
        
        registered_count = 0
        
        for conn_info in builtin_connectors:
            try:
                module = importlib.import_module(conn_info['module'])
                connector_class = getattr(module, conn_info['class'])
                
                self.register(
                    name=conn_info['name'],
                    connector_class=connector_class,
                    description=conn_info['description'],
                    supported_protocols=conn_info['protocols']
                )
                
                registered_count += 1
                
            except ImportError as e:
                from rich.console import Console
                console = Console()
                console.print(
                    f"[yellow]警告: 无法加载连接器 {conn_info['name']}: "
                    f"{e}[/yellow]"
                )
            except Exception as e:
                from rich.console import Console
                console = Console()
                console.print(
                    f"[yellow]警告: 注册连接器 {conn_info['name']} 失败: "
                    f"{e}[/yellow]"
                )
                
        return registered_count
    
    def get_stats(self) -> Dict[str, Any]:
        """获取注册表统计信息"""
        return {
            'total_connectors': len(self._connectors),
            'supported_protocols': len(self._protocol_map),
            'connector_names': list(self._connectors.keys()),
            'protocols': list(self._protocol_map.keys())
        }
    
    def clear(self) -> None:
        """清空所有注册的连接器"""
        self._connectors.clear()
        self._protocol_map.clear()
    
    def __len__(self) -> int:
        return len(self._connectors)
    
    def __contains__(self, name: str) -> bool:
        return name in self._connectors or name.lower() in self._protocol_map


def get_registry() -> ConnectorRegistry:
    """
    获取全局连接器注册表实例
    
    Returns:
        连接器注册表单例
    """
    registry = ConnectorRegistry()
    
    if len(registry) == 0:
        registry.discover_builtin_connectors()
        
    return registry
