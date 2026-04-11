"""
目标抽象层

提供统一的扫描目标接口，支持本地文件、远程服务器、网站和物理设备。
"""

import os
import asyncio
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Any, AsyncIterator, Union
from dataclasses import dataclass, field
from datetime import datetime
import mimetypes

from rich.console import Console

console = Console()


@dataclass
class TargetInfo:
    """目标信息数据类"""
    
    target_type: str  # local, remote-server, website, direct-connect
    target_uri: str   # file:///path, ssh://user@host, https://example.com, serial:///dev/ttyUSB0
    credentials: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'target_type': self.target_type,
            'target_uri': self.target_uri,
            'credentials': self.credentials,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TargetInfo':
        """从字典创建"""
        return cls(
            target_type=data.get('target_type', 'local'),
            target_uri=data.get('target_uri', ''),
            credentials=data.get('credentials'),
            metadata=data.get('metadata', {})
        )


@dataclass
class FileInfo:
    """文件信息数据类（统一本地和远程）"""
    
    path: str           # 文件路径（本地绝对路径或远程相对路径）
    name: str           # 文件名
    size: int = 0       # 文件大小（字节）
    modified_time: Optional[datetime] = None  # 修改时间
    is_file: bool = True  # 是否为文件（False表示目录）
    is_symlink: bool = False  # 是否为符号链接
    mime_type: Optional[str] = None  # MIME类型
    language: Optional[str] = None  # 编程语言
    
    @property
    def extension(self) -> str:
        """获取文件扩展名"""
        _, ext = os.path.splitext(self.name)
        return ext.lower()
    
    def detect_language(self) -> Optional[str]:
        """检测编程语言"""
        ext_lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.hpp': 'cpp',
            '.go': 'go',
            '.rs': 'rust',
            '.rb': 'ruby',
            '.php': 'php',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.cs': 'csharp',
            '.html': 'html',
            '.htm': 'html',
            '.css': 'css',
            '.scss': 'css',
            '.less': 'css',
            '.json': 'json',
            '.xml': 'xml',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.md': 'markdown',
            '.sql': 'sql',
            '.sh': 'shell',
            '.bash': 'shell',
            '.bat': 'batch',
            '.ps1': 'powershell',
            '.dockerfile': 'dockerfile',
            '.tf': 'terraform',
            '.vue': 'vue',
            '.svelte': 'svelte'
        }
        
        lang = ext_lang_map.get(self.extension)
        if lang:
            self.language = lang
        return lang


class BaseTarget(ABC):
    """
    目标基类 - 统一接口
    
    所有扫描目标（本地、远程、网站、设备）都必须实现此接口。
    提供统一的文件访问、命令执行等功能。
    """
    
    def __init__(self, info: TargetInfo):
        """
        初始化目标
        
        Args:
            info: 目标信息
        """
        self.info = info
        self._connected = False
        self._connection_time: Optional[datetime] = None
        
    @abstractmethod
    async def connect(self) -> bool:
        """
        建立连接
        
        Returns:
            连接是否成功
        """
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """断开连接"""
        pass
    
    @abstractmethod
    async def list_files(
        self, 
        path: str = "/", 
        recursive: bool = False,
        **kwargs
    ) -> List[FileInfo]:
        """
        列出文件/目录
        
        Args:
            path: 路径
            recursive: 是否递归列出子目录
            
        Returns:
            文件信息列表
        """
        pass
    
    @abstractmethod
    async def read_file(self, path: str, **kwargs) -> str:
        """
        读取文件内容
        
        Args:
            path: 文件路径
            
        Returns:
            文件内容字符串
        """
        pass
    
    @abstractmethod
    async def get_file_info(self, path: str, **kwargs) -> FileInfo:
        """
        获取单个文件信息
        
        Args:
            path: 文件路径
            
        Returns:
            文件信息对象
        """
        pass
    
    @abstractmethod
    async def execute_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """
        执行命令（可选功能，某些目标可能不支持）
        
        Args:
            command: 要执行的命令
            
        Returns:
            执行结果字典，包含：
            - stdout: 标准输出
            - stderr: 标准错误
            - exit_code: 退出码
            - success: 是否成功
        """
        pass
    
    @property
    def is_connected(self) -> bool:
        """检查连接状态"""
        return self._connected
    
    @property
    def connection_duration(self) -> Optional[float]:
        """获取连接持续时间（秒）"""
        if self._connection_time:
            return (datetime.now() - self._connection_time).total_seconds()
        return None
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.disconnect()
        return False
    
    def validate_path(self, path: str) -> bool:
        """
        验证路径安全性
        
        防止路径遍历攻击等安全问题
        
        Args:
            path: 要验证的路径
            
        Returns:
            路径是否安全
        """
        if not path:
            return False
            
        dangerous_patterns = [
            '..',
            '/proc/',
            '/sys/',
            '/dev/',
            '~/.ssh/',
            '~/.gnupg/',
            '/etc/shadow',
            '/etc/passwd'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in path:
                console.print(f"[red][SECURITY] 检测到危险路径模式: {pattern}[/red]")
                return False
                
        return True


class LocalTarget(BaseTarget):
    """
    本地文件系统目标
    
    包装现有的本地文件扫描逻辑，提供统一的目标接口。
    """
    
    def __init__(self, base_path: Union[str, Path] = ".", **kwargs):
        """
        初始化本地目标
        
        Args:
            base_path: 基础路径（默认当前目录）
        """
        if isinstance(base_path, str):
            base_path = Path(base_path)
            
        self.base_path = base_path.resolve()
        
        info = TargetInfo(
            target_type='local',
            target_uri=f'file://{self.base_path}',
            metadata={
                'base_path': str(self.base_path),
                'absolute_path': str(self.base_path.absolute())
            }
        )
        
        super().__init__(info)
        
    async def connect(self) -> bool:
        """建立连接（验证路径是否存在且可访问）"""
        try:
            if not self.base_path.exists():
                console.print(f"[red]错误: 路径不存在: {self.base_path}[/red]")
                return False
                
            if not os.access(str(self.base_path), os.R_OK):
                console.print(f"[red]错误: 路径不可读: {self.base_path}[/red]")
                return False
                
            self._connected = True
            self._connection_time = datetime.now()
            
            if console:
                console.print(f"[green]✓ 本地目标已连接: {self.base_path}[/green]")
                
            return True
            
        except Exception as e:
            console.print(f"[red]连接失败: {e}[/red]")
            return False
    
    async def disconnect(self) -> None:
        """断开连接（本地目标无需特殊处理）"""
        self._connected = False
        if console:
            console.print("[dim]本地目标已断开[/dim]")
    
    async def list_files(
        self, 
        path: str = "/", 
        recursive: bool = True,
        exclude_patterns: List[str] = None,
        include_patterns: List[str] = None,
        **kwargs
    ) -> List[FileInfo]:
        """
        列出本地文件
        
        Args:
            path: 相对于 base_path 的路径
            recursive: 是否递归
            exclude_patterns: 排除模式（如 ['*.pyc', '__pycache__']）
            include_patterns: 包含模式（如 ['*.py', '*.js']）
            
        Returns:
            文件信息列表
        """
        files = []
        
        if path == "/":
            search_path = self.base_path
        else:
            search_path = self.base_path / path.lstrip('/')
            
        if not search_path.exists():
            return files
            
        default_exclude = [
            '*.pyc',
            '*.pyo',
            '__pycache__',
            '.git',
            '.svn',
            '.hg',
            'node_modules',
            '.venv',
            'venv',
            'dist',
            'build',
            '*.min.js',
            '*.min.css',
            '.DS_Store',
            'Thumbs.db'
        ]
        
        default_include = [
            '*.py', '*.js', '*.ts', '*.jsx', '*.tsx',
            '*.java', '*.cpp', '*.c', '*.h', '*.hpp',
            '*.go', '*.rs', '*.rb', '*.php', '*.swift',
            '*.kt', '*.cs', '*.html', '*.htm', '*.css',
            '*.scss', '*.json', '*.xml', '*.yaml', '*.yml',
            '*.md', '*.sql', '*.sh', '*.bash', '*.dockerfile',
            '*.tf', '*.vue', '*.svelte'
        ]
        
        exclude_patterns = exclude_patterns or default_exclude
        include_patterns = include_patterns or default_include
        
        import fnmatch
        
        if recursive:
            for root, dirs, filenames in os.walk(str(search_path)):
                dirs[:] = [d for d in dirs if not any(
                    fnmatch.fnmatch(d, pattern) for pattern in exclude_patterns
                )]
                
                for filename in filenames:
                    if any(fnmatch.fnmatch(filename, pattern) for pattern in include_patterns):
                        filepath = Path(root) / filename
                        
                        try:
                            stat = filepath.stat()
                            file_info = FileInfo(
                                path=str(filepath),
                                name=filename,
                                size=stat.st_size,
                                modified_time=datetime.fromtimestamp(stat.st_mtime),
                                is_file=filepath.is_file(),
                                is_symlink=filepath.is_symlink(),
                                mime_type=mimetypes.guess_type(str(filepath))[0]
                            )
                            file_info.detect_language()
                            files.append(file_info)
                        except (OSError, PermissionError) as e:
                            console.print(f"[yellow]警告: 无法读取文件 {filepath}: {e}[/yellow]")
        else:
            try:
                for item in search_path.iterdir():
                    if item.is_file() and any(
                        fnmatch.fnmatch(item.name, pattern) 
                        for pattern in include_patterns
                    ):
                        stat = item.stat()
                        file_info = FileInfo(
                            path=str(item),
                            name=item.name,
                            size=stat.st_size,
                            modified_time=datetime.fromtimestamp(stat.st_mtime),
                            is_file=item.is_file(),
                            is_symlink=item.is_symlink(),
                            mime_type=mimetypes.guess_type(str(item))[0]
                        )
                        file_info.detect_language()
                        files.append(file_info)
            except (OSError, PermissionError) as e:
                console.print(f"[yellow]警告: 无法读取目录 {search_path}: {e}[/yellow]")
                
        return files
    
    async def read_file(self, path: str, encoding: str = 'utf-8', **kwargs) -> str:
        """
        读取本地文件内容
        
        Args:
            path: 相对于 base_path 的文件路径
            encoding: 编码格式
            
        Returns:
            文件内容字符串
        """
        if path == "/":
            full_path = self.base_path
        else:
            full_path = self.base_path / path.lstrip('/')
            
        if not self.validate_path(str(full_path)):
            raise PermissionError(f"不安全的路径: {full_path}")
            
        try:
            with open(full_path, 'r', encoding=encoding, errors='ignore') as f:
                content = f.read()
            return content
        except Exception as e:
            console.print(f"[red]读取文件失败 {full_path}: {e}[/red]")
            raise
    
    async def get_file_info(self, path: str, **kwargs) -> FileInfo:
        """
        获取本地文件信息
        
        Args:
            path: 文件路径
            
        Returns:
            文件信息对象
        """
        if path == "/":
            full_path = self.base_path
        else:
            full_path = self.base_path / path.lstrip('/')
            
        if not full_path.exists():
            raise FileNotFoundError(f"文件不存在: {full_path}")
            
        stat = full_path.stat()
        
        file_info = FileInfo(
            path=str(full_path),
            name=full_path.name,
            size=stat.st_size,
            modified_time=datetime.fromtimestamp(stat.st_mtime),
            is_file=full_path.is_file(),
            is_symlink=full_path.is_symlink(),
            mime_type=mimetypes.guess_type(str(full_path))[0]
        )
        file_info.detect_language()
        
        return file_info
    
    async def execute_command(self, command: str, timeout: int = 30, **kwargs) -> Dict[str, Any]:
        """
        在本地执行命令
        
        Args:
            command: 要执行的命令
            timeout: 超时时间（秒）
            
        Returns:
            执行结果字典
        """
        import subprocess
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.base_path)
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            result = {
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'exit_code': process.returncode,
                'success': process.returncode == 0
            }
            
            return result
            
        except asyncio.TimeoutError:
            process.kill()
            return {
                'stdout': '',
                'stderr': f'命令执行超时 ({timeout}s)',
                'exit_code': -1,
                'success': False
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'success': False
            }


class RemoteServerTarget(BaseTarget):
    """
    远程服务器目标（SSH/SFTP）
    
    通过 SSH/SFTP 协议连接远程服务器并进行文件操作。
    实际的连接逻辑由对应的 Connector 处理。
    """
    
    def __init__(self, host: str, port: int = 22, username: str = "", 
                 password: str = None, key_file: str = None, **kwargs):
        """
        初始化远程服务器目标
        
        Args:
            host: 主机地址或域名
            port: 端口号（默认22）
            username: 用户名
            password: 密码（可选）
            key_file: SSH密钥文件路径（可选）
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self._ssh_client = None
        self._sftp_client = None
        
        uri = f"ssh://{username}@{host}:{port}" if username else f"ssh://{host}:{port}"
        
        info = TargetInfo(
            target_type='remote-server',
            target_uri=uri,
            credentials={
                'username': username,
                'password': password,
                'key_file': key_file
            },
            metadata={
                'host': host,
                'port': port,
                'protocol': 'ssh'
            }
        )
        
        super().__init__(info)
    
    async def connect(self) -> bool:
        """建立SSH连接（由Connector实际执行）"""
        try:
            from src.remote.connectors.ssh_connector import SSHConnector
            
            connector = SSHConnector(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                key_file=self.key_file
            )
            
            success = await connector.test_connection()
            
            if success:
                self._connected = True
                self._connection_time = datetime.now()
                self._connector = connector
                
                if console:
                    console.print(f"[green]✓ 远程服务器已连接: {self.info.target_uri}[/green]")
                    
            return success
            
        except ImportError:
            console.print("[red]错误: 请安装 asyncssh 库 (pip install asyncssh)[/red]")
            return False
        except Exception as e:
            console.print(f"[red]SSH连接失败: {e}[/red]")
            return False
    
    async def disconnect(self) -> None:
        """断开SSH连接"""
        if hasattr(self, '_connector') and self._connector:
            await self._connector.close()
            
        self._connected = False
        if console:
            console.print("[dim]远程服务器连接已关闭[/dim]")
    
    async def list_files(
        self, 
        path: str = "/", 
        recursive: bool = True,
        **kwargs
    ) -> List[FileInfo]:
        """列出远程文件（通过SFTP）"""
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到远程服务器")
            
        return await self._connector.list_files(path, recursive=recursive, **kwargs)
    
    async def read_file(self, path: str, **kwargs) -> str:
        """读取远程文件（通过SFTP）"""
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到远程服务器")
            
        return await self._connector.read_file(path, **kwargs)
    
    async def get_file_info(self, path: str, **kwargs) -> FileInfo:
        """获取远程文件信息"""
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到远程服务器")
            
        return await self._connector.get_file_info(path, **kwargs)
    
    async def execute_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """在远程服务器执行命令"""
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到远程服务器")
            
        return await self._connector.execute_command(command, **kwargs)


class WebTarget(BaseTarget):
    """
    网站/Web应用目标（HTTP/HTTPS）
    
    通过HTTP协议爬取和分析网站内容。
    """
    
    def __init__(self, url: str, **kwargs):
        """
        初始化网站目标
        
        Args:
            url: 网站URL
        """
        self.url = url
        self._http_client = None
        
        info = TargetInfo(
            target_type='website',
            target_uri=url,
            metadata={
                'url': url,
                'protocol': url.split('://')[0] if '://' in url else 'https'
            }
        )
        
        super().__init__(info)
    
    async def connect(self) -> bool:
        """测试网站可访问性"""
        try:
            from src.remote.connectors.http_connector import HTTPConnector
            
            connector = HTTPConnector(url=self.url)
            success = await connector.test_connection()
            
            if success:
                self._connected = True
                self._connection_time = datetime.now()
                self._connector = connector
                
                if console:
                    console.print(f"[green]✓ 网站已连接: {self.url}[/green]")
                    
            return success
            
        except ImportError:
            console.print("[red]错误: 请安装 httpx 库 (pip install httpx)[/red]")
            return False
        except Exception as e:
            console.print(f"[red]网站连接失败: {e}[/red]")
            return False
    
    async def disconnect(self) -> None:
        """关闭HTTP客户端"""
        if hasattr(self, '_connector') and self._connector:
            await self._connector.close()
            
        self._connected = False
        if console:
            console.print("[dim]网站连接已关闭[/dim]")
    
    async def list_files(
        self, 
        path: str = "/", 
        recursive: bool = False,
        crawl_depth: int = 3,
        **kwargs
    ) -> List[FileInfo]:
        """
        爬取网站页面/资源
        
        Args:
            path: URL路径
            recursive: 是否递归爬取
            crawl_depth: 爬取深度
            
        Returns:
            页面/资源信息列表
        """
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到网站")
            
        return await self._connector.crawl(path, depth=crawl_depth, **kwargs)
    
    async def read_file(self, path: str, **kwargs) -> str:
        """获取网页/资源内容"""
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到网站")
            
        return await self._connector.fetch_page(path, **kwargs)
    
    async def get_file_info(self, path: str, **kwargs) -> FileInfo:
        """获取网页/资源信息"""
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到网站")
            
        return await self._connector.get_resource_info(path, **kwargs)
    
    async def execute_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """
        发送API请求（模拟命令执行）
        
        对于Web目标，这里的"命令"可以是：
        - API端点请求
        - 表单提交
        - 特殊操作
        """
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到网站")
            
        return await self._connector.send_request(command, **kwargs)


class DirectConnectTarget(BaseTarget):
    """
    物理设备直连目标（串口/网线）
    
    用于连接IoT设备、工控设备等物理设备。
    """
    
    def __init__(
        self, 
        connection_type: str = "serial",
        port: str = "/dev/ttyUSB0",
        baudrate: int = 9600,
        interface: str = None,
        ip_address: str = None,
        **kwargs
    ):
        """
        初始化直连目标
        
        Args:
            connection_type: 连接类型 (serial/direct-ethernet)
            port: 串口端口（如 /dev/ttyUSB0 或 COM3）
            baudrate: 波特率（仅串口）
            interface: 网络接口名称（仅网线直连）
            ip_address: IP地址（仅网线直连）
        """
        self.connection_type = connection_type
        self.port = port
        self.baudrate = baudrate
        self.interface = interface
        self.ip_address = ip_address
        self._device = None
        
        if connection_type == "serial":
            uri = f"serial://{port}"
        elif connection_type == "direct-ethernet":
            uri = f"direct://{interface}@{ip_address}"
        else:
            uri = f"unknown://{port}"
            
        info = TargetInfo(
            target_type='direct-connect',
            target_uri=uri,
            metadata={
                'connection_type': connection_type,
                'port': port,
                'baudrate': baudrate,
                'interface': interface,
                'ip_address': ip_address
            }
        )
        
        super().__init__(info)
    
    async def connect(self) -> bool:
        """建立设备连接"""
        try:
            if self.connection_type == "serial":
                from src.remote.connectors.serial_connector import SerialConnector
                
                connector = SerialConnector(
                    port=self.port,
                    baudrate=self.baudrate
                )
            elif self.connection_type == "direct-ethernet":
                from src.remote.connectors.direct_connector import DirectEthernetConnector
                
                connector = DirectEthernetConnector(
                    interface=self.interface,
                    ip_address=self.ip_address
                )
            else:
                raise ValueError(f"不支持的连接类型: {self.connection_type}")
                
            success = await connector.test_connection()
            
            if success:
                self._connected = True
                self._connection_time = datetime.now()
                self._connector = connector
                
                if console:
                    console.print(f"[green]✓ 设备已连接: {self.info.target_uri}[/green]")
                    
            return success
            
        except ImportError as e:
            console.print(f"[red]错误: 缺少依赖库: {e}[/red]")
            console.print("[yellow]提示: pip install pyserial scapy[/yellow]")
            return False
        except Exception as e:
            console.print(f"[red]设备连接失败: {e}[/red]")
            return False
    
    async def disconnect(self) -> None:
        """断开设备连接"""
        if hasattr(self, '_connector') and self._connector:
            await self._connector.close()
            
        self._connected = False
        if console:
            console.print("[dim]设备连接已关闭[/dim]")
    
    async def list_files(
        self, 
        path: str = "/", 
        recursive: bool = False,
        **kwargs
    ) -> List[FileInfo]:
        """
        列出设备上的文件/资源
        
        对于物理设备，这可能包括：
        - 固件文件
        - 配置文件
        - 日志文件
        - 数据存储
        """
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到设备")
            
        return await self._connector.list_resources(path, recursive=recursive, **kwargs)
    
    async def read_file(self, path: str, **kwargs) -> str:
        """读取设备文件/资源"""
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到设备")
            
        return await self._connector.read_resource(path, **kwargs)
    
    async def get_file_info(self, path: str, **kwargs) -> FileInfo:
        """获取设备资源信息"""
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到设备")
            
        return await self._connector.get_resource_info(path, **kwargs)
    
    async def execute_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """
        向设备发送命令
        
        对于物理设备，这可能是：
        - AT命令
        - 自定义协议指令
        - Shell命令（如果支持）
        """
        if not self._connected or not hasattr(self, '_connector'):
            raise ConnectionError("未连接到设备")
            
        return await self._connector.send_command(command, **kwargs)


class TargetFactory:
    """
    目标工厂类
    
    根据目标URI自动创建适当的目标实例。
    支持以下URI格式：
    - file:///path/to/dir (本地)
    - ssh://user@host:port (SSH)
    - sftp://user@host:port (SFTP)
    - https://example.com (HTTPS)
    - http://example.com (HTTP)
    - serial:///dev/ttyUSB0 (串口)
    - direct://eth0@192.168.1.100 (网线直连)
    """
    
    @staticmethod
    def create(target_uri: str, **kwargs) -> BaseTarget:
        """
        根据URI创建目标实例
        
        Args:
            target_uri: 目标URI
            **kwargs: 额外参数（如用户名、密码等）
            
        Returns:
            目标实例
            
        Raises:
            ValueError: 不支持的URI格式
        """
        if not target_uri:
            return LocalTarget(**kwargs)
            
        target_uri = target_uri.strip().lower()
        
        if target_uri.startswith(('file:///', './', '/', '.')):
            path = target_uri.replace('file:///', '').replace('file://', '')
            return LocalTarget(base_path=path, **kwargs)
            
        elif target_uri.startswith(('ssh://', 'sftp://')):
            from urllib.parse import urlparse
            parsed = urlparse(target_uri)
            
            return RemoteServerTarget(
                host=parsed.hostname or '',
                port=parsed.port or 22,
                username=parsed.username or kwargs.get('username', ''),
                password=kwargs.get('password'),
                key_file=kwargs.get('key_file')
            )
            
        elif target_uri.startswith(('https://', 'http://')):
            return WebTarget(url=target_uri, **kwargs)
            
        elif target_uri.startswith('serial://'):
            port = target_uri.replace('serial://', '')
            return DirectConnectTarget(
                connection_type="serial",
                port=port,
                baudrate=kwargs.get('baudrate', 9600)
            )
            
        elif target_uri.startswith('direct://'):
            from urllib.parse import urlparse
            parsed = urlparse(target_uri)
            
            return DirectConnectTarget(
                connection_type="direct-ethernet",
                interface=parsed.hostname or kwargs.get('interface'),
                ip_address=parsed.username or kwargs.get('ip_address')
            )
            
        else:
            try:
                path = Path(target_uri)
                if path.exists():
                    return LocalTarget(base_path=path, **kwargs)
            except:
                pass
                
            raise ValueError(f"不支持的目标URI格式: {target_uri}")
    
    @staticmethod
    def detect_target_type(target_uri: str) -> str:
        """
        检测目标类型
        
        Args:
            target_uri: 目标URI
            
        Returns:
            目标类型字符串
        """
        if not target_uri:
            return 'local'
            
        target_uri_lower = target_uri.lower().strip()
        
        if target_uri_lower.startswith(('file:///', './', '/', '.', 'C:\\', 'D:\\')):
            return 'local'
        elif target_uri_lower.startswith(('ssh://', 'sftp://')):
            return 'remote-server'
        elif target_uri_lower.startswith(('https://', 'http://')):
            return 'website'
        elif target_uri_lower.startswith('serial://'):
            return 'direct-connect'
        elif target_uri_lower.startswith('direct://'):
            return 'direct-connect'
        else:
            try:
                Path(target_uri)
                return 'local'
            except:
                return 'unknown'


def create_target_from_config(config_dict: Dict[str, Any]) -> BaseTarget:
    """
    从配置字典创建目标
    
    Args:
        config_dict: 配置字典，包含目标信息
        
    Returns:
        目标实例
    """
    target_type = config_dict.get('type', config_dict.get('target_type', 'local'))
    uri = config_dict.get('uri', config_dict.get('target_uri', '.'))
    credentials = config_dict.get('credentials', {})
    options = config_dict.get('options', {})
    
    kwargs = {**credentials, **options}
    
    if target_type in ('local',):
        return LocalTarget(base_path=uri, **kwargs)
    elif target_type in ('remote-server', 'remote', 'ssh'):
        return RemoteServerTarget(
            host=options.get('host', credentials.get('host', '')),
            port=options.get('port', 22),
            username=credentials.get('username', ''),
            password=credentials.get('password'),
            key_file=credentials.get('key_file'),
            **kwargs
        )
    elif target_type in ('website', 'web', 'http', 'https'):
        return WebTarget(url=uri, **kwargs)
    elif target_type in ('direct-connect', 'direct', 'serial', 'device'):
        return DirectConnectTarget(
            connection_type=options.get('connection_type', 'serial'),
            port=options.get('port', '/dev/ttyUSB0'),
            baudrate=options.get('baudrate', 9600),
            interface=options.get('interface'),
            ip_address=options.get('ip_address'),
            **kwargs
        )
    else:
        return TargetFactory.create(uri, **kwargs)
