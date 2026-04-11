"""
SSH/SFTP 连接器

基于 asyncssh 实现的高性能异步 SSH/SFTP 连接器。
支持文件传输、远程命令执行、端口转发等功能。
"""

import asyncio
import os
import stat as stat_module
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, AsyncIterator

from .base_connector import (
    BaseConnector,
    ConnectionResult,
    ConnectionStatus,
    ConnectionConfig
)
from ..target import FileInfo

try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False

from rich.console import Console

console = Console()


class SSHConnector(BaseConnector):
    """
    SSH/SFTP 远程服务器连接器
    
    功能特性：
    - 异步高性能（基于 asyncssh）
    - 支持密码和密钥认证
    - SFTP 文件传输
    - 远程命令执行
    - 端口转发（可选）
    - 连接复用和池化
    """
    
    connector_type = "ssh"
    
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "",
        password: str = None,
        key_file: str = None,
        passphrase: str = None,
        known_hosts: str = None,
        config: ConnectionConfig = None,
        **kwargs
    ):
        """
        初始化 SSH 连接器
        
        Args:
            host: 主机地址或域名
            port: 端口号（默认22）
            username: 用户名
            password: 密码（可选，与key_file二选一）
            key_file: SSH私钥文件路径（可选）
            passphrase: 私钥密码（如果私钥有加密）
            known_hosts: known_hosts文件路径（默认自动处理）
            config: 连接配置
            **kwargs: 额外参数
        """
        super().__init__(config=config, **kwargs)
        
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.passphrase = passphrase
        self.known_hosts = known_hosts
        
        self._ssh_conn: Optional[asyncssh.SSHClientConnection] = None
        self._sftp_client: Optional[asyncssh.SFTPClient] = None
        
        if not ASYNCSSH_AVAILABLE:
            raise ImportError(
                "请安装 asyncssh 库: pip install asyncssh"
            )
    
    async def _do_connect(self) -> ConnectionResult:
        """建立SSH连接"""
        try:
            connect_kwargs = {
                'host': self.host,
                'port': self.port,
                'username': self.username or None,
                'known_hosts': self.known_hosts if self.known_hosts else None,
                'connect_timeout': self.config.timeout
            }
            
            if self.password:
                connect_kwargs['password'] = self.password
            elif self.key_file:
                if os.path.exists(self.key_file):
                    connect_kwargs['client_keys'] = self.key_file
                    if self.passphrase:
                        connect_kwargs['passphrase'] = self.passphrase
                else:
                    return ConnectionResult(
                        success=False,
                        status=ConnectionStatus.ERROR,
                        message=f"SSH密钥文件不存在: {self.key_file}"
                    )
            
            self._ssh_conn = await asyncssh.connect(**connect_kwargs)
            
            await self._init_sftp()
            
            hostname = await self._execute_simple('hostname')
            
            return ConnectionResult(
                success=True,
                status=ConnectionStatus.CONNECTED,
                message=f"已连接到 {self.username}@{self.host}:{self.port}",
                metadata={
                    'hostname': hostname.strip() if hostname else self.host,
                    'host': self.host,
                    'port': self.port,
                    'username': self.username
                }
            )
            
        except asyncssh.misc.PermissionDenied:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message="认证失败：用户名或密码错误",
                error=PermissionError("Authentication failed")
            )
        except asyncssh.misc.HostKeyNotVerifiable:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message="主机密钥验证失败",
                error=SecurityError("Host key verification failed")
            )
        except OSError as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=f"网络错误: {e}",
                error=e
            )
        except Exception as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=str(e),
                error=e
            )
    
    async def _do_disconnect(self) -> None:
        """断开SSH连接"""
        try:
            if self._sftp_client:
                self._sftp_client.close()
                self._sftp_client = None
                
            if self._ssh_conn:
                self._ssh_conn.close()
                await self._ssh_conn.wait_closed()
                self._ssh_conn = None
                
        except Exception as e:
            console.print(f"[yellow]断开SSH连接时出错: {e}[/yellow]")
    
    async def _init_sftp(self) -> None:
        """初始化SFTP客户端"""
        if self._ssh_conn and not self._sftp_client:
            self._sftp_client = await self._ssh_conn.start_sftp_client()
    
    async def _execute_simple(self, command: str) -> str:
        """执行简单命令并返回输出"""
        result = await self._ssh_conn.run(command)
        return result.stdout
    
    async def list_files(
        self,
        path: str = "/",
        recursive: bool = False,
        exclude_patterns: List[str] = None,
        include_patterns: List[str] = None,
        **kwargs
    ) -> List[FileInfo]:
        """
        列出远程文件
        
        Args:
            path: 远程路径
            recursive: 是否递归列出子目录
            exclude_patterns: 排除模式
            include_patterns: 包含模式
            
        Returns:
            文件信息列表
        """
        if not self.is_connected:
            raise ConnectionError("未连接到远程服务器")
            
        await self._init_sftp()
        
        files = []
        
        default_exclude = [
            '*.pyc', '*.pyo', '__pycache__', '.git', 
            '.svn', '.hg', 'node_modules', '.venv',
            'venv', 'dist', 'build', '*.min.js',
            '*.min.css', '.DS_Store'
        ]
        
        default_include = [
            '*.py', '*.js', '*.ts', '*.jsx', '*.tsx',
            '*.java', '*.cpp', '*.c', '*.h', '*.hpp',
            '*.go', '*.rs', '*.rb', '*.php', '*.swift',
            '*.kt', '*.cs', '*.html', '*.css', '*.json',
            '*.xml', '*.yaml', '*.yml', '*.md', '*.sql',
            '*.sh', '*.dockerfile', '*.tf', '*.vue'
        ]
        
        exclude_patterns = exclude_patterns or default_exclude
        include_patterns = include_patterns or default_include
        
        import fnmatch
        
        async def _scan_directory(current_path: str):
            try:
                entries = await self._sftp_client.listdir(current_path)
                
                for entry in sorted(entries):
                    full_path = f"{current_path}/{entry}" if current_path != '/' else f"/{entry}"
                    
                    try:
                        file_attr = await self._sftp_client.stat(full_path)
                        
                        is_dir = stat_module.S_ISDIR(file_attr.permissions)
                        
                        if is_dir and recursive:
                            should_exclude = any(
                                fnmatch.fnmatch(entry, pattern)
                                for pattern in exclude_patterns
                            )
                            
                            if not should_exclude:
                                await _scan_directory(full_path)
                                
                        elif not is_dir:
                            should_include = any(
                                fnmatch.fnmatch(entry, pattern)
                                for pattern in include_patterns
                            )
                            
                            if should_include:
                                file_info = FileInfo(
                                    path=full_path,
                                    name=entry,
                                    size=file_attr.size,
                                    modified_time=datetime.fromtimestamp(file_attr.mtime),
                                    is_file=True,
                                    is_symlink=stat_module.S_ISLNK(file_attr.permissions)
                                )
                                file_info.detect_language()
                                files.append(file_info)
                                
                    except asyncssh.sftp.SFTPError as e:
                        console.print(
                            f"[yellow]警告: 无法访问 {full_path}: {e}[/yellow]"
                        )
                        
            except asyncssh.sftp.SFTPError as e:
                console.print(
                    f"[yellow]警告: 无法列出目录 {current_path}: {e}[/yellow]"
                )
        
        await _scan_directory(path)
        
        return files
    
    async def read_file(self, path: str, encoding: str = 'utf-8', **kwargs) -> str:
        """
        读取远程文件内容
        
        Args:
            path: 远程文件路径
            encoding: 编码格式
            
        Returns:
            文件内容字符串
        """
        if not self.is_connected:
            raise ConnectionError("未连接到远程服务器")
            
        await self._init_sftp()
        
        try:
            async with self._sftp_client.open(path, 'rb') as f:
                content_bytes = await f.read()
                content = content_bytes.decode(encoding, errors='ignore')
                return content
                
        except asyncssh.sftp.SFTPNoSuchFile:
            raise FileNotFoundError(f"远程文件不存在: {path}")
        except asyncssh.sftp.SFTPPermissionDenied:
            raise PermissionError(f"无权限读取文件: {path}")
        except Exception as e:
            raise IOError(f"读取远程文件失败: {path} - {e}")
    
    async def get_file_info(self, path: str, **kwargs) -> FileInfo:
        """
        获取远程文件信息
        
        Args:
            path: 远程文件路径
            
        Returns:
            文件信息对象
        """
        if not self.is_connected:
            raise ConnectionError("未连接到远程服务器")
            
        await self._init_sftp()
        
        try:
            file_attr = await self._sftp_client.stat(path)
            
            file_info = FileInfo(
                path=path,
                name=path.split('/')[-1],
                size=file_attr.size,
                modified_time=datetime.fromtimestamp(file_attr.mtime),
                is_file=not stat_module.S_ISDIR(file_attr.permissions),
                is_symlink=stat_module.S_ISLNK(file_attr.permissions)
            )
            file_info.detect_language()
            
            return file_info
            
        except asyncssh.sftp.SFTPNoSuchFile:
            raise FileNotFoundError(f"远程文件不存在: {path}")
        except Exception as e:
            raise IOError(f"获取文件信息失败: {path} - {e}")
    
    async def execute_command(
        self, 
        command: str, 
        timeout: int = 30,
        **kwargs
    ) -> Dict[str, Any]:
        """
        在远程服务器执行命令
        
        Args:
            command: 要执行的命令
            timeout: 超时时间（秒）
            
        Returns:
            执行结果字典：
            - stdout: 标准输出
            - stderr: 标准错误
            - exit_code: 退出码
            - success: 是否成功
        """
        if not self.is_connected:
            raise ConnectionError("未连接到远程服务器")
            
        try:
            process = await self._ssh_conn.create_process(command)
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            result = {
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'exit_code': process.exit_status,
                'success': process.exit_status == 0
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
    
    async def upload_file(
        self,
        local_path: str,
        remote_path: str,
        callback=None
    ) -> bool:
        """
        上传本地文件到远程服务器
        
        Args:
            local_path: 本地文件路径
            remote_path: 远程目标路径
            callback: 进度回调函数 (bytes_transferred, total_size)
            
        Returns:
            是否上传成功
        """
        if not self.is_connected:
            raise ConnectionError("未连接到远程服务器")
            
        await self._init_sftp()
        
        try:
            async with self._sftp_client.open(remote_path, 'w') as remote_file:
                with open(local_path, 'rb') as local_file:
                    data = local_file.read()
                    await remote_file.write(data)
                    
                    if callback:
                        callback(len(data), len(data))
                        
            return True
            
        except Exception as e:
            console.print(f"[red]上传文件失败: {e}[/red]")
            return False
    
    async def download_file(
        self,
        remote_path: str,
        local_path: str,
        callback=None
    ) -> bool:
        """
        下载远程文件到本地
        
        Args:
            remote_path: 远程文件路径
            local_path: 本地保存路径
            callback: 进度回调函数
            
        Returns:
            是否下载成功
        """
        if not self.is_connected:
            raise ConnectionError("未连接到远程服务器")
            
        await self._init_sftp()
        
        try:
            async with self._sftp_client.open(remote_path, 'r') as remote_file:
                data = await remote_file.read()
                
                with open(local_path, 'wb') as local_file:
                    local_file.write(data)
                    
                if callback:
                    callback(len(data), len(data))
                    
            return True
            
        except Exception as e:
            console.print(f"[red]下载文件失败: {e}[/red]")
            return False
    
    async def create_directory(self, path: str, mode: int = 0o755) -> bool:
        """
        创建远程目录
        
        Args:
            path: 目录路径
            mode: 权限模式
            
        Returns:
            是否创建成功
        """
        if not self.is_connected:
            raise ConnectionError("未连接到远程服务器")
            
        await self._init_sftp()
        
        try:
            await self._sftp_client.mkdir(path, mode=mode)
            return True
        except asyncssh.sftp.SFTPError as e:
            console.print(f"[red]创建目录失败: {e}[/red]")
            return False
    
    async def get_system_info(self) -> Dict[str, Any]:
        """
        获取远程系统信息
        
        Returns:
            系统信息字典
        """
        if not self.is_connected:
            raise ConnectionError("未连接到远程服务器")
            
        commands = {
            'hostname': 'hostname',
            'os_type': 'uname -s',
            'os_version': 'uname -r',
            'architecture': 'uname -m',
            'kernel_version': 'uname -v',
            'uptime': 'uptime',
            'cpu_info': "cat /proc/cpuinfo | grep 'model name' | head -1 | awk -F': '{print $2}'",
            'memory_info': "free -h | grep Mem | awk '{print $2}'",
            'disk_usage': "df -h / | tail -1 | awk '{print $5}'"
        }
        
        info = {}
        
        for key, cmd in commands.items():
            try:
                output = await self._execute_simple(cmd)
                info[key] = output.strip()
            except Exception:
                info[key] = 'Unknown'
                
        return info
    
    async def close(self) -> None:
        """关闭连接（别名）"""
        await self.disconnect()


def create_ssh_connector_from_config(config_dict: Dict[str, Any]) -> SSHConnector:
    """
    从配置字典创建SSH连接器
    
    Args:
        config_dict: 配置字典
        
    Returns:
        SSH连接器实例
    """
    credentials = config_dict.get('credentials', {})
    options = config_dict.get('options', {})
    
    return SSHConnector(
        host=options.get('host', ''),
        port=options.get('port', 22),
        username=credentials.get('username', ''),
        password=credentials.get('password'),
        key_file=credentials.get('key_file'),
        passphrase=credentials.get('passphrase')
    )


class SecurityError(Exception):
    """安全相关错误"""
    pass
