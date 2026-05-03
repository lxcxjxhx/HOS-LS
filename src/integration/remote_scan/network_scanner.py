"""Network Scanner

网络远程扫描实现，支持SSH和HTTP协议。
"""

import logging
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..base_scanner import BaseRemoteScanner, RemoteFile, ScanResult, ScannerType
from ..exceptions import ConnectionError, FileNotFoundError as RemoteFileNotFoundError

logger = logging.getLogger(__name__)


class NetworkScanner(BaseRemoteScanner):
    """网络扫描器，支持SSH和HTTP协议进行远程文件扫描"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get('host')
        self.port = config.get('port', 22)
        self.protocol_type = config.get('protocol_type', 'ssh').lower()
        self.username = config.get('username')
        self.password = config.get('password')
        self.key_path = config.get('key_path')
        self.use_ssl = config.get('use_ssl', False)
        self.remote_path = config.get('remote_path', '/')

        self._protocol = None
        self._file_extensions: Optional[List[str]] = None
        self._max_depth: int = config.get('max_depth', 10)
        self._timeout: int = config.get('timeout', 30)

        self._init_protocol()

    def _init_protocol(self) -> None:
        """初始化协议实例"""
        if self.protocol_type == 'ssh':
            from ..protocol.ssh_protocol import SSHProtocol
            self._protocol = SSHProtocol(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                key_path=self.key_path,
                timeout=self._timeout,
            )
        elif self.protocol_type == 'http':
            from ..protocol.http_protocol import HTTPProtocol
            self._protocol = HTTPProtocol(
                host=self.host,
                port=self.port,
                use_ssl=self.use_ssl,
                username=self.username,
                password=self.password,
                timeout=self._timeout,
            )
        else:
            raise ValueError(f"Unsupported protocol type: {self.protocol_type}")

    def connect(self) -> bool:
        """建立连接"""
        if self._protocol is None:
            logger.error("Protocol not initialized")
            return False

        try:
            return self._protocol.connect()
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            return False

    def disconnect(self) -> None:
        """断开连接"""
        if self._protocol is not None:
            self._protocol.disconnect()

    def is_connected(self) -> bool:
        """检查连接状态"""
        if self._protocol is None:
            return False
        return self._protocol.is_connected()

    def discover_files(self, remote_path: str) -> List[RemoteFile]:
        """发现远程文件

        Args:
            remote_path: 远程目录路径

        Returns:
            RemoteFile列表
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to remote host")

        if self.protocol_type == 'ssh':
            return self._discover_files_ssh(remote_path)
        elif self.protocol_type == 'http':
            return self._discover_files_http(remote_path)
        else:
            raise ConnectionError(f"Unsupported protocol: {self.protocol_type}")

    def _discover_files_ssh(self, remote_path: str) -> List[RemoteFile]:
        """通过SSH发现文件

        Args:
            remote_path: 远程目录路径

        Returns:
            RemoteFile列表
        """
        files: List[RemoteFile] = []

        try:
            from ..protocol.ssh_protocol import SSHProtocol
            ssh_protocol = self._protocol

            try:
                find_cmd = f"find {remote_path} -type f"
                result = ssh_protocol.execute_command(find_cmd)

                if result.get('exit_code') == 0:
                    file_paths = result.get('stdout', '').strip().split('\n')
                    file_paths = [p.strip() for p in file_paths if p.strip()]

                    for file_path in file_paths:
                        file_info = self._get_file_info_ssh(file_path)
                        if file_info and self._filter_file(file_info.path):
                            files.append(file_info)

            except Exception as e:
                logger.debug(f"Find command failed, using SFTP fallback: {e}")
                files = self._discover_files_sftp(remote_path)

        except Exception as e:
            logger.error(f"Error discovering files via SSH: {e}")
            raise ConnectionError(f"Error discovering files: {e}")

        return files

    def _discover_files_sftp(self, remote_path: str, current_depth: int = 0) -> List[RemoteFile]:
        """通过SFTP递归发现文件

        Args:
            remote_path: 远程目录路径
            current_depth: 当前递归深度

        Returns:
            RemoteFile列表
        """
        files: List[RemoteFile] = []

        if current_depth >= self._max_depth:
            logger.debug(f"Max depth {self._max_depth} reached at {remote_path}")
            return files

        try:
            file_list = self._protocol.list_directory(remote_path)

            for file_info in file_list:
                full_path = file_info.path

                if file_info.filename in ('.', '..'):
                    continue

                if self._is_directory(file_info.mode):
                    files.extend(self._discover_files_sftp(full_path, current_depth + 1))
                else:
                    remote_file = self._convert_to_remote_file(file_info)
                    if self._filter_file(remote_file.path):
                        files.append(remote_file)

        except RemoteFileNotFoundError:
            logger.warning(f"Directory not found: {remote_path}")
        except Exception as e:
            logger.debug(f"Error listing directory {remote_path}: {e}")

        return files

    def _get_file_info_ssh(self, file_path: str) -> Optional[RemoteFile]:
        """通过SSH命令获取文件信息

        Args:
            file_path: 文件路径

        Returns:
            RemoteFile或None
        """
        try:
            stat_cmd = f"stat -c '%s %Y %a %U %G' '{file_path}' 2>/dev/null || stat -f '%z %m %Lp %Su %Sg' '{file_path}'"
            result = self._protocol.execute_command(stat_cmd)

            if result.get('exit_code') == 0:
                stat_output = result.get('stdout', '').strip()
                parts = stat_output.split()

                if len(parts) >= 5:
                    size = int(parts[0])
                    mtime = float(parts[1])
                    permissions = parts[2]
                    owner = parts[3]
                    group = parts[4]

                    return RemoteFile(
                        path=file_path,
                        size=size,
                        modified_time=mtime,
                        permissions=permissions,
                        owner=owner,
                        group=group,
                    )

            ls_cmd = f"ls -la '{file_path}'"
            result = self._protocol.execute_command(ls_cmd)

            if result.get('exit_code') == 0:
                return self._parse_ls_output(file_path, result.get('stdout', ''))

        except Exception as e:
            logger.debug(f"Error getting file info for {file_path}: {e}")

        return None

    def _parse_ls_output(self, file_path: str, ls_output: str) -> Optional[RemoteFile]:
        """解析ls命令输出

        Args:
            file_path: 文件路径
            ls_output: ls -la 输出

        Returns:
            RemoteFile或None
        """
        try:
            lines = ls_output.strip().split('\n')
            for line in lines:
                parts = line.split()
                if len(parts) >= 8:
                    permissions = parts[0]
                    links = int(parts[1])
                    owner = parts[2]
                    group = parts[3]
                    size = int(parts[4])

                    date_str = ' '.join(parts[5:8])
                    mtime = self._parse_ls_date(date_str)

                    path_from_ls = parts[-1]
                    actual_path = file_path if path_from_ls.endswith(file_path.split('/')[-1]) else path_from_ls

                    return RemoteFile(
                        path=actual_path,
                        size=size,
                        modified_time=mtime,
                        permissions=permissions,
                        owner=owner,
                        group=group,
                    )
        except Exception as e:
            logger.debug(f"Error parsing ls output: {e}")

        return None

    def _parse_ls_date(self, date_str: str) -> float:
        """解析ls命令中的日期字符串

        Args:
            date_str: 日期字符串 (如 "Jan 15 10:30")

        Returns:
            Unix时间戳
        """
        import time
        try:
            current_year = time.localtime().tm_year
            full_date_str = f"{date_str} {current_year}"
            parsed_time = time.strptime(full_date_str, "%b %d %H:%M %Y")
            return time.mktime(parsed_time)
        except Exception:
            return 0.0

    def _discover_files_http(self, remote_path: str) -> List[RemoteFile]:
        """通过HTTP协议发现文件

        Args:
            remote_path: 远程路径

        Returns:
            RemoteFile列表
        """
        files: List[RemoteFile] = []

        try:
            response = self._protocol.get(remote_path)

            if response.get('status_code') == 200:
                content = response.get('text', '')
                files.extend(self._parse_html_for_files(content, remote_path))

        except Exception as e:
            logger.error(f"Error discovering files via HTTP: {e}")

        return files

    def _parse_html_for_files(self, html_content: str, base_path: str) -> List[RemoteFile]:
        """解析HTML内容查找文件链接

        Args:
            html_content: HTML内容
            base_path: 基础路径

        Returns:
            RemoteFile列表
        """
        files: List[RemoteFile] = []
        import re
        import time

        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        hrefs = href_pattern.findall(html_content)

        for href in hrefs:
            if href.startswith('/'):
                full_path = href
            elif href.startswith('http'):
                continue
            else:
                full_path = f"{base_path.rstrip('/')}/{href}"

            if self._is_file_path(href):
                file = RemoteFile(
                    path=full_path,
                    size=0,
                    modified_time=time.time(),
                    permissions='644',
                    owner=None,
                    group=None,
                )
                if self._filter_file(file.path):
                    files.append(file)

        return files

    def _is_file_path(self, path: str) -> bool:
        """判断路径是否为文件路径

        Args:
            path: 路径

        Returns:
            是否为文件
        """
        if path.endswith('/'):
            return False

        file_extensions = ['.py', '.txt', '.log', '.json', '.xml', '.yaml', '.yml',
                           '.conf', '.config', '.sh', '.bash', '.md', '.rst',
                           '.html', '.css', '.js', '.java', '.c', '.cpp', '.h',
                           '.sql', '.db', '.dat']

        path_lower = path.lower()
        return any(path_lower.endswith(ext) for ext in file_extensions)

    def _convert_to_remote_file(self, file_info) -> RemoteFile:
        """将SSHFileInfo转换为RemoteFile

        Args:
            file_info: SSHFileInfo对象

        Returns:
            RemoteFile对象
        """
        import stat

        permissions = oct(file_info.mode)[-3:] if hasattr(file_info, 'mode') else '644'

        return RemoteFile(
            path=file_info.path,
            size=file_info.size,
            modified_time=file_info.mtime,
            permissions=permissions,
            owner=None,
            group=None,
        )

    def _is_directory(self, mode: int) -> bool:
        """判断是否为目录

        Args:
            mode: 文件模式

        Returns:
            是否为目录
        """
        import stat
        return stat.S_ISDIR(mode)

    def _filter_file(self, file_path: str) -> bool:
        """过滤文件

        Args:
            file_path: 文件路径

        Returns:
            是否应该包含此文件
        """
        if self._file_extensions is None:
            return True

        path_lower = file_path.lower()
        return any(path_lower.endswith(ext) for ext in self._file_extensions)

    def set_file_filter(self, extensions: List[str]) -> None:
        """设置文件扩展名过滤器

        Args:
            extensions: 文件扩展名列表，如 ['.py', '.txt']
        """
        self._file_extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in extensions]

    def clear_file_filter(self) -> None:
        """清除文件过滤器"""
        self._file_extensions = None

    def read_file(self, remote_path: str) -> bytes:
        """读取远程文件

        Args:
            remote_path: 远程文件路径

        Returns:
            文件内容字节
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to remote host")

        if self.protocol_type == 'ssh':
            return self._protocol.read_file(remote_path)
        elif self.protocol_type == 'http':
            response = self._protocol.get(remote_path)
            if response.get('status_code') == 200:
                content = response.get('content', b'')
                if isinstance(content, str):
                    return content.encode('utf-8')
                return content
            else:
                raise RemoteFileNotFoundError(f"HTTP {response.get('status_code')}: {remote_path}")
        else:
            raise ConnectionError(f"Unsupported protocol: {self.protocol_type}")

    def execute_command(self, command: str) -> Dict[str, Any]:
        """执行远程命令

        Args:
            command: 要执行的命令

        Returns:
            包含exit_code, stdout, stderr的字典
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to remote host")

        if self.protocol_type != 'ssh':
            raise ConnectionError(f"Command execution is only supported via SSH, not {self.protocol_type}")

        try:
            return self._protocol.execute_command(command)
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            raise ConnectionError(f"Error executing command: {e}")

    @property
    def scanner_type(self) -> ScannerType:
        """获取扫描器类型"""
        return ScannerType.NETWORK

    def scan(self, remote_path: Optional[str] = None, file_extensions: Optional[List[str]] = None) -> ScanResult:
        """执行扫描

        Args:
            remote_path: 远程扫描路径，默认为配置中的路径
            file_extensions: 文件扩展名过滤器

        Returns:
            ScanResult扫描结果
        """
        if file_extensions:
            self.set_file_filter(file_extensions)

        target_path = remote_path or self.remote_path

        if not self.is_connected():
            connected = self.connect()
            if not connected:
                return ScanResult(
                    files=[],
                    target=f"{self.host}:{self.port}{target_path}",
                    scanner_type=self.scanner_type,
                    metadata={
                        'error': f'Failed to connect to {self.host}:{self.port}',
                        'protocol': self.protocol_type,
                    }
                )

        files: List[RemoteFile] = []
        error_message: Optional[str] = None

        try:
            files = self.discover_files(target_path)
        except Exception as e:
            error_message = str(e)
            logger.error(f"Error during scan: {e}")

        metadata: Dict[str, Any] = {
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol_type,
            'scan_path': target_path,
            'file_count': len(files),
        }

        if error_message:
            metadata['error'] = error_message

        if self._file_extensions:
            metadata['file_extensions'] = self._file_extensions

        return ScanResult(
            files=files,
            target=f"{self.host}:{self.port}{target_path}",
            scanner_type=self.scanner_type,
            metadata=metadata,
        )

    def __enter__(self) -> 'NetworkScanner':
        """上下文管理器入口"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """上下文管理器出口"""
        self.disconnect()
