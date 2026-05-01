"""Serial Scanner

串口远程扫描实现，支持串口控制台交互。
"""

import logging
import re
import time
from typing import List, Dict, Any, Optional

from ..base_scanner import BaseRemoteScanner, RemoteFile, ScanResult, ScannerType
from .protocol.serial_protocol import SerialProtocol
from .config import RemoteScanConfig

logger = logging.getLogger(__name__)


class SerialScanner(BaseRemoteScanner):
    """串口扫描器"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.port = config.get('port', 'COM1')
        self.baudrate = config.get('baudrate', 115200)
        self.bytesize = config.get('bytesize', 8)
        self.parity = config.get('parity', 'N')
        self.stopbits = config.get('stopbits', 1)
        self.timeout = config.get('timeout', 30)
        self._remote_path = config.get('remote_path', '/')

        self._protocol = SerialProtocol(
            port=self.port,
            baudrate=self.baudrate,
            bytesize=self.bytesize,
            parity=self.parity,
            stopbits=self.stopbits,
            timeout=self.timeout,
        )

    def connect(self) -> bool:
        """建立连接"""
        try:
            return self._protocol.connect()
        except Exception as e:
            logger.error(f"Failed to connect to serial port {self.port}: {e}")
            return False

    def disconnect(self) -> None:
        """断开连接"""
        try:
            self._protocol.disconnect()
        except Exception as e:
            logger.warning(f"Error while disconnecting from {self.port}: {e}")

    def is_connected(self) -> bool:
        """检查连接状态"""
        return self._protocol.is_connected()

    def discover_files(self, remote_path: str) -> List[RemoteFile]:
        """发现远程文件"""
        if not self.is_connected():
            logger.error("Not connected to serial port")
            return []

        try:
            self._protocol.flush_input()

            if remote_path:
                cd_result = self._protocol.send_command(f"cd {remote_path}", timeout=self.timeout)
                logger.debug(f"cd result: {cd_result}")

            self._protocol.write_line("ls -la")
            time.sleep(0.5)

            output_lines = []
            start_time = time.time()

            while True:
                elapsed = time.time() - start_time
                if elapsed >= self.timeout:
                    break

                remaining = self.timeout - elapsed
                line = self._protocol.read_line(timeout=int(remaining))

                if not line:
                    break

                if "ls -la" in line or "drwx" in line or "-rw" in line or "total" in line:
                    output_lines.append(line)

                if "Permission denied" in line or "Not a directory" in line:
                    logger.warning(f"Access denied for path: {remote_path}")
                    break

            output = "\n".join(output_lines)
            logger.debug(f"ls output: {output}")

            files = self._parse_ls_output(output)

            if not files:
                dir_output = "\n".join(output_lines)
                files = self._parse_dir_output(dir_output)

            return files

        except Exception as e:
            logger.error(f"Error discovering files at {remote_path}: {e}")
            return []

    def read_file(self, remote_path: str) -> bytes:
        """读取远程文件"""
        if not self.is_connected():
            raise ConnectionError("Not connected to serial port")

        try:
            cat_command = f"cat {remote_path}"
            response = self._protocol.send_command(cat_command, timeout=self.timeout)

            if "No such file" in response or "cannot access" in response:
                raise FileNotFoundError(f"File not found: {remote_path}")

            if "Permission denied" in response:
                raise PermissionError(f"Permission denied: {remote_path}")

            content = response.encode('utf-8')
            return content

        except Exception as e:
            logger.error(f"Error reading file {remote_path}: {e}")
            raise

    def execute_command(self, command: str) -> Dict[str, Any]:
        """执行远程命令"""
        if not self.is_connected():
            return {
                'success': False,
                'error': 'Not connected to serial port',
                'output': ''
            }

        try:
            response = self._protocol.send_command(command, timeout=self.timeout)

            return {
                'success': True,
                'output': response,
                'error': ''
            }

        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return {
                'success': False,
                'error': str(e),
                'output': ''
            }

    def send_command(self, command: str, wait_response: bool = True) -> str:
        """发送命令"""
        if not self.is_connected():
            raise ConnectionError("Not connected to serial port")

        try:
            return self._protocol.send_command(command, wait_response=wait_response, timeout=self.timeout)
        except Exception as e:
            logger.error(f"Error sending command '{command}': {e}")
            raise

    @property
    def scanner_type(self) -> ScannerType:
        """获取扫描器类型"""
        return ScannerType.SERIAL

    def scan(self, remote_path: Optional[str] = None) -> ScanResult:
        """执行扫描"""
        target_path = remote_path or self._remote_path

        if not self.is_connected():
            if not self.connect():
                return ScanResult(
                    files=[],
                    target=target_path,
                    scanner_type=ScannerType.SERIAL,
                    metadata={'error': 'Failed to connect to serial port'}
                )

        try:
            files = self.discover_files(target_path)

            return ScanResult(
                files=files,
                target=target_path,
                scanner_type=ScannerType.SERIAL,
                metadata={
                    'port': self.port,
                    'baudrate': self.baudrate,
                    'file_count': len(files)
                }
            )

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanResult(
                files=[],
                target=target_path,
                scanner_type=ScannerType.SERIAL,
                metadata={'error': str(e)}
            )

    def _parse_ls_output(self, output: str) -> List[RemoteFile]:
        """解析ls命令输出"""
        files = []

        ls_pattern = re.compile(
            r'^([drwx-]{10})\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|\w+\s+\d+\s+\d{2}:\d{2}|\w+\s+\d+\s+\d{4})\s+(.+)$',
            re.MULTILINE
        )

        for match in ls_pattern.finditer(output):
            permissions = match.group(1)
            owner = match.group(2)
            group = match.group(3)
            size_str = match.group(4)
            date_str = match.group(5)
            name = match.group(6).strip()

            if name in ('.', '..'):
                continue

            try:
                size = int(size_str)
            except ValueError:
                size = 0

            modified_time = self._parse_date(date_str)

            file_type = 'd' if permissions.startswith('d') else 'f'

            if file_type == 'f' and '.' in name:
                pass

            files.append(RemoteFile(
                path=name,
                size=size,
                modified_time=modified_time,
                permissions=permissions,
                owner=owner,
                group=group
            ))

        return files

    def _parse_dir_output(self, output: str) -> List[RemoteFile]:
        """解析Windows dir命令输出"""
        files = []

        dir_pattern = re.compile(
            r'^(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}\s*[AP]M)\s+(<DIR>|\d+)\s+(.+)$',
            re.MULTILINE | re.IGNORECASE
        )

        for match in dir_pattern.finditer(output):
            date_str = match.group(1)
            time_str = match.group(2)
            size_or_dir = match.group(3)
            name = match.group(4).strip()

            if name in ('.', '..'):
                continue

            if size_or_dir == '<DIR>':
                permissions = 'drwxrwxr-x'
                size = 0
            else:
                permissions = '-rw-rw-rw-'
                try:
                    size = int(size_or_dir.replace(',', ''))
                except ValueError:
                    size = 0

            modified_time = self._parse_windows_date(date_str, time_str)

            files.append(RemoteFile(
                path=name,
                size=size,
                modified_time=modified_time,
                permissions=permissions,
                owner=None,
                group=None
            ))

        return files

    def _parse_date(self, date_str: str) -> float:
        """解析Linux ls日期"""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%b %d %H:%M',
            '%b %d %Y',
        ]

        for fmt in formats:
            try:
                from datetime import datetime
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.timestamp()
            except ValueError:
                continue

        return time.time()

    def _parse_windows_date(self, date_str: str, time_str: str) -> float:
        """解析Windows dir日期"""
        try:
            from datetime import datetime
            date_str = date_str.strip()
            time_str = time_str.strip().upper()

            if 'AM' in time_str or 'PM' in time_str:
                dt = datetime.strptime(f"{date_str} {time_str}", '%m/%d/%Y %I:%M %p')
            else:
                dt = datetime.strptime(f"{date_str} {time_str}", '%m/%d/%Y %H:%M')

            return dt.timestamp()
        except ValueError:
            return time.time()
