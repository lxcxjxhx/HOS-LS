"""SSH Protocol

SSH协议实现，支持远程命令执行和文件读取。
"""

import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import time

import paramiko
from paramiko import SSHClient, SFTPClient, AutoAddPolicy

from ..exceptions import ConnectionError as RemoteConnectionError, AuthenticationError as RemoteAuthenticationError, TimeoutError as RemoteTimeoutError, FileNotFoundError as RemoteFileNotFoundError

logger = logging.getLogger(__name__)


@dataclass
class SSHFileInfo:
    """SSH文件信息"""
    filename: str
    path: str
    size: int
    mode: int
    mtime: float


class SSHProtocol:
    """SSH协议类"""

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        timeout: int = 30,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.timeout = timeout
        self._client: Optional[SSHClient] = None
        self._sftp: Optional[SFTPClient] = None
        self._transport = None

    def connect(self) -> bool:
        """建立SSH连接"""
        if self._client is not None and self.is_connected():
            logger.warning(f"SSH connection to {self.host}:{self.port} already established")
            return True

        try:
            self._client = SSHClient()
            self._client.set_missing_host_key_policy(AutoAddPolicy())

            connect_kwargs: Dict[str, Any] = {
                "hostname": self.host,
                "port": self.port,
                "timeout": self.timeout,
            }

            if self.username:
                connect_kwargs["username"] = self.username

            if self.key_path:
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(self.key_path)
                    connect_kwargs["pkey"] = private_key
                except paramiko.SSHException as e:
                    try:
                        private_key = paramiko.Ed25519Key.from_private_key_file(self.key_path)
                        connect_kwargs["pkey"] = private_key
                    except paramiko.SSHException:
                        try:
                            private_key = paramiko.ECDSAKey.from_private_key_file(self.key_path)
                            connect_kwargs["pkey"] = private_key
                        except paramiko.SSHException:
                            logger.error(f"Failed to load private key from {self.key_path}: {e}")
                            raise RemoteAuthenticationError(f"Failed to load private key: {e}") from e
                except FileNotFoundError:
                    logger.error(f"Private key file not found: {self.key_path}")
                    raise RemoteConnectionError(f"Private key file not found: {self.key_path}") from FileNotFoundError
            elif self.password:
                connect_kwargs["password"] = self.password
            else:
                logger.error("No authentication method provided (password or key_path required)")
                raise RemoteAuthenticationError("No authentication method provided (password or key_path required)")

            self._client.connect(**connect_kwargs)
            self._transport = self._client.get_transport()
            if self._transport is not None:
                self._transport.set_keepalive(30)

            logger.info(f"SSH connection established to {self.host}:{self.port}")
            return True

        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed for {self.host}:{self.port}: {e}")
            self._cleanup()
            raise RemoteAuthenticationError(f"SSH authentication failed: {e}") from e
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error to {self.host}:{self.port}: {e}")
            self._cleanup()
            raise RemoteConnectionError(f"SSH connection error: {e}") from e
        except OSError as e:
            logger.error(f"Network error connecting to {self.host}:{self.port}: {e}")
            self._cleanup()
            raise RemoteConnectionError(f"Network error: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error connecting to {self.host}:{self.port}: {e}")
            self._cleanup()
            raise RemoteConnectionError(f"Unexpected connection error: {e}") from e

    def disconnect(self) -> None:
        """断开SSH连接"""
        self._cleanup()
        logger.info(f"SSH connection to {self.host}:{self.port} disconnected")

    def _cleanup(self) -> None:
        """清理SSH连接资源"""
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None

        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

        self._transport = None

    def is_connected(self) -> bool:
        """检查连接状态"""
        if self._client is None:
            return False
        try:
            transport = self._client.get_transport()
            return transport is not None and transport.is_active()
        except Exception:
            return False

    def send(self, data: bytes) -> int:
        """发送数据（通过exec_command）"""
        if not self.is_connected():
            raise RemoteConnectionError("Not connected to SSH server")

        try:
            stdin, stdout, stderr = self._client.exec_command("")
            channel = stdout.channel
            channel.sendall(data)
            return len(data)
        except Exception as e:
            logger.error(f"Error sending data: {e}")
            raise RemoteConnectionError(f"Error sending data: {e}") from e

    def recv(self, size: int) -> bytes:
        """接收数据"""
        if not self.is_connected():
            raise RemoteConnectionError("Not connected to SSH server")

        try:
            stdin, stdout, stderr = self._client.exec_command("")
            channel = stdout.channel
            return channel.recv(size)
        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            raise RemoteConnectionError(f"Error receiving data: {e}") from e

    def execute_command(self, command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """执行远程命令"""
        if not self.is_connected():
            raise RemoteConnectionError("Not connected to SSH server")

        if timeout is None:
            timeout = self.timeout

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)

            stdout_data = stdout.read()
            stderr_data = stderr.read()
            exit_code = stdout.channel.recv_exit_status()

            return {
                "exit_code": exit_code,
                "stdout": stdout_data.decode("utf-8", errors="replace"),
                "stderr": stderr_data.decode("utf-8", errors="replace"),
            }

        except paramiko.SSHException as e:
            if "Timeout" in str(e):
                logger.error(f"Command execution timeout: {command}")
                raise RemoteTimeoutError(f"Command execution timeout: {e}") from e
            logger.error(f"SSH error executing command: {e}")
            raise RemoteConnectionError(f"SSH error executing command: {e}") from e
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            raise RemoteConnectionError(f"Error executing command: {e}") from e

    def _get_sftp(self) -> SFTPClient:
        """获取SFTP客户端（延迟初始化）"""
        if not self.is_connected():
            raise RemoteConnectionError("Not connected to SSH server")

        if self._sftp is None:
            try:
                self._sftp = self._client.open_sftp()
            except Exception as e:
                logger.error(f"Failed to open SFTP session: {e}")
                raise RemoteConnectionError(f"Failed to open SFTP session: {e}") from e

        return self._sftp

    def read_file(self, remote_path: str) -> bytes:
        """通过SFTP读取远程文件"""
        if not self.is_connected():
            raise RemoteConnectionError("Not connected to SSH server")

        try:
            sftp = self._get_sftp()
            with sftp.file(remote_path, "rb") as f:
                data = f.read()
            return data
        except FileNotFoundError:
            logger.error(f"Remote file not found: {remote_path}")
            raise RemoteFileNotFoundError(f"Remote file not found: {remote_path}") from FileNotFoundError
        except PermissionError as e:
            logger.error(f"Permission denied reading {remote_path}: {e}")
            raise RemoteFileNotFoundError(f"Permission denied: {remote_path}") from e
        except Exception as e:
            logger.error(f"Error reading remote file {remote_path}: {e}")
            raise RemoteConnectionError(f"Error reading remote file: {e}") from e

    def list_directory(self, remote_path: str) -> List[SSHFileInfo]:
        """列出远程目录"""
        if not self.is_connected():
            raise RemoteConnectionError("Not connected to SSH server")

        try:
            sftp = self._get_sftp()
            file_list = sftp.listdir_attr(remote_path)

            result = []
            for attr in file_list:
                filename = attr.filename
                path = remote_path.rstrip("/") + "/" + filename if remote_path != "/" else "/" + filename
                result.append(SSHFileInfo(
                    filename=filename,
                    path=path,
                    size=attr.st_size,
                    mode=attr.st_mode,
                    mtime=attr.st_mtime,
                ))

            return result

        except FileNotFoundError:
            logger.error(f"Remote directory not found: {remote_path}")
            raise RemoteFileNotFoundError(f"Remote directory not found: {remote_path}") from FileNotFoundError
        except PermissionError as e:
            logger.error(f"Permission denied listing {remote_path}: {e}")
            raise RemoteFileNotFoundError(f"Permission denied: {remote_path}") from e
        except Exception as e:
            logger.error(f"Error listing remote directory {remote_path}: {e}")
            raise RemoteConnectionError(f"Error listing remote directory: {e}") from e

    def file_exists(self, remote_path: str) -> bool:
        """检查文件是否存在"""
        if not self.is_connected():
            raise RemoteConnectionError("Not connected to SSH server")

        try:
            sftp = self._get_sftp()
            sftp.stat(remote_path)
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False
