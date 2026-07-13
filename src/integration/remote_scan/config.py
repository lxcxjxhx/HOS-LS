"""Remote Scan Configuration

远程扫描配置模型。
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RemoteScanConfig:
    """远程扫描配置"""
    enabled: bool = False
    connection_timeout: int = 30
    read_timeout: int = 60
    retry_times: int = 3
    ssh_port: int = 22
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    serial_port: str = "COM1"
    serial_baudrate: int = 115200
    serial_bytesize: int = 8
    serial_parity: str = "N"
    serial_stopbits: int = 1

    @classmethod
    def from_dict(cls, data: dict) -> "RemoteScanConfig":
        """从字典创建配置"""
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})