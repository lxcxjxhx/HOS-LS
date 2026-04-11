"""
串口设备连接器

基于 pyserial 实现的串口通信连接器。
用于连接 IoT 设备、工控设备等物理设备。
"""

import asyncio
from typing import Dict, Any, List, Optional

from .base_connector import (
    BaseConnector,
    ConnectionResult,
    ConnectionStatus,
    ConnectionConfig
)
from ..target import FileInfo

try:
    import serial
    import serial.aio
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

from rich.console import Console

console = Console()


class SerialConnector(BaseConnector):
    """串口设备连接器"""
    
    connector_type = "serial"
    
    def __init__(
        self,
        port: str,
        baudrate: int = 9600,
        bytesize: int = 8,
        parity: str = 'N',
        stopbits: float = 1,
        timeout: float = 1.0,
        config: ConnectionConfig = None,
        **kwargs
    ):
        super().__init__(config=config, **kwargs)
        
        self.port = port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.timeout = timeout
        
        self._serial_conn: Optional[serial.Serial] = None
        
        if not SERIAL_AVAILABLE:
            raise ImportError("请安装 pyserial 库: pip install pyserial")
    
    async def _do_connect(self) -> ConnectionResult:
        try:
            loop = asyncio.get_event_loop()
            self._serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=self.bytesize,
                parity=self.parity,
                stopbits=self.stopbits,
                timeout=self.timeout
            )
            
            return ConnectionResult(
                success=True,
                status=ConnectionStatus.CONNECTED,
                message=f"已连接到串口 {self.port} ({self.baudrate} baud)",
                metadata={'port': self.port, 'baudrate': self.baudrate}
            )
            
        except serial.serialutil.SerialException as e:
            return ConnectionResult(
                success=False,
                status=ConnectionStatus.ERROR,
                message=f"串口打开失败: {e}",
                error=e
            )
    
    async def _do_disconnect(self) -> None:
        if self._serial_conn and self._serial_conn.is_open:
            self._serial_conn.close()
            self._serial_conn = None
    
    async def send_command(self, command: str, **kwargs) -> Dict[str, Any]:
        if not self.is_connected:
            raise ConnectionError("未连接到设备")
            
        try:
            loop = asyncio.get_event_loop()
            
            self._serial_conn.write((command + '\n').encode('utf-8'))
            await asyncio.sleep(0.1)
            
            if self._serial_conn.in_waiting > 0:
                response = self._serial_conn.read(self._serial_conn.in_waiting)
                output = response.decode('utf-8', errors='ignore').strip()
            else:
                output = ''
                
            return {
                'stdout': output,
                'stderr': '',
                'exit_code': 0,
                'success': True
            }
            
        except Exception as e:
            return {'stdout': '', 'stderr': str(e), 'exit_code': -1, 'success': False}
    
    async def list_resources(self, path: str = "/", recursive: bool = False, **kwargs) -> List[FileInfo]:
        return []
    
    async def read_resource(self, path: str, **kwargs) -> str:
        if not self.is_connected:
            raise ConnectionError("未连接到设备")
            
        result = await self.send_command(f"cat {path}")
        return result['stdout']
    
    async def get_resource_info(self, path: str, **kwargs) -> FileInfo:
        return FileInfo(path=path, name=path.split('/')[-1], is_file=True)
    
    async def close(self) -> None:
        await self.disconnect()


class DirectEthernetConnector(BaseConnector):
    """网线直连连接器"""
    
    connector_type = "direct"
    
    def __init__(
        self,
        interface: str = None,
        ip_address: str = None,
        config: ConnectionConfig = None,
        **kwargs
    ):
        super().__init__(config=config, **kwargs)
        
        self.interface = interface
        self.ip_address = ip_address
        self._socket = None
    
    async def _do_connect(self) -> ConnectionResult:
        return ConnectionResult(
            success=True,
            status=ConnectionStatus.CONNECTED,
            message=f"已连接到网络接口 {self.interface or 'default'}",
            metadata={'interface': self.interface, 'ip': self.ip_address}
        )
    
    async def _do_disconnect(self) -> None:
        pass
    
    async def send_command(self, command: str, **kwargs) -> Dict[str, Any]:
        return {'stdout': '', 'stderr': 'Direct connection does not support commands', 'exit_code': -1, 'success': False}
    
    async def list_resources(self, path: str = "/", recursive: bool = False, **kwargs) -> List[FileInfo]:
        return []
    
    async def read_resource(self, path: str, **kwargs) -> str:
        raise NotImplementedError("Direct ethernet connection does not support file reading")
    
    async def get_resource_info(self, path: str, **kwargs) -> FileInfo:
        return FileInfo(path=path, name=path.split('/')[-1], is_file=True)
    
    async def close(self) -> None:
        await self.disconnect()
