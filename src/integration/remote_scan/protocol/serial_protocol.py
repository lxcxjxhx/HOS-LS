"""Serial Protocol

串口协议实现，支持串口控制台交互。
"""

import logging
import time
import re
from typing import Optional
import serial
import serial.tools.list_ports

from .exceptions import (
    SerialException,
    SerialConnectionError,
    SerialTimeoutError,
    SerialReadError,
    SerialWriteError,
    SerialConfigurationError,
    SerialPatternNotFoundError,
)

logger = logging.getLogger(__name__)


class SerialProtocol:
    """串口协议类"""

    @staticmethod
    def list_ports() -> list:
        """列出可用串口"""
        ports = serial.tools.list_ports.comports()
        return [port.device for port in ports]

    def __init__(
        self,
        port: str = "COM1",
        baudrate: int = 115200,
        bytesize: int = 8,
        parity: str = "N",
        stopbits: int = 1,
        timeout: int = 30,
    ):
        self.port = port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.timeout = timeout
        self._serial: Optional[serial.Serial] = None
        self._parity_map = {
            "N": serial.PARITY_NONE,
            "E": serial.PARITY_EVEN,
            "O": serial.PARITY_ODD,
            "M": serial.PARITY_MARK,
            "S": serial.PARITY_SPACE,
        }
        self._bytesize_map = {
            5: serial.FIVEBITS,
            6: serial.SIXBITS,
            7: serial.SEVENBITS,
            8: serial.EIGHTBITS,
        }
        self._stopbits_map = {
            1: serial.STOPBITS_ONE,
            1.5: serial.STOPBITS_ONE_POINT_FIVE,
            2: serial.STOPBITS_TWO,
        }

    def connect(self) -> bool:
        """建立串口连接"""
        if self._serial is not None and self._serial.is_open:
            logger.warning(f"Serial port {self.port} already connected")
            return True

        try:
            parity_constant = self._parity_map.get(self.parity.upper(), serial.PARITY_NONE)
            bytesize_constant = self._bytesize_map.get(self.bytesize, serial.EIGHTBITS)
            stopbits_constant = self._stopbits_map.get(self.stopbits, serial.STOPBITS_ONE)

            self._serial = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=bytesize_constant,
                parity=parity_constant,
                stopbits=stopbits_constant,
                timeout=self.timeout,
                write_timeout=self.timeout,
            )
            logger.info(f"Connected to serial port {self.port} at {self.baudrate} baud")
            return True
        except serial.SerialException as e:
            logger.error(f"Failed to connect to serial port {self.port}: {e}")
            raise SerialConnectionError(f"Failed to connect to {self.port}: {e}")
        except KeyError as e:
            logger.error(f"Invalid serial configuration: {e}")
            raise SerialConfigurationError(f"Invalid serial configuration: {e}")

    def disconnect(self) -> None:
        """断开串口连接"""
        if self._serial is not None:
            try:
                if self._serial.is_open:
                    self._serial.close()
                    logger.info(f"Disconnected from serial port {self.port}")
                self._serial = None
            except serial.SerialException as e:
                logger.warning(f"Error while disconnecting from {self.port}: {e}")
                self._serial = None

    def is_connected(self) -> bool:
        """检查串口连接状态"""
        return self._serial is not None and self._serial.is_open

    def send(self, data: bytes) -> int:
        """发送原始数据"""
        if not self.is_connected():
            raise SerialConnectionError("Not connected to serial port")

        try:
            bytes_written = self._serial.write(data)
            self._serial.flush()
            return bytes_written
        except serial.SerialException as e:
            logger.error(f"Failed to send data: {e}")
            raise SerialWriteError(f"Failed to send data: {e}")

    def recv(self, size: int) -> bytes:
        """接收原始数据"""
        if not self.is_connected():
            raise SerialConnectionError("Not connected to serial port")

        try:
            data = self._serial.read(size)
            return data
        except serial.SerialException as e:
            logger.error(f"Failed to receive data: {e}")
            raise SerialReadError(f"Failed to receive data: {e}")

    def read_line(self, timeout: Optional[int] = None) -> str:
        """读取一行数据"""
        if not self.is_connected():
            raise SerialConnectionError("Not connected to serial port")

        if timeout is not None:
            old_timeout = self._serial.timeout
            self._serial.timeout = timeout

        try:
            line_bytes = self._serial.readline()
            if timeout is not None:
                self._serial.timeout = old_timeout

            if not line_bytes:
                raise SerialTimeoutError("Read line timeout")

            try:
                return line_bytes.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError:
                return line_bytes.decode("latin-1").rstrip("\r\n")
        except serial.SerialException as e:
            if timeout is not None:
                self._serial.timeout = old_timeout
            logger.error(f"Failed to read line: {e}")
            raise SerialReadError(f"Failed to read line: {e}")

    def write_line(self, data: str) -> None:
        """写入一行数据"""
        if not self.is_connected():
            raise SerialConnectionError("Not connected to serial port")

        try:
            line_data = data.encode("utf-8") + b"\r\n"
            self._serial.write(line_data)
            self._serial.flush()
        except serial.SerialException as e:
            logger.error(f"Failed to write line: {e}")
            raise SerialWriteError(f"Failed to write line: {e}")

    def send_command(
        self,
        command: str,
        wait_response: bool = True,
        timeout: int = 5,
        clear_buffer: bool = True,
    ) -> str:
        """发送命令并等待响应"""
        if not self.is_connected():
            raise SerialConnectionError("Not connected to serial port")

        if clear_buffer:
            self.flush_input()

        try:
            self.write_line(command)

            if not wait_response:
                return ""

            old_timeout = self._serial.timeout
            self._serial.timeout = timeout

            response_lines = []
            start_time = time.time()

            while True:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    self._serial.timeout = old_timeout
                    break

                remaining_timeout = timeout - elapsed
                self._serial.timeout = remaining_timeout

                try:
                    line = self._serial.readline()
                    if not line:
                        break

                    try:
                        decoded_line = line.decode("utf-8").rstrip("\r\n")
                    except UnicodeDecodeError:
                        decoded_line = line.decode("latin-1").rstrip("\r\n")

                    response_lines.append(decoded_line)
                except serial.SerialException:
                    break

            self._serial.timeout = old_timeout
            return "\n".join(response_lines)

        except SerialWriteError:
            raise
        except SerialTimeoutError:
            raise
        except SerialReadError:
            raise
        except Exception as e:
            logger.error(f"Error in send_command: {e}")
            raise SerialException(f"Error in send_command: {e}")

    def expect(self, pattern: str, timeout: int = 5) -> str:
        """等待指定模式出现"""
        if not self.is_connected():
            raise SerialConnectionError("Not connected to serial port")

        try:
            regex = re.compile(pattern)
        except re.error as e:
            raise SerialConfigurationError(f"Invalid regex pattern: {e}")

        buffer = ""
        start_time = time.time()

        while True:
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                raise SerialPatternNotFoundError(
                    f"Pattern '{pattern}' not found within {timeout}s. Buffer: {buffer[:500]}"
                )

            remaining_timeout = timeout - elapsed
            self._serial.timeout = remaining_timeout

            try:
                chunk = self._serial.read(1024)
                if not chunk:
                    raise SerialPatternNotFoundError(
                        f"Pattern '{pattern}' not found (timeout). Buffer: {buffer[:500]}"
                    )

                try:
                    buffer += chunk.decode("utf-8")
                except UnicodeDecodeError:
                    buffer += chunk.decode("latin-1")

                match = regex.search(buffer)
                if match:
                    matched_content = buffer[:match.end()]
                    return matched_content

            except serial.SerialException as e:
                if "timeout" not in str(e).lower():
                    logger.error(f"Error in expect: {e}")
                    raise SerialReadError(f"Error in expect: {e}")

    def flush_input(self) -> None:
        """清空输入缓冲区"""
        if not self.is_connected():
            raise SerialConnectionError("Not connected to serial port")

        try:
            self._serial.reset_input_buffer()
        except serial.SerialException as e:
            logger.warning(f"Failed to flush input buffer: {e}")

    def flush_output(self) -> None:
        """清空输出缓冲区"""
        if not self.is_connected():
            raise SerialConnectionError("Not connected to serial port")

        try:
            self._serial.reset_output_buffer()
        except serial.SerialException as e:
            logger.warning(f"Failed to flush output buffer: {e}")