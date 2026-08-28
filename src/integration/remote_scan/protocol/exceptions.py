"""Remote Scan Exceptions

远程扫描协议异常定义。
"""


class SerialException(Exception):
    """串口异常基类"""


class SerialConnectionError(SerialException):
    """串口连接错误"""


class SerialTimeoutError(SerialException):
    """串口超时错误"""


class SerialReadError(SerialException):
    """串口读取错误"""


class SerialWriteError(SerialException):
    """串口写入错误"""


class SerialConfigurationError(SerialException):
    """串口配置错误"""


class SerialPatternNotFoundError(SerialException):
    """串口模式匹配失败"""
