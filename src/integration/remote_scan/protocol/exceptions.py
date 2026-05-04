"""Remote Scan Exceptions

远程扫描协议异常定义。
"""


class SerialException(Exception):
    """串口异常基类"""
    pass


class SerialConnectionError(SerialException):
    """串口连接错误"""
    pass


class SerialTimeoutError(SerialException):
    """串口超时错误"""
    pass


class SerialReadError(SerialException):
    """串口读取错误"""
    pass


class SerialWriteError(SerialException):
    """串口写入错误"""
    pass


class SerialConfigurationError(SerialException):
    """串口配置错误"""
    pass


class SerialPatternNotFoundError(SerialException):
    """串口模式匹配失败"""
    pass