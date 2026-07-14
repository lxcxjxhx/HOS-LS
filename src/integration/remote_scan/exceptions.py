"""Remote Scan Exceptions

远程扫描相关异常类。
"""


class RemoteScanError(Exception):
    """远程扫描基础异常"""


class ConnectionError(RemoteScanError):
    """连接异常"""


class AuthenticationError(RemoteScanError):
    """认证异常"""


class TimeoutError(RemoteScanError):
    """超时异常"""


class FileNotFoundError(RemoteScanError):
    """文件未找到异常"""


class PermissionError(RemoteScanError):
    """权限异常"""


class ProtocolError(RemoteScanError):
    """协议异常"""
