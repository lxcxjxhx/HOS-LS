"""AI 错误定义

提供 AI 提供商共用的异常类。
"""

from typing import Optional


class APIError(Exception):
    """API 通用错误"""

    def __init__(self, code: int, message: str, should_truncate: bool = True):
        self.code = code
        self.message = message
        self.should_truncate = should_truncate
        super().__init__(f"[{code}] {message}")

    @classmethod
    def from_exception(cls, error: Exception) -> "APIError":
        """从通用异常创建 APIError"""
        return cls(code=0, message=str(error), should_truncate=True)
