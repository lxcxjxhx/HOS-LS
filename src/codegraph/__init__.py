"""CodeGraph - 基于 AST 的代码图分析引擎

提供轻量级代码调用图构建能力，使用 Python ast 模块进行精确的
函数定义和调用检测。
"""

from .engine import CodeGraphEngine

__all__ = ["CodeGraphEngine"]
