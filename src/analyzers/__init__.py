"""代码分析模块

提供多种代码分析功能，包括 AST 分析、CST 分析、污点追踪和编码检测。
"""

from src.analyzers.base import BaseAnalyzer, AnalysisResult
from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.input_tracer import InputTracer, ControllabilityResult, TraceNode
# 临时注释掉 CSTAnalyzer 的导入，以避免 libcst 的依赖问题
# from src.analyzers.cst_analyzer import CSTAnalyzer

__all__ = [
    "BaseAnalyzer",
    "AnalysisResult",
    "ASTAnalyzer",
    "InputTracer",
    "ControllabilityResult",
    "TraceNode",
    # "CSTAnalyzer",
]
