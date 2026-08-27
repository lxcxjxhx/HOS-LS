"""污点分析引擎模块

提供基于 CPG（Code Property Graph）的污点分析基础设施，包括：
- CPG 构建（AST + CFG + PDG/DDG 联合图）
- 污点源/汇/消毒器声明
- 过程内污点传播
- 调用图驱动的过程间传播
- C/C++ 内存安全漏洞专用分析规则

此模块是 hos-ls 三层过滤架构的第二层（Layer 2: Taint Analysis），
向上对接 risk_engine.py 和 langgraph_flow.py 中已有的导入引用。
"""

from src.taint.engine import (
    CPGNode,
    CPGEdge,
    CodePropertyGraph,
    TaintSource,
    TaintSink,
    Sanitizer,
    TaintPath,
    CallGraphBuilder,
    TaintEngine,
    get_taint_engine,
)

from src.taint.analyzer import TaintAnalyzer

__all__ = [
    "CPGNode",
    "CPGEdge",
    "CodePropertyGraph",
    "TaintSource",
    "TaintSink",
    "Sanitizer",
    "TaintPath",
    "CallGraphBuilder",
    "TaintEngine",
    "get_taint_engine",
    "TaintAnalyzer",
]
