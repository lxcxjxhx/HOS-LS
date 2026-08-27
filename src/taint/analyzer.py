"""污点分析器模块

提供与 langgraph_flow.py 兼容的 TaintAnalyzer 接口。
封装 TaintEngine，提供标准化的分析结果输出。
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from src.analyzers.base import AnalysisContext
from src.taint.engine import TaintEngine, get_taint_engine
from src.utils.logger import get_logger

logger = get_logger(__name__)


class TaintAnalyzer:
    """污点分析器

    作为三层过滤架构（Layer 2）的一部分，对 AST/结构过滤后的候选
    函数调用点执行污点传播分析。

    用法（与 langgraph_flow.py 兼容）:
        analyzer = TaintAnalyzer()
        paths = analyzer.analyze(context)
        output = analyzer.get_standardized_output(paths)
    """

    def __init__(self, engine: Optional[TaintEngine] = None):
        self._engine = engine or get_taint_engine()
        self._last_results: List[Dict[str, Any]] = []

    def analyze(self, context: AnalysisContext) -> List[Dict[str, Any]]:
        """执行污点分析（与 langgraph_flow.py 中 taint_analysis_node 兼容）

        Args:
            context: 分析上下文（通常包含 file_path, language, file_content 等）

        Returns:
            标准化污点路径列表
        """
        try:
            file_path = getattr(context, 'file_path', None)
            if file_path is None:
                # 尝试从 context.__dict__ 获取
                file_path = getattr(context, 'target', None) or \
                           context.__dict__.get('file_path') or \
                           context.__dict__.get('target', "")

            if not file_path:
                logger.warning("TaintAnalyzer 上下文缺少 file_path")
                return []

            language = getattr(context, 'language', 'c') or 'c'

            if isinstance(file_path, str) and Path(file_path).is_file():
                # 单个文件
                paths = self._engine.analyze_file(file_path, language)
            elif isinstance(file_path, str) and Path(file_path).is_dir():
                # 目录
                paths = self._engine.analyze_directory(file_path, language)
            else:
                # 尝试作为文件列表
                try:
                    files = context.__dict__.get('source_files', [])
                    if not files:
                        files = [file_path] if file_path else []
                    paths = self._engine.analyze(files, language)
                except Exception:
                    paths = []

            self._last_results = [p.to_dict() for p in paths]
            return self._last_results

        except Exception as e:
            logger.error(f"TaintAnalyzer.analyze 失败: {e}")
            return []

    def get_standardized_output(self, paths: Optional[List[Dict[str, Any]]] = None) \
            -> List[Dict[str, Any]]:
        """生成标准化输出（与 ast_analyzer.get_standardized_output 格式兼容）

        Args:
            paths: TaintEngine 返回的路径字典列表；None 时使用上次结果

        Returns:
            标准化的分析发现列表
        """
        items = paths if paths is not None else self._last_results
        output = []

        for p in items:
            source = p.get("source", {})
            sink = p.get("sink", {})

            output.append({
                "type": "finding",
                "rule_id": f"TAINT-{p.get('cwe_id', 'UNKNOWN')}",
                "message": (
                    f"污点路径: {source.get('label', '?')} "
                    f"→ ... → {sink.get('label', '?')} "
                    f"({p.get('cwe_id', '?')})"
                ),
                "severity": p.get("severity", "high"),
                "confidence": p.get("confidence", 0.7),
                "location": {
                    "file": sink.get("file_path", ""),
                    "line": sink.get("line_start", 0),
                },
                "source_location": {
                    "file": source.get("file_path", ""),
                    "line": source.get("line_start", 0),
                },
                "evidence": [
                    f"污点源: {source.get('label', '?')} "
                    f"({source.get('file_path', '?')}:{source.get('line_start', 0)})",
                    f"污点汇: {sink.get('label', '?')} "
                    f"({sink.get('file_path', '?')}:{sink.get('line_start', 0)})",
                    f"传播路径长度: {p.get('path_length', 0)}",
                ],
                "attack_prerequisites": p.get("attack_prerequisites", []),
                "source_agent": "TaintEngine",
                "metadata": {
                    "cwe_id": p.get("cwe_id", ""),
                    "path_preview": p.get("path_preview", []),
                    "is_interprocedural": p.get("is_interprocedural", False),
                },
            })

        return output

    def clear(self) -> None:
        """清空缓存的结果"""
        self._last_results.clear()
        self._engine.cpg.clear()
