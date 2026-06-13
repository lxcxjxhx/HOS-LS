"""Taint Analyzer module for legacy compatibility.

Provides the TaintAnalyzer class used by langgraph_flow.py.
This module delegates to src.taint.engine for the actual analysis.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import logging

from src.taint.engine import (
    TaintEngine, TaintSource, TaintSink, TaintPath, get_taint_engine,
)

logger = logging.getLogger(__name__)


@dataclass
class AnalysisContext:
    """Context for taint analysis."""
    file_path: str = ""
    file_content: str = ""
    language: str = "python"
    metadata: Dict[str, Any] = field(default_factory=dict)


class TaintAnalyzer:
    """Taint analyzer compatible with langgraph_flow.py usage.

    Usage:
        taint_analyzer = TaintAnalyzer()
        paths = taint_analyzer.analyze(context)
        taint_results = taint_analyzer.get_standardized_output(paths)
    """

    def __init__(self):
        self._engine = get_taint_engine()

    def analyze(self, context: AnalysisContext) -> List[TaintPath]:
        """Run taint analysis on the given context.

        Args:
            context: AnalysisContext with file_path, file_content, and language

        Returns:
            List of detected TaintPath objects
        """
        if not context.file_content or not context.file_path:
            logger.debug("TaintAnalyzer: Empty context, skipping analysis")
            return []

        try:
            paths = self._engine._analyze_file(
                context.file_path,
                context.file_content,
                context.language,
            )
            logger.debug(f"TaintAnalyzer: Found {len(paths)} taint paths in {context.file_path}")
            return paths
        except Exception as e:
            logger.debug(f"TaintAnalyzer: Analysis failed for {context.file_path}: {e}")
            return []

    def get_standardized_output(self, paths: List[TaintPath]) -> List[Dict[str, Any]]:
        """Convert taint paths to standardized output format.

        Args:
            paths: List of TaintPath objects

        Returns:
            List of dictionaries with standardized format
        """
        return [path.to_dict() for path in paths]

    def analyze_files(self, files: List[str], language: str = "python") -> List[TaintPath]:
        """Analyze multiple files for taint paths.

        Args:
            files: List of file paths
            language: Programming language

        Returns:
            List of detected TaintPath objects
        """
        return self._engine.analyze(files, language)
