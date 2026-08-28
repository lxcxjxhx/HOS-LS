"""结果转换模块

将 MultiAgentPipeline 的原始输出转换为标准 VulnerabilityFinding 列表。
这是一个与 PureAIAnalyzer 配合使用的辅助类。
"""

from typing import Any, Dict, List, Optional

from src.ai.models import VulnerabilityFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ResultConverter:
    """结果转换器 — 将 Pipeline 原始输出转换为标准化发现列表。

    接收 PureAIAnalyzer 引用，委托调用其工具方法以保持逻辑一致。
    """

    def __init__(self, analyzer):
        """初始化结果转换器

        Args:
            analyzer: PureAIAnalyzer 实例引用
        """
        self._a = analyzer

    def convert(self, result: Dict[str, Any]) -> List[VulnerabilityFinding]:
        # 直接委托给 analyzer 的 _convert_to_findings
        return self._a._convert_to_findings(result)

    def validate(self, result: Dict[str, Any], strict: bool = False) -> bool:
        return self._a._validate_results(result, strict)

    def detect_language(self, file_path: str) -> str:
        return self._a._detect_language(file_path)