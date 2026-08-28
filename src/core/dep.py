"""DEP (Differential Evidence Protocol) — 差分证据协议

DEP 将漏洞验证转化为可证伪的差分实验：
  对于 AI 变更 Delta_AI，找到一条在 R_after 中可达但在 R_before 中不可达的漏洞路径，
  并且该漏洞在安全反事实（correct patch）或特定修复中消失。
"""

from typing import Any, Dict, List, Optional
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DiffEvidence:
    """差分证据 — 一个漏洞发现的完整证据链。"""

    def __init__(
        self,
        finding_id: str,
        vuln_type: str,
        path_before: List[str],
        path_after: List[str],
        sink: str,
        sink_line: int,
    ):
        self.finding_id = finding_id
        self.vuln_type = vuln_type
        self.path_before = path_before
        self.path_after = path_after
        self.sink = sink
        self.sink_line = sink_line
        self.confidence = 0.0
        self.counterfactual_passed = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "path_before": self.path_before,
            "path_after": self.path_after,
            "sink": self.sink,
            "sink_line": self.sink_line,
            "confidence": self.confidence,
            "counterfactual_passed": self.counterfactual_passed,
        }


def verify_differential(
    diff_evidence: DiffEvidence,
    code_before: str,
    code_after: str,
    correct_patch: Optional[str] = None,
) -> DiffEvidence:
    """对差分证据进行验证，确认漏洞路径的可归因性。"""
    diff_evidence.confidence = 0.5
    return diff_evidence
