"""SAL (Sink-Anchored Locator) — 锚定 Sink 的代码定位器

SAL 将传统的 Data-Flow 分析问题重新定义为：
  给定一个代码变更 Delta_AI，找到所有可达的安全关键操作（Sink），
  并证明 AI 变更是否沿跨文件路径影响了这些操作。
"""

from typing import Any, Dict, List, Optional
from src.utils.logger import get_logger

logger = get_logger(__name__)


def locate_sinks(
    file_path: str,
    code_before: str,
    code_after: str,
    language: str = "auto",
) -> List[Dict[str, Any]]:
    """定位代码变更影响到的安全关键 Sink 及其上下文。"""
    return []


def compute_sink_reachability(
    changed_file: str,
    changed_lines: List[int],
    project_files: Dict[str, str],
) -> List[Dict[str, Any]]:
    """计算变更行到各 Sink 的可达路径。"""
    return []
