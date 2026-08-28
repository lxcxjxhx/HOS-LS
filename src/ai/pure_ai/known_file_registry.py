"""已知文件注册表

维护已知文件注册表，防止 AI 幻觉引用不存在的文件。
"""

from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


class KnownFileRegistry:
    """已知文件注册表 - 防止幻觉引用

    维护一个已知文件的注册表，确保所有引用的 location
    都在已知的文件范围内，防止 AI 生成不存在的文件引用。
    """

    def __init__(self):
        self._files: Dict[str, str] = {}
        self._line_counts: Dict[str, int] = {}

    def register(self, file_path: str, content: str) -> None:
        """注册文件到注册表

        Args:
            file_path: 文件路径
            content: 文件内容
        """
        self._files[file_path] = content
        self._line_counts[file_path] = content.count("\n") + 1 if content else 1

    def clear(self) -> None:
        """清空注册表"""
        self._files.clear()
        self._line_counts.clear()

    def validate_location(self, location: str) -> Tuple[bool, str]:
        """验证 location 是否有效

        Args:
            location: 位置字符串（格式：文件路径:行号）

        Returns:
            (是否有效, 错误信息)
        """
        if not location:
            return False, "Empty location"

        parts = location.rsplit(":", 1)
        if len(parts) != 2:
            return False, f"Invalid location format: {location}"

        path, line_str = parts

        if path not in self._files:
            available = ", ".join(list(self._files.keys())[:3])
            return False, f"Unknown file: {path}. Available: {available}"

        try:
            line_num = int(line_str)
        except ValueError:
            return False, f"Invalid line number: {line_str}"

        max_line = self._line_counts[path]
        if line_num < 1 or line_num > max_line:
            return False, f"Line {line_num} out of range (1-{max_line})"

        return True, ""

    def get_file_content(self, file_path: str) -> Optional[str]:
        """获取文件内容"""
        return self._files.get(file_path)

    def get_known_file_paths(self) -> List[str]:
        """获取所有已知文件路径"""
        return list(self._files.keys())

    def get_file_summary(self) -> str:
        """获取文件摘要列表"""
        return "\n".join(
            [f"- {path} ({self._line_counts[path]} lines)" for path in self._files.keys()]
        )

