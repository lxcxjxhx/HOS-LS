"""智能 JSON 解析器

支持从各种格式的输出中提取 JSON。
"""

import json
import re
from typing import Any, Dict, Optional


class SmartJSONParser:
    """智能 JSON 解析器

    支持从多种格式中提取 JSON 内容。
    """

    def __init__(self) -> None:
        self._patterns = [
            # 标准的 JSON 对象
            (r"\{[\s\S]*\}", self._parse_json),
            # 代码块中的 JSON
            (r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", self._extract_first_group),
            # JSON 数组
            (r"\[[\s\S]*\]", self._parse_json),
            # 带注释的 JSON（尝试去除注释后解析）
            (r"\{[\s\S]*\}", self._parse_json_with_comments),
        ]

    def parse(self, content: str) -> Optional[Dict[str, Any]]:
        """解析 JSON

        Args:
            content: 原始内容

        Returns:
            解析后的字典，如果解析失败则返回 None
        """
        # 首先尝试直接解析
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # 尝试各种模式
        for pattern, parser in self._patterns:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                result = parser(match.group(1) if match.lastindex else match.group())
                if result is not None:
                    return result

        # 尝试清理并解析
        cleaned = self._clean_content(content)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        return None

    def _parse_json(self, content: str) -> Optional[Dict[str, Any]]:
        """解析标准 JSON"""
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    def _extract_first_group(self, content: str) -> Optional[Dict[str, Any]]:
        """提取第一个捕获组"""
        match = re.match(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", content, re.MULTILINE)
        if match:
            return self._parse_json(match.group(1))
        return self._parse_json(content)

    def _parse_json_with_comments(self, content: str) -> Optional[Dict[str, Any]]:
        """解析带注释的 JSON"""
        cleaned = self._remove_comments(content)
        return self._parse_json(cleaned)

    def _clean_content(self, content: str) -> str:
        """清理内容"""
        # 移除 markdown 代码块标记
        content = re.sub(r"```(?:json)?", "", content)
        content = re.sub(r"```", "", content)

        # 移除行号
        content = re.sub(r'^\s*\d+\s+', "", content, flags=re.MULTILINE)

        # 移除多余空白
        content = content.strip()

        return content

    def _remove_comments(self, content: str) -> str:
        """移除 JSON 中的注释"""
        # 移除单行注释
        content = re.sub(r"//.*?$", "", content, flags=re.MULTILINE)
        # 移除多行注释
        content = re.sub(r"/\*[\s\S]*?\*/", "", content)
        return content

    def parse_array(self, content: str) -> Optional[list]:
        """解析 JSON 数组"""
        parsed = self.parse(content)
        if isinstance(parsed, list):
            return parsed
        return None

    def parse_with_fallback(
        self, content: str, fallback: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """解析 JSON，失败时返回默认值

        Args:
            content: 原始内容
            fallback: 默认值

        Returns:
            解析后的字典
        """
        result = self.parse(content)
        return result if result is not None else (fallback or {})
