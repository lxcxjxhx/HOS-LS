"""上下文构建器

构建代码分析所需的上下文信息。
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.ai.models import ContextInfo


class ContextBuilder:
    """上下文构建器

    从代码中提取上下文信息。
    """

    def __init__(self) -> None:
        self._max_context_lines = 50

    def build_context(
        self,
        file_path: str,
        file_content: str,
        language: str,
        target_line: Optional[int] = None,
    ) -> ContextInfo:
        """构建上下文

        Args:
            file_path: 文件路径
            file_content: 文件内容
            language: 语言
            target_line: 目标行号（可选）

        Returns:
            上下文信息
        """
        imports = self._extract_imports(file_content, language)
        dependencies = self._extract_dependencies(file_content, language)
        related_files = self._find_related_files(file_path, imports)

        context = ContextInfo(
            file_path=file_path,
            imports=imports,
            dependencies=dependencies,
            related_files=related_files,
        )

        # 如果指定了目标行，提取函数/类名
        if target_line:
            context.function_name = self._extract_function_at_line(
                file_content, target_line, language
            )
            context.class_name = self._extract_class_at_line(
                file_content, target_line, language
            )

        return context

    def _extract_imports(self, content: str, language: str) -> List[str]:
        """提取导入语句"""
        imports = []

        if language == "python":
            # Python 导入
            patterns = [
                r"^import\s+([\w.]+)",
                r"^from\s+([\w.]+)\s+import",
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    imports.append(match.group(1))

        elif language in ["javascript", "typescript"]:
            # JavaScript/TypeScript 导入
            patterns = [
                r"import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]",
                r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    imports.append(match.group(1))

        return list(set(imports))

    def _extract_dependencies(self, content: str, language: str) -> List[str]:
        """提取依赖项"""
        dependencies = []

        if language == "python":
            # 提取函数调用
            pattern = r"(\w+)\s*\("
            for match in re.finditer(pattern, content):
                func_name = match.group(1)
                if func_name not in ["if", "for", "while", "def", "class"]:
                    dependencies.append(func_name)

        return list(set(dependencies))

    def _find_related_files(self, file_path: str, imports: List[str]) -> List[str]:
        """查找相关文件"""
        related = []
        base_path = Path(file_path).parent

        for imp in imports:
            # 尝试找到导入对应的文件
            parts = imp.split(".")
            possible_names = [
                "/".join(parts) + ".py",
                "/".join(parts) + ".js",
                "/".join(parts) + ".ts",
            ]

            for name in possible_names:
                possible_path = base_path / name
                if possible_path.exists():
                    related.append(str(possible_path))
                    break

        return related

    def _extract_function_at_line(
        self, content: str, line: int, language: str
    ) -> Optional[str]:
        """提取指定行的函数名"""
        lines = content.split("\n")

        if language == "python":
            # 向上查找函数定义
            for i in range(line - 1, -1, -1):
                match = re.match(r"\s*def\s+(\w+)", lines[i])
                if match:
                    return match.group(1)

        return None

    def _extract_class_at_line(
        self, content: str, line: int, language: str
    ) -> Optional[str]:
        """提取指定行的类名"""
        lines = content.split("\n")

        if language == "python":
            # 向上查找类定义
            for i in range(line - 1, -1, -1):
                match = re.match(r"\s*class\s+(\w+)", lines[i])
                if match:
                    return match.group(1)

        return None

    def build_surrounding_context(
        self,
        content: str,
        target_line: int,
        context_lines: int = 10,
    ) -> str:
        """构建目标行周围的上下文

        Args:
            content: 文件内容
            target_line: 目标行号（1-based）
            context_lines: 上下文行数

        Returns:
            上下文代码
        """
        lines = content.split("\n")
        start = max(0, target_line - context_lines - 1)
        end = min(len(lines), target_line + context_lines)

        return "\n".join(lines[start:end])
