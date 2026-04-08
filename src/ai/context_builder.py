"""上下文构建器模块

实现伪RAG功能，构建文件的上下文信息，包括导入、相关文件和函数调用等。
"""

import asyncio
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.ai.models import AnalysisContext


class ContextBuilder:
    """上下文构建器

    实现伪RAG功能，构建文件的上下文信息。
    """

    def __init__(self):
        """初始化上下文构建器"""
        self.import_patterns = {
            "python": r"^(import|from)\s+([\w\.]+)",
            "javascript": r"^(import|require)\s*\(?(?:['\"]([^'\"]+)['\"]|\{[^\}]+\}\s+from\s+['\"]([^'\"]+)['\"])",
            "typescript": r"^(import|require)\s*\(?(?:['\"]([^'\"]+)['\"]|\{[^\}]+\}\s+from\s+['\"]([^'\"]+)['\"])",
            "java": r"^import\s+([\w\.]+);",
            "cpp": r"^#include\s+[<\"]([^>\"]+)[>\"]",
            "c": r"^#include\s+[<\"]([^>\"]+)[>\"]",
            "go": r"^import\s+(?:\(|\")([^\)\"]+)(?:\)|\")",
            "ruby": r"^require\s+['\"]([^'\"]+)['\"]",
            "php": r"^require_once\s+['\"]([^'\"]+)['\"]|^include\s+['\"]([^'\"]+)['\"]",
            "swift": r"^import\s+([\w]+)",
            "kotlin": r"^import\s+([\w\.]+)",
            "rust": r"^use\s+([\w\:]+)"
        }

    async def build_context(self, context: AnalysisContext) -> Dict[str, Any]:
        """构建上下文

        Args:
            context: 分析上下文

        Returns:
            增强的上下文信息
        """
        # 提取导入
        imports = self._extract_imports(context.code_content, context.language)

        # 加载相关文件
        related_files = await self._load_related_files(context.file_path, imports, limit=3)

        # 提取函数调用
        function_calls = self._extract_function_calls(context.code_content, context.language)

        return {
            "imports": imports,
            "related_files": related_files,
            "function_calls": function_calls,
            "file_path": context.file_path,
            "language": context.language
        }

    def _extract_imports(self, code_content: str, language: str) -> List[str]:
        """提取导入

        Args:
            code_content: 代码内容
            language: 语言

        Returns:
            导入列表
        """
        imports = []
        pattern = self.import_patterns.get(language)
        if not pattern:
            return imports

        lines = code_content.split('\n')
        for line in lines:
            match = re.search(pattern, line.strip())
            if match:
                # 提取导入路径
                for group in match.groups():
                    if group and not group in ['import', 'from', 'require', 'include', 'use']:
                        imports.append(group)
                        break

        return imports[:10]  # 限制导入数量

    async def _load_related_files(self, file_path: str, imports: List[str], limit: int = 3) -> List[Dict[str, Any]]:
        """加载相关文件

        Args:
            file_path: 文件路径
            imports: 导入列表
            limit: 限制数量

        Returns:
            相关文件列表
        """
        related_files = []
        file_dir = Path(file_path).parent

        # 查找相关文件
        for imp in imports:
            if len(related_files) >= limit:
                break

            # 尝试解析导入路径
            imp_path = self._resolve_import_path(imp, file_dir)
            if imp_path and imp_path.exists() and imp_path.is_file():
                try:
                    with open(imp_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    related_files.append({
                        "path": str(imp_path),
                        "content": content[:1000]  # 限制内容长度
                    })
                except:
                    pass

        # 如果相关文件不足，添加同目录下的其他文件
        if len(related_files) < limit:
            for sibling in file_dir.iterdir():
                if len(related_files) >= limit:
                    break
                if sibling.is_file() and sibling != Path(file_path):
                    try:
                        with open(sibling, 'r', encoding='utf-8') as f:
                            content = f.read()
                        related_files.append({
                            "path": str(sibling),
                            "content": content[:1000]
                        })
                    except:
                        pass

        return related_files

    def _resolve_import_path(self, imp: str, base_dir: Path) -> Optional[Path]:
        """解析导入路径

        Args:
            imp: 导入路径
            base_dir: 基础目录

        Returns:
            解析后的路径
        """
        # 简单的路径解析逻辑
        imp_path = imp.replace('.', '/')
        
        # 尝试不同的文件扩展名
        extensions = ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.go', '.rb', '.php', '.swift', '.kt', '.rs']
        for ext in extensions:
            test_path = base_dir / f"{imp_path}{ext}"
            if test_path.exists():
                return test_path
            # 尝试目录下的index文件
            test_path = base_dir / imp_path / f"index{ext}"
            if test_path.exists():
                return test_path

        return None

    def _extract_function_calls(self, code_content: str, language: str) -> List[str]:
        """提取函数调用

        Args:
            code_content: 代码内容
            language: 语言

        Returns:
            函数调用列表
        """
        function_calls = []
        # 简单的函数调用正则
        pattern = r'([a-zA-Z_]\w*)\s*\('

        matches = re.findall(pattern, code_content)
        # 去重并限制数量
        unique_calls = list(set(matches))
        return unique_calls[:15]  # 限制函数调用数量
