"""语义分块器

实现基于代码结构的语义分块，提高检索的准确性和相关性。
"""

import re
from typing import List, Dict, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class SemanticChunker:
    """语义分块器

    根据代码结构（如函数、类、语句等）进行分块，保持代码的语义完整性。
    """

    def __init__(self):
        """初始化语义分块器"""
        # 代码语言的分块规则
        self.chunking_rules = {
            "python": {
                "function": r"def\s+\w+\s*\([^)]*\)\s*:\s*",
                "class": r"class\s+\w+\s*\([^)]*\)\s*:\s*",
                "import": r"import\s+\w+",
                "from": r"from\s+\w+\s+import\s+\w+"
            },
            "javascript": {
                "function": r"function\s+\w+\s*\([^)]*\)\s*{\s*",
                "class": r"class\s+\w+\s*{\s*",
                "import": r"import\s+.*\s+from\s+['\"].*['\"]",
                "require": r"const\s+\w+\s*=\s*require\(['\"].*['\"]\)"
            },
            "java": {
                "class": r"public\s+class\s+\w+\s*{\s*",
                "method": r"public\s+\w+\s+\w+\s*\([^)]*\)\s*{\s*",
                "import": r"import\s+.*;"
            },
            "c": {
                "function": r"\w+\s+\w+\s*\([^)]*\)\s*{\s*",
                "include": r"#include\s*<[^>]+>"
            },
            "cpp": {
                "function": r"\w+\s+\w+\s*\([^)]*\)\s*{\s*",
                "class": r"class\s+\w+\s*{\s*",
                "include": r"#include\s*<[^>]+>"
            }
        }

    def chunk_code(self, code: str, language: str = "python") -> List[Dict[str, Any]]:
        """对代码进行语义分块

        Args:
            code: 代码文本
            language: 代码语言

        Returns:
            分块列表
        """
        if not code:
            return []
        
        # 根据语言选择分块规则
        if language not in self.chunking_rules:
            # 回退到简单分块
            return self._simple_chunking(code)
        
        rules = self.chunking_rules[language]
        chunks = []
        
        # 按函数分块
        if "function" in rules:
            function_chunks = self._chunk_by_pattern(code, rules["function"], "function", language)
            chunks.extend(function_chunks)
        
        # 按类分块
        if "class" in rules:
            class_chunks = self._chunk_by_pattern(code, rules["class"], "class", language)
            chunks.extend(class_chunks)
        
        # 按导入语句分块
        if "import" in rules:
            import_chunks = self._chunk_by_pattern(code, rules["import"], "import", language)
            chunks.extend(import_chunks)
        
        # 如果没有匹配的分块，使用简单分块
        if not chunks:
            chunks = self._simple_chunking(code)
        
        # 去重
        chunks = self._deduplicate_chunks(chunks)
        
        return chunks

    def chunk_cve(self, cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """对 CVE 数据进行分块

        Args:
            cve_data: CVE 数据

        Returns:
            分块列表
        """
        chunks = []
        
        # 描述分块
        if "description" in cve_data:
            chunks.append({
                "type": "description",
                "content": cve_data["description"],
                "metadata": {"part": "description"}
            })
        
        # 漏洞利用分块
        if "exploit" in cve_data:
            chunks.append({
                "type": "exploit",
                "content": cve_data["exploit"],
                "metadata": {"part": "exploit"}
            })
        
        # 修复方案分块
        if "fix" in cve_data:
            chunks.append({
                "type": "fix",
                "content": cve_data["fix"],
                "metadata": {"part": "fix"}
            })
        
        # 影响范围分块
        if "affected" in cve_data:
            chunks.append({
                "type": "affected",
                "content": cve_data["affected"],
                "metadata": {"part": "affected"}
            })
        
        return chunks

    def chunk_ast(self, ast_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """对 AST 数据进行分块

        Args:
            ast_data: AST 数据

        Returns:
            分块列表
        """
        chunks = []
        
        # 调用链分块
        if "call_chain" in ast_data:
            for chain in ast_data["call_chain"]:
                chunks.append({
                    "type": "call_chain",
                    "content": " -> ".join(chain),
                    "metadata": {"part": "call_chain"}
                })
        
        # 函数定义分块
        if "functions" in ast_data:
            for func in ast_data["functions"]:
                chunks.append({
                    "type": "function_def",
                    "content": func,
                    "metadata": {"part": "function_def"}
                })
        
        # 变量定义分块
        if "variables" in ast_data:
            for var in ast_data["variables"]:
                chunks.append({
                    "type": "variable_def",
                    "content": var,
                    "metadata": {"part": "variable_def"}
                })
        
        return chunks

    def _chunk_by_pattern(self, code: str, pattern: str, chunk_type: str, language: str) -> List[Dict[str, Any]]:
        """根据正则表达式模式分块

        Args:
            code: 代码文本
            pattern: 正则表达式模式
            chunk_type: 分块类型
            language: 代码语言

        Returns:
            分块列表
        """
        chunks = []
        lines = code.split('\n')
        
        # 查找匹配的模式
        for i, line in enumerate(lines):
            if re.search(pattern, line):
                # 提取函数/类的完整定义
                start_line = i
                end_line = self._find_block_end(lines, i, language)
                
                # 提取内容
                content = '\n'.join(lines[start_line:end_line+1])
                
                chunks.append({
                    "type": chunk_type,
                    "content": content,
                    "metadata": {
                        "start_line": start_line + 1,
                        "end_line": end_line + 1,
                        "language": language
                    }
                })
        
        return chunks

    def _find_block_end(self, lines: List[str], start_line: int, language: str) -> int:
        """查找代码块的结束位置

        Args:
            lines: 代码行列表
            start_line: 起始行
            language: 代码语言

        Returns:
            结束行索引
        """
        # 缩进级别
        indent_level = self._get_indent_level(lines[start_line])
        
        # 查找结束位置
        end_line = start_line
        for i in range(start_line + 1, len(lines)):
            current_indent = self._get_indent_level(lines[i])
            if current_indent <= indent_level and lines[i].strip():
                break
            end_line = i
        
        return end_line

    def _get_indent_level(self, line: str) -> int:
        """获取行的缩进级别

        Args:
            line: 代码行

        Returns:
            缩进级别
        """
        return len(line) - len(line.lstrip())

    def _simple_chunking(self, text: str, chunk_size: int = 500, overlap: int = 50) -> List[Dict[str, Any]]:
        """简单分块（回退方案）

        Args:
            text: 文本
            chunk_size: 分块大小
            overlap: 重叠大小

        Returns:
            分块列表
        """
        chunks = []
        text_length = len(text)
        
        if text_length <= chunk_size:
            chunks.append({
                "type": "simple",
                "content": text,
                "metadata": {"size": text_length}
            })
            return chunks
        
        start = 0
        while start < text_length:
            end = min(start + chunk_size, text_length)
            content = text[start:end]
            
            chunks.append({
                "type": "simple",
                "content": content,
                "metadata": {
                    "start": start,
                    "end": end,
                    "size": len(content)
                }
            })
            
            start += chunk_size - overlap
        
        return chunks

    def _deduplicate_chunks(self, chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """去重分块

        Args:
            chunks: 分块列表

        Returns:
            去重后的分块列表
        """
        seen = set()
        unique_chunks = []
        
        for chunk in chunks:
            content = chunk["content"]
            if content not in seen:
                seen.add(content)
                unique_chunks.append(chunk)
        
        return unique_chunks

    def get_chunk_stats(self, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """获取分块统计信息

        Args:
            chunks: 分块列表

        Returns:
            统计信息
        """
        if not chunks:
            return {
                "total_chunks": 0,
                "avg_chunk_size": 0,
                "max_chunk_size": 0,
                "min_chunk_size": 0,
                "chunk_types": {}
            }
        
        chunk_sizes = [len(chunk["content"]) for chunk in chunks]
        chunk_types = {}
        
        for chunk in chunks:
            chunk_type = chunk.get("type", "unknown")
            if chunk_type not in chunk_types:
                chunk_types[chunk_type] = 0
            chunk_types[chunk_type] += 1
        
        return {
            "total_chunks": len(chunks),
            "avg_chunk_size": sum(chunk_sizes) / len(chunk_sizes),
            "max_chunk_size": max(chunk_sizes),
            "min_chunk_size": min(chunk_sizes),
            "chunk_types": chunk_types
        }
