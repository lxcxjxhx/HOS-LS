"""代码切片器模块

提供函数级代码切片功能，支持 Python、JavaScript、TypeScript 等语言。
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any
from enum import Enum


class Language(Enum):
    """支持的编程语言"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    UNKNOWN = "unknown"


@dataclass
class CodeSlice:
    """代码切片"""

    slice_id: str = ""
    file_path: str = ""
    language: Language = Language.UNKNOWN
    slice_type: str = ""  # "function", "class", "module"
    name: str = ""
    start_line: int = 0
    end_line: int = 0
    code: str = ""
    context: str = ""  # 上下文信息（导入、类定义等）
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "slice_id": self.slice_id,
            "file_path": self.file_path,
            "language": self.language.value,
            "slice_type": self.slice_type,
            "name": self.name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "code": self.code,
            "context": self.context,
            "metadata": self.metadata,
        }


class BaseCodeSlicer:
    """基础代码切片器"""

    def __init__(self, file_path: str, language: Language):
        self.file_path = file_path
        self.language = language
        self.lines: List[str] = []
        self.slices: List[CodeSlice] = []

    def load_file(self) -> bool:
        """加载文件内容"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                self.lines = f.readlines()
            return True
        except Exception as e:
            print(f"[ERROR] 加载文件失败 {self.file_path}: {e}")
            return False

    def slice(self) -> List[CodeSlice]:
        """执行切片（子类实现）"""
        raise NotImplementedError

    def _get_line_content(self, start: int, end: int) -> str:
        """获取指定行范围的内容"""
        if start < 0:
            start = 0
        if end > len(self.lines):
            end = len(self.lines)
        return ''.join(self.lines[start:end])

    def _generate_slice_id(self, slice_type: str, name: str, start_line: int) -> str:
        """生成切片 ID"""
        import hashlib
        content = f"{self.file_path}:{slice_type}:{name}:{start_line}"
        return hashlib.md5(content.encode()).hexdigest()[:12]


class PythonSlicer(BaseCodeSlicer):
    """Python 代码切片器"""

    def slice(self) -> List[CodeSlice]:
        """切片 Python 代码"""
        if not self.load_file():
            return []

        self.slices = []
        context_lines = []
        in_function = False
        in_class = False
        current_indent = 0
        function_start = 0
        function_name = ""
        class_start = 0
        class_name = ""

        for i, line in enumerate(self.lines):
            stripped = line.strip()

            # 收集上下文（导入、装饰器等）
            if not in_function and not in_class:
                if stripped.startswith(('import ', 'from ')) or stripped.startswith('@'):
                    context_lines.append(line)
                elif stripped and not stripped.startswith('#'):
                    # 遇到非空非注释行，重置上下文（保留最近的导入）
                    if len(context_lines) > 20:
                        context_lines = context_lines[-10:]

            # 检测函数定义
            if stripped.startswith('def ') or stripped.startswith('async def '):
                if in_function:
                    # 结束上一个函数
                    self._add_function_slice(function_name, function_start, i, context_lines)
                function_start = i
                function_name = self._extract_function_name(stripped)
                in_function = True
                current_indent = len(line) - len(line.lstrip())
                continue

            # 检测类定义
            if stripped.startswith('class '):
                if in_function:
                    self._add_function_slice(function_name, function_start, i, context_lines)
                    in_function = False
                if in_class:
                    self._add_class_slice(class_name, class_start, i, context_lines)
                class_start = i
                class_name = self._extract_class_name(stripped)
                in_class = True
                current_indent = len(line) - len(line.lstrip())
                continue

            # 检测函数/类结束（缩进减少）
            if in_function or in_class:
                if stripped and not stripped.startswith('#'):
                    indent = len(line) - len(line.lstrip())
                    if indent <= current_indent and not stripped.endswith(':'):
                        if in_function:
                            self._add_function_slice(function_name, function_start, i + 1, context_lines)
                            in_function = False
                        elif in_class and indent < current_indent:
                            self._add_class_slice(class_name, class_start, i, context_lines)
                            in_class = False

        # 处理文件末尾的函数/类
        if in_function:
            self._add_function_slice(function_name, function_start, len(self.lines), context_lines)
        if in_class:
            self._add_class_slice(class_name, class_start, len(self.lines), context_lines)

        # 如果没有找到函数/类，添加整个文件作为一个切片
        if not self.slices and self.lines:
            self._add_whole_file_slice(context_lines)

        return self.slices

    def _extract_function_name(self, line: str) -> str:
        """提取函数名"""
        match = re.search(r'(?:async\s+)?def\s+(\w+)', line)
        return match.group(1) if match else "unknown"

    def _extract_class_name(self, line: str) -> str:
        """提取类名"""
        match = re.search(r'class\s+(\w+)', line)
        return match.group(1) if match else "unknown"

    def _add_function_slice(self, name: str, start: int, end: int, context: List[str]):
        """添加函数切片"""
        code = self._get_line_content(start, end)
        context_str = ''.join(context[-10:])  # 保留最近 10 行上下文
        slice_id = self._generate_slice_id("function", name, start)
        self.slices.append(CodeSlice(
            slice_id=slice_id,
            file_path=self.file_path,
            language=Language.PYTHON,
            slice_type="function",
            name=name,
            start_line=start + 1,
            end_line=end,
            code=code,
            context=context_str,
            metadata={"has_async": "async" in self.lines[start]}
        ))

    def _add_class_slice(self, name: str, start: int, end: int, context: List[str]):
        """添加类切片"""
        code = self._get_line_content(start, end)
        context_str = ''.join(context[-10:])
        slice_id = self._generate_slice_id("class", name, start)
        self.slices.append(CodeSlice(
            slice_id=slice_id,
            file_path=self.file_path,
            language=Language.PYTHON,
            slice_type="class",
            name=name,
            start_line=start + 1,
            end_line=end,
            code=code,
            context=context_str,
            metadata={}
        ))

    def _add_whole_file_slice(self, context: List[str]):
        """添加整个文件切片"""
        code = ''.join(self.lines)
        slice_id = self._generate_slice_id("module", "whole_file", 0)
        self.slices.append(CodeSlice(
            slice_id=slice_id,
            file_path=self.file_path,
            language=Language.PYTHON,
            slice_type="module",
            name="whole_file",
            start_line=1,
            end_line=len(self.lines),
            code=code,
            context='',
            metadata={}
        ))


class JavaScriptSlicer(BaseCodeSlicer):
    """JavaScript/TypeScript 代码切片器"""

    def slice(self) -> List[CodeSlice]:
        """切片 JavaScript/TypeScript 代码"""
        if not self.load_file():
            return []

        self.slices = []
        context_lines = []
        function_stack = []
        class_stack = []
        brace_count = 0

        for i, line in enumerate(self.lines):
            stripped = line.strip()

            # 收集上下文
            if not function_stack and not class_stack:
                if stripped.startswith(('import ', 'export ', 'const ', 'let ', 'var ')):
                    context_lines.append(line)

            # 统计大括号
            brace_count += line.count('{') - line.count('}')

            # 检测函数定义
            func_match = self._match_function(stripped, i)
            if func_match:
                function_stack.append({
                    'name': func_match['name'],
                    'start': i,
                    'start_brace': brace_count - line.count('{')
                })

            # 检测类定义
            class_match = self._match_class(stripped, i)
            if class_match:
                class_stack.append({
                    'name': class_match['name'],
                    'start': i,
                    'start_brace': brace_count - line.count('{')
                })

            # 检测函数结束
            while function_stack and brace_count <= function_stack[-1]['start_brace']:
                func = function_stack.pop()
                self._add_function_slice(func['name'], func['start'], i + 1, context_lines)

            # 检测类结束
            while class_stack and brace_count <= class_stack[-1]['start_brace']:
                cls = class_stack.pop()
                self._add_class_slice(cls['name'], cls['start'], i + 1, context_lines)

        # 处理未闭合的函数/类
        for func in function_stack:
            self._add_function_slice(func['name'], func['start'], len(self.lines), context_lines)
        for cls in class_stack:
            self._add_class_slice(cls['name'], cls['start'], len(self.lines), context_lines)

        # 如果没有切片，添加整个文件
        if not self.slices and self.lines:
            self._add_whole_file_slice(context_lines)

        return self.slices

    def _match_function(self, line: str, line_num: int) -> Optional[Dict[str, str]]:
        """匹配函数定义"""
        patterns = [
            r'(?:async\s+)?function\s+(\w+)',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>)',
            r'(\w+)\s*:\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)',
        ]
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return {'name': match.group(1)}
        return None

    def _match_class(self, line: str, line_num: int) -> Optional[Dict[str, str]]:
        """匹配类定义"""
        match = re.search(r'class\s+(\w+)', line)
        if match:
            return {'name': match.group(1)}
        return None

    def _add_function_slice(self, name: str, start: int, end: int, context: List[str]):
        """添加函数切片"""
        code = self._get_line_content(start, end)
        context_str = ''.join(context[-10:])
        slice_id = self._generate_slice_id("function", name, start)
        self.slices.append(CodeSlice(
            slice_id=slice_id,
            file_path=self.file_path,
            language=self.language,
            slice_type="function",
            name=name,
            start_line=start + 1,
            end_line=end,
            code=code,
            context=context_str,
            metadata={}
        ))

    def _add_class_slice(self, name: str, start: int, end: int, context: List[str]):
        """添加类切片"""
        code = self._get_line_content(start, end)
        context_str = ''.join(context[-10:])
        slice_id = self._generate_slice_id("class", name, start)
        self.slices.append(CodeSlice(
            slice_id=slice_id,
            file_path=self.file_path,
            language=self.language,
            slice_type="class",
            name=name,
            start_line=start + 1,
            end_line=end,
            code=code,
            context=context_str,
            metadata={}
        ))

    def _add_whole_file_slice(self, context: List[str]):
        """添加整个文件切片"""
        code = ''.join(self.lines)
        slice_id = self._generate_slice_id("module", "whole_file", 0)
        self.slices.append(CodeSlice(
            slice_id=slice_id,
            file_path=self.file_path,
            language=self.language,
            slice_type="module",
            name="whole_file",
            start_line=1,
            end_line=len(self.lines),
            code=code,
            context='',
            metadata={}
        ))


def get_slicer(file_path: str, language: Optional[str] = None) -> BaseCodeSlicer:
    """获取对应的代码切片器"""
    if not language:
        language = _detect_language(file_path)

    lang_enum = Language(language) if language in [e.value for e in Language] else Language.UNKNOWN

    if lang_enum == Language.PYTHON:
        return PythonSlicer(file_path, lang_enum)
    elif lang_enum in [Language.JAVASCRIPT, Language.TYPESCRIPT]:
        return JavaScriptSlicer(file_path, lang_enum)
    else:
        return BaseCodeSlicer(file_path, lang_enum)


def _detect_language(file_path: str) -> str:
    """根据文件扩展名检测语言"""
    ext = Path(file_path).suffix.lower()
    if ext == '.py':
        return 'python'
    elif ext in ['.js', '.jsx']:
        return 'javascript'
    elif ext in ['.ts', '.tsx']:
        return 'typescript'
    elif ext == '.java':
        return 'java'
    return 'unknown'


def slice_code(file_path: str, language: Optional[str] = None) -> List[CodeSlice]:
    """切片代码文件的便捷函数"""
    slicer = get_slicer(file_path, language)
    return slicer.slice()
