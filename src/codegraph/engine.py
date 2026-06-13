"""CodeGraphEngine - 基于 AST 的代码调用图构建引擎

使用 Python ast 模块进行精确的函数定义和调用检测，
替代原有的正则表达式方案。
支持动态调用检测: getattr/eval/exec/__import__/importlib/反射
"""

import ast
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# 危险动态调用函数
_DYNAMIC_CALL_FUNCTIONS = frozenset({
    "eval", "exec", "compile", "__import__",
})

# 内置函数和关键字，不需要追踪
_BUILTIN_CALLS = frozenset({
    "print", "len", "range", "str", "int", "float", "list", "dict", "set",
    "tuple", "open", "isinstance", "hasattr", "getattr", "setattr", "type",
    "super", "repr", "abs", "all", "any", "bin", "bool", "bytes", "chr",
    "complex", "delattr", "dir", "divmod", "enumerate", "filter", "format",
    "frozenset", "globals", "hash", "hex", "id", "input", "iter", "locals",
    "map", "max", "min", "next", "oct", "ord", "pow", "property", "reversed",
    "round", "slice", "sorted", "staticmethod", "sum", "vars", "zip",
    "NotImplemented", "Ellipsis", "quit", "exit", "copyright", "credits",
    "license", "help",
})

_KEYWORDS = frozenset({
    "if", "for", "while", "with", "import", "from", "class", "def", "return",
    "lambda", "yield", "assert", "raise", "try", "except", "finally", "pass",
    "break", "continue", "in", "not", "and", "or", "is", "elif", "else",
    "async", "await",
})


class CodeGraphEngine:
    """基于 AST 的代码调用图构建引擎

    通过解析 Python AST 树，精确提取函数定义和调用关系，
    支持类方法、装饰器、嵌套函数等复杂场景。
    """

    def __init__(self):
        self._call_graph: Dict[str, List[str]] = {}
        self._import_map: Dict[str, Dict[str, str]] = {}  # file -> {alias: module}

    def build_call_graph(self, files: List[str]) -> Dict[str, List[str]]:
        """构建调用图

        Args:
            files: 源文件路径列表

        Returns:
            调用图字典: "file:func" -> ["file:callee1", ...]
        """
        self._call_graph = {}
        self._import_map = {}

        # 第一阶段: 解析所有文件，提取函数定义和导入
        func_defs: Dict[str, Set[str]] = {}  # func_name -> set of file_paths
        file_functions: List[Tuple[str, List[Dict]]] = []  # (file, [(func_key, calls, line_no)])

        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=file_path)
            except SyntaxError as e:
                logger.debug(f"AST parse failed for {file_path}: {e}, falling back to regex")
                self._fallback_regex(file_path)
                continue
            except Exception as e:
                logger.debug(f"Unexpected error parsing {file_path}: {e}")
                continue

            # 提取导入信息
            imports = self._extract_imports(tree)
            self._import_map[file_path] = imports

            # 提取函数定义和调用
            func_info = self._extract_functions(tree, file_path)
            file_functions.append((file_path, func_info))

            # 记录函数名到文件的映射
            for func_key, _, _ in func_info:
                func_name = func_key.split(":")[-1].split(".")[-1]
                func_defs.setdefault(func_name, set()).add(file_path)

        # 第二阶段: 构建调用图，解析调用目标
        for file_path, func_info in file_functions:
            for func_key, calls, _ in func_info:
                resolved_callees = []
                for call_name in calls:
                    # dynamic_call: 前缀的调用已经是最终标记，不需要解析
                    if call_name.startswith("dynamic_call:"):
                        resolved_callees.append(call_name)
                        continue
                    callee_key = self._resolve_call(
                        call_name, file_path, func_defs
                    )
                    if callee_key:
                        resolved_callees.append(callee_key)

                self._call_graph[func_key] = resolved_callees

        return self._call_graph

    def _extract_imports(self, tree: ast.Module) -> Dict[str, str]:
        """从 AST 中提取导入映射 {alias: module_name}"""
        imports: Dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imports[name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imports[name] = f"{module}.{alias.name}" if module else alias.name

        return imports

    def _extract_functions(
        self, tree: ast.Module, file_path: str
    ) -> List[Tuple[str, List[str], int]]:
        """提取所有函数定义及其调用

        Returns:
            [(func_key, [call_names], line_no), ...]
        """
        results: List[Tuple[str, List[str], int]] = []
        visitor = _FunctionVisitor(file_path)
        visitor.visit(tree)
        results.extend(visitor.function_calls)
        return results

    def _resolve_call(
        self,
        call_name: str,
        current_file: str,
        func_defs: Dict[str, Set[str]],
    ) -> Optional[str]:
        """解析调用目标为 "file:func" 格式"""
        if call_name in _BUILTIN_CALLS or call_name in _KEYWORDS:
            return None

        # 处理属性调用: obj.method -> 提取 method
        if "." in call_name:
            parts = call_name.split(".")
            base = parts[0]
            method = parts[-1]

            # 如果是 self.method 或 cls.method，查找当前文件中的方法
            if base in ("self", "cls"):
                # 查找当前文件中同名的方法
                for fname, file_set in func_defs.items():
                    if fname == method and current_file in file_set:
                        return f"{current_file}:{method}"
                return None

            # 如果是导入的模块调用: module.func
            imports = self._import_map.get(current_file, {})
            if base in imports:
                module_path = imports[base]
                # 尝试找到对应的文件
                module_file = self._module_to_file(module_path, Path(current_file).parent)
                if module_file and module_file in [f for f_set in func_defs.values() for f in f_set]:
                    return f"{module_file}:{method}"
                return f"{module_path}:{method}"

            # 一般属性调用，无法精确解析
            return None

        # 普通函数调用
        if call_name in func_defs:
            file_set = func_defs[call_name]
            if len(file_set) == 1:
                target_file = next(iter(file_set))
                return f"{target_file}:{call_name}"
            # 多定义情况，优先选择同文件
            if current_file in file_set:
                return f"{current_file}:{call_name}"
            # 选择第一个
            target_file = sorted(file_set)[0]
            return f"{target_file}:{call_name}"

        return None

    def _module_to_file(self, module_path: str, base_dir: Path) -> Optional[str]:
        """将模块路径转换为文件路径"""
        parts = module_path.split(".")
        # 尝试多种可能的路径
        candidates = [
            base_dir / f"{parts[-1]}.py",
            base_dir / parts[-1] / "__init__.py",
            base_dir / ".." / f"{parts[-1]}.py",
            base_dir / ".." / parts[-1] / "__init__.py",
        ]

        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved.exists() and resolved.is_file():
                return str(resolved)

        return None

    def _fallback_regex(self, file_path: str) -> None:
        """AST 解析失败时回退到正则表达式"""
        path = Path(file_path)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            lines = content.split("\n")

            def_pattern = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")
            call_pattern = re.compile(r"(?:^|\s)(\w+)\s*\(")

            current_func: Optional[str] = None
            file_calls: Set[str] = set()

            for line in lines:
                def_match = def_pattern.search(line)
                if def_match:
                    func_name = def_match.group(1)
                    if func_name:
                        current_func = f"{file_path}:{func_name}"
                        if current_func not in self._call_graph:
                            self._call_graph[current_func] = []

                for call_match in call_pattern.finditer(line):
                    call_name = call_match.group(1)
                    if call_name and call_name not in _BUILTIN_CALLS and call_name not in _KEYWORDS:
                        file_calls.add(call_name)

            if current_func:
                self._call_graph[current_func] = list(file_calls)

        except Exception as e:
            logger.debug(f"Regex fallback failed for {file_path}: {e}")


class _FunctionVisitor(ast.NodeVisitor):
    """AST 访问器，提取函数定义和调用"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.function_calls: List[Tuple[str, List[str], int]] = []
        self._class_stack: List[str] = []  # 当前类名栈
        self._func_stack: List[str] = []  # 当前函数名栈

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._process_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._process_function(node)

    def _process_function(self, node) -> None:
        func_name = node.name
        # 如果在类中，使用 ClassName.method_name 格式
        if self._class_stack:
            func_key = f"{self.file_path}:{'.'.join(self._class_stack)}.{func_name}"
        else:
            func_key = f"{self.file_path}:{func_name}"

        # 提取函数体内的所有调用
        calls = self._extract_calls_from_node(node)

        # 提取装饰器调用
        for dec in getattr(node, 'decorator_list', []):
            dec_name = self._get_decorator_name(dec)
            if dec_name and dec_name not in calls:
                calls.append(dec_name)

        self.function_calls.append((func_key, calls, node.lineno))

        # 进入函数作用域
        self._func_stack.append(func_name)
        # 访问函数体（但不递归进入嵌套函数定义）
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.visit(child)
        self._func_stack.pop()

    def _extract_calls_from_node(self, node: ast.AST) -> List[str]:
        """从 AST 节点中提取所有函数调用，包含动态调用检测"""
        calls: List[str] = []
        seen: Set[str] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name and call_name not in seen:
                    seen.add(call_name)
                    calls.append(call_name)
                # 动态调用检测
                dynamic_label = self._detect_dynamic_call(child)
                if dynamic_label and dynamic_label not in seen:
                    seen.add(dynamic_label)
                    calls.append(dynamic_label)

        return calls

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """从 Call 节点中提取调用名称"""
        func = node.func

        if isinstance(func, ast.Name):
            return func.id

        elif isinstance(func, ast.Attribute):
            # 处理 obj.method() 形式
            parts = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
            return None

        elif isinstance(func, ast.Subscript):
            # self.__dict__[key]() 或 obj[key]() 模式
            base = self._get_subscript_base(func)
            if base:
                return f"{base}[dynamic]"
            return None

        return None

    def _get_subscript_base(self, node: ast.Subscript) -> Optional[str]:
        """获取 Subscript 节点的基础名称"""
        value = node.value
        if isinstance(value, ast.Attribute):
            parts = []
            current = value
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        elif isinstance(value, ast.Name):
            return value.id
        return None

    def _get_decorator_name(self, node) -> Optional[str]:
        """从装饰器节点提取名称"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        elif isinstance(node, ast.Call):
            return self._get_decorator_name(node.func)
        return None

    def _detect_dynamic_call(self, node: ast.Call) -> Optional[str]:
        """检测动态调用模式，返回 special label

        检测:
        - getattr(obj, name)() 动态方法调用
        - eval()/exec()/compile() 代码执行
        - __import__()/importlib.import_module() 动态导入
        - self.__dict__[key]() / obj[key]() 字典式调用
        """
        func = node.func

        # 1. eval/exec/compile/__import__ 直接调用
        if isinstance(func, ast.Name) and func.id in _DYNAMIC_CALL_FUNCTIONS:
            return f"dynamic_call:{func.id}"

        # 2. getattr(obj, method_name) 调用
        if isinstance(func, ast.Name) and func.id == "getattr":
            return "dynamic_call:getattr"

        # 3. importlib.import_module() / importlib.__import__()
        if isinstance(func, ast.Attribute) and func.attr == "import_module":
            if isinstance(func.value, ast.Name) and func.value.id == "importlib":
                return "dynamic_call:importlib.import_module"

        # 4. self.__dict__[key]() / obj[key]() 字典式动态调用
        if isinstance(func, ast.Subscript):
            if isinstance(func.value, ast.Attribute) and func.value.attr == "__dict__":
                return "dynamic_call:__dict__"
            if isinstance(func.value, ast.Name) and func.value.id in ("self", "cls"):
                return "dynamic_call:dict_access"

        # 5. operator.methodcaller() / operator.attrgetter()
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "operator":
                if func.attr in ("methodcaller", "attrgetter"):
                    return f"dynamic_call:operator.{func.attr}"

        return None
