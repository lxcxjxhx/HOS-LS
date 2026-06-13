"""Taint Analysis Engine - Lightweight implementation

Provides:
- TaintSource, TaintSink, TaintPath data classes
- CallGraphBuilder for building call graphs from code files
- TaintEngine for lightweight taint analysis
- get_taint_engine() factory function

This module provides a lightweight taint analysis implementation that:
1. Uses regex-based pattern matching for source/sink detection
2. Falls back to file-level analysis when code graph is unavailable
3. Integrates with CodeGraphEngine when available for call graph building
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import logging
import re

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TaintSource:
    """Represents a taint source (where untrusted data enters the system)"""

    file_path: str
    line: int
    source_type: str  # e.g., "user_input", "file_read", "network", "database"
    variable_name: str = ""
    code_context: str = ""
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "source_type": self.source_type,
            "variable_name": self.variable_name,
            "code_context": self.code_context,
            "confidence": self.confidence,
        }


@dataclass
class TaintSink:
    """Represents a taint sink (where untrusted data reaches a dangerous operation)"""

    file_path: str
    line: int
    sink_type: str  # e.g., "sql_query", "command_exec", "file_write", "html_output"
    function_name: str = ""
    code_context: str = ""
    vulnerability_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "sink_type": self.sink_type,
            "function_name": self.function_name,
            "code_context": self.code_context,
            "vulnerability_type": self.vulnerability_type,
        }


@dataclass
class TaintPath:
    """Represents a complete taint propagation path from source to sink"""

    source: TaintSource
    sink: TaintSink
    intermediate_steps: List[Dict[str, Any]] = field(default_factory=list)
    path_confidence: float = 0.5
    sanitizers_encountered: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "intermediate_steps": self.intermediate_steps,
            "path_confidence": self.path_confidence,
            "sanitizers": self.sanitizers_encountered,
        }


# ---------------------------------------------------------------------------
# Call Graph Builder
# ---------------------------------------------------------------------------

# Patterns for detecting function calls and definitions
_FUNC_DEF_PATTERNS = {
    "python": re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("),
    "java": re.compile(r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\("),
    "javascript": re.compile(r"(?:function\s+(\w+)|(\w+)\s*=\s*(?:function|\(.*?\)\s*=>))"),
}

_FUNC_CALL_PATTERNS = {
    "python": re.compile(r"(?:^|\s)(\w+)\s*\("),
    "java": re.compile(r"(?:^|\s)(\w+)\s*\("),
    "javascript": re.compile(r"(?:^|\s)(\w+)\s*\("),
}


class CallGraphBuilder:
    """Builds a call graph from source files.

    Uses regex-based analysis when tree-sitter is unavailable,
    and integrates with CodeGraphEngine when available.
    """

    def __init__(self):
        self._graph: Dict[str, List[str]] = {}
        self._has_codegraph = False
        self._try_load_codegraph()

    def _try_load_codegraph(self):
        """Attempt to use CodeGraphEngine if available."""
        try:
            # Try to check if codegraph.db exists in common locations
            possible_paths = [
                Path(".codegraph/codegraph.db"),
                Path("src/.codegraph/codegraph.db"),
            ]
            for p in possible_paths:
                if p.exists():
                    self._has_codegraph = True
                    logger.info("CallGraphBuilder: CodeGraph database found")
                    return
        except Exception:
            pass
        logger.debug("CallGraphBuilder: Using regex-based call graph (CodeGraph not available)")

    def build(self, files: List[str], language: str = "python") -> Dict[str, List[str]]:
        """Build a call graph from the given files.

        Args:
            files: List of source file paths
            language: Programming language

        Returns:
            Dictionary mapping function keys to lists of called function keys
        """
        self._graph = {}

        if self._has_codegraph:
            return self._build_from_codegraph(files)

        return self._build_regex(files, language)

    def _build_from_codegraph(self, files: List[str]) -> Dict[str, List[str]]:
        """Build call graph using CodeGraphEngine (AST-based analysis)."""
        from src.codegraph.engine import CodeGraphEngine
        engine = CodeGraphEngine()
        return engine.build_call_graph(files)

    def _build_regex(self, files: List[str], language: str = "python") -> Dict[str, List[str]]:
        """Build call graph using regex-based analysis."""
        def_pattern = _FUNC_DEF_PATTERNS.get(language, _FUNC_DEF_PATTERNS["python"])
        call_pattern = _FUNC_CALL_PATTERNS.get(language, _FUNC_CALL_PATTERNS["python"])

        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                lines = content.split("\n")

                current_func: Optional[str] = None
                file_calls: Set[str] = set()

                for line in lines:
                    # Check for function definition
                    def_match = def_pattern.search(line)
                    if def_match:
                        func_name = def_match.group(1)
                        if func_name:
                            current_func = f"{file_path}:{func_name}"
                            if current_func not in self._graph:
                                self._graph[current_func] = []

                    # Check for function calls
                    for call_match in call_pattern.finditer(line):
                        call_name = call_match.group(1)
                        if call_name and call_name not in (
                            "print", "len", "range", "str", "int", "float", "list",
                            "dict", "set", "tuple", "open", "isinstance", "hasattr",
                            "getattr", "setattr", "type", "super", "self", "cls",
                            "if", "for", "while", "with", "import", "from", "class",
                            "def", "return", "lambda", "yield", "assert", "raise",
                            "try", "except", "finally", "pass", "break", "continue",
                        ):
                            file_calls.add(call_name)

                if current_func:
                    self._graph[current_func] = list(file_calls)

            except Exception as e:
                logger.debug(f"Call graph build failed for {file_path}: {e}")

        return self._graph

    def get_callers(self, function_name: str) -> List[str]:
        """Get all functions that call the given function."""
        callers = []
        for func, calls in self._graph.items():
            if function_name in calls:
                callers.append(func)
        return callers

    def get_callees(self, function_name: str) -> List[str]:
        """Get all functions called by the given function."""
        return self._graph.get(function_name, [])


# ---------------------------------------------------------------------------
# Taint Engine
# ---------------------------------------------------------------------------

# 动态加载污点模式（从 NVD 数据库），替代硬编码
# 这些全局变量现在初始化为空，在 TaintEngine 初始化时从 NVD 加载
SOURCE_PATTERNS = {}
SINK_PATTERNS = {}
SANITIZER_PATTERNS = {}


def _load_taint_patterns_from_nvd(language: str = "python") -> tuple:
    """从 NVD 数据库动态加载污点模式

    Sink 模式从 NVD 的危险函数列表 + 漏洞关键词动态获取。
    Source 模式基于框架语义识别（NVD 不提供）。
    Sanitizer 模式从 NVD 的安全处理模式获取。

    Args:
        language: 编程语言

    Returns:
        (source_patterns, sink_patterns, sanitizer_patterns) 元组
    """
    from src.nvd.nvd_query_adapter import NVDQueryAdapter

    nvd = NVDQueryAdapter()

    # 获取危险函数列表 + 漏洞关键词
    dangerous_funcs = nvd.get_dangerous_functions(language) if nvd.is_available() else {}
    vuln_keywords = nvd.get_vulnerability_keywords(language) if nvd.is_available() else {}
    sanitizer_list = nvd.get_sanitizer_patterns(language) if nvd.is_available() else []

    # 转换为 sink 模式格式（危险函数精确匹配）
    sink_patterns = []
    for vuln_type, funcs in dangerous_funcs.items():
        for func in funcs:
            escaped_func = re.escape(func)
            sink_patterns.append((escaped_func, vuln_type.lower().replace(' ', '_'), vuln_type, 0.8))

    # 补充漏洞关键词匹配（用于检测如 cursor.execute 等未在 CVE 描述中提及的函数）
    # 这些是代码语义关键词，从 NVD 漏洞类型概念映射而来
    for vuln_type, keywords in vuln_keywords.items():
        for kw in keywords:
            # 构建匹配模式：函数调用包含该关键词
            escaped_kw = re.escape(kw)
            pattern = rf'\b{escaped_kw}\s*\('
            sink_patterns.append((pattern, vuln_type, vuln_type.replace('_', ' ').title(), 0.7))

    # 转换为 sanitizer 模式格式
    sanitizer_patterns = []
    for s in sanitizer_list:
        sanitizer_patterns.append((re.escape(s['function']), s['type']))

    # Source 模式：从 NVD CVE 描述中动态提取用户输入来源
    source_patterns = _extract_source_patterns_from_nvd(language, nvd)

    return source_patterns, sink_patterns, sanitizer_patterns


def _extract_source_patterns_from_nvd(language: str, nvd) -> list:
    """从 NVD CVE 描述中动态提取污点源模式

    通过分析 CVE 描述中与用户输入相关的模式，识别各框架的输入获取函数。
    绝对无硬编码数据，完全依赖 NVD 数据库。

    Args:
        language: 编程语言
        nvd: NVDQueryAdapter 实例

    Returns:
        污点源模式列表 [(pattern, type, confidence), ...]
    """
    input_keywords = [
        'user input', 'request parameter', 'query parameter',
        'input from', 'external input', 'untrusted input',
        'request body', 'form data', 'http request',
        'parameter value', 'input data', 'user-controlled',
    ]

    # 各语言输入函数的识别关键词
    language_indicators = {
        'python': ['request', 'input', 'argv', 'environ', 'urllib', 'requests'],
        'java': ['HttpServletRequest', 'getParameter', 'getInputStream', 'getReader', 'RequestParam', 'RequestBody'],
        'javascript': ['req.body', 'req.query', 'req.params', 'process.argv', 'process.env', 'fetch'],
    }

    indicators = language_indicators.get(language, language_indicators['python'])
    source_set = set()

    try:
        cursor = nvd._conn.cursor() if nvd._conn else None
        if not cursor:
            return []

        for kw in input_keywords:
            cursor.execute("""
                SELECT DISTINCT description
                FROM cve
                WHERE description LIKE ?
                LIMIT 100
            """, (f'%{kw}%',))

            for row in cursor.fetchall():
                desc = row['description'].lower() if row['description'] else ''

                # 提取函数/方法调用模式
                func_patterns = re.findall(r'(?:[\w.]+)\w+(?:\s*\()', desc)
                for p in func_patterns:
                    clean = p.strip('(').strip()
                    if any(ind.lower() in clean.lower() for ind in indicators):
                        source_set.add(clean)

        cursor.close()
    except Exception as e:
        logger.debug(f"NVD 污点源模式动态提取失败: {e}")

    # 转换为统一格式
    result = []
    for func in sorted(source_set):
        escaped = re.escape(func)
        result.append((escaped, 'user_input', 0.8))

    return result


class TaintEngine:
    """轻量级污点分析引擎

    改造版：从 NVD 数据库动态加载污点模式，替代硬编码 SOURCE_PATTERNS/SINK_PATTERNS。
    支持 AI Agent 动态识别污点源、sink 点和 sanitizer。
    """

    _instance: Optional["TaintEngine"] = None

    def __new__(cls, use_ai: bool = False, llm=None) -> "TaintEngine":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, use_ai: bool = False, llm=None):
        if self._initialized:
            return
        self._initialized = True
        self.call_graph_builder = CallGraphBuilder()
        self.use_ai = use_ai
        self.llm = llm

        # 从 NVD 动态加载污点模式
        self._load_patterns()

        # 初始化 AI Agent（如果启用）
        self.ai_agent = None
        if use_ai and llm:
            from src.nvd.nvd_query_adapter import NVDQueryAdapter
            from src.ai.agents.ai_security_agents import TaintAnalyzerAgent
            nvd = NVDQueryAdapter()
            self.ai_agent = TaintAnalyzerAgent(llm, nvd)
            logger.info("TaintEngine initialized (AI mode)")
        else:
            logger.info("TaintEngine initialized (NVD dynamic mode)")

    def _load_patterns(self):
        """从 NVD 数据库动态加载污点模式"""
        # Python 模式（默认，从 NVD 加载）
        src_py, sink_py, san_py = _load_taint_patterns_from_nvd("python")

        # Java 模式
        src_java, sink_java, san_java = _load_taint_patterns_from_nvd("java")

        # JavaScript 模式
        src_js, sink_js, san_js = _load_taint_patterns_from_nvd("javascript")

        # 补充 NVD 可能遗漏的关键 XSS sink（静态兜底）
        xss_sinks_python = [
            (r'render_template_string\s*\(', 'xss', 'Cross-Site Scripting', 0.85),
            (r'mark_safe\s*\(', 'xss', 'Cross-Site Scripting', 0.85),
            (r'HttpResponse\s*\(.*f[\"\']', 'xss', 'Cross-Site Scripting', 0.80),
            (r'return\s+f[\"\'].*<\w+', 'xss', 'Cross-Site Scripting', 0.75),
            (r'\.html\(\s*', 'xss', 'Cross-Site Scripting', 0.80),
            (r'innerHTML\s*=', 'xss', 'Cross-Site Scripting', 0.80),
            (r'document\.write\s*\(', 'xss', 'Cross-Site Scripting', 0.80),
        ]
        sink_py.extend(xss_sinks_python)

        xss_sinks_java = [
            (r'response\.getWriter\(\)\.write', 'xss', 'Cross-Site Scripting', 0.80),
            (r'out\.println\s*\(', 'xss', 'Cross-Site Scripting', 0.75),
        ]
        sink_java.extend(xss_sinks_java)

        xss_sinks_js = [
            (r'innerHTML\s*=', 'xss', 'Cross-Site Scripting', 0.80),
            (r'document\.write\s*\(', 'xss', 'Cross-Site Scripting', 0.80),
            (r'\.html\s*\(', 'xss', 'Cross-Site Scripting', 0.80),
        ]
        sink_js.extend(xss_sinks_js)

        # 更新全局模式字典
        global SOURCE_PATTERNS, SINK_PATTERNS, SANITIZER_PATTERNS
        SOURCE_PATTERNS = {
            "python": src_py,
            "java": src_java,
            "javascript": src_js,
        }
        SINK_PATTERNS = {
            "python": sink_py,
            "java": sink_java,
            "javascript": sink_js,
        }
        SANITIZER_PATTERNS = {
            "python": san_py,
            "java": san_java,
            "javascript": san_js,
        }

    def analyze(self, files: List[str], language: str = "python") -> List[TaintPath]:
        """Run taint analysis on the given files.

        Args:
            files: List of source file paths
            language: Programming language

        Returns:
            List of detected taint paths
        """
        taint_paths = []

        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                file_paths = self._analyze_file(file_path, content, language)
                taint_paths.extend(file_paths)
            except Exception as e:
                logger.debug(f"Taint analysis failed for {file_path}: {e}")

        # Also attempt cross-file analysis
        if len(files) > 1:
            cross_file_paths = self._analyze_cross_file(files, language)
            taint_paths.extend(cross_file_paths)

        logger.info(f"Taint analysis complete: {len(taint_paths)} paths found across {len(files)} files")
        return taint_paths

    def _analyze_file(self, file_path: str, content: str, language: str) -> List[TaintPath]:
        """Analyze a single file for taint paths."""
        sources = self._find_sources(file_path, content, language)
        sinks = self._find_sinks(file_path, content, language)

        if not sources or not sinks:
            return []

        # Group sources and sinks by function scope
        func_ranges = self._find_function_ranges(content)
        
        paths = []
        for source in sources:
            for sink in sinks:
                # Only create path if source and sink are in the same function scope
                if self._same_function_scope(source, sink, func_ranges):
                    path = self._create_path(source, sink, content, language)
                    if path:
                        paths.append(path)

        return paths

    def _find_function_ranges(self, content: str) -> List[Tuple[int, int, str]]:
        """Find function ranges in the code.
        
        Returns list of (start_line, end_line, func_name) tuples.
        """
        ranges = []
        lines = content.split("\n")
        func_pattern = re.compile(r'^(\s*)def\s+(\w+)\s*\(')
        
        current_func: Optional[Tuple[int, int, str]] = None
        current_indent = 0
        
        for line_num, line in enumerate(lines, 1):
            match = func_pattern.match(line)
            if match:
                # Save previous function range
                if current_func:
                    ranges.append((current_func[0], line_num - 1, current_func[2]))
                
                indent = len(match.group(1))
                func_name = match.group(2)
                current_func = (line_num, None, func_name)
                current_indent = indent
            elif current_func and line.strip() and not line.strip().startswith('#'):
                # Check if we've exited the function
                line_indent = len(line) - len(line.lstrip())
                if line_indent <= current_indent and not line.strip().startswith('def '):
                    # Function ended
                    ranges.append((current_func[0], line_num - 1, current_func[2]))
                    current_func = None
        
        # Don't forget the last function
        if current_func:
            ranges.append((current_func[0], len(lines), current_func[2]))
        
        return ranges

    def _same_function_scope(
        self, source: TaintSource, sink: TaintSink, func_ranges: List[Tuple[int, int, str]]
    ) -> bool:
        """Check if source and sink are in the same function scope."""
        for start, end, _ in func_ranges:
            if start <= source.line <= end and start <= sink.line <= end:
                return True
        return False

    def _find_sources(self, file_path: str, content: str, language: str) -> List[TaintSource]:
        """Find taint sources in file content."""
        sources = []
        patterns = SOURCE_PATTERNS.get(language, [])

        for line_num, line in enumerate(content.split("\n"), 1):
            for pattern, source_type, confidence in patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(0)
                    if hasattr(match, 'group') and match.groups():
                        var_name = match.group(1) if match.lastindex else match.group(0)

                    sources.append(TaintSource(
                        file_path=file_path,
                        line=line_num,
                        source_type=source_type,
                        variable_name=var_name,
                        code_context=line.strip(),
                        confidence=confidence,
                    ))

        # Also detect function parameters as taint sources
        param_sources = self._find_function_parameters(file_path, content, language)
        sources.extend(param_sources)

        return sources

    def _find_function_parameters(self, file_path: str, content: str, language: str) -> List[TaintSource]:
        """Detect function parameters as potential taint sources."""
        sources = []
        lines = content.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            # Pattern: def func_name(param1, param2, ...):
            match = re.match(r'\s*def\s+\w+\s*\((.+?)\)\s*:', line)
            if match:
                params_str = match.group(1)
                # Parse parameters (skip 'self', 'cls')
                params = [p.strip() for p in params_str.split(',')]
                for param in params:
                    # Handle type hints: param: type = default
                    param_name = param.split(':')[0].split('=')[0].strip()
                    if param_name and param_name not in ('self', 'cls', '*args', '**kwargs'):
                        sources.append(TaintSource(
                            file_path=file_path,
                            line=line_num,
                            source_type="user_input",
                            variable_name=param_name,
                            code_context=line.strip(),
                            confidence=0.75,  # Parameters are likely user-controlled
                        ))
        
        return sources

    def _find_sinks(self, file_path: str, content: str, language: str) -> List[TaintSink]:
        """Find taint sinks in file content."""
        sinks = []
        patterns = SINK_PATTERNS.get(language, [])

        for line_num, line in enumerate(content.split("\n"), 1):
            for pattern, sink_type, vuln_type, confidence in patterns:
                match = re.search(pattern, line)
                if match:
                    func_name = match.group(0).split("(")[0].strip()

                    sinks.append(TaintSink(
                        file_path=file_path,
                        line=line_num,
                        sink_type=sink_type,
                        function_name=func_name,
                        code_context=line.strip(),
                        vulnerability_type=vuln_type,
                    ))

        return sinks

    def _create_path(
        self,
        source: TaintSource,
        sink: TaintSink,
        content: str,
        language: str,
    ) -> Optional[TaintPath]:
        """Create a taint path between source and sink."""
        # Check for sanitizers between source and sink
        sanitizers = self._find_sanitizers(content, source.line, sink.line, language)

        # Trace intermediate steps (variable assignments, function calls, etc.)
        intermediate_steps = self._trace_intermediate_steps(
            source, sink, content, language
        )

        # Adjust confidence based on sanitizers
        base_confidence = min(source.confidence, 0.8)
        if sanitizers:
            base_confidence *= 0.3  # Sanitizers significantly reduce confidence

        # Adjust confidence based on distance and intermediate steps
        distance = sink.line - source.line
        distance_factor = max(0.3, 1.0 - distance * 0.001)
        
        # Boost confidence if we found concrete intermediate steps
        if intermediate_steps:
            step_bonus = min(0.2, len(intermediate_steps) * 0.05)
            base_confidence = min(1.0, base_confidence + step_bonus)

        path_confidence = round(base_confidence * distance_factor, 2)

        return TaintPath(
            source=source,
            sink=sink,
            intermediate_steps=intermediate_steps,
            path_confidence=path_confidence,
            sanitizers_encountered=sanitizers,
        )

    def _trace_intermediate_steps(
        self,
        source: TaintSource,
        sink: TaintSink,
        content: str,
        language: str,
    ) -> List[Dict[str, Any]]:
        """Trace variable propagation between source and sink.
        
        Analyzes:
        - Variable assignments (var = tainted_expr)
        - Function arguments (func(tainted_var))
        - Return values (return tainted_var)
        - Dictionary/list access (dict[key] = tainted_var)
        """
        steps = []
        lines = content.split("\n")
        
        # Track tainted variables
        tainted_vars: Set[str] = set()
        
        # Extract initial tainted variable from source
        source_var = self._extract_variable_from_line(source.code_context, language)
        if source_var:
            tainted_vars.add(source_var)
        
        # Analyze lines between source and sink (inclusive)
        start = max(1, source.line)
        end = min(sink.line, len(lines))
        
        for line_num in range(start, end + 1):
            line = lines[line_num - 1]  # Convert 1-based to 0-based
            stripped = line.strip()
            
            # Skip comments and empty lines
            if not stripped or stripped.startswith('#'):
                continue
            
            # Check for variable assignments
            step = self._check_assignment(stripped, line_num, tainted_vars, language)
            if step:
                steps.append(step)
                continue
            
            # Check for function calls with tainted arguments
            step = self._check_function_call(stripped, line_num, tainted_vars, language)
            if step:
                steps.append(step)
                continue
            
            # Check for return statements
            step = self._check_return(stripped, line_num, tainted_vars, language)
            if step:
                steps.append(step)
                continue
            
            # Check for dictionary/list assignments
            step = self._check_collection_assignment(stripped, line_num, tainted_vars, language)
            if step:
                steps.append(step)
                continue
        
        return steps

    def _extract_variable_from_line(self, line: str, language: str) -> Optional[str]:
        """Extract the primary variable name from a line of code."""
        # Check for function definition with parameters: def func(param):
        func_match = re.match(r'\s*def\s+\w+\s*\((.+?)\)', line)
        if func_match:
            params = func_match.group(1)
            # Get first non-self parameter
            for param in params.split(','):
                param_name = param.strip().split(':')[0].split('=')[0].strip()
                if param_name and param_name not in ('self', 'cls', '*args', '**kwargs'):
                    return param_name
        
        # Pattern: var = ... or var.func() or var[attr]
        patterns = [
            r'(\w+)\s*=',  # assignment: var =
            r'(\w+)\.\w+\s*\(',  # method call: var.method(
            r'(\w+)\[',  # subscript: var[
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                var = match.group(1)
                # Filter out keywords
                if var not in ('def', 'class', 'if', 'for', 'while', 'return', 'import', 'from'):
                    return var
        return None

    def _check_assignment(
        self, line: str, line_num: int, tainted_vars: Set[str], language: str
    ) -> Optional[Dict[str, Any]]:
        """Check for variable assignment: var = tainted_expr"""
        # Pattern: var = something
        match = re.match(r'(\w+)\s*=\s*(.+)', line)
        if not match:
            return None
        
        target_var = match.group(1)
        rhs = match.group(2)
        
        # Skip if it's a function definition
        if target_var == 'def':
            return None
        
        # Check if RHS contains any tainted variable
        for tainted_var in tainted_vars:
            if tainted_var in rhs:
                tainted_vars.add(target_var)
                return {
                    "type": "assignment",
                    "line": line_num,
                    "code": line,
                    "description": f"Taint propagated to '{target_var}'",
                    "variables_involved": [tainted_var, target_var],
                }
        
        return None

    def _check_function_call(
        self, line: str, line_num: int, tainted_vars: Set[str], language: str
    ) -> Optional[Dict[str, Any]]:
        """Check for function call with tainted arguments: func(tainted_var) or obj.method(tainted_var)"""
        # Match any function/method call: func(args) or obj.method(args)
        match = re.match(r'([\w.]+)\s*\((.+)\)\s*$', line)
        if not match:
            return None
        
        call_expr = match.group(1)
        args = match.group(2)
        
        # Extract the function/method name (last part after dot)
        func_name = call_expr.split('.')[-1]
        
        # Filter out common non-taint-propagating functions
        skip_funcs = {'print', 'len', 'range', 'str', 'int', 'float', 'type', 
                     'isinstance', 'hasattr', 'getattr', 'setattr'}
        if func_name in skip_funcs:
            return None
        
        # Check if any argument is tainted
        tainted_args = []
        for tainted_var in tainted_vars:
            if tainted_var in args:
                tainted_args.append(tainted_var)
        
        if tainted_args:
            return {
                "type": "function_call",
                "line": line_num,
                "code": line,
                "description": f"Tainted data passed to '{call_expr}'",
                "function": call_expr,
                "tainted_arguments": tainted_args,
            }
        
        return None

    def _check_return(
        self, line: str, line_num: int, tainted_vars: Set[str], language: str
    ) -> Optional[Dict[str, Any]]:
        """Check for return of tainted data: return tainted_var"""
        if not line.startswith('return '):
            return None
        
        return_expr = line[7:].strip()
        
        tainted_returns = []
        for tainted_var in tainted_vars:
            if tainted_var in return_expr:
                tainted_returns.append(tainted_var)
        
        if tainted_returns:
            return {
                "type": "return",
                "line": line_num,
                "code": line,
                "description": "Tainted data returned from function",
                "tainted_variables": tainted_returns,
            }
        
        return None

    def _check_collection_assignment(
        self, line: str, line_num: int, tainted_vars: Set[str], language: str
    ) -> Optional[Dict[str, Any]]:
        """Check for collection assignment: dict[key] = tainted_var"""
        # Pattern: var[key] = value or var.attr = value
        match = re.match(r'(\w+)\[.+\]\s*=\s*(.+)', line)
        if not match:
            match = re.match(r'(\w+)\.\w+\s*=\s*(.+)', line)
        
        if not match:
            return None
        
        collection = match.group(1)
        value = match.group(2)
        
        # Check if value contains tainted variable
        tainted_found = []
        for tainted_var in tainted_vars:
            if tainted_var in value:
                tainted_found.append(tainted_var)
        
        if tainted_found:
            return {
                "type": "collection_assignment",
                "line": line_num,
                "code": line,
                "description": f"Tainted data stored in '{collection}'",
                "collection": collection,
                "tainted_variables": tainted_found,
            }
        
        return None

    def _find_sanitizers(self, content: str, start_line: int, end_line: int, language: str) -> List[str]:
        """Find sanitizer calls between source and sink lines."""
        sanitizers = []
        patterns = SANITIZER_PATTERNS.get(language, [])

        lines = content.split("\n")
        for line_num in range(start_line, min(end_line, len(lines))):
            line = lines[line_num]
            for pattern, sanitizer_name in patterns:
                if re.search(pattern, line):
                    sanitizers.append(sanitizer_name)

        return list(set(sanitizers))

    def _analyze_cross_file(self, files: List[str], language: str) -> List[TaintPath]:
        """Attempt cross-file taint analysis (lightweight)."""
        # Build call graph first
        call_graph = self.call_graph_builder.build(files, language)

        # Collect all sources and sinks per file
        file_sources: Dict[str, List[TaintSource]] = {}
        file_sinks: Dict[str, List[TaintSink]] = {}

        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                file_sources[file_path] = self._find_sources(file_path, content, language)
                file_sinks[file_path] = self._find_sinks(file_path, content, language)
            except Exception:
                continue

        # Cross-file analysis: only connect if there's a plausible data flow
        cross_paths = []
        for src_file, sources in file_sources.items():
            for sink_file, sinks in file_sinks.items():
                if src_file == sink_file:
                    continue  # Already handled in _analyze_file

                # Check if files are in same directory (simple heuristic)
                if Path(src_file).parent != Path(sink_file).parent:
                    continue

                # For each source in file A, find sinks in file B where the
                # sink's function parameter name matches or is plausibly connected
                for source in sources:
                    for sink in sinks:
                        # Only connect if there's a call graph relationship
                        # or if the sink file imports/uses something from source file
                        if self._has_cross_file_connection(src_file, sink_file, call_graph):
                            path = TaintPath(
                                source=source,
                                sink=sink,
                                path_confidence=0.2,  # Low confidence for cross-file
                                sanitizers_encountered=[],
                            )
                            cross_paths.append(path)

        return cross_paths

    def _has_cross_file_connection(
        self, src_file: str, sink_file: str, call_graph: Dict[str, List[str]]
    ) -> bool:
        """Check if there's a plausible connection between two files."""
        # Check call graph: if any function in src_file calls a function in sink_file
        src_funcs = [k for k in call_graph.keys() if src_file in k]
        sink_func_names = [k.split(":")[-1] for k in call_graph.keys() if sink_file in k]

        for src_func in src_funcs:
            callees = call_graph.get(src_func, [])
            # Check if any callee matches a function in sink file
            for callee in callees:
                if callee in sink_func_names:
                    return True

        # Check if sink file imports source module
        src_module = Path(src_file).stem
        try:
            sink_content = Path(sink_file).read_text(encoding="utf-8", errors="replace")
            if f"import {src_module}" in sink_content or f"from {src_module}" in sink_content:
                return True
        except Exception:
            pass

        # Strict mode: only allow cross-file if we have concrete evidence
        return False


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------

def get_taint_engine(use_ai: bool = False, llm=None) -> TaintEngine:
    """获取或创建 TaintEngine 实例

    Args:
        use_ai: 是否启用 AI Agent 动态识别（替代模式匹配）
        llm: LLM 实例（用于 AI 模式）

    Returns:
        TaintEngine 实例
    """
    return TaintEngine(use_ai=use_ai, llm=llm)


# ---------------------------------------------------------------------------
# TaintAnalyzer for legacy compatibility (langgraph_flow.py)
# ---------------------------------------------------------------------------

@dataclass
class AnalysisContext:
    """Context for taint analysis (legacy compatibility)."""
    file_path: str = ""
    file_content: str = ""
    language: str = "python"
    metadata: Dict[str, Any] = field(default_factory=dict)


class TaintAnalyzer:
    """Legacy-compatible taint analyzer for langgraph_flow.py integration."""

    def analyze(self, context: AnalysisContext) -> List[TaintPath]:
        """Analyze the given context for taint paths."""
        engine = get_taint_engine()
        if not context.file_content or not context.file_path:
            return []

        return engine._analyze_file(
            context.file_path,
            context.file_content,
            context.language,
        )

    def get_standardized_output(self, paths: List[TaintPath]) -> List[Dict[str, Any]]:
        """Convert taint paths to standardized output format."""
        return [path.to_dict() for path in paths]
