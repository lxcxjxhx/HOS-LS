"""Taint 分析引擎模块

实现跨函数、跨文件的污点传播分析，支持完整的 source → propagation → sink 路径跟踪。
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import hashlib
import json

from tree_sitter import Language, Parser, Node


@dataclass
class TaintSource:
    name: str
    node: Any
    file_path: str
    line: int
    description: str
    confidence: float = 1.0


@dataclass
class TaintSink:
    name: str
    node: Any
    file_path: str
    line: int
    description: str
    vulnerability_type: str
    confidence: float = 1.0


@dataclass
class TaintPath:
    source: TaintSource
    sink: TaintSink
    path: List[str]
    confidence: float
    cross_function: bool = False
    cross_file: bool = False
    propagation_steps: List[Dict[str, Any]] = field(default_factory=list)
    sanitizers_found: List[str] = field(default_factory=list)
    severity: str = "medium"

    def evaluate_severity(self) -> str:
        severity_map = {
            "SQL Injection": "high",
            "Command Injection": "high",
            "Code Injection": "critical",
            "XSS": "medium",
            "Path Traversal": "medium",
            "SSRF": "high",
            "Deserialization": "critical",
        }
        base = severity_map.get(self.sink.vulnerability_type, "medium")

        if self.cross_function:
            base = _escalate_severity(base)
        if self.cross_file:
            base = _escalate_severity(base)
        if self.sanitizers_found:
            base = _deescalate_severity(base)

        return base

    def is_high_risk(self) -> bool:
        severity = self.evaluate_severity()
        return severity in ["critical", "high"]


def _escalate_severity(severity: str) -> str:
    escalation = {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"}
    return escalation.get(severity, severity)


def _deescalate_severity(severity: str) -> str:
    deescalation = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
    return deescalation.get(severity, severity)


@dataclass
class FunctionInfo:
    name: str
    file_path: str
    line: int
    params: List[str]
    local_vars: List[str]
    calls: List[str]
    is_entry_point: bool = False


class CallGraphBuilder:
    def __init__(self):
        self.functions: Dict[str, FunctionInfo] = {}
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_graph: Dict[str, List[str]] = {}

    def build(self, files: List[str]) -> Dict[str, List[str]]:
        for file_path in files:
            self._analyze_file(file_path)

        self._build_graph()
        return self.call_graph

    def _analyze_file(self, file_path: str) -> None:
        path = Path(file_path)
        if not path.exists():
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return

        language = self._detect_language(path)
        if not language:
            return

        try:
            parser = Parser(language)
            tree = parser.parse(content.encode())
            if not tree:
                return

            self._extract_functions(tree, content, file_path)
        except Exception:
            return

    def _detect_language(self, path: Path) -> Optional[Language]:
        languages = {}
        try:
            from tree_sitter_python import language as python_language
            languages["python"] = Language(python_language())
        except ImportError:
            pass

        try:
            from tree_sitter_javascript import language as js_language
            languages["javascript"] = Language(js_language())
        except ImportError:
            pass

        ext = path.suffix.lower()
        lang_map = {".py": "python", ".js": "javascript", ".ts": "typescript"}
        lang_key = lang_map.get(ext)

        return languages.get(lang_key)

    def _extract_functions(self, tree: Node, content: str, file_path: str) -> None:
        cursor = tree.walk()

        current_function = None
        current_file = file_path

        def visit(node):
            nonlocal current_function

            if node.type == "function_definition":
                func_name = self._get_function_name(node)
                if func_name:
                    params = self._get_parameters(node)
                    local_vars = self._get_local_vars(node)
                    calls = self._get_function_calls(node)

                    func_key = f"{current_file}:{func_name}"
                    self.functions[func_key] = FunctionInfo(
                        name=func_name,
                        file_path=current_file,
                        line=node.start_point[0] + 1,
                        params=params,
                        local_vars=local_vars,
                        calls=calls,
                    )
                    current_function = func_key

            elif node.type == "call" and current_function:
                func_name = self._get_function_name(node)
                if func_name and func_name in self.functions:
                    if current_function not in self.call_graph:
                        self.call_graph[current_function] = []
                    if func_name not in self.call_graph[current_function]:
                        self.call_graph[current_function].append(func_name)

        self._traverse(cursor, visit)

    def _get_function_name(self, node: Node) -> Optional[str]:
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child)
        return None

    def _get_parameters(self, node: Node) -> List[str]:
        params = []
        for child in node.children:
            if child.type == "parameters":
                for param in child.children:
                    if param.type == "identifier":
                        params.append(self._get_node_text(param))
        return params

    def _get_local_vars(self, node: Node) -> List[str]:
        vars = []
        for child in node.children:
            if child.type == "block":
                for var_node in self._find_nodes(child, "identifier"):
                    var_name = self._get_node_text(var_node)
                    if var_name and var_name not in vars:
                        vars.append(var_name)
        return vars

    def _get_function_calls(self, node: Node) -> List[str]:
        calls = []
        for call_node in self._find_nodes(node, "call"):
            func_name = self._get_function_name(call_node)
            if func_name:
                calls.append(func_name)
        return calls

    def _find_nodes(self, node: Node, node_type: str) -> List[Node]:
        results = []
        if node.type == node_type:
            results.append(node)
        for child in node.children:
            results.extend(self._find_nodes(child, node_type))
        return results

    def _get_node_text(self, node: Node) -> str:
        if node.text:
            return node.text.decode()
        return ""

    def _traverse(self, cursor, callback) -> None:
        try:
            while True:
                callback(cursor.node)
                if cursor.goto_first_child():
                    self._traverse(cursor, callback)
                    cursor.goto_parent()
                if not cursor.goto_next_sibling():
                    break
        except Exception:
            pass

    def _build_graph(self) -> None:
        self.reverse_graph.clear()
        for caller, callees in self.call_graph.items():
            for callee in callees:
                if callee not in self.reverse_graph:
                    self.reverse_graph[callee] = []
                if caller not in self.reverse_graph[callee]:
                    self.reverse_graph[callee].append(caller)

    def get_callers(self, function: str) -> List[str]:
        return self.reverse_graph.get(function, [])

    def get_callees(self, function: str) -> List[str]:
        return self.call_graph.get(function, [])


class TaintPropagationTracker:
    def __init__(self, call_graph: CallGraphBuilder):
        self.call_graph = call_graph
        self.tainted_vars: Dict[str, Set[str]] = {}
        self.visited_paths: Set[str] = set()

    def track_propagation(
        self,
        source: TaintSource,
        initial_var: str,
        start_function: str,
    ) -> List[Dict[str, Any]]:
        steps = []
        self.tainted_vars = {start_function: {initial_var}}
        self.visited_paths = set()

        current_function = start_function
        current_var = initial_var

        func_key = f"{source.file_path}:{current_function}" if ":" not in current_function else current_function

        visited_functions = set()
        max_depth = 10

        while len(steps) < max_depth:
            if func_key in visited_functions:
                break
            visited_functions.add(func_key)

            func_info = self.call_graph.functions.get(func_key)
            if not func_info:
                break

            step = self._analyze_function_context(func_info, current_var, source)
            if step:
                steps.append(step)
                if step.get("propagated_to"):
                    current_var = step["propagated_to"]
                if step.get("propagated_to_function"):
                    func_key = step["propagated_to_function"]

            if not step.get("propagated_to"):
                break

        return steps

    def _analyze_function_context(
        self,
        func_info: FunctionInfo,
        tainted_var: str,
        source: TaintSource,
    ) -> Dict[str, Any]:
        step = {
            "function": func_info.name,
            "file": func_info.file_path,
            "line": func_info.line,
            "tainted_input": tainted_var,
            "propagated_to": None,
            "propagated_to_function": None,
            "assignments": [],
        }

        if tainted_var in func_info.params:
            step["context"] = "parameter_propagation"
            for call_func in func_info.calls:
                step["propagated_to_function"] = call_func
                step["propagated_to"] = tainted_var
                break

        if tainted_var in func_info.local_vars:
            step["context"] = "local_var_propagation"

        for call_func in func_info.calls:
            if call_func in self.call_graph.functions:
                step["propagated_to_function"] = call_func
                break

        return step


class TaintEngine:
    _instance: Optional["TaintEngine"] = None

    def __new__(cls) -> "TaintEngine":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        self.call_graph_builder = CallGraphBuilder()
        self.propagation_tracker: Optional[TaintPropagationTracker] = None
        self._languages: Dict[str, Language] = {}
        self._initialize_languages()
        self._source_patterns: Dict[str, List[str]] = {}
        self._sink_patterns: Dict[str, Dict[str, List[str]]] = {}
        self._sanitizer_patterns: Dict[str, List[str]] = {}
        self._load_builtin_patterns()

    def _initialize_languages(self) -> None:
        try:
            from tree_sitter_python import language as python_language
            self._languages["python"] = Language(python_language())
        except ImportError:
            pass

        try:
            from tree_sitter_javascript import language as js_language
            self._languages["javascript"] = Language(js_language())
            self._languages["typescript"] = Language(js_language())
        except ImportError:
            pass

    def _load_builtin_patterns(self) -> None:
        self._source_patterns = {
            "python": [
                "input", "raw_input", "sys.stdin.read",
                "open", "file", "os.environ.get",
                "os.getenv", "request.args", "request.json",
                "request.values", "request.form",
            ],
            "javascript": [
                "process.argv", "require", "fs.readFileSync",
                "JSON.parse", "eval", "Function",
            ],
        }

        self._sink_patterns = {
            "python": {
                "SQL Injection": ["execute", "executemany", "cursor.execute", "raw", "query"],
                "Command Injection": ["os.system", "os.popen", "subprocess.Popen", "subprocess.call", "subprocess.run", "exec", "eval", "compile"],
                "Code Injection": ["eval", "exec", "execfile", "compile", "type(code)"],
                "XSS": ["django.utils.html.format_html", "flask.render_template_string"],
                "Path Traversal": ["open", "os.path.join", "os.path.expanduser", "file"],
                "Deserialization": ["pickle.loads", "pickle.load", "yaml.load", "marshal.loads"],
            },
            "javascript": {
                "SQL Injection": ["mysql.query", "pg.query", "mongodb.find"],
                "Command Injection": ["child_process.exec", "child_process.spawn", "eval", "Function"],
                "Code Injection": ["eval", "new Function", "setTimeout", "setInterval"],
                "XSS": ["document.write", "innerHTML", "outerHTML", "insertAdjacentHTML"],
                "Path Traversal": ["fs.readFile", "fs.readFileSync", "path.join"],
                "Deserialization": ["JSON.parse"],
            },
        }

        self._sanitizer_patterns = {
            "python": [
                "sqlalchemy.text", "psycopg2.sql.SQL",
                "shlex.quote", "subprocess.list2cmdline",
                "html.escape", "cgi.escape",
                "markupsafe.escape", "bleach.clean",
                "django.utils.html.strip_tags",
            ],
            "javascript": [
                "encodeURIComponent", "escape",
                "DOMPurify.sanitize", "validator.escape",
            ],
        }

    def analyze(
        self,
        files: List[str],
        language: str = "python",
    ) -> List[TaintPath]:
        self.call_graph_builder = CallGraphBuilder()
        self.call_graph_builder.build(files)

        self.propagation_tracker = TaintPropagationTracker(self.call_graph_builder)

        sources = self._find_sources(files, language)
        sinks = self._find_sinks(files, language)

        paths = []

        for source in sources:
            for sink in sinks:
                path = self._analyze_path(source, sink, language)
                if path:
                    paths.append(path)

        paths = self._filter_sanitized_paths(paths, language)

        paths.sort(key=lambda p: p.confidence, reverse=True)

        return paths

    def _find_sources(self, files: List[str], language: str) -> List[TaintSource]:
        sources = []

        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue

            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            lang = self._languages.get(language)
            if not lang:
                continue

            try:
                parser = Parser(lang)
                tree = parser.parse(content.encode())
                if not tree:
                    continue

                sources.extend(self._extract_sources(tree, content, file_path))
            except Exception:
                continue

        return sources

    def _extract_sources(self, tree: Node, content: str, file_path: str) -> List[TaintSource]:
        sources = []
        lang = Path(file_path).suffix.lstrip(".")

        cursor = tree.walk()

        def visit(node):
            if node.type == "call":
                func_name = self._get_function_name(node)
                if func_name:
                    source_keywords = self._source_patterns.get(lang, [])
                    for keyword in source_keywords:
                        if keyword in func_name:
                            sources.append(TaintSource(
                                name=func_name,
                                node=node,
                                file_path=file_path,
                                line=node.start_point[0] + 1,
                                description=f"Potential source: {func_name}",
                                confidence=0.8,
                            ))
                            break

        self._traverse(cursor, visit)
        return sources

    def _find_sinks(self, files: List[str], language: str) -> List[TaintSink]:
        sinks = []

        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue

            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            lang = self._languages.get(language)
            if not lang:
                continue

            try:
                parser = Parser(lang)
                tree = parser.parse(content.encode())
                if not tree:
                    continue

                sinks.extend(self._extract_sinks(tree, content, file_path, language))
            except Exception:
                continue

        return sinks

    def _extract_sinks(self, tree: Node, content: str, file_path: str, language: str) -> List[TaintSink]:
        sinks = []
        lang = language

        sink_rules = self._sink_patterns.get(lang, {})

        cursor = tree.walk()

        def visit(node):
            if node.type == "call":
                func_name = self._get_function_name(node)
                if func_name:
                    for vuln_type, keywords in sink_rules.items():
                        for keyword in keywords:
                            if keyword in func_name:
                                sinks.append(TaintSink(
                                    name=func_name,
                                    node=node,
                                    file_path=file_path,
                                    line=node.start_point[0] + 1,
                                    description=f"Potential sink: {func_name}",
                                    vulnerability_type=vuln_type,
                                    confidence=0.8,
                                ))
                                break

        self._traverse(cursor, visit)
        return sinks

    def _analyze_path(self, source: TaintSource, sink: TaintSink, language: str) -> Optional[TaintPath]:
        if source.file_path != sink.file_path:
            return self._analyze_cross_file_path(source, sink, language)
        else:
            return self._analyze_same_file_path(source, sink, language)

    def _analyze_same_file_path(self, source: TaintSource, sink: TaintSink, language: str) -> Optional[TaintPath]:
        propagation_steps = []

        if self.propagation_tracker:
            steps = self.propagation_tracker.track_propagation(
                source=source,
                initial_var=source.name,
                start_function="",
            )
            propagation_steps = steps

        cross_function = False
        for step in propagation_steps:
            if step.get("function") and step["function"] != "":
                cross_function = True
                break

        path = TaintPath(
            source=source,
            sink=sink,
            path=[source.name, sink.name],
            confidence=0.7 if cross_function else 0.85,
            cross_function=cross_function,
            cross_file=False,
            propagation_steps=propagation_steps,
        )

        return path

    def _analyze_cross_file_path(self, source: TaintSource, sink: TaintSink, language: str) -> Optional[TaintPath]:
        propagation_steps = []

        source_func = self._find_function_containing(source.file_path, source.line)
        sink_func = self._find_function_containing(sink.file_path, sink.line)

        if source_func and sink_func:
            if self.propagation_tracker:
                steps = self.propagation_tracker.track_propagation(
                    source=source,
                    initial_var=source.name,
                    start_function=source_func,
                )
                propagation_steps = steps

        path = TaintPath(
            source=source,
            sink=sink,
            path=[source.name, f"{source_func}()", f"{sink_func}()", sink.name],
            confidence=0.6,
            cross_function=True,
            cross_file=True,
            propagation_steps=propagation_steps,
        )

        return path

    def _find_function_containing(self, file_path: str, line: int) -> Optional[str]:
        for func_key, func_info in self.call_graph_builder.functions.items():
            if func_info.file_path == file_path:
                if abs(func_info.line - line) < 50:
                    return func_info.name
        return None

    def _filter_sanitized_paths(self, paths: List[TaintPath], language: str) -> List[TaintPath]:
        filtered = []

        for path in paths:
            sanitizers_found = []

            for sanitizer in self._sanitizer_patterns.get(language, []):
                if sanitizer in str(path.propagation_steps):
                    sanitizers_found.append(sanitizer)

            path.sanitizers_found = sanitizers_found

            if len(sanitizers_found) < len(path.propagation_steps) / 2:
                filtered.append(path)

        return filtered

    def _get_function_name(self, node: Node) -> Optional[str]:
        for child in node.children:
            if child.type in ["identifier", "attribute"]:
                return self._get_node_text(child)
        return None

    def _get_node_text(self, node: Node) -> str:
        if node.text:
            return node.text.decode()
        return ""

    def _traverse(self, cursor, callback) -> None:
        try:
            while True:
                callback(cursor.node)
                if cursor.goto_first_child():
                    self._traverse(cursor, callback)
                    cursor.goto_parent()
                if not cursor.goto_next_sibling():
                    break
        except Exception:
            pass

    def get_standardized_output(self, paths: List[TaintPath]) -> List[Dict[str, Any]]:
        output = []

        for path in paths:
            output.append({
                "type": "taint_path",
                "source": {
                    "name": path.source.name,
                    "file": path.source.file_path,
                    "line": path.source.line,
                    "description": path.source.description,
                },
                "sink": {
                    "name": path.sink.name,
                    "file": path.sink.file_path,
                    "line": path.sink.line,
                    "vulnerability_type": path.sink.vulnerability_type,
                },
                "path": path.path,
                "confidence": path.confidence,
                "cross_function": path.cross_function,
                "cross_file": path.cross_file,
                "propagation_steps": path.propagation_steps,
                "sanitizers_found": path.sanitizers_found,
                "severity": path.evaluate_severity(),
                "is_high_risk": path.is_high_risk(),
            })

        return output


def get_taint_engine() -> TaintEngine:
    return TaintEngine()
