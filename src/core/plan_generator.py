"""扫描计划生成器模块

实现 Plan-first 扫描策略，根据代码特征生成最优扫描计划。
核心理念：结构化系统 → 极限缩小问题空间 → AI只做最终裁决
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import hashlib
import json

from tree_sitter import Language, Parser

from src.analyzers.base import AnalysisContext


class ScanStrategy(Enum):
    TAINT_FIRST = "taint-first"
    RULE_FIRST = "rule-first"
    DEEP = "deep"
    FAST = "fast"


class ScanPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ScanPlan:
    targets: List[str]
    focus: List[str]
    strategy: ScanStrategy
    depth: int
    priority: ScanPriority
    use_rag: bool = False
    use_graph: bool = False
    use_llm_judge: bool = True
    max_candidates: int = 50
    cache_enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": self.targets,
            "focus": self.focus,
            "strategy": self.strategy.value,
            "depth": self.depth,
            "priority": self.priority.value,
            "use_rag": self.use_rag,
            "use_graph": self.use_graph,
            "use_llm_judge": self.use_llm_judge,
            "max_candidates": self.max_candidates,
            "cache_enabled": self.cache_enabled,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @property
    def cache_key(self) -> str:
        content = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()


class VulnerabilityFocus(Enum):
    SQL_INJECTION = "SQL Injection"
    COMMAND_INJECTION = "Command Injection"
    CODE_INJECTION = "Code Injection"
    XSS = "XSS"
    PATH_TRAVERSAL = "Path Traversal"
    SSRF = "SSRF"
    DESERIALIZATION = "Deserialization"
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    CRYPTO = "Cryptography"


class PlanGenerator:
    _instance: Optional["PlanGenerator"] = None
    _languages: Dict[str, Language] = {}
    _strategy_cache: Dict[str, ScanPlan] = {}

    def __new__(cls) -> "PlanGenerator":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize_languages()
        return cls._instance

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

    def generate_plan(
        self,
        target: str,
        context: Optional[AnalysisContext] = None,
        user_focus: Optional[List[str]] = None,
        force_strategy: Optional[ScanStrategy] = None,
    ) -> ScanPlan:
        targets = [target] if isinstance(target, str) else target

        code_info = self._analyze_targets(targets)

        if force_strategy:
            strategy = force_strategy
        else:
            strategy = self._select_strategy(code_info)

        if user_focus:
            focus = user_focus
        else:
            focus = self._identify_vulnerability_focus(code_info)

        priority = self._assess_priority(code_info)

        use_rag = self._should_use_rag(code_info, strategy)
        use_graph = self._should_use_graph(code_info, focus)
        use_llm_judge = strategy != ScanStrategy.FAST

        depth = self._determine_depth(code_info, strategy)

        max_candidates = self._calculate_max_candidates(strategy, code_info)

        metadata = {
            "file_count": len(targets),
            "total_lines": code_info.get("total_lines", 0),
            "complexity": code_info.get("complexity", "unknown"),
            "identified_sources": code_info.get("source_count", 0),
            "identified_sinks": code_info.get("sink_count", 0),
        }

        plan = ScanPlan(
            targets=targets,
            focus=focus,
            strategy=strategy,
            depth=depth,
            priority=priority,
            use_rag=use_rag,
            use_graph=use_graph,
            use_llm_judge=use_llm_judge,
            max_candidates=max_candidates,
            metadata=metadata,
        )

        cache_key = plan.cache_key
        self._strategy_cache[cache_key] = plan

        return plan

    def _analyze_targets(self, targets: List[str]) -> Dict[str, Any]:
        info = {
            "total_lines": 0,
            "complexity": "low",
            "source_count": 0,
            "sink_count": 0,
            "api_entries": [],
            "db_operations": [],
            "io_operations": [],
            "dangerous_functions": [],
            "imports": [],
            "has_eval": False,
            "has_sql": False,
            "has_network": False,
        }

        for target in targets:
            target_path = Path(target)
            if not target_path.exists():
                continue

            if target_path.is_file():
                file_info = self._analyze_file(target_path)
                self._merge_code_info(info, file_info)
            else:
                for file_path in target_path.rglob("*.py"):
                    file_info = self._analyze_file(file_path)
                    self._merge_code_info(info, file_info)

        return info

    def _analyze_file(self, file_path: Path) -> Dict[str, Any]:
        info = {
            "total_lines": 0,
            "source_count": 0,
            "sink_count": 0,
            "api_entries": [],
            "db_operations": [],
            "io_operations": [],
            "dangerous_functions": [],
            "imports": [],
            "has_eval": False,
            "has_sql": False,
            "has_network": False,
        }

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            info["total_lines"] = len(content.splitlines())

            lang = self._detect_language(file_path)
            if lang in self._languages:
                info.update(self._fast_ast_scan(content, lang))
            else:
                info.update(self._regex_scan(content))

        except Exception:
            pass

        return info

    def _fast_ast_scan(self, content: str, language: str) -> Dict[str, Any]:
        info = {
            "source_count": 0,
            "sink_count": 0,
            "api_entries": [],
            "db_operations": [],
            "io_operations": [],
            "dangerous_functions": [],
            "imports": [],
            "has_eval": False,
            "has_sql": False,
            "has_network": False,
        }

        parser = Parser(self._languages[language])
        try:
            tree = parser.parse(content.encode())
            if not tree:
                return self._regex_scan(content)

            cursor = tree.walk()

            visited_functions = set()

            def visit_node(node):
                node_type = node.type

                if node_type == "import_statement":
                    for child in node.children:
                        if child.type == "identifier":
                            info["imports"].append(self._get_node_text(child))

                elif node_type == "call":
                    func_name = self._get_function_name(node)
                    if func_name:
                        if func_name in ["eval", "exec", "execfile"]:
                            info["has_eval"] = True
                            info["dangerous_functions"].append(func_name)
                            info["sink_count"] += 1

                        elif func_name in ["input", "raw_input"]:
                            info["source_count"] += 1

                        elif func_name in ["execute", "executemany", "cursor"]:
                            info["db_operations"].append(func_name)
                            info["sink_count"] += 1
                            info["has_sql"] = True

                        elif func_name in ["open", "read", "write", "file"]:
                            info["io_operations"].append(func_name)

                        elif func_name in ["requests.get", "requests.post", "urllib.request"]:
                            info["has_network"] = True
                            info["io_operations"].append(func_name)

                elif node_type == "function_definition":
                    func_name = self._get_function_name(node)
                    if func_name and func_name not in visited_functions:
                        visited_functions.add(func_name)
                        info["api_entries"].append(func_name)

            self._traverse_tree(cursor, visit_node)

        except Exception:
            return self._regex_scan(content)

        return info

    def _regex_scan(self, content: str) -> Dict[str, Any]:
        import re

        info = {
            "source_count": 0,
            "sink_count": 0,
            "api_entries": [],
            "db_operations": [],
            "io_operations": [],
            "dangerous_functions": [],
            "imports": [],
            "has_eval": False,
            "has_sql": False,
            "has_network": False,
        }

        dangerous_patterns = [
            (r'\beval\s*\(', 'eval'),
            (r'\bexec\s*\(', 'exec'),
            (r'\bos\.system\s*\(', 'os.system'),
            (r'\bsubprocess\s*\.', 'subprocess'),
            (r'\bexecute\s*\(', 'execute'),
            (r'\bcursor\s*\(', 'cursor'),
        ]

        source_patterns = [
            (r'\binput\s*\(', 'input'),
            (r'\braw_input\s*\(', 'raw_input'),
        ]

        db_patterns = [
            (r'\.execute\s*\(', 'execute'),
            (r'\.executemany\s*\(', 'executemany'),
            (r'\.cursor\s*\(', 'cursor'),
        ]

        io_patterns = [
            (r'\bopen\s*\(', 'open'),
            (r'\bread\s*\(', 'read'),
        ]

        for pattern, name in dangerous_patterns:
            if re.search(pattern, content):
                info["dangerous_functions"].append(name)
                info["sink_count"] += 1
                if name in ['eval', 'exec']:
                    info["has_eval"] = True

        for pattern, name in source_patterns:
            if re.search(pattern, content):
                info["source_count"] += 1

        for pattern, name in db_patterns:
            if re.search(pattern, content):
                info["db_operations"].append(name)
                info["has_sql"] = True

        for pattern, name in io_patterns:
            if re.search(pattern, content):
                info["io_operations"].append(name)

        if "socket" in content or "requests" in content or "urllib" in content:
            info["has_network"] = True

        import_pattern = r'^import\s+(\w+)|^from\s+(\w+)\s+import'
        for match in re.finditer(import_pattern, content, re.MULTILINE):
            info["imports"].append(match.group(1) or match.group(2))

        return info

    def _get_function_name(self, node) -> Optional[str]:
        for child in node.children:
            if child.type in ["identifier", "attribute"]:
                return self._get_node_text(child)
        return None

    def _get_node_text(self, node) -> str:
        if node.text:
            return node.text.decode()
        return ""

    def _traverse_tree(self, cursor, callback) -> None:
        try:
            while True:
                callback(cursor.node)

                if cursor.goto_first_child():
                    self._traverse_tree(cursor, callback)
                    cursor.goto_parent()

                if not cursor.goto_next_sibling():
                    break
        except Exception:
            pass

    def _detect_language(self, file_path: Path) -> str:
        ext = file_path.suffix.lower()
        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
        }
        return lang_map.get(ext, "")

    def _merge_code_info(self, base: Dict, addition: Dict) -> None:
        base["total_lines"] += addition.get("total_lines", 0)
        base["source_count"] += addition.get("source_count", 0)
        base["sink_count"] += addition.get("sink_count", 0)
        base["has_eval"] = base["has_eval"] or addition.get("has_eval", False)
        base["has_sql"] = base["has_sql"] or addition.get("has_sql", False)
        base["has_network"] = base["has_network"] or addition.get("has_network", False)

        for item in addition.get("api_entries", []):
            if item not in base["api_entries"]:
                base["api_entries"].append(item)
        for item in addition.get("db_operations", []):
            if item not in base["db_operations"]:
                base["db_operations"].append(item)
        for item in addition.get("io_operations", []):
            if item not in base["io_operations"]:
                base["io_operations"].append(item)
        for item in addition.get("dangerous_functions", []):
            if item not in base["dangerous_functions"]:
                base["dangerous_functions"].append(item)
        for item in addition.get("imports", []):
            if item not in base["imports"]:
                base["imports"].append(item)

    def _select_strategy(self, code_info: Dict[str, Any]) -> ScanStrategy:
        if code_info.get("total_lines", 0) < 50:
            return ScanStrategy.FAST

        if code_info.get("sink_count", 0) > 10:
            return ScanStrategy.TAINT_FIRST

        if code_info.get("has_eval") or code_info.get("has_sql"):
            return ScanStrategy.TAINT_FIRST

        if code_info.get("complexity") == "high":
            return ScanStrategy.DEEP

        return ScanStrategy.RULE_FIRST

    def _identify_vulnerability_focus(self, code_info: Dict[str, Any]) -> List[str]:
        focus = []

        if code_info.get("has_sql") or code_info.get("db_operations"):
            focus.append(VulnerabilityFocus.SQL_INJECTION.value)

        if code_info.get("has_eval") or "eval" in code_info.get("dangerous_functions", []):
            focus.append(VulnerabilityFocus.CODE_INJECTION.value)

        if "os.system" in code_info.get("dangerous_functions", []) or "subprocess" in code_info.get("imports", []):
            focus.append(VulnerabilityFocus.COMMAND_INJECTION.value)

        if "open" in code_info.get("io_operations", []) or "file" in code_info.get("io_operations", []):
            focus.append(VulnerabilityFocus.PATH_TRAVERSAL.value)

        if code_info.get("has_network"):
            focus.append(VulnerabilityFocus.SSRF.value)

        if "pickle" in code_info.get("imports", []) or "yaml" in code_info.get("imports", []):
            focus.append(VulnerabilityFocus.DESERIALIZATION.value)

        if not focus:
            focus = [
                VulnerabilityFocus.SQL_INJECTION.value,
                VulnerabilityFocus.COMMAND_INJECTION.value,
                VulnerabilityFocus.CODE_INJECTION.value,
            ]

        return focus

    def _assess_priority(self, code_info: Dict[str, Any]) -> ScanPriority:
        risk_score = 0

        if code_info.get("has_eval"):
            risk_score += 3
        if code_info.get("has_sql"):
            risk_score += 2
        if code_info.get("sink_count", 0) > 5:
            risk_score += 2
        if code_info.get("source_count", 0) > 3:
            risk_score += 1
        if code_info.get("has_network"):
            risk_score += 1

        if risk_score >= 6:
            return ScanPriority.CRITICAL
        elif risk_score >= 4:
            return ScanPriority.HIGH
        elif risk_score >= 2:
            return ScanPriority.MEDIUM
        else:
            return ScanPriority.LOW

    def _should_use_rag(self, code_info: Dict[str, Any], strategy: ScanStrategy) -> bool:
        if strategy == ScanStrategy.DEEP:
            return True

        if code_info.get("sink_count", 0) > 20:
            return True

        if code_info.get("complexity") == "high":
            return True

        return False

    def _should_use_graph(self, code_info: Dict[str, Any], focus: List[str]) -> bool:
        if VulnerabilityFocus.SQL_INJECTION.value in focus:
            return True

        if code_info.get("sink_count", 0) > 10 and code_info.get("source_count", 0) > 5:
            return True

        return False

    def _determine_depth(self, code_info: Dict[str, Any], strategy: ScanStrategy) -> int:
        if strategy == ScanStrategy.FAST:
            return 1
        elif strategy == ScanStrategy.TAINT_FIRST:
            return 2
        elif strategy == ScanStrategy.DEEP:
            return 3
        else:
            return 2

    def _calculate_max_candidates(self, strategy: ScanStrategy, code_info: Dict[str, Any]) -> int:
        base_max = 50

        if strategy == ScanStrategy.FAST:
            return 10
        elif strategy == ScanStrategy.TAINT_FIRST:
            return 30
        elif strategy == ScanStrategy.DEEP:
            return 100

        return base_max

    def get_cached_plan(self, cache_key: str) -> Optional[ScanPlan]:
        return self._strategy_cache.get(cache_key)

    def clear_cache(self) -> None:
        self._strategy_cache.clear()


def get_plan_generator() -> PlanGenerator:
    return PlanGenerator()
