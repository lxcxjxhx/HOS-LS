"""可达性分析模块

实现漏洞可达性分析，评估漏洞是否可被实际利用
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
import re

from src.core.config import Config, get_config
from src.taint.engine import CallGraphBuilder, TaintSource, TaintSink
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EntryPoint:
    """入口点"""
    name: str
    file_path: str
    line: int
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    access_modifier: str = "public"
    annotations: List[str] = field(default_factory=list)


@dataclass
class ReachabilityResult:
    """可达性分析结果"""
    reachable: bool
    reachability_score: float
    entry_point: Optional[str]
    data_flow_path: List[str]
    barriers: List[str]
    confidence: float
    vulnerability_type: str
    source_location: Optional[str] = None
    sink_location: Optional[str] = None


class ReachabilityCalculator:
    """可达性计算器"""

    ENTRY_POINT_PATTERNS = {
        "java": [
            (r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)", "handler"),
            (r"@(RestController|Controller)", "controller"),
            (r"public\s+\w+\s+\w+\s*\(", "public_method"),
        ],
        "python": [
            (r"@(app|router)\.(get|post|put|delete)", "endpoint"),
            (r"def\s+\w+\s*\(", "function"),
        ],
        "javascript": [
            (r"(app|router)\.(get|post|put|delete)\s*\(", "endpoint"),
            (r"function\s+\w+\s*\(", "function"),
            (r"exports?\.\w+\s*=", "exported"),
        ]
    }

    SINK_PATTERNS = {
        "SQL_INJECTION": ["execute", "query", "cursor.execute", "Statement.execute", "createQuery"],
        "XSS": ["innerHTML", "outerHTML", "document.write", "eval", "Response.Write"],
        "COMMAND_INJECTION": ["system", "exec", "popen", "Runtime.exec", "ProcessBuilder"],
        "PATH_TRAVERSAL": ["File", "Path", "open", "Files.read", "new FileInputStream"],
    }

    SANITIZER_PATTERNS = {
        "SQL_INJECTION": ["PreparedStatement", "parameterized", "sanitize", "escape", "sqlEsc"],
        "XSS": ["escapeHtml", "escape", "HTML.escape", "textContent", "innerText"],
        "COMMAND_INJECTION": ["shellEscape", "sanitizeCommand", "validCommand"],
        "PATH_TRAVERSAL": ["normalize", "getCanonicalPath", "resolve"],
    }

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self.call_graph_builder = CallGraphBuilder()
        self._entry_points_cache: Dict[str, List[EntryPoint]] = {}

    def calculate_reachability(
        self,
        finding: Dict[str, Any],
        codebase_context: Dict[str, Any]
    ) -> ReachabilityResult:
        """计算漏洞可达性

        Args:
            finding: 漏洞发现
            codebase_context: 代码库上下文

        Returns:
            ReachabilityResult: 可达性分析结果
        """
        vuln_type = finding.get("vulnerability_type", finding.get("cwe_id", "UNKNOWN"))
        file_path = finding.get("file", "")
        line = finding.get("line", 0)

        entry_points = self.find_entry_points(codebase_context.get("source_files", []))
        source_location = f"{file_path}:{line}"

        if not entry_points:
            return ReachabilityResult(
                reachable=True,
                reachability_score=0.7,
                entry_point=None,
                data_flow_path=[],
                barriers=[],
                confidence=0.3,
                vulnerability_type=vuln_type,
                source_location=source_location,
                sink_location=source_location
            )

        reachable_entry_points = self._find_reachable_entry_points(
            file_path, line, entry_points, vuln_type
        )

        if not reachable_entry_points:
            return ReachabilityResult(
                reachable=False,
                reachability_score=0.0,
                entry_point=None,
                data_flow_path=[],
                barriers=[],
                confidence=0.9,
                vulnerability_type=vuln_type,
                source_location=source_location,
                sink_location=source_location
            )

        best_entry = reachable_entry_points[0]
        data_flow_path = self._trace_data_flow(
            best_entry, file_path, line, vuln_type, codebase_context
        )

        barriers = self._find_barriers(data_flow_path, vuln_type)

        score = self._calculate_reachability_score(
            len(reachable_entry_points),
            len(data_flow_path),
            len(barriers),
            vuln_type
        )

        return ReachabilityResult(
            reachable=True,
            reachability_score=score,
            entry_point=f"{best_entry.file_path}:{best_entry.line}",
            data_flow_path=data_flow_path,
            barriers=barriers,
            confidence=0.8,
            vulnerability_type=vuln_type,
            source_location=source_location,
            sink_location=source_location
        )

    def find_entry_points(self, source_files: List[str]) -> List[EntryPoint]:
        """查找所有入口点

        Args:
            source_files: 源文件列表

        Returns:
            入口点列表
        """
        cache_key = "|".join(sorted(source_files))
        if cache_key in self._entry_points_cache:
            return self._entry_points_cache[cache_key]

        entry_points = []
        language = self._detect_language_from_files(source_files)

        for file_path in source_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                found = self._extract_entry_points(content, file_path, language)
                entry_points.extend(found)
            except Exception as e:
                logger.debug(f"分析入口点失败 {file_path}: {e}")

        self._entry_points_cache[cache_key] = entry_points
        return entry_points

    def _detect_language_from_files(self, source_files: List[str]) -> str:
        """检测语言"""
        extensions = set()
        for f in source_files:
            ext = Path(f).suffix.lower()
            extensions.add(ext)

        if ".java" in extensions:
            return "java"
        elif ".py" in extensions:
            return "python"
        elif ".js" in extensions or ".ts" in extensions:
            return "javascript"
        return "java"

    def _extract_entry_points(
        self,
        content: str,
        file_path: str,
        language: str
    ) -> List[EntryPoint]:
        """从内容中提取入口点"""
        entry_points = []
        patterns = self.ENTRY_POINT_PATTERNS.get(language, [])

        for line_num, line in enumerate(content.split("\n"), 1):
            for pattern, ptype in patterns:
                if re.search(pattern, line):
                    annotations = self._extract_annotations(content, line_num)
                    entry_points.append(EntryPoint(
                        name=self._extract_function_name(line, language),
                        file_path=file_path,
                        line=line_num,
                        annotations=annotations,
                        access_modifier=self._extract_access_modifier(line)
                    ))
                    break

        return entry_points

    def _extract_annotations(self, content: str, target_line: int) -> List[str]:
        """提取注解"""
        annotations = []
        lines = content.split("\n")
        start = max(0, target_line - 3)
        end = target_line

        for i in range(start, end):
            line = lines[i].strip()
            if line.startswith("@"):
                annotations.append(line)
            else:
                break

        return annotations

    def _extract_function_name(self, line: str, language: str) -> str:
        """提取函数名"""
        if language == "java":
            match = re.search(r"(public|private|protected)?\s*\w+\s+(\w+)\s*\(", line)
            if match:
                return match.group(2)
        elif language == "python":
            match = re.search(r"def\s+(\w+)\s*\(", line)
            if match:
                return match.group(1)
        return "unknown"

    def _extract_access_modifier(self, line: str) -> str:
        """提取访问修饰符"""
        if "public" in line:
            return "public"
        elif "private" in line:
            return "private"
        elif "protected" in line:
            return "protected"
        return "package"

    def _find_reachable_entry_points(
        self,
        sink_file: str,
        sink_line: int,
        entry_points: List[EntryPoint],
        vuln_type: str
    ) -> List[EntryPoint]:
        """查找可达入口点"""
        reachable = []
        call_graph = self.call_graph_builder.build(
            [ep.file_path for ep in entry_points]
        )

        for ep in entry_points:
            if self._is_reachable_via_call_graph(ep, sink_file, sink_line, call_graph):
                reachable.append(ep)
            elif self._is_direct_reachable(ep.file_path, sink_file):
                reachable.append(ep)

        return reachable

    def _is_reachable_via_call_graph(
        self,
        entry_point: EntryPoint,
        sink_file: str,
        sink_line: int,
        call_graph: Dict[str, List[str]]
    ) -> bool:
        """检查通过调用图是否可达"""
        entry_key = f"{entry_point.file_path}:{entry_point.name}"
        return entry_key in call_graph

    def _is_direct_reachable(self, file1: str, file2: str) -> bool:
        """检查是否直接可达（同文件或调用关系）"""
        return Path(file1).parent == Path(file2).parent

    def _trace_data_flow(
        self,
        entry_point: EntryPoint,
        sink_file: str,
        sink_line: int,
        vuln_type: str,
        context: Dict[str, Any]
    ) -> List[str]:
        """追踪数据流路径"""
        path = [
            f"{entry_point.file_path}:{entry_point.line} ({entry_point.name})",
            f"{sink_file}:{sink_line} (sink)"
        ]
        return path

    def _find_barriers(self, data_flow_path: List[str], vuln_type: str) -> List[str]:
        """查找屏障（净化点）"""
        sanitizers = self.SANITIZER_PATTERNS.get(vuln_type, [])
        barriers = []

        for step in data_flow_path:
            for sanitizer in sanitizers:
                if sanitizer.lower() in step.lower():
                    barriers.append(sanitizer)

        return barriers

    def _calculate_reachability_score(
        self,
        num_entry_points: int,
        path_length: int,
        num_barriers: int,
        vuln_type: str
    ) -> float:
        """计算可达性分数"""
        base_score = 1.0

        if num_entry_points == 0:
            return 0.0

        entry_factor = min(1.0, num_entry_points / 3.0)
        path_factor = max(0.0, 1.0 - (path_length - 2) * 0.2)
        barrier_factor = max(0.0, 1.0 - num_barriers * 0.3)

        vulnerability_modifiers = {
            "SQL_INJECTION": 1.0,
            "COMMAND_INJECTION": 1.1,
            "XSS": 0.9,
            "PATH_TRAVERSAL": 0.9,
        }

        modifier = vulnerability_modifiers.get(vuln_type, 1.0)
        score = base_score * entry_factor * path_factor * barrier_factor * modifier

        return min(1.0, max(0.0, score))

    def get_reachability_for_findings(
        self,
        findings: List[Dict[str, Any]],
        codebase_context: Dict[str, Any]
    ) -> List[ReachabilityResult]:
        """批量计算漏洞可达性

        Args:
            findings: 漏洞发现列表
            codebase_context: 代码库上下文

        Returns:
            可达性分析结果列表
        """
        results = []
        for finding in findings:
            try:
                result = self.calculate_reachability(finding, codebase_context)
                results.append(result)
            except Exception as e:
                logger.debug(f"可达性分析失败: {e}")
                results.append(ReachabilityResult(
                    reachable=False,
                    reachability_score=0.0,
                    entry_point=None,
                    data_flow_path=[],
                    barriers=[],
                    confidence=0.0,
                    vulnerability_type=finding.get("vulnerability_type", "UNKNOWN")
                ))

        return results


def calculate_findings_reachability(
    findings: List[Dict[str, Any]],
    source_files: List[str]
) -> List[ReachabilityResult]:
    """便捷函数：计算漏洞可达性

    Args:
        findings: 漏洞发现列表
        source_files: 源代码文件列表

    Returns:
        可达性分析结果列表
    """
    calculator = ReachabilityCalculator()
    context = {"source_files": source_files}
    return calculator.get_reachability_for_findings(findings, context)
