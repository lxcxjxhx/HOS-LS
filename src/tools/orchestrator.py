"""工具编排器

整合多个安全扫描工具，按顺序或并行执行，并统一结果格式
"""
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from src.tools.semgrep_runner import SemgrepRunner
from src.tools.trivy_runner import TrivyRunner
from src.tools.gitleaks_runner import GitleaksRunner
from src.analyzers.code_vuln_scanner import CodeVulnScanner, CodeVulnLevel


STANDARD_TOOL_CHAIN = ["semgrep", "trivy", "gitleaks", "code_vuln_scanner"]

LINE_PROXIMITY_THRESHOLD = 5


@dataclass
class ToolExecutionStats:
    """工具执行统计"""
    tool_name: str
    execution_time: float = 0.0
    findings_count: int = 0
    is_available: bool = True
    error_message: Optional[str] = None


@dataclass
class AggregatedFinding:
    """聚合后的漏洞发现"""
    file: str
    line: int
    cwe_id: Optional[str]
    cve_id: Optional[str]
    severity: str
    confidence: float
    description: str
    source: str
    tool_confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_tools: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "source": self.source,
            "tool_confidence": self.tool_confidence,
            "metadata": self.metadata,
            "source_tools": self.source_tools
        }


class ToolOrchestrator:
    """安全工具编排器"""

    SEVERITY_PRIORITY = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "UNKNOWN": 4
    }

    CONFIDENCE_MAP = {
        "semgrep": 0.9,
        "trivy": 0.85,
        "gitleaks": 0.95,
        "code_vuln_scanner": 0.75
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.semgrep = SemgrepRunner(
            rules_dir=self.config.get("semgrep_rules_dir")
        )
        self.trivy = TrivyRunner()
        self.gitleaks = GitleaksRunner()
        self.code_vuln_scanner = CodeVulnScanner()
        self.stats: Dict[str, ToolExecutionStats] = {}

    def execute_chain(
        self,
        tool_chain: List[str],
        target: str
    ) -> List[Dict[str, Any]]:
        """按顺序执行工具链

        Args:
            tool_chain: 工具名称列表
            target: 目标路径

        Returns:
            聚合后的漏洞发现列表
        """
        all_results: List[List[Dict[str, Any]]] = []

        for tool_name in tool_chain:
            start_time = time.time()
            stats = ToolExecutionStats(tool_name=tool_name)

            try:
                results = self._execute_single_tool(tool_name, target)
                stats.findings_count = len(results)
                all_results.append(results)
            except Exception as e:
                stats.error_message = str(e)
                stats.is_available = False
            finally:
                stats.execution_time = time.time() - start_time
                self.stats[tool_name] = stats

        return self.aggregate_results(all_results)

    def execute_parallel(
        self,
        tools: List[str],
        target: str
    ) -> List[Dict[str, Any]]:
        """并行执行工具

        Args:
            tools: 工具名称列表
            target: 目标路径

        Returns:
            聚合后的漏洞发现列表
        """
        all_results: List[List[Dict[str, Any]]] = []

        for tool_name in tools:
            start_time = time.time()
            stats = ToolExecutionStats(tool_name=tool_name)

            try:
                results = self._execute_single_tool(tool_name, target)
                stats.findings_count = len(results)
                all_results.append(results)
            except Exception as e:
                stats.error_message = str(e)
                stats.is_available = False
            finally:
                stats.execution_time = time.time() - start_time
                self.stats[tool_name] = stats

        return self.aggregate_results(all_results)

    def _execute_single_tool(
        self,
        tool_name: str,
        target: str
    ) -> List[Dict[str, Any]]:
        """执行单个工具

        Args:
            tool_name: 工具名称
            target: 目标路径

        Returns:
            工具扫描结果
        """
        if tool_name == "semgrep":
            return self._run_semgrep(target)
        elif tool_name == "trivy":
            return self._run_trivy(target)
        elif tool_name == "gitleaks":
            return self._run_gitleaks(target)
        elif tool_name == "code_vuln_scanner":
            return self._run_code_vuln_scanner(target)
        else:
            raise ValueError(f"未知工具: {tool_name}")

    def _run_semgrep(self, target: str) -> List[Dict[str, Any]]:
        """运行 Semgrep 扫描"""
        from pathlib import Path

        path = Path(target)
        if path.is_file():
            return self.semgrep.scan_file(target)
        elif path.is_dir():
            return self.semgrep.scan_directory(target)
        return []

    def _run_trivy(self, target: str) -> List[Dict[str, Any]]:
        """运行 Trivy 扫描"""
        return self.trivy.scan_filesystem(target)

    def _run_gitleaks(self, target: str) -> List[Dict[str, Any]]:
        """运行 Gitleaks 扫描"""
        return self.gitleaks.scan_directory(target)

    def _run_code_vuln_scanner(self, target: str) -> List[Dict[str, Any]]:
        """运行代码漏洞扫描"""
        from pathlib import Path

        results = []
        path = Path(target)

        if path.is_file():
            findings = self.code_vuln_scanner.scan_file(str(path))
        elif path.is_dir():
            code_files = []
            for ext in CodeVulnScanner.CODE_EXTENSIONS:
                code_files.extend(path.rglob(f"*{ext}"))
            findings = self.code_vuln_scanner.scan_files([str(f) for f in code_files])
        else:
            findings = []

        for finding in findings:
            results.append({
                "file": finding.file_path,
                "line": finding.line_number,
                "cwe_id": self._map_vuln_type_to_cwe(finding.vuln_type),
                "cve_id": None,
                "severity": finding.level.value.upper(),
                "confidence": 0.75,
                "description": finding.description,
                "source": "code_vuln_scanner",
                "tool_confidence": self.CONFIDENCE_MAP["code_vuln_scanner"],
                "metadata": {
                    "vuln_type": finding.vuln_type,
                    "code_snippet": finding.code_snippet,
                    "remediation": finding.remediation
                }
            })

        return results

    def _map_vuln_type_to_cwe(self, vuln_type: str) -> Optional[str]:
        """将漏洞类型映射到 CWE ID"""
        mapping = {
            "sql_string_concat": "CWE-89",
            "python_sql_concat": "CWE-89",
            "python_sql_format": "CWE-89",
            "mybatis_dollar_brace_sql": "CWE-89",
            "java_runtime_exec": "CWE-78",
            "java_processbuilder": "CWE-78",
            "python_os_system": "CWE-78",
            "python_subprocess_shell": "CWE-78",
            "python_exec_concat": "CWE-94",
            "python_eval_concat": "CWE-94",
            "hardcoded_password": "CWE-259",
            "hardcoded_secret": "CWE-321",
            "hardcoded_api_key": "CWE-321",
            "hardcoded_access_key": "CWE-321",
            "hardcoded_token": "CWE-321",
            "weak_hash_md5": "CWE-327",
            "weak_hash_sha1": "CWE-327",
            "weak_cipher_des": "CWE-327",
            "weak_cipher_rc4": "CWE-327",
            "xss_innerHTML": "CWE-79",
            "xss_document_write": "CWE-79",
            "csrf_disabled": "CWE-352",
            "java_file_path_join": "CWE-22",
            "java_paths_get_concat": "CWE-22",
            "python_file_open_concat": "CWE-22",
            "java_fileinputstream_concat": "CWE-22",
        }
        return mapping.get(vuln_type)

    def aggregate_results(
        self,
        all_results: List[List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """聚合并去重所有工具结果

        Args:
            all_results: 所有工具的扫描结果列表

        Returns:
            去重后的漏洞发现列表
        """
        all_findings: List[Dict[str, Any]] = []

        for tool_results in all_results:
            for result in tool_results:
                normalized = self._normalize_result(result)
                if normalized:
                    all_findings.append(normalized)

        deduplicated = self._deduplicate_findings(all_findings)
        sorted_results = self._sort_by_severity(deduplicated)

        return sorted_results

    def _normalize_result(
        self,
        result: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """标准化不同工具的结果格式"""
        source = result.get("source", "")

        if source == "semgrep":
            return self._normalize_semgrep_result(result)
        elif source == "trivy":
            return self._normalize_trivy_result(result)
        elif source == "gitleaks":
            return self._normalize_gitleaks_result(result)
        elif source == "code_vuln_scanner":
            return self._normalize_code_vuln_result(result)

        return {
            "file": result.get("file", ""),
            "line": result.get("line", 0),
            "cwe_id": result.get("cwe_id"),
            "cve_id": result.get("cve_id"),
            "severity": result.get("severity", "UNKNOWN"),
            "confidence": result.get("confidence", 0.5),
            "description": result.get("description", result.get("message", "")),
            "source": source,
            "tool_confidence": self.CONFIDENCE_MAP.get(source, 0.5),
            "metadata": result.get("metadata", {})
        }

    def _normalize_semgrep_result(
        self,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """标准化 Semgrep 结果"""
        return {
            "file": result.get("file", ""),
            "line": result.get("line", 0),
            "cwe_id": result.get("cwe_id"),
            "cve_id": None,
            "severity": result.get("severity", "MEDIUM"),
            "confidence": result.get("confidence", 0.9),
            "description": result.get("message", result.get("description", "")),
            "source": "semgrep",
            "tool_confidence": self.CONFIDENCE_MAP["semgrep"],
            "metadata": {
                "check_id": result.get("check_id", ""),
                "pattern": result.get("pattern", "")
            }
        }

    def _normalize_trivy_result(
        self,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """标准化 Trivy 结果"""
        return {
            "file": result.get("file", ""),
            "line": result.get("line", 0),
            "cwe_id": result.get("cwe_id"),
            "cve_id": result.get("cve_id"),
            "severity": result.get("severity", "UNKNOWN"),
            "confidence": 0.85,
            "description": result.get("description", ""),
            "source": "trivy",
            "tool_confidence": self.CONFIDENCE_MAP["trivy"],
            "metadata": {
                "package": result.get("package", ""),
                "installed_version": result.get("installed_version", ""),
                "fixed_version": result.get("fixed_version", "")
            }
        }

    def _normalize_gitleaks_result(
        self,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """标准化 Gitleaks 结果"""
        return {
            "file": result.get("file", ""),
            "line": result.get("line", 0),
            "cwe_id": "CWE-321",
            "cve_id": None,
            "severity": "CRITICAL",
            "confidence": 0.95,
            "description": f"发现硬编码密钥: {result.get('secret_type', 'Unknown')}",
            "source": "gitleaks",
            "tool_confidence": self.CONFIDENCE_MAP["gitleaks"],
            "metadata": {
                "secret_type": result.get("secret_type", ""),
                "match": result.get("match", ""),
                "author": result.get("author", ""),
                "commit_hash": result.get("commit_hash", "")
            }
        }

    def _normalize_code_vuln_result(
        self,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """标准化代码漏洞扫描结果"""
        return {
            "file": result.get("file", ""),
            "line": result.get("line", 0),
            "cwe_id": result.get("cwe_id"),
            "cve_id": None,
            "severity": result.get("severity", "MEDIUM"),
            "confidence": result.get("confidence", 0.75),
            "description": result.get("description", ""),
            "source": "code_vuln_scanner",
            "tool_confidence": self.CONFIDENCE_MAP["code_vuln_scanner"],
            "metadata": result.get("metadata", {})
        }

    def _deduplicate_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """去重漏洞发现

        相同文件 + 相同 CWE + 相似行号（5行以内）只保留最高置信度
        """
        finding_groups: Dict[Tuple[str, Optional[str], int], List[Dict[str, Any]]] = defaultdict(list)

        for finding in findings:
            key = self._get_dedup_key(finding)
            finding_groups[key].append(finding)

        deduplicated = []
        for key, group in finding_groups.items():
            best_finding = self._select_best_finding(group)
            deduplicated.append(best_finding)

        return deduplicated

    def _get_dedup_key(
        self,
        finding: Dict[str, Any]
    ) -> Tuple[str, Optional[str], int]:
        """生成去重的键值"""
        file_path = str(finding.get("file", ""))
        cwe_id = finding.get("cwe_id")
        base_line = finding.get("line", 0)
        normalized_line = (base_line // LINE_PROXIMITY_THRESHOLD) * LINE_PROXIMITY_THRESHOLD

        return (file_path, cwe_id, normalized_line)

    def _select_best_finding(
        self,
        group: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """从一组相似发现中选择最佳结果"""
        if len(group) == 1:
            return group[0]

        best = group[0]
        for finding in group[1:]:
            if self._is_better_finding(finding, best):
                best = finding

        source_tools = list(set(f.get("source", "") for f in group))
        best["source_tools"] = source_tools
        best["metadata"]["duplicate_count"] = len(group)

        return best

    def _is_better_finding(
        self,
        new: Dict[str, Any],
        current: Dict[str, Any]
    ) -> bool:
        """比较两个发现，判断新发现是否更好"""
        new_confidence = new.get("confidence", 0.0)
        current_confidence = current.get("confidence", 0.0)

        if abs(new_confidence - current_confidence) > 0.1:
            return new_confidence > current_confidence

        new_severity = new.get("severity", "UNKNOWN")
        current_severity = current.get("severity", "UNKNOWN")

        new_priority = self.SEVERITY_PRIORITY.get(new_severity, 4)
        current_priority = self.SEVERITY_PRIORITY.get(current_severity, 4)

        if new_priority != current_priority:
            return new_priority < current_priority

        new_tool_conf = new.get("tool_confidence", 0.5)
        current_tool_conf = current.get("tool_confidence", 0.5)

        return new_tool_conf > current_tool_conf

    def _sort_by_severity(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """按严重级别排序"""
        return sorted(
            findings,
            key=lambda f: (
                self.SEVERITY_PRIORITY.get(f.get("severity", "UNKNOWN"), 4),
                -(f.get("confidence", 0.0))
            )
        )

    def get_statistics(self) -> Dict[str, Any]:
        """获取执行统计信息"""
        total_time = sum(s.execution_time for s in self.stats.values())
        total_findings = sum(s.findings_count for s in self.stats.values())
        available_tools = [t for t, s in self.stats.items() if s.is_available]

        return {
            "total_execution_time": total_time,
            "total_findings": total_findings,
            "tool_statistics": {
                tool: {
                    "execution_time": stats.execution_time,
                    "findings_count": stats.findings_count,
                    "is_available": stats.is_available,
                    "error": stats.error_message
                }
                for tool, stats in self.stats.items()
            },
            "available_tools": available_tools,
            "unavailable_tools": [
                t for t, s in self.stats.items() if not s.is_available
            ]
        }

    def run_full_scan(self, target: str) -> Dict[str, Any]:
        """运行完整扫描（使用标准工具链）

        Args:
            target: 目标路径

        Returns:
            包含聚合结果和统计信息的字典
        """
        results = self.execute_chain(STANDARD_TOOL_CHAIN, target)
        statistics = self.get_statistics()

        return {
            "findings": results,
            "statistics": statistics,
            "tool_chain": STANDARD_TOOL_CHAIN
        }


def create_orchestrator(
    config: Optional[Dict[str, Any]] = None
) -> ToolOrchestrator:
    """创建工具编排器实例

    Args:
        config: 配置字典

    Returns:
        ToolOrchestrator 实例
    """
    return ToolOrchestrator(config)
