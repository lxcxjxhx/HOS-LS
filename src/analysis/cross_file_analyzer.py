"""多文件漏洞关联分析模块

分析跨多个文件的漏洞信号组合，识别多文件漏洞模式。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from src.db.models import Finding, CrossFileVulnerability, VulnerabilityStep
from src.analysis.file_dependency_graph import FileDependencyGraph
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VulnerabilityPattern:
    """漏洞模式"""
    name: str
    description: str
    required_files: int
    file_roles: Dict[str, str]
    confidence_boost: float


class CrossFileVulnerabilityAnalyzer:
    """跨文件漏洞关联分析器

    识别跨多个文件的漏洞信号组合，如：
    - 入口文件 + 配置错误
    - 数据入口 + 处理逻辑 + 存储操作
    - 认证绕过 + 权限检查缺失
    """

    COMMON_PATTERNS = [
        VulnerabilityPattern(
            name="config_bypass",
            description="配置错误导致安全绕过",
            required_files=2,
            file_roles={"entry": "入口配置文件", "config": "配置错误文件"},
            confidence_boost=0.15,
        ),
        VulnerabilityPattern(
            name="sql_injection_chain",
            description="SQL注入完整链路",
            required_files=2,
            file_roles={"input": "输入处理", "query": "SQL执行"},
            confidence_boost=0.2,
        ),
        VulnerabilityPattern(
            name="auth_bypass",
            description="认证绕过",
            required_files=2,
            file_roles={"entry": "认证入口", "check": "检查逻辑"},
            confidence_boost=0.15,
        ),
        VulnerabilityPattern(
            name="data_exposure",
            description="数据泄露链路",
            required_files=2,
            file_roles={"source": "数据源", "exposure": "泄露点"},
            confidence_boost=0.15,
        ),
    ]

    def __init__(self, dependency_graph: Optional[FileDependencyGraph] = None):
        """初始化跨文件漏洞分析器

        Args:
            dependency_graph: 文件依赖图
        """
        self.dependency_graph = dependency_graph
        self.findings: List[Finding] = []
        self.correlation_results: List[Dict[str, Any]] = []

    def add_findings(self, findings: List[Finding]) -> None:
        """添加漏洞发现

        Args:
            findings: 漏洞发现列表
        """
        self.findings.extend(findings)

    def analyze(self) -> List[CrossFileVulnerability]:
        """执行跨文件漏洞关联分析

        Returns:
            跨文件漏洞列表
        """
        cross_file_vulnerabilities = []

        file_to_findings = self._group_findings_by_file()

        for file_path, file_findings in file_to_findings.items():
            if not self.dependency_graph:
                continue

            related_files = self.dependency_graph.get_related_files(file_path, depth=2)
            for related_file in related_files:
                if related_file in file_to_findings:
                    related_findings = file_to_findings[related_file]
                    for main_finding in file_findings:
                        for rel_finding in related_findings:
                            if self._can_correlate(main_finding, rel_finding):
                                xfv = self._create_cross_file_vulnerability(
                                    main_finding,
                                    rel_finding,
                                )
                                if xfv:
                                    cross_file_vulnerabilities.append(xfv)

        return cross_file_vulnerabilities

    def _group_findings_by_file(self) -> Dict[str, List[Finding]]:
        """按文件分组漏洞发现"""
        grouped: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            if finding.file_path not in grouped:
                grouped[finding.file_path] = []
            grouped[finding.file_path].append(finding)
        return grouped

    def _can_correlate(self, finding1: Finding, finding2: Finding) -> bool:
        """判断两个漏洞是否可以关联

        Args:
            finding1: 漏洞1
            finding2: 漏洞2

        Returns:
            是否可以关联
        """
        if not finding1.file_path or not finding2.file_path:
            return False

        if finding1.file_path == finding2.file_path:
            return False

        if finding1.rule_id == finding2.rule_id:
            return False

        compatible_rules = {
            ("sql_injection", "hardcoded_credentials"),
            ("xss", "input_validation"),
            ("auth_bypass", "access_control"),
            ("ssrf", "network_config"),
        }

        rule_pair = (finding1.rule_id, finding2.rule_id)
        reverse_rule_pair = (finding2.rule_id, finding1.rule_id)

        if rule_pair in compatible_rules or reverse_rule_pair in compatible_rules:
            return True

        if self.dependency_graph:
            chain = self.dependency_graph.get_call_chain(
                finding1.file_path,
                finding2.file_path,
            )
            return len(chain) > 0

        return False

    def _create_cross_file_vulnerability(
        self,
        main_finding: Finding,
        related_finding: Finding,
    ) -> Optional[CrossFileVulnerability]:
        """创建跨文件漏洞

        Args:
            main_finding: 主漏洞
            related_finding: 关联漏洞

        Returns:
            跨文件漏洞对象
        """
        files = [main_finding.file_path, related_finding.file_path]
        snippets = {
            main_finding.file_path: main_finding.code_snippet,
            related_finding.file_path: related_finding.code_snippet,
        }
        line_ranges = {
            main_finding.file_path: (main_finding.line, main_finding.line + 10),
            related_finding.file_path: (related_finding.line, related_finding.line + 10),
        }

        chain = [
            VulnerabilityStep(
                file_path=main_finding.file_path,
                line=main_finding.line,
                description=f"入口点: {main_finding.description}",
                code_snippet=main_finding.code_snippet,
            ),
            VulnerabilityStep(
                file_path=related_finding.file_path,
                line=related_finding.line,
                description=f"关联点: {related_finding.description}",
                code_snippet=related_finding.code_snippet,
            ),
        ]

        avg_confidence = (main_finding.confidence + related_finding.confidence) / 2
        severity = self._combine_severity(main_finding.severity, related_finding.severity)

        vuln_id = f"xfv_{main_finding.rule_id}_{main_finding.file_path}_{main_finding.line}"

        xfv = CrossFileVulnerability(
            vuln_id=vuln_id,
            files=files,
            line_ranges=line_ranges,
            snippets=snippets,
            chain=chain,
            score=avg_confidence + 0.1,
            confidence=avg_confidence,
            severity=severity,
            rule_id=f"multi_file_{main_finding.rule_id}",
            rule_name=f"跨文件: {main_finding.rule_name}",
            description=f"{main_finding.description} + {related_finding.description}",
            fix_suggestion=f"需要同时修复 {main_finding.file_path} 和 {related_finding.file_path}",
        )

        return xfv

    def _combine_severity(self, sev1: str, sev2: str) -> str:
        """合并严重级别"""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        level1 = severity_order.get(sev1.lower(), 2)
        level2 = severity_order.get(sev2.lower(), 2)
        max_level = max(level1, level2)

        for sev, level in severity_order.items():
            if level == max_level:
                return sev
        return "medium"

    def get_multi_file_findings(self) -> List[Finding]:
        """获取包含多文件信息的 Finding 对象

        Returns:
            包含多文件信息的 Finding 列表
        """
        cross_file_vulns = self.analyze()
        findings = []

        for xfv in cross_file_vulns:
            finding = Finding(
                rule_id=xfv.rule_id,
                rule_name=xfv.rule_name,
                description=xfv.description,
                severity=xfv.severity,
                file_path=xfv.files[0],
                line=xfv.line_ranges[xfv.files[0]][0] if xfv.files else 0,
                confidence=xfv.confidence,
                code_snippet=xfv.snippets.get(xfv.files[0], ""),
                fix_suggestion=xfv.fix_suggestion,
                files=xfv.files,
                snippets=xfv.snippets,
                chain=xfv.chain,
                cross_file_vulnerability=xfv,
            )
            findings.append(finding)

        return findings


def correlate_findings(
    findings: List[Finding],
    dependency_graph: Optional[FileDependencyGraph] = None,
) -> List[CrossFileVulnerability]:
    """关联漏洞发现

    Args:
        findings: 漏洞发现列表
        dependency_graph: 文件依赖图

    Returns:
        跨文件漏洞列表
    """
    analyzer = CrossFileVulnerabilityAnalyzer(dependency_graph)
    analyzer.add_findings(findings)
    return analyzer.analyze()
