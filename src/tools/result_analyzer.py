"""结果分析器

聚合多工具扫描结果，AI辅助验证，减少误报。
"""

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AggregatedFinding:
    """聚合后的漏洞发现"""

    cwe_id: Optional[str]
    description: str
    severity: str
    confidence: float
    sources: List[str]
    evidence: List[str]
    affected_urls: List[str]
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "sources": self.sources,
            "evidence": self.evidence,
            "affected_urls": self.affected_urls,
            "remediation": self.remediation,
        }


@dataclass
class AnalysisReport:
    """分析报告"""

    total_findings: int
    aggregated_findings: List[AggregatedFinding]
    high_confidence_findings: List[AggregatedFinding]
    false_positive_candidates: List[AggregatedFinding]
    recommendations: List[str]
    next_steps: List[str]
    confidence: float
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "aggregated_findings": [f.to_dict() for f in self.aggregated_findings],
            "high_confidence_findings": [f.to_dict() for f in self.high_confidence_findings],
            "false_positive_candidates": [f.to_dict() for f in self.false_positive_candidates],
            "recommendations": self.recommendations,
            "next_steps": self.next_steps,
            "confidence": self.confidence,
            "summary": self.summary,
        }


class ResultAnalyzer:
    """结果分析器

    聚合多工具扫描结果，识别高置信度发现，标记可能的误报。
    """

    SEVERITY_ORDER = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    CWE_MAPPINGS = {
        "sql": "CWE-89",
        "sql injection": "CWE-89",
        "sqli": "CWE-89",
        "xss": "CWE-79",
        "cross-site scripting": "CWE-79",
        "command injection": "CWE-78",
        "cmd injection": "CWE-78",
        "os command": "CWE-78",
        "path traversal": "CWE-22",
        "directory traversal": "CWE-22",
        "lfi": "CWE-22",
        "rfi": "CWE-98",
        "remote file inclusion": "CWE-98",
        "xxe": "CWE-611",
        "xml external entity": "CWE-611",
        "csrf": "CWE-352",
        "cross-site request": "CWE-352",
        "csrf": "CWE-352",
        "ssrf": "CWE-918",
        "server-side request": "CWE-918",
        "idor": "CWE-639",
        "broken authentication": "CWE-287",
        "sensitive data": "CWE-200",
        "information disclosure": "CWE-200",
        "secret": "CWE-798",
        "api key": "CWE-798",
        "hardcoded": "CWE-547",
    }

    FALSE_POSITIVE_PATTERNS = [
        r"test",
        r"example",
        r"sample",
        r"demo",
        r"localhost",
        r"127\.0\.0\.1",
        r"0\.0\.0\.0",
        r"\.example\.com",
        r"favicon\.ico",
        r"robots\.txt",
        r"\.css",
        r"\.js",
        r"\.png",
        r"\.jpg",
    ]

    def __init__(
        self,
        confidence_threshold: float = 0.7,
        ai_verification_enabled: bool = True,
    ):
        self.confidence_threshold = confidence_threshold
        self.ai_verification_enabled = ai_verification_enabled

    def analyze(
        self,
        results: List[Dict[str, Any]],
        target_url: str = "",
    ) -> AnalysisReport:
        """分析扫描结果

        Args:
            results: 扫描结果列表
            target_url: 目标URL

        Returns:
            分析报告
        """
        if not results:
            return AnalysisReport(
                total_findings=0,
                aggregated_findings=[],
                high_confidence_findings=[],
                false_positive_candidates=[],
                recommendations=["无发现，建议扩大扫描范围"],
                next_steps=[],
                confidence=0.0,
            )

        aggregated = self._aggregate_findings(results)

        high_confidence = self._filter_high_confidence(aggregated)

        false_positives = self._identify_false_positives(aggregated)

        severity_counts = self._count_by_severity(aggregated)

        recommendations = self._generate_recommendations(aggregated, severity_counts)

        next_steps = self._determine_next_steps(aggregated, high_confidence)

        avg_confidence = sum(f.confidence for f in aggregated) / len(aggregated) if aggregated else 0.0

        summary = {
            "total_raw_findings": len(results),
            "total_aggregated": len(aggregated),
            "high_confidence_count": len(high_confidence),
            "false_positive_candidates": len(false_positives),
            "severity_breakdown": severity_counts,
            "average_confidence": avg_confidence,
        }

        return AnalysisReport(
            total_findings=len(results),
            aggregated_findings=aggregated,
            high_confidence_findings=high_confidence,
            false_positive_candidates=false_positives,
            recommendations=recommendations,
            next_steps=next_steps,
            confidence=avg_confidence,
            summary=summary,
        )

    def _aggregate_findings(
        self,
        results: List[Dict[str, Any]],
    ) -> List[AggregatedFinding]:
        """聚合发现

        Args:
            results: 原始结果列表

        Returns:
            聚合后的发现列表
        """
        grouped = defaultdict(lambda: {
            "cwe_id": None,
            "description": "",
            "severities": [],
            "confidences": [],
            "sources": [],
            "evidence": [],
            "affected_urls": [],
        })

        for result in results:
            key = self._generate_key(result)

            cwe_id = result.get("cwe_id") or self._map_to_cwe(result.get("description", ""))
            if cwe_id and not grouped[key]["cwe_id"]:
                grouped[key]["cwe_id"] = cwe_id
            elif cwe_id and grouped[key]["cwe_id"] and cwe_id != grouped[key]["cwe_id"]:
                grouped[key]["cwe_id"] = self._merge_cwe(grouped[key]["cwe_id"], cwe_id)

            if not grouped[key]["description"]:
                grouped[key]["description"] = result.get("description", "Unknown finding")

            grouped[key]["severities"].append(result.get("severity", "INFO"))
            grouped[key]["confidences"].append(result.get("confidence", result.get("tool_confidence", 0.5)))

            source = result.get("source", "unknown")
            if source not in grouped[key]["sources"]:
                grouped[key]["sources"].append(source)

            evidence = result.get("evidence") or result.get("metadata", {}).get("evidence", "")
            if evidence and evidence not in grouped[key]["evidence"]:
                grouped[key]["evidence"].append(str(evidence)[:200])

            url = result.get("file", result.get("url", ""))
            if url and url not in grouped[key]["affected_urls"]:
                grouped[key]["affected_urls"].append(url)

        aggregated = []

        for key, data in grouped.items():
            severity = self._highest_severity(data["severities"])
            confidence = sum(data["confidences"]) / len(data["confidences"]) if data["confidences"] else 0.0

            if len(data["confidences"]) > 1:
                confidence = min(confidence + 0.1, 1.0)

            remediation = self._suggest_remediation(data["cwe_id"], data["description"])

            aggregated.append(AggregatedFinding(
                cwe_id=data["cwe_id"],
                description=data["description"],
                severity=severity,
                confidence=confidence,
                sources=data["sources"],
                evidence=data["evidence"],
                affected_urls=data["affected_urls"],
                remediation=remediation,
            ))

        aggregated.sort(
            key=lambda f: (
                self.SEVERITY_ORDER.get(f.severity, 5),
                -f.confidence,
            )
        )

        return aggregated

    def _generate_key(self, result: Dict[str, Any]) -> str:
        """生成发现key

        Args:
            result: 单个发现

        Returns:
            唯一key
        """
        cwe_id = result.get("cwe_id", "")
        desc = result.get("description", "")[:50].lower()
        url = result.get("file", result.get("url", ""))[:100]

        return f"{cwe_id}:{desc}:{url}"

    def _map_to_cwe(self, description: str) -> Optional[str]:
        """将描述映射到CWE

        Args:
            description: 漏洞描述

        Returns:
            CWE ID
        """
        desc_lower = description.lower()

        for pattern, cwe_id in self.CWE_MAPPINGS.items():
            if pattern in desc_lower:
                return cwe_id

        return None

    def _merge_cwe(self, cwe1: str, cwe2: str) -> str:
        """合并CWE ID

        Args:
            cwe1: CWE 1
            cwe2: CWE 2

        Returns:
            合并后的CWE
        """
        if cwe1 == cwe2:
            return cwe1

        if cwe1.startswith("CWE-") and cwe2.startswith("CWE-"):
            nums1 = int(cwe1.split("-")[1]) if "-" in cwe1 else 0
            nums2 = int(cwe2.split("-")[1]) if "-" in cwe2 else 0
            if nums1 < nums2:
                return cwe1
            return cwe2

        return cwe1 or cwe2

    def _highest_severity(self, severities: List[str]) -> str:
        """获取最高严重程度

        Args:
            severities: 严重程度列表

        Returns:
            最高严重程度
        """
        if not severities:
            return "INFO"

        severities_upper = [s.upper() for s in severities]

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in severities_upper:
                return severity

        return "INFO"

    def _filter_high_confidence(
        self,
        findings: List[AggregatedFinding],
    ) -> List[AggregatedFinding]:
        """筛选高置信度发现

        Args:
            findings: 聚合后的发现列表

        Returns:
            高置信度发现列表
        """
        return [
            f for f in findings
            if f.confidence >= self.confidence_threshold
        ]

    def _identify_false_positives(
        self,
        findings: List[AggregatedFinding],
    ) -> List[AggregatedFinding]:
        """识别可能的误报

        Args:
            findings: 聚合后的发现列表

        Returns:
            可能的误报列表
        """
        candidates = []

        for finding in findings:
            if self._is_likely_false_positive(finding):
                candidates.append(finding)

        return candidates

    def _is_likely_false_positive(self, finding: AggregatedFinding) -> bool:
        """判断是否可能是误报

        Args:
            finding: 漏洞发现

        Returns:
            是否可能是误报
        """
        if finding.confidence < 0.5:
            return True

        for url in finding.affected_urls:
            url_lower = url.lower()
            for pattern in self.FALSE_POSITIVE_PATTERNS:
                if re.search(pattern, url_lower, re.IGNORECASE):
                    return True

        if len(finding.evidence) == 0 and len(finding.sources) == 1:
            return True

        return False

    def _count_by_severity(
        self,
        findings: List[AggregatedFinding],
    ) -> Dict[str, int]:
        """按严重程度统计

        Args:
            findings: 聚合后的发现列表

        Returns:
            统计字典
        """
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for finding in findings:
            severity = finding.severity.upper()
            if severity in counts:
                counts[severity] += 1

        return counts

    def _generate_recommendations(
        self,
        findings: List[AggregatedFinding],
        severity_counts: Dict[str, int],
    ) -> List[str]:
        """生成建议

        Args:
            findings: 聚合后的发现列表
            severity_counts: 严重程度统计

        Returns:
            建议列表
        """
        recommendations = []

        if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0:
            recommendations.append("发现高危漏洞，建议立即修复")
            recommendations.append("优先处理 CRITICAL/HIGH 级别的漏洞")

        if severity_counts["MEDIUM"] > 0:
            recommendations.append("中等风险漏洞建议在下一迭代中修复")

        if not findings:
            recommendations.append("未发现明显漏洞，建议进行更深入的渗透测试")

        cwe_counts = self._count_by_cwe(findings)
        if cwe_counts:
            top_cwe = max(cwe_counts.items(), key=lambda x: x[1])
            if top_cwe[1] > 1:
                recommendations.append(f"检测到 {top_cwe[0]} 类型漏洞较多，建议进行全面排查")

        recommendations.append("建议定期进行安全扫描和代码审查")

        return recommendations

    def _count_by_cwe(self, findings: List[AggregatedFinding]) -> Dict[str, int]:
        """按CWE统计

        Args:
            findings: 聚合后的发现列表

        Returns:
            CWE统计
        """
        counts = {}

        for finding in findings:
            cwe = finding.cwe_id or "Unknown"
            counts[cwe] = counts.get(cwe, 0) + 1

        return counts

    def _determine_next_steps(
        self,
        findings: List[AggregatedFinding],
        high_confidence: List[AggregatedFinding],
    ) -> List[str]:
        """确定后续步骤

        Args:
            findings: 聚合后的发现列表
            high_confidence: 高置信度发现

        Returns:
            后续步骤列表
        """
        next_steps = []

        if high_confidence:
            next_steps.append("验证高置信度漏洞的可利用性")

            cwe_ids = set(f.cwe_id for f in high_confidence if f.cwe_id)
            if "CWE-89" in cwe_ids:
                next_steps.append("尝试使用 sqlmap 进行深度SQL注入测试")
            if "CWE-79" in cwe_ids:
                next_steps.append("验证XSS漏洞并检查浏览器实际执行")

        if len(findings) < 3:
            next_steps.append("发现数量较少，建议尝试更多工具进行扫描")

        has_source_code = any("semgrep" in f.sources or "gitleaks" in f.sources for f in findings)
        if not has_source_code:
            next_steps.append("建议进行源码静态分析以发现更多潜在漏洞")

        next_steps.append("生成详细的渗透测试报告")

        return next_steps

    def _suggest_remediation(self, cwe_id: Optional[str], description: str) -> str:
        """建议修复方案

        Args:
            cwe_id: CWE ID
            description: 漏洞描述

        Returns:
            修复建议
        """
        if cwe_id:
            remediations = {
                "CWE-89": "使用参数化查询或ORM框架避免SQL注入",
                "CWE-79": "实施输出编码和使用Content-Security-Policy",
                "CWE-78": "避免直接使用用户输入执行系统命令",
                "CWE-22": "对用户输入进行严格验证并使用安全路径操作函数",
                "CWE-98": "禁止远程文件包含或使用白名单",
                "CWE-611": "禁用XML外部实体解析",
                "CWE-352": "实施CSRF令牌验证",
                "CWE-918": "限制请求允许的URL范围",
                "CWE-287": "实施强身份验证和会话管理",
                "CWE-200": "避免敏感数据暴露",
                "CWE-798": "使用安全的密钥管理方案",
            }

            if cwe_id in remediations:
                return remediations[cwe_id]

        desc_lower = description.lower()
        if "sql" in desc_lower:
            return "使用参数化查询或ORM框架"
        if "xss" in desc_lower:
            return "实施输出编码和使用Content-Security-Policy"
        if "command" in desc_lower:
            return "避免直接执行系统命令，使用安全的API"
        if "secret" in desc_lower or "key" in desc_lower:
            return "使用环境变量或密钥管理服务存储敏感信息"

        return "根据具体漏洞类型实施相应的安全措施"


def analyze_results(
    results: List[Dict[str, Any]],
    target_url: str = "",
) -> AnalysisReport:
    """分析扫描结果的便捷函数

    Args:
        results: 扫描结果列表
        target_url: 目标URL

    Returns:
        分析报告
    """
    analyzer = ResultAnalyzer()
    return analyzer.analyze(results, target_url)
