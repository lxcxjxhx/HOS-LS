"""输出格式化器模块

提供统一的漏洞输出格式化，支持中英文双语展示。
"""

from typing import Dict, Any, List, Optional
from src.utils.translation import (
    translate_severity,
    translate_verdict,
    translate_vulnerability_title,
    translate_recommendation,
    SEVERITY_MAP,
    VERDICT_MAP,
    STATUS_MAP
)

class OutputFormatter:
    """输出格式化器

    提供统一的漏洞输出格式化，不修改原始数据结构，只做展示层转换。
    """

    def __init__(self, lang: str = "zh"):
        """初始化格式化器

        Args:
            lang: 语言偏好，默认为中文
        """
        self.lang = lang

    def format_finding(self, vuln: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
        """格式化单个漏洞输出

        Args:
            vuln: 漏洞字典
            include_raw: 是否包含原始字段

        Returns:
            格式化后的漏洞字典
        """
        if self.lang != "zh":
            return vuln

        formatted = {}

        if include_raw:
            formatted["raw"] = vuln.copy()

        severity = vuln.get("severity", "")
        formatted["severity"] = severity
        formatted["severity_cn"] = translate_severity(severity)

        vulnerability = vuln.get("vulnerability", "")
        formatted["vulnerability"] = vulnerability
        formatted["vulnerability_cn"] = translate_vulnerability_title(vulnerability)

        location = vuln.get("location", "")
        formatted["location"] = location

        status = vuln.get("status", "")
        formatted["status"] = status
        formatted["status_cn"] = STATUS_MAP.get(status.upper(), status) if status else ""

        evidence = vuln.get("evidence", "")
        formatted["evidence"] = evidence

        recommendation = vuln.get("recommendation", "")
        if isinstance(recommendation, str):
            formatted["recommendation"] = recommendation
            formatted["recommendation_cn"] = translate_recommendation(recommendation)
        elif isinstance(recommendation, list):
            formatted["recommendation"] = recommendation
            formatted["recommendation_cn"] = [translate_recommendation(r) for r in recommendation]
        else:
            formatted["recommendation"] = ""
            formatted["recommendation_cn"] = ""

        formatted["cvss_score"] = vuln.get("cvss_score", "")
        formatted["confidence"] = vuln.get("confidence", "")
        formatted["requires_human_review"] = vuln.get("requires_human_review", False)

        return formatted

    def format_findings(self, findings: List[Dict[str, Any]], include_raw: bool = False) -> List[Dict[str, Any]]:
        """格式化多个漏洞输出

        Args:
            findings: 漏洞列表
            include_raw: 是否包含原始字段

        Returns:
            格式化后的漏洞列表
        """
        return [self.format_finding(f, include_raw) for f in findings]

    def format_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """格式化摘要输出

        Args:
            summary: 摘要字典

        Returns:
            格式化后的摘要字典
        """
        if self.lang != "zh":
            return summary

        formatted = summary.copy()

        formatted["high_cn"] = SEVERITY_MAP.get("HIGH", "高危")
        formatted["medium_cn"] = SEVERITY_MAP.get("MEDIUM", "中危")
        formatted["low_cn"] = SEVERITY_MAP.get("LOW", "低危")
        formatted["critical_cn"] = SEVERITY_MAP.get("CRITICAL", "严重")
        formatted["info_cn"] = SEVERITY_MAP.get("INFO", "信息")

        return formatted

    def format_display_text(self, vuln: Dict[str, Any]) -> str:
        """生成易读的漏洞展示文本

        Args:
            vuln: 漏洞字典

        Returns:
            格式化后的文本
        """
        severity_cn = translate_severity(vuln.get("severity", ""))
        vuln_title = translate_vulnerability_title(vuln.get("vulnerability", ""))
        location = vuln.get("location", "未知位置")
        status_cn = STATUS_MAP.get(vuln.get("status", "").upper(), "")

        lines = [
            f"{severity_cn} {vuln_title}",
            f"位置: {location}",
            f"状态: {status_cn}",
        ]

        evidence = vuln.get("evidence", "")
        if evidence:
            lines.append(f"证据: {evidence[:100]}")

        recommendation = vuln.get("recommendation", "")
        if recommendation:
            if isinstance(recommendation, list):
                lines.append("建议:")
                for r in recommendation:
                    lines.append(f"  - {translate_recommendation(r)}")
            else:
                lines.append(f"建议: {translate_recommendation(recommendation)}")

        return "\n".join(lines)

def format_finding_cn(vuln: Dict[str, Any], include_raw: bool = False) -> Dict[str, Any]:
    """便捷函数：格式化漏洞输出（中文优先）

    Args:
        vuln: 漏洞字典
        include_raw: 是否包含原始字段

    Returns:
        格式化后的漏洞字典
    """
    formatter = OutputFormatter(lang="zh")
    return formatter.format_finding(vuln, include_raw)

def format_findings_cn(findings: List[Dict[str, Any]], include_raw: bool = False) -> List[Dict[str, Any]]:
    """便捷函数：格式化多个漏洞输出

    Args:
        findings: 漏洞列表
        include_raw: 是否包含原始字段

    Returns:
        格式化后的漏洞列表
    """
    formatter = OutputFormatter(lang="zh")
    return formatter.format_findings(findings, include_raw)
