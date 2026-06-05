"""输出格式化器模块

提供统一的漏洞输出格式化，支持中英文双语展示。
APTS合规增强:
- APTS-RP-003: 置信度评分 (0.0-1.0) 带可审计方法论
- APTS-RP-004: 证据链 (文件路径、行号、代码片段、调用链)
- APTS-RP-006: 误报率估算
- APTS-RP-008: 漏洞覆盖率统计
- APTS-RP-004: 发现溯源 (规则来源、分析器来源)
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

        APTS-RP-003: 置信度评分 (0.0-1.0) 带可审计方法论
        APTS-RP-004: 证据链 (文件路径、行号、代码片段、调用链)
        APTS-RP-004: 发现溯源 (规则来源、分析器来源)

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

        formatted["apts"] = self._format_apts_compliance(vuln)

        return formatted

    def _format_apts_compliance(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """格式化APTS合规字段

        APTS-RP-003: 置信度评分带方法论
        APTS-RP-004: 证据链
        APTS-RP-004: 发现溯源
        APTS-RP-006: 误报率

        Args:
            vuln: 漏洞字典

        Returns:
            APTS合规信息字典
        """
        apts = {}

        apts["confidence"] = self._format_confidence_score(vuln)

        apts["evidence_chain"] = self._format_evidence_chain(vuln)

        apts["provenance"] = self._format_finding_provenance(vuln)

        apts["false_positive"] = self._format_false_positive_rate(vuln)

        return apts

    def _format_confidence_score(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """格式化置信度评分 (APTS-RP-003)

        置信度评分范围 0.0-1.0，包含可审计方法论

        Args:
            vuln: 漏洞字典

        Returns:
            置信度评分字典
        """
        confidence = vuln.get("confidence", 0.0)
        metadata = vuln.get("metadata", {}) or {}

        methodology = metadata.get("confidence_methodology", "default")
        if methodology == "default":
            evidence_count = len(metadata.get("evidence", []) or [])
            if evidence_count >= 3:
                methodology_detail = "多证据验证 (>=3条证据)"
                base_score = 0.9
            elif evidence_count == 2:
                methodology_detail = "双证据验证 (2条证据)"
                base_score = 0.75
            elif evidence_count == 1:
                methodology_detail = "单证据验证 (1条证据)"
                base_score = 0.6
            else:
                methodology_detail = "无直接证据，基于模式匹配"
                base_score = 0.4
            confidence = min(1.0, base_score + (evidence_count * 0.05))
        elif methodology == "line_validated":
            methodology_detail = "行号验证通过"
        elif methodology == "ai_analyzed":
            methodology_detail = "AI深度分析"
        else:
            methodology_detail = f"自定义方法: {methodology}"

        return {
            "score": round(confidence, 2),
            "methodology": methodology_detail,
            "methodology_id": metadata.get("confidence_methodology", "default"),
            "evidence_count": len(metadata.get("evidence", []) or []),
            "verified": metadata.get("line_match_status", "") == "EXACT",
            "auditable": True,
        }

    def _format_evidence_chain(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """格式化证据链 (APTS-RP-004)

        包含文件路径、行号、代码片段、调用链

        Args:
            vuln: 漏洞字典

        Returns:
            证据链字典
        """
        metadata = vuln.get("metadata", {}) or {}
        evidence = metadata.get("evidence", []) or []

        chain_links = []
        for i, ev in enumerate(evidence):
            if isinstance(ev, dict):
                chain_links.append({
                    "index": i + 1,
                    "file_path": ev.get("file_path", ""),
                    "line_number": ev.get("line", ev.get("line_number", 0)),
                    "code_snippet": ev.get("code_snippet", ev.get("snippet", "")),
                    "description": ev.get("description", ""),
                    "type": ev.get("type", "evidence"),
                })
            elif isinstance(ev, str):
                chain_links.append({
                    "index": i + 1,
                    "file_path": metadata.get("file_path", ""),
                    "line_number": metadata.get("line", 0),
                    "code_snippet": ev,
                    "description": "",
                    "type": "evidence",
                })

        call_chain = []
        chain_data = vuln.get("chain", []) or metadata.get("call_chain", [])
        for i, step in enumerate(chain_data):
            if isinstance(step, dict):
                call_chain.append({
                    "index": i + 1,
                    "file_path": step.get("file_path", ""),
                    "line_number": step.get("line", 0),
                    "code_snippet": step.get("code_snippet", ""),
                    "description": step.get("description", ""),
                })
            elif hasattr(step, "file_path"):
                call_chain.append({
                    "index": i + 1,
                    "file_path": step.file_path,
                    "line_number": step.line if hasattr(step, "line") else 0,
                    "code_snippet": step.code_snippet if hasattr(step, "code_snippet") else "",
                    "description": step.description if hasattr(step, "description") else "",
                })

        location = vuln.get("location", {})
        if isinstance(location, str):
            file_path = location
            line_number = 0
        elif isinstance(location, dict):
            file_path = location.get("file", "")
            line_number = location.get("line", 0)
        else:
            file_path = ""
            line_number = 0

        code_snippet = vuln.get("code_snippet", metadata.get("code_snippet", ""))

        return {
            "primary": {
                "file_path": file_path,
                "line_number": line_number,
                "code_snippet": code_snippet,
            },
            "evidence_links": chain_links,
            "call_chain": call_chain,
            "total_evidence_items": len(chain_links) + len(call_chain),
        }

    def _format_finding_provenance(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """格式化发现溯源 (APTS-RP-004)

        追踪发现来源：哪个规则、哪个分析器

        Args:
            vuln: 漏洞字典

        Returns:
            溯源字典
        """
        metadata = vuln.get("metadata", {}) or {}
        rule_id = vuln.get("rule_id", metadata.get("rule_id", ""))
        rule_name = vuln.get("rule_name", metadata.get("rule_name", ""))
        analyzer = metadata.get("analyzer", metadata.get("source", "ai"))
        analyzer_version = metadata.get("analyzer_version", "1.0.0")

        category = metadata.get("category", "general")
        scan_area = metadata.get("scan_area", "static_analysis")

        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "analyzer": analyzer,
            "analyzer_version": analyzer_version,
            "scan_area": scan_area,
            "category": category,
            "timestamp": metadata.get("timestamp", ""),
            "engine_version": metadata.get("engine_version", "1.0.0"),
        }

    def _format_false_positive_rate(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """格式化误报率估算 (APTS-RP-006)

        基于证据数量和验证状态估算误报率

        Args:
            vuln: 漏洞字典

        Returns:
            误报率字典
        """
        metadata = vuln.get("metadata", {}) or {}
        status = vuln.get("status", metadata.get("status", "UNCERTAIN"))

        evidence_count = len(metadata.get("evidence", []) or [])
        line_verified = metadata.get("line_match_status", "") == "EXACT"

        if status == "CONFIRMED":
            estimated_fpr = 0.01
            confidence = "high"
        elif status == "REFINED":
            estimated_fpr = 0.05
            confidence = "medium-high"
        elif status == "REJECTED":
            estimated_fpr = 1.0
            confidence = "confirmed"
        elif line_verified:
            estimated_fpr = 0.08
            confidence = "medium"
        elif evidence_count >= 2:
            estimated_fpr = 0.15
            confidence = "medium"
        elif evidence_count == 1:
            estimated_fpr = 0.30
            confidence = "low-medium"
        else:
            estimated_fpr = 0.50
            confidence = "low"

        return {
            "estimated_rate": round(estimated_fpr, 2),
            "confidence_level": confidence,
            "evidence_count": evidence_count,
            "line_verified": line_verified,
            "status": status,
            "methodology": "evidence_based_estimation",
        }

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

        APTS-RP-008: 漏洞覆盖率统计

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

        if "apts_coverage" in summary:
            formatted["apts_coverage"] = self._format_coverage_disclosure(summary["apts_coverage"])

        return formatted

    def _format_coverage_disclosure(self, coverage: Dict[str, Any]) -> Dict[str, Any]:
        """格式化覆盖率统计 (APTS-RP-008)

        Args:
            coverage: 覆盖率字典

        Returns:
            格式化后的覆盖率字典
        """
        if not isinstance(coverage, dict):
            return {}

        return {
            "total_rules_checked": coverage.get("total_rules_checked", 0),
            "rules_with_findings": coverage.get("rules_with_findings", 0),
            "coverage_percentage": round(coverage.get("coverage_percentage", 0.0), 2),
            "vulnerability_types_covered": coverage.get("vulnerability_types_covered", []),
            "vulnerability_types_total": coverage.get("vulnerability_types_total", 0),
            "by_severity": coverage.get("by_severity", {}),
            "verified_findings": coverage.get("verified_findings", 0),
            "unverified_findings": coverage.get("unverified_findings", 0),
            "false_positive_count": coverage.get("false_positive_count", 0),
            "false_positive_rate": round(coverage.get("false_positive_rate", 0.0), 2),
        }

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
