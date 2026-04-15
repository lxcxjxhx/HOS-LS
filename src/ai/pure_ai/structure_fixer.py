"""结构修复Agent模块

当JSON解析失败或Schema验证失败时，自动调用此Agent修复结构。
"""

import json
import re
from typing import Dict, Any, Optional, List
from src.ai.pure_ai.schema import FINAL_DECISION_SCHEMA

class StructureFixer:
    """结构修复Agent

    当检测到输出不符合Schema时，自动修复结构。
    """

    def __init__(self, client=None):
        self.client = client

    def fix_final_decision(self, raw_output: str) -> Dict[str, Any]:
        """修复 final_decision 结构

        Args:
            raw_output: AI原始输出

        Returns:
            修复后的结构
        """
        vulnerabilities = self._extract_vulnerabilities(raw_output)

        if vulnerabilities:
            return {
                "final_findings": vulnerabilities,
                "summary": self._generate_summary(vulnerabilities)
            }

        return {
            "final_findings": [],
            "summary": {
                "total_vulnerabilities": 0,
                "valid_vulnerabilities": 0,
                "uncertain_vulnerabilities": 0,
                "invalid_vulnerabilities": 0,
                "high_severity_count": 0,
                "medium_severity_count": 0,
                "low_severity_count": 0
            }
        }

    def _extract_vulnerabilities(self, text: str) -> List[Dict[str, Any]]:
        """从文本中提取漏洞信息

        Args:
            text: 文本

        Returns:
            漏洞列表
        """
        vulnerabilities = []

        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFO",
            "高危": "HIGH",
            "中危": "MEDIUM",
            "低危": "LOW",
            "严重": "CRITICAL"
        }

        vulnerability_types = [
            "SQL Injection", "SQL注入",
            "XSS", "Cross-Site Scripting", "跨站脚本",
            "Command Injection", "命令注入",
            "Path Traversal", "路径遍历",
            "SSRF", "Server-Side Request Forgery",
            "CSRF", "Cross-Site Request Forgery",
            "Authentication", "认证",
            "Authorization", "授权",
            "Sensitive Data", "敏感数据",
            "Hardcoded", "硬编码",
            "Insecure", "不安全",
            "Weak Crypto", "弱加密",
            "SQL", "注入"
        ]

        lines = text.split('\n')
        current_vuln = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            severity = None
            for keyword, sev in severity_map.items():
                if keyword in line:
                    severity = sev
                    break

            if severity:
                if current_vuln:
                    vulnerabilities.append(current_vuln)

                vuln_type = None
                for vtype in vulnerability_types:
                    if vtype.lower() in line.lower():
                        vuln_type = vtype
                        break

                current_vuln = {
                    "vulnerability": vuln_type or "Unknown Vulnerability",
                    "location": self._extract_location(line),
                    "severity": severity,
                    "status": "UNCERTAIN",
                    "confidence": "MEDIUM",
                    "cvss_score": self._estimate_cvss(severity),
                    "recommendation": "Manual review required",
                    "evidence": line[:200],
                    "requires_human_review": True
                }
            elif current_vuln and "→" in line:
                current_vuln["evidence"] = (current_vuln.get("evidence", "") + " " + line[:200]).strip()

        if current_vuln:
            vulnerabilities.append(current_vuln)

        return vulnerabilities[:10]

    def _extract_location(self, line: str) -> str:
        """提取位置信息

        Args:
            line: 文本行

        Returns:
            位置字符串
        """
        patterns = [
            r'line\s*(\d+)',
            r'第\s*(\d+)\s*行',
            r'at\s+(\w+\.\w+):(\d+)',
            r'位置[：:]\s*([^\s,，]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(0)

        return "Unknown location"

    def _estimate_cvss(self, severity: str) -> str:
        """估算CVSS评分

        Args:
            severity: 严重程度

        Returns:
            CVSS评分字符串
        """
        cvss_map = {
            "CRITICAL": "9.0-10.0",
            "HIGH": "7.0-8.9",
            "MEDIUM": "4.0-6.9",
            "LOW": "0.1-3.9",
            "INFO": "0.0"
        }
        return cvss_map.get(severity, "0.0")

    def _generate_summary(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """生成摘要

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            摘要字典
        """
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "valid_vulnerabilities": 0,
            "uncertain_vulnerabilities": 0,
            "invalid_vulnerabilities": 0,
            "high_severity_count": 0,
            "medium_severity_count": 0,
            "low_severity_count": 0
        }

        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO")
            severity_count[severity] = severity_count.get(severity, 0) + 1

            status = vuln.get("status", "UNCERTAIN")
            if status == "VALID":
                summary["valid_vulnerabilities"] += 1
            elif status == "UNCERTAIN":
                summary["uncertain_vulnerabilities"] += 1
            elif status == "INVALID":
                summary["invalid_vulnerabilities"] += 1

        summary["high_severity_count"] = severity_count.get("CRITICAL", 0) + severity_count.get("HIGH", 0)
        summary["medium_severity_count"] = severity_count.get("MEDIUM", 0)
        summary["low_severity_count"] = severity_count.get("LOW", 0) + severity_count.get("INFO", 0)

        return summary

    def fix_json(self, raw_text: str, schema_name: str = "final_decision") -> Dict[str, Any]:
        """修复JSON结构

        Args:
            raw_text: 原始文本
            schema_name: Schema名称

        Returns:
            修复后的数据
        """
        if schema_name == "final_decision":
            return self.fix_final_decision(raw_text)

        return {"raw": raw_text}
