"""结果解析器模块

解析 HTML/JSON 报告，提取结构化数据。
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from html.parser import HTMLParser


@dataclass
class Finding:
    """单个发现"""
    rule_id: str
    rule_name: str
    description: str
    severity: str
    file: str
    line: int = 0
    column: int = 0
    confidence: float = 0.0
    message: str = ""
    code_snippet: str = ""
    fix_suggestion: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportSummary:
    """报告摘要"""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_duration: float = 0.0
    scan_time: Optional[str] = None
    target: str = ""
    status: str = "unknown"


@dataclass
class ParsedReport:
    """解析后的报告"""
    summary: ReportSummary
    findings: List[Finding]
    raw_data: Dict[str, Any] = field(default_factory=dict)
    parse_errors: List[str] = field(default_factory=list)
    is_complete: bool = False


class HTMLFindingParser(HTMLParser):
    """HTML 发现解析器"""

    def __init__(self):
        super().__init__()
        self.findings: List[Finding] = []
        self.current_finding: Optional[Finding] = None
        self.current_tag: str = ""
        self.current_class: str = ""
        self.current_text: str = ""
        self.in_finding: bool = False
        self.in_severity_block: bool = False
        self.current_severity: str = "info"

    def handle_starttag(self, tag: str, attrs: List[tuple]) -> None:
        self.current_tag = tag
        self.current_class = ""
        for attr_name, attr_value in attrs:
            if attr_name == "class":
                self.current_class = attr_value or ""

        if "finding" in self.current_class or tag == "div" and "severity-" in self.current_class:
            if not self.in_finding:
                self.in_finding = True
                self.current_finding = None

        if "severity-critical" in self.current_class:
            self.current_severity = "critical"
        elif "severity-high" in self.current_class:
            self.current_severity = "high"
        elif "severity-medium" in self.current_class:
            self.current_severity = "medium"
        elif "severity-low" in self.current_class:
            self.current_severity = "low"
        elif "severity-info" in self.current_class:
            self.current_severity = "info"

    def handle_endtag(self, tag: str) -> None:
        if tag == "div" and self.in_finding and self.current_finding:
            self.findings.append(self.current_finding)
            self.in_finding = False
            self.current_finding = None

    def handle_data(self, data: str) -> None:
        self.current_text += data.strip()


class JSONReportParser:
    """JSON 报告解析器"""

    @staticmethod
    def parse_report(report_path: Path) -> ParsedReport:
        """解析 JSON 报告"""
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            summary = ReportSummary()
            findings: List[Finding] = []

            if "summary" in data:
                s = data["summary"]
                summary.total_findings = s.get("total_findings", 0)
                severity_counts = s.get("severity_counts", {})
                summary.critical_count = severity_counts.get("critical", 0)
                summary.high_count = severity_counts.get("high", 0)
                summary.medium_count = severity_counts.get("medium", 0)
                summary.low_count = severity_counts.get("low", 0)
                summary.info_count = severity_counts.get("info", 0)

            if "results" in data:
                for result in data["results"]:
                    summary.target = result.get("target", "")
                    summary.scan_duration = result.get("duration", 0.0)

                    for f in result.get("findings", []):
                        finding = Finding(
                            rule_id=f.get("rule_id", ""),
                            rule_name=f.get("rule_name", ""),
                            description=f.get("description", ""),
                            severity=f.get("severity", "info"),
                            file=f.get("location", {}).get("file", ""),
                            line=f.get("location", {}).get("line", 0),
                            column=f.get("location", {}).get("column", 0),
                            confidence=f.get("confidence", 0.0),
                            message=f.get("message", ""),
                            code_snippet=f.get("code_snippet", ""),
                            fix_suggestion=f.get("fix_suggestion", ""),
                            references=f.get("references", []),
                            metadata=f.get("metadata", {})
                        )
                        findings.append(finding)

            summary.total_findings = len(findings)

            return ParsedReport(
                summary=summary,
                findings=findings,
                raw_data=data,
                is_complete=True
            )

        except Exception as e:
            return ParsedReport(
                summary=ReportSummary(),
                findings=[],
                parse_errors=[f"JSON 解析失败: {str(e)}"]
            )


class HTMLReportParser:
    """HTML 报告解析器"""

    @staticmethod
    def parse_report(report_path: Path) -> ParsedReport:
        """解析 HTML 报告"""
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                html_content = f.read()

            summary = ReportSummary()
            findings: List[Finding] = []

            summary.total_findings = HTMLReportParser._extract_total_findings(html_content)
            severity_counts = HTMLReportParser._extract_severity_counts(html_content)
            summary.critical_count = severity_counts.get("critical", 0)
            summary.high_count = severity_counts.get("high", 0)
            summary.medium_count = severity_counts.get("medium", 0)
            summary.low_count = severity_counts.get("low", 0)
            summary.info_count = severity_counts.get("info", 0)

            findings = HTMLReportParser._extract_findings(html_content)

            summary.total_findings = len(findings)

            return ParsedReport(
                summary=summary,
                findings=findings,
                raw_data={"html": html_content},
                is_complete=len(findings) > 0 or summary.total_findings > 0
            )

        except Exception as e:
            return ParsedReport(
                summary=ReportSummary(),
                findings=[],
                parse_errors=[f"HTML 解析失败: {str(e)}"]
            )

    @staticmethod
    def _extract_total_findings(html: str) -> int:
        """提取总发现数"""
        patterns = [
            r"发现问题数[:\s]*(\d+)",
            r"total_findings[:\s]*(\d+)",
            r"Issues Found[:\s]*(\d+)",
            r"共\s*(\d+)\s*个问题"
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return int(match.group(1))
        return 0

    @staticmethod
    def _extract_severity_counts(html: str) -> Dict[str, int]:
        """提取严重级别统计"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        patterns = {
            "critical": [r"严重[:\s]*(\d+)", r"Critical[:\s]*(\d+)", r"severity-critical"],
            "high": [r"高[:\s]*(\d+)", r"High[:\s]*(\d+)", r"severity-high"],
            "medium": [r"中[:\s]*(\d+)", r"Medium[:\s]*(\d+)", r"severity-medium"],
            "low": [r"低[:\s]*(\d+)", r"Low[:\s]*(\d+)", r"severity-low"],
            "info": [r"信息[:\s]*(\d+)", r"Info[:\s]*(\d+)", r"severity-info"]
        }

        for severity, severity_patterns in patterns.items():
            for pattern in severity_patterns:
                if pattern.startswith("severity-"):
                    counts[severity] = len(re.findall(pattern, html))
                else:
                    match = re.search(pattern, html)
                    if match:
                        counts[severity] = int(match.group(1))
                        break

        return counts

    @staticmethod
    def _extract_findings(html: str) -> List[Finding]:
        """提取发现列表"""
        findings: List[Finding] = []

        severity_blocks = re.findall(
            r'<div[^>]*class="[^"]*severity-(critical|high|medium|low|info)[^"]*"[^>]*>(.*?)</div>',
            html,
            re.DOTALL
        )

        for severity, block_content in severity_blocks:
            rule_id_match = re.search(r'\(([^)]+)\)', block_content)
            rule_id = rule_id_match.group(1) if rule_id_match else "UNKNOWN"

            rule_name_match = re.search(r'<h3>([^<]+)', block_content)
            rule_name = rule_name_match.group(1) if rule_name_match else "Unknown Issue"

            location_match = re.search(r'位置[:\s]*([^<\n]+)', block_content)
            location = location_match.group(1).strip() if location_match else ""

            description_match = re.search(r'描述[:\s]*([^<\n]+)', block_content)
            description = description_match.group(1).strip() if description_match else ""

            file_match = re.search(r'([^:/\\]+):(\d+)(?::(\d+))?$', location)
            if file_match:
                file_path = file_match.group(1)
                line = int(file_match.group(2))
                column = int(file_match.group(3) or "0")
            else:
                file_path = location
                line = 0
                column = 0

            finding = Finding(
                rule_id=rule_id,
                rule_name=rule_name,
                description=description,
                severity=severity,
                file=file_path,
                line=line,
                column=column
            )
            findings.append(finding)

        return findings


class ReportParser:
    """报告解析器工厂"""

    @staticmethod
    def parse(report_path: str) -> ParsedReport:
        """
        解析报告文件

        Args:
            report_path: 报告文件路径

        Returns:
            解析后的报告
        """
        path = Path(report_path)

        if not path.exists():
            return ParsedReport(
                summary=ReportSummary(),
                findings=[],
                parse_errors=[f"报告文件不存在: {report_path}"]
            )

        if path.suffix.lower() == ".json":
            return JSONReportParser.parse_report(path)
        elif path.suffix.lower() == ".html":
            return HTMLReportParser.parse_report(path)
        else:
            try:
                return JSONReportParser.parse_report(path)
            except:
                return HTMLReportParser.parse_report(path)

    @staticmethod
    def compare_reports(
        old_report: ParsedReport,
        new_report: ParsedReport
    ) -> Dict[str, Any]:
        """
        对比两份报告

        Returns:
            对比结果
        """
        old_severity = old_report.summary
        new_severity = new_report.summary

        return {
            "findings_delta": new_report.summary.total_findings - old_report.summary.total_findings,
            "critical_delta": new_severity.critical_count - old_severity.critical_count,
            "high_delta": new_severity.high_count - old_severity.high_count,
            "medium_delta": new_severity.medium_count - old_severity.medium_count,
            "low_delta": new_severity.low_count - old_severity.low_count,
            "improved": new_report.summary.total_findings < old_report.summary.total_findings,
            "degraded": new_report.summary.total_findings > old_report.summary.total_findings,
            "same": new_report.summary.total_findings == old_report.summary.total_findings
        }
