"""结果聚合引擎模块

提供去重、归类、排序的扫描结果聚合功能。
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set, Tuple
from enum import Enum


class Severity(Enum):
    """严重级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        """从字符串创建"""
        s = s.lower()
        for sev in cls:
            if sev.value == s:
                return sev
        return cls.MEDIUM

    def get_order(self) -> int:
        """获取排序顺序（数值越小越严重）"""
        order_map = {
            self.CRITICAL: 0,
            self.HIGH: 1,
            self.MEDIUM: 2,
            self.LOW: 3,
            self.INFO: 4,
        }
        return order_map.get(self, 2)


@dataclass
class AggregatedFinding:
    """聚合后的发现"""

    finding_id: str = ""
    rule_id: str = ""
    rule_name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    file_path: str = ""
    line: int = 0
    column: int = 0
    confidence: float = 0.0
    message: str = ""
    code_snippet: str = ""
    fix_suggestion: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_deduplication_key(self) -> Tuple[str, str, int, str]:
        """获取去重键"""
        snippet_prefix = self.code_snippet[:50] if self.code_snippet else ""
        return (self.rule_id, self.file_path, self.line, snippet_prefix)


@dataclass
class AggregatedResult:
    """聚合结果"""

    summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[AggregatedFinding] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    rule_counts: Dict[str, int] = field(default_factory=dict)
    file_counts: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "summary": self.summary,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "description": f.description,
                    "severity": f.severity.value,
                    "file_path": f.file_path,
                    "line": f.line,
                    "column": f.column,
                    "confidence": f.confidence,
                    "message": f.message,
                    "code_snippet": f.code_snippet,
                    "fix_suggestion": f.fix_suggestion,
                    "references": f.references,
                    "tags": f.tags,
                    "metadata": f.metadata,
                }
                for f in self.findings
            ],
            "severity_counts": self.severity_counts,
            "rule_counts": self.rule_counts,
            "file_counts": self.file_counts,
            "metadata": self.metadata,
        }


class ResultAggregator:
    """结果聚合引擎"""

    def __init__(self):
        self.findings: List[AggregatedFinding] = []
        self._seen_keys: Set[Tuple[str, str, int, str]] = set()

    def add_finding(self, finding: AggregatedFinding) -> bool:
        """添加发现（自动去重）"""
        key = finding.get_deduplication_key()
        if key in self._seen_keys:
            return False
        
        self._seen_keys.add(key)
        self.findings.append(finding)
        return True

    def add_findings(self, findings: List[AggregatedFinding]) -> int:
        """批量添加发现"""
        added_count = 0
        for finding in findings:
            if self.add_finding(finding):
                added_count += 1
        return added_count

    def deduplicate(self) -> int:
        """去重（返回移除的数量）"""
        original_count = len(self.findings)
        unique_findings: List[AggregatedFinding] = []
        seen_keys: Set[Tuple[str, str, int, str]] = set()

        for finding in self.findings:
            key = finding.get_deduplication_key()
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(finding)

        self.findings = unique_findings
        self._seen_keys = seen_keys
        return original_count - len(self.findings)

    def sort_by_severity(self, descending: bool = True) -> None:
        """按严重级别排序"""
        self.findings.sort(
            key=lambda f: (
                f.severity.get_order(),
                -f.confidence,
                f.file_path,
                f.line,
            ),
            reverse=descending,
        )

    def sort_by_confidence(self, descending: bool = True) -> None:
        """按置信度排序"""
        self.findings.sort(
            key=lambda f: (
                -f.confidence,
                f.severity.get_order(),
                f.file_path,
                f.line,
            ),
            reverse=descending,
        )

    def sort_by_file(self) -> None:
        """按文件排序"""
        self.findings.sort(
            key=lambda f: (f.file_path, f.line, f.column),
        )

    def filter_by_severity(self, min_severity: Severity) -> List[AggregatedFinding]:
        """按最小严重级别过滤"""
        min_order = min_severity.get_order()
        return [
            f for f in self.findings
            if f.severity.get_order() <= min_order
        ]

    def filter_by_file(self, file_path: str) -> List[AggregatedFinding]:
        """按文件过滤"""
        return [f for f in self.findings if f.file_path == file_path]

    def filter_by_rule(self, rule_id: str) -> List[AggregatedFinding]:
        """按规则过滤"""
        return [f for f in self.findings if f.rule_id == rule_id]

    def filter_by_confidence(self, min_confidence: float) -> List[AggregatedFinding]:
        """按最小置信度过滤"""
        return [f for f in self.findings if f.confidence >= min_confidence]

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        rule_counts: Dict[str, int] = {}
        file_counts: Dict[str, int] = {}

        for finding in self.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            rule_id = finding.rule_id
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

            file_path = finding.file_path
            file_counts[file_path] = file_counts.get(file_path, 0) + 1

        total_findings = len(self.findings)
        avg_confidence = (
            sum(f.confidence for f in self.findings) / total_findings
            if total_findings > 0
            else 0.0
        )

        return {
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "rule_counts": rule_counts,
            "file_counts": file_counts,
            "avg_confidence": avg_confidence,
            "unique_files": len(file_counts),
            "unique_rules": len(rule_counts),
        }

    def aggregate(self, sort_by: str = "severity") -> AggregatedResult:
        """执行聚合"""
        stats = self.get_statistics()

        if sort_by == "severity":
            self.sort_by_severity()
        elif sort_by == "confidence":
            self.sort_by_confidence()
        elif sort_by == "file":
            self.sort_by_file()

        summary = {
            "total_findings": stats["total_findings"],
            "avg_confidence": stats["avg_confidence"],
            "unique_files": stats["unique_files"],
            "unique_rules": stats["unique_rules"],
        }

        return AggregatedResult(
            summary=summary,
            findings=self.findings.copy(),
            severity_counts=stats["severity_counts"],
            rule_counts=stats["rule_counts"],
            file_counts=stats["file_counts"],
        )

    def clear(self) -> None:
        """清空"""
        self.findings = []
        self._seen_keys = set()


def convert_to_aggregated_finding(data: Dict[str, Any]) -> AggregatedFinding:
    """从字典转换为聚合发现"""
    import hashlib

    severity = Severity.from_str(data.get("severity", "medium"))
    file_path = data.get("file_path", "")
    line = data.get("line", 0)
    rule_id = data.get("rule_id", "")

    finding_id = hashlib.md5(
        f"{rule_id}:{file_path}:{line}".encode()
    ).hexdigest()[:16]

    return AggregatedFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        rule_name=data.get("rule_name", ""),
        description=data.get("description", ""),
        severity=severity,
        file_path=file_path,
        line=line,
        column=data.get("column", 0),
        confidence=data.get("confidence", 0.5),
        message=data.get("message", ""),
        code_snippet=data.get("code_snippet", ""),
        fix_suggestion=data.get("fix_suggestion", ""),
        references=data.get("references", []),
        tags=data.get("tags", []),
        metadata=data.get("metadata", {}),
    )
