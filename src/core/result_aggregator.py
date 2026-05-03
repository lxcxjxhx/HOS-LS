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

    def _normalize_rule_id(self) -> str:
        """规范化规则ID，将相似的规则归为一组

        例如: RULE_windows, RULE_linux -> RULE
              SQL_INJECTION_1, SQL_INJECTION_2 -> SQL_INJECTION
              RemoteTokenServices_SSRF -> SSRF
        """
        import re
        rule_id = self.rule_id
        parts = rule_id.split('_')

        if len(parts) > 2:
            if parts[-1].isdigit():
                base_rule = '_'.join(parts[:-1])
                return base_rule

        if rule_id.endswith('_windows') or rule_id.endswith('_linux') or rule_id.endswith('_unix'):
            return '_'.join(parts[:-1])

        rule_id_lower = rule_id.lower()

        if 'ssrf' in rule_id_lower:
            return 'SSRF'
        if 'sql' in rule_id_lower and 'inject' in rule_id_lower:
            return 'SQL_INJECTION'
        if 'xss' in rule_id_lower or 'crosssite' in rule_id_lower:
            return 'XSS'
        if 'csrf' in rule_id_lower or 'crosssite' in rule_id_lower:
            return 'CSRF'
        if 'path' in rule_id_lower and 'traversal' in rule_id_lower:
            return 'PATH_TRAVERSAL'
        if 'command' in rule_id_lower and 'inject' in rule_id_lower:
            return 'COMMAND_INJECTION'
        if 'xxe' in rule_id_lower:
            return 'XXE'
        if 'json' in rule_id_lower and ('web' in rule_id_lower or 'vulnerability' in rule_id_lower):
            return 'JSON_WEB_VULNERABILITY'
        if 'spring' in rule_id_lower and 'cloud' in rule_id_lower:
            return 'SPRING_CLOUD_VULNERABILITY'
        if 'authentication' in rule_id_lower or 'auth' in rule_id_lower:
            return 'AUTHENTICATION'
        if 'authorization' in rule_id_lower or 'authz' in rule_id_lower:
            return 'AUTHORIZATION'
        if 'credential' in rule_id_lower or 'secret' in rule_id_lower or 'password' in rule_id_lower:
            return 'CREDENTIAL'
        if 'token' in rule_id_lower and ('jwt' in rule_id_lower or 'session' in rule_id_lower):
            return 'TOKEN_VULNERABILITY'
        if 'remote' in rule_id_lower and 'code' in rule_id_lower and 'exec' in rule_id_lower:
            return 'RCE'
        if 'deserializ' in rule_id_lower:
            return 'DESERIALIZATION'
        if 'access' in rule_id_lower and 'control' in rule_id_lower:
            return 'ACCESS_CONTROL'
        if 'rate' in rule_id_lower and 'limit' in rule_id_lower:
            return 'RATE_LIMITING'
        if 'cors' in rule_id_lower:
            return 'CORS'
        if 'redirect' in rule_id_lower and ('open' in rule_id_lower or 'unvalidated' in rule_id_lower):
            return 'OPEN_REDIRECT'
        if 'idor' in rule_id_lower or 'indirect' in rule_id_lower and 'object' in rule_id_lower:
            return 'IDOR'
        if 'ssti' in rule_id_lower or ('server' in rule_id_lower and 'template' in rule_id_lower and 'inject' in rule_id_lower):
            return 'SSTI'
        if 'websocket' in rule_id_lower:
            return 'WEBSOCKET'
        if 'htt' in rule_id_lower and 'response' in rule_id_lower and 'split' in rule_id_lower:
            return 'HTTP_RESPONSE_SPLITTING'

        common_suffixes = ['vulnerability', 'vuln', 'issue', 'problem', 'risk', 'weakness', 'finding', 'security']
        for suffix in common_suffixes:
            pattern = r'(.+?)' + suffix + r'$'
            match = re.match(pattern, rule_id_lower)
            if match:
                return match.group(1).upper()

        return rule_id

    def _normalize_line(self, proximity: int = 5) -> int:
        """规范化行号，将相邻的发现归为一组

        Args:
            proximity: 行号接近范围
        """
        return (self.line // proximity) * proximity

    def get_signal_key(self) -> Tuple[str, str, int]:
        """获取风险信号键，用于智能去重

        将相似规则的发现归为一组（规范化规则ID）
        将相邻行号的发现归为一组（规范化行号）
        """
        normalized_rule = self._normalize_rule_id()
        normalized_line = self._normalize_line()
        return (normalized_rule, self.file_path, normalized_line)


@dataclass
class AggregatedResult:
    """聚合结果"""

    summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[AggregatedFinding] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    rule_counts: Dict[str, int] = field(default_factory=dict)
    file_counts: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    verification_stats: Dict[str, Any] = field(default_factory=dict)

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
            "verification_stats": self.verification_stats,
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

    def smart_deduplicate(self) -> int:
        """智能去重 - 基于风险信号去重（返回移除的数量）

        使用规范化规则ID和相邻行号分组
        保留同组中置信度最高的发现
        """
        original_count = len(self.findings)
        signal_groups: Dict[Tuple[str, str, int], List[AggregatedFinding]] = {}

        for finding in self.findings:
            signal_key = finding.get_signal_key()
            if signal_key not in signal_groups:
                signal_groups[signal_key] = []
            signal_groups[signal_key].append(finding)

        unique_findings: List[AggregatedFinding] = []
        removed_count = 0

        for signal_key, group in signal_groups.items():
            if len(group) == 1:
                unique_findings.append(group[0])
            else:
                best_finding = max(group, key=lambda f: f.confidence)
                unique_findings.append(best_finding)
                removed_count += len(group) - 1
                print(f"[DEBUG] 智能去重: 合并 {len(group)} 个相似发现 -> 保留 1 个, 规则: {signal_key[0]}, 文件: {signal_key[1]}, 行号: {signal_key[2]}")

        self.findings = unique_findings
        print(f"[DEBUG] 智能去重完成: 原始 {original_count} 个发现, 去重后 {len(unique_findings)} 个发现, 移除 {removed_count} 个重复")
        return removed_count

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

    def get_statistics(self, include_verification: bool = True) -> Dict[str, Any]:
        """获取统计信息

        Args:
            include_verification: 是否包含验证统计
        """
        severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        rule_counts: Dict[str, int] = {}
        file_counts: Dict[str, int] = {}

        verification_stats = {
            "triple_verified": 0,
            "double_verified": 0,
            "single_verified": 0,
            "needs_review": 0,
            "potential_hallucination": 0,
            "unknown": 0,
        }

        for finding in self.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            rule_id = finding.rule_id
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

            file_path = finding.file_path
            file_counts[file_path] = file_counts.get(file_path, 0) + 1

            if include_verification:
                v_level = finding.metadata.get('verification_level', 'unknown')
                if v_level in verification_stats:
                    verification_stats[v_level] += 1

        total_findings = len(self.findings)
        avg_confidence = (
            sum(f.confidence for f in self.findings) / total_findings
            if total_findings > 0
            else 0.0
        )

        result = {
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "rule_counts": rule_counts,
            "file_counts": file_counts,
            "avg_confidence": avg_confidence,
            "unique_files": len(file_counts),
            "unique_rules": len(rule_counts),
        }

        if include_verification:
            result["verification_stats"] = verification_stats

        return result

    def aggregate(
        self,
        findings: List[AggregatedFinding] = None,
        sort_by: str = "severity",
        include_verification: bool = True,
        enable_smart_dedup: bool = True
    ) -> AggregatedResult:
        """执行聚合

        Args:
            findings: 发现列表（如果为None则使用已添加的发现）
            sort_by: 排序方式 (severity/confidence/file)
            include_verification: 是否包含验证统计
            enable_smart_dedup: 是否启用智能去重
        """
        if findings is not None:
            if findings and isinstance(findings[0], dict):
                self.findings = [convert_to_aggregated_finding(f) for f in findings]
            else:
                self.findings = findings
        else:
            if not self.findings:
                return AggregatedResult(
                    summary={"total_findings": 0},
                    findings=[],
                    severity_counts={},
                    rule_counts={},
                    file_counts={},
                )

        if enable_smart_dedup:
            removed = self.smart_deduplicate()
            if removed > 0:
                print(f"[INFO] 智能去重移除 {removed} 个重复发现")

        stats = self.get_statistics(include_verification=include_verification)

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

        if include_verification and "verification_stats" in stats:
            summary["verification_stats"] = stats["verification_stats"]

        return AggregatedResult(
            summary=summary,
            findings=self.findings.copy(),
            severity_counts=stats["severity_counts"],
            rule_counts=stats["rule_counts"],
            file_counts=stats["file_counts"],
            verification_stats=stats.get("verification_stats", {}),
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
