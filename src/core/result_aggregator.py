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
        if not rule_id:
            return ""
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

        # 新增：处理中文漏洞名称的相似性
        if 'sql注入' in rule_id_lower or 'sql injection' in rule_id_lower:
            return 'SQL_INJECTION'
        if '路径变量' in rule_id_lower and ('modeid' in rule_id_lower or 'mode_id' in rule_id_lower):
            return 'PATH_VARIABLE_SQL_INJECTION'
        if '路径变量未经验证' in rule_id_lower:
            return 'UNVALIDATED_PATH_VARIABLE'
        if '未授权访问' in rule_id_lower or '越权' in rule_id_lower:
            return 'UNAUTHORIZED_ACCESS'
        if '硬编码路径' in rule_id_lower or 'hardcoded' in rule_id_lower:
            return 'HARDCODED_PATH'
        if '反序列化' in rule_id_lower or 'deserial' in rule_id_lower:
            return 'DESERIALIZATION'
        if 'swagger' in rule_id_lower:
            return 'SWAGGER_EXPOSURE'
        if '验证码' in rule_id_lower or 'kaptcha' in rule_id_lower:
            return 'CAPTCHA_EXPOSURE'
        if 'redis' in rule_id_lower and 'keys' in rule_id_lower:
            return 'REDIS_KEYS_BLOCKING'
        if '注销' in rule_id_lower or 'logout' in rule_id_lower:
            return 'LOGOUT_AUTH'
        if '配置数据' in rule_id_lower or 'config' in rule_id_lower and '未授权' in rule_id_lower:
            return 'UNAUTHORIZED_CONFIG_ACCESS'
        if '输入校验' in rule_id_lower or 'valid' in rule_id_lower and '输入' in rule_id_lower:
            return 'INPUT_VALIDATION'
        if '类型转换' in rule_id_lower or 'cast' in rule_id_lower:
            return 'TYPE_CONVERSION'
        if '刷新' in rule_id_lower or 'refresh' in rule_id_lower:
            return 'CONFIG_REFRESH'
        if '错误码' in rule_id_lower or 'error_code' in rule_id_lower:
            return 'ERROR_CODE_LEAK'
        if 'id删除' in rule_id_lower or 'delete.*id' in rule_id_lower:
            return 'DELETE_BY_ID'
        if 'preauthorize' in rule_id_lower:
            return 'PREAUTHORIZE_ISSUE'
        if '凭据' in rule_id_lower or 'credential' in rule_id_lower:
            return 'CREDENTIAL_REUSE'

        common_suffixes = ['vulnerability', 'vuln', 'issue', 'problem', 'risk', 'weakness', 'finding', 'security', '漏洞', '风险', '问题']
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

    SEMANTIC_SIMILARITY_THRESHOLD = 0.7

    def __init__(self):
        self.findings: List[AggregatedFinding] = []
        self._seen_keys: Set[Tuple[str, str, int, str]] = set()

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return ResultAggregator._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @staticmethod
    def _string_similarity(s1: str, s2: str) -> float:
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        distance = ResultAggregator._levenshtein_distance(s1, s2)
        return 1.0 - (distance / max_len)

    @staticmethod
    def _token_overlap_similarity(s1: str, s2: str) -> float:
        tokens1 = set(s1.lower().split())
        tokens2 = set(s2.lower().split())
        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0
        intersection = tokens1 & tokens2
        union = tokens1 | tokens2
        return len(intersection) / len(union) if union else 0.0

    @staticmethod
    def _code_pattern_similarity(code1: str, code2: str) -> float:
        if not code1 and not code2:
            return 1.0
        if not code1 or not code2:
            return 0.0
        import re
        pattern1 = re.sub(r'\s+', '', re.sub(r'[a-zA-Z_]\w*', 'ID', code1))
        pattern2 = re.sub(r'\s+', '', re.sub(r'[a-zA-Z_]\w*', 'ID', code2))
        return ResultAggregator._string_similarity(pattern1, pattern2)

    def _calculate_finding_similarity(self, f1: AggregatedFinding, f2: AggregatedFinding) -> float:
        weights = {
            'vuln_type': 0.35,
            'description': 0.25,
            'code_pattern': 0.25,
            'severity': 0.15,
        }
        vuln_type1 = f1._normalize_rule_id()
        vuln_type2 = f2._normalize_rule_id()
        vuln_type_sim = 1.0 if vuln_type1 == vuln_type2 else 0.0

        desc_sim = max(
            self._string_similarity(f1.description, f2.description),
            self._token_overlap_similarity(f1.description, f2.description),
        )

        code_sim = self._code_pattern_similarity(f1.code_snippet, f2.code_snippet)

        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        sev1 = severity_order.get(f1.severity.value if hasattr(f1.severity, 'value') else str(f1.severity).lower(), 0)
        sev2 = severity_order.get(f2.severity.value if hasattr(f2.severity, 'value') else str(f2.severity).lower(), 0)
        severity_sim = 1.0 - (abs(sev1 - sev2) / 4.0)

        total_score = (
            weights['vuln_type'] * vuln_type_sim +
            weights['description'] * desc_sim +
            weights['code_pattern'] * code_sim +
            weights['severity'] * severity_sim
        )
        return total_score

    @staticmethod
    def _merge_title(findings: List[AggregatedFinding]) -> str:
        vuln_types = set()
        for f in findings:
            vt = f._normalize_rule_id()
            if vt:
                vuln_types.add(vt)
        base_name = findings[0].rule_name if findings[0].rule_name else (vuln_types.pop() if vuln_types else "Issue")
        file_count = len(findings)
        if file_count == 1:
            return base_name
        return f"{base_name} found in {file_count} locations"

    @staticmethod
    def _merge_description(findings: List[AggregatedFinding]) -> str:
        unique_descs = []
        seen = set()
        for f in findings:
            d = f.description.strip()
            if d and d not in seen:
                seen.add(d)
                unique_descs.append(d)
        if len(unique_descs) == 1:
            return unique_descs[0]
        affected_files = [f.file_path for f in findings[:5]]
        desc_parts = [f"此问题在 {len(findings)} 个位置被发现"]
        desc_parts.append(f"涉及文件: {', '.join(affected_files)}")
        if unique_descs:
            desc_parts.append(f"典型描述: {unique_descs[0]}")
        return ' | '.join(desc_parts)

    @staticmethod
    def _merge_code_snippet(findings: List[AggregatedFinding]) -> str:
        best = max(findings, key=lambda f: len(f.code_snippet) if f.code_snippet else 0)
        snippet = best.code_snippet if best.code_snippet else "N/A"
        if len(findings) > 1:
            files = [f.file_path for f in findings[:3]]
            header = f"[示例来自: {', '.join(files)}]"
            return f"{header}\n{snippet}"
        return snippet

    @staticmethod
    def _merge_severity(findings: List[AggregatedFinding]) -> Severity:
        return max(findings, key=lambda f: f.severity.get_order()).severity

    @staticmethod
    def _merge_confidence(findings: List[AggregatedFinding]) -> float:
        return sum(f.confidence for f in findings) / len(findings)

    @staticmethod
    def _merge_fix_suggestion(findings: List[AggregatedFinding]) -> str:
        unique_fixes = []
        seen = set()
        for f in findings:
            fix = f.fix_suggestion.strip()
            if fix and fix not in seen:
                seen.add(fix)
                unique_fixes.append(fix)
        if len(unique_fixes) == 1:
            return unique_fixes[0]
        if unique_fixes:
            return ' | '.join(unique_fixes[:3])
        return "请审查所有受影响的位置并应用适当的修复措施"

    @staticmethod
    def _merge_references(findings: List[AggregatedFinding]) -> List[str]:
        refs = []
        seen = set()
        for f in findings:
            for ref in f.references:
                if ref not in seen:
                    seen.add(ref)
                    refs.append(ref)
        return refs

    @staticmethod
    def _merge_tags(findings: List[AggregatedFinding]) -> List[str]:
        tags = set()
        for f in findings:
            tags.update(f.tags)
        return list(tags)

    def _merge_similar_findings(self) -> List[AggregatedFinding]:
        threshold = self.SEMANTIC_SIMILARITY_THRESHOLD
        visited = set()
        merged_results = []
        finding_ids = list(range(len(self.findings)))

        for i in finding_ids:
            if i in visited:
                continue
            visited.add(i)
            group = [self.findings[i]]
            for j in finding_ids:
                if j in visited or j == i:
                    continue
                sim_score = self._calculate_finding_similarity(self.findings[i], self.findings[j])
                if sim_score >= threshold:
                    visited.add(j)
                    group.append(self.findings[j])

            if len(group) == 1:
                merged_results.append(group[0])
            else:
                merged_finding = AggregatedFinding(
                    finding_id=self.findings[i].finding_id,
                    rule_id=self.findings[i].rule_id,
                    rule_name=self._merge_title(group),
                    description=self._merge_description(group),
                    severity=self._merge_severity(group),
                    file_path=group[0].file_path,
                    line=group[0].line,
                    column=group[0].column,
                    confidence=self._merge_confidence(group),
                    message=self._merge_description(group),
                    code_snippet=self._merge_code_snippet(group),
                    fix_suggestion=self._merge_fix_suggestion(group),
                    references=self._merge_references(group),
                    tags=self._merge_tags(group),
                    metadata={
                        'is_merged': True,
                        'merged_count': len(group),
                        'merged_findings': [
                            {
                                'file': f.file_path,
                                'line': f.line,
                                'rule_id': f.rule_id,
                                'confidence': f.confidence,
                            }
                            for f in group
                        ],
                        'affected_files': list(set(f.file_path for f in group)),
                        'similarity_threshold': threshold,
                        'original_severity_levels': list(set(
                            f.severity.value for f in group
                        )),
                    },
                )
                merged_results.append(merged_finding)

        return merged_results

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

    def smart_deduplicate(self) -> List[AggregatedFinding]:
        """O(n) 复杂度的智能去重 - 使用哈希分组"""
        if not self.findings:
            return []
        
        # 第一轮：基于信号键分组（O(n)）
        signal_groups: Dict[str, List[AggregatedFinding]] = {}
        for finding in self.findings:
            key = self._get_signal_key(finding)
            if key not in signal_groups:
                signal_groups[key] = []
            signal_groups[key].append(finding)
        
        # 第二轮：组内去重（O(n)）
        deduplicated: List[AggregatedFinding] = []
        for key, group in signal_groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # 组内保留最高严重性、最高置信度
                best = self._select_best_finding(group)
                best.metadata['merged_count'] = len(group)
                best.metadata['merged_findings'] = [
                    {'file': f.file_path, 'line': f.line}
                    for f in group[1:]
                ]
                deduplicated.append(best)
        
        self.findings = deduplicated
        return deduplicated

    def _get_signal_key(self, finding: AggregatedFinding) -> str:
        """生成信号键 - 用于分组"""
        file_path = str(finding.file_path) if hasattr(finding, 'file_path') else ''
        line = finding.line if hasattr(finding, 'line') else 0
        vuln_type = finding._normalize_rule_id() if hasattr(finding, '_normalize_rule_id') else finding.rule_id
        
        # 允许行号有±3的偏差
        line_bucket = (line // 5) * 5  # 每5行一个桶
        return f"{file_path}:{line_bucket}:{vuln_type}"

    def _select_best_finding(self, findings: List[AggregatedFinding]) -> AggregatedFinding:
        """选择组内最佳发现 - 最高严重性和置信度"""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        
        best = findings[0]
        best_score = severity_order.get(best.severity.value if hasattr(best.severity, 'value') else str(best.severity).lower(), 0)
        
        for f in findings[1:]:
            score = severity_order.get(f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower(), 0)
            if score > best_score:
                best = f
                best_score = score
        
        return best

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
        enable_smart_dedup: bool = True,
        enable_semantic_merge: bool = True,
    ) -> AggregatedResult:
        """执行聚合

        Args:
            findings: 发现列表（如果为None则使用已添加的发现）
            sort_by: 排序方式 (severity/confidence/file)
            include_verification: 是否包含验证统计
            enable_smart_dedup: 是否启用智能去重
            enable_semantic_merge: 是否启用语义相似度合并
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
            original_count = len(self.findings)
            self.smart_deduplicate()
            removed = original_count - len(self.findings)
            if removed > 0:
                print(f"[INFO] 智能去重移除 {removed} 个重复发现")

        if enable_semantic_merge:
            original_count = len(self.findings)
            self.findings = self._merge_similar_findings()
            merged = original_count - len(self.findings)
            if merged > 0:
                print(f"[INFO] 语义相似度合并: {merged} 个发现被合并为 {len([f for f in self.findings if f.metadata.get('is_merged')])} 个聚合发现")

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
