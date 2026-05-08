"""报告生成器

提供多格式报告生成功能。
APTS合规增强:
- APTS-RP-003: 置信度评分 (0.0-1.0) 带可审计方法论
- APTS-RP-004: 证据链 (文件路径、行号、代码片段、调用链)
- APTS-RP-006: 误报率估算
- APTS-RP-008: 漏洞覆盖率统计
- APTS-RP-004: 发现溯源 (规则来源、分析器来源)
"""

import html
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.engine import ScanResult
from src.core.config import Config, get_config
from src.reporting.category import (
    VulnerabilityCategory,
    SPECIAL_SCAN_AREAS,
    classify_rule,
    get_special_scan_area,
    CategorizedReportData,
    VulnerabilityMetadata,
)

try:
    from src.ai.pure_ai.schema_validator import LineNumberValidator
    from src.ai.pure_ai.schema import LineMatchStatus
    LINENUMBER_VALIDATOR_AVAILABLE = True
except ImportError:
    LINENUMBER_VALIDATOR_AVAILABLE = False
    LineMatchStatus = None

# 尝试导入 Jinja2，如果没有安装则使用简单的字符串替换
try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

# 调试日志和 Token 记录限制
MAX_DEBUG_LOGS = 200
MAX_TOKEN_RECORDS = 50
MAX_LOG_LENGTH = 1000
MAX_RESPONSE_LENGTH = 2000


def _classify_findings(findings: List[Any]) -> Dict[str, Any]:
    """分类发现结果

    Args:
        findings: 发现列表

    Returns:
        包含 port_related_findings, general_static_findings, special_scan_findings 的字典
    """
    port_related_findings = []
    general_static_findings = []
    special_scan_findings: Dict[str, List] = {area: [] for area in SPECIAL_SCAN_AREAS}

    for finding in findings:
        rule_id = getattr(finding, 'rule_id', '') or ''
        category = classify_rule(rule_id)

        if category == VulnerabilityCategory.PORT_RELATED:
            port_related_findings.append(finding)
        elif category == VulnerabilityCategory.SPECIAL_SCAN:
            area = get_special_scan_area(rule_id)
            if area:
                special_scan_findings[area].append(finding)
            else:
                general_static_findings.append(finding)
        else:
            general_static_findings.append(finding)

    return {
        "port_related_findings": port_related_findings,
        "general_static_findings": general_static_findings,
        "special_scan_findings": special_scan_findings,
    }


def _generate_category_statistics(classified: Dict[str, Any]) -> Dict[str, Any]:
    """生成分类统计信息

    Args:
        classified: _classify_findings 返回的分类结果

    Returns:
        包含按类别和按区域统计的字典
    """
    port_count = len(classified["port_related_findings"])
    general_count = len(classified["general_static_findings"])
    special_counts = {area: len(findings) for area, findings in classified["special_scan_findings"].items()}

    return {
        "by_category": {
            "port_related": port_count,
            "general_static": general_count,
        },
        "by_area": special_counts,
    }


def _calculate_apts_coverage_statistics(all_findings: List[Any]) -> Dict[str, Any]:
    """计算APTS覆盖率统计 (APTS-RP-008)

    Args:
        all_findings: 所有发现列表

    Returns:
        APTS覆盖率统计字典
    """
    total_rules = set()
    rules_with_findings = set()
    vulnerability_types_covered = set()
    verified_count = 0
    unverified_count = 0
    false_positive_count = 0

    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in all_findings:
        rule_id = getattr(finding, 'rule_id', '') or ''
        total_rules.add(rule_id)

        metadata = getattr(finding, 'metadata', {}) or {}
        if isinstance(metadata, dict):
            source = metadata.get('source', 'ai')
        else:
            source = 'ai'

        vulnerability = getattr(finding, 'vulnerability', '') or metadata.get('vulnerability', '')
        if vulnerability:
            vulnerability_types_covered.add(vulnerability)

        severity = getattr(finding, 'severity', None)
        if severity and hasattr(severity, 'value'):
            severity_str = severity.value
        else:
            severity_str = str(severity).lower().split('.')[-1] if severity else 'info'
        severity_breakdown[severity_str] = severity_breakdown.get(severity_str, 0) + 1

        status = metadata.get('status', 'UNCERTAIN')
        if status == 'CONFIRMED' or status == 'REFINED':
            rules_with_findings.add(rule_id)
            if status == 'REFINED':
                false_positive_count += 1
        elif status == 'UNCERTAIN':
            confidence = getattr(finding, 'confidence', 0) or metadata.get('confidence', 0)
            evidence_count = len(metadata.get('evidence', []) or [])
            if confidence < 0.7 and evidence_count < 2:
                unverified_count += 1
            else:
                rules_with_findings.add(rule_id)
                verified_count += 1
        else:
            rules_with_findings.add(rule_id)

        line_match_status = metadata.get('line_match_status', '')
        if line_match_status == 'EXACT':
            verified_count += 1
        elif line_match_status == 'UNVERIFIED':
            unverified_count += 1

    total_rules_count = len(total_rules) if total_rules else 1
    coverage_percentage = (len(rules_with_findings) / total_rules_count * 100) if total_rules_count > 0 else 0

    false_positive_rate = (false_positive_count / len(all_findings)) if all_findings else 0.0

    return {
        "total_rules_checked": total_rules_count,
        "rules_with_findings": len(rules_with_findings),
        "coverage_percentage": round(coverage_percentage, 2),
        "vulnerability_types_covered": list(vulnerability_types_covered),
        "vulnerability_types_total": len(vulnerability_types_covered),
        "by_severity": severity_breakdown,
        "verified_findings": verified_count,
        "unverified_findings": unverified_count,
        "false_positive_count": false_positive_count,
        "false_positive_rate": round(false_positive_rate * 100, 2),
    }


def _calculate_apts_false_positive_rate(all_findings: List[Any]) -> Dict[str, Any]:
    """计算APTS误报率统计 (APTS-RP-006)

    Args:
        all_findings: 所有发现列表

    Returns:
        误报率统计字典
    """
    if not all_findings:
        return {
            "total_findings": 0,
            "confirmed": 0,
            "refined": 0,
            "rejected": 0,
            "uncertain": 0,
            "estimated_false_positive_rate": 0.0,
            "by_severity": {},
        }

    status_counts = {
        "CONFIRMED": 0,
        "REFINED": 0,
        "REJECTED": 0,
        "UNCERTAIN": 0,
    }

    severity_fpr = {}

    for finding in all_findings:
        metadata = getattr(finding, 'metadata', {}) or {}
        status = metadata.get('status', 'UNCERTAIN')
        status_upper = status.upper()
        if status_upper in status_counts:
            status_counts[status_upper] += 1
        else:
            status_counts["UNCERTAIN"] += 1

        severity = getattr(finding, 'severity', None)
        if severity and hasattr(severity, 'value'):
            severity_str = severity.value
        else:
            severity_str = 'info'

        if severity_str not in severity_fpr:
            severity_fpr[severity_str] = {"total": 0, "false_positive": 0}

        severity_fpr[severity_str]["total"] += 1

        if status_upper == "REFINED":
            severity_fpr[severity_str]["false_positive"] += 1

    estimated_fpr = status_counts["REFINED"] / len(all_findings) if all_findings else 0.0

    by_severity_fp = {}
    for sev, counts in severity_fpr.items():
        if counts["total"] > 0:
            by_severity_fp[sev] = {
                "total": counts["total"],
                "estimated_fp": counts["false_positive"],
                "estimated_fpr": round(counts["false_positive"] / counts["total"] * 100, 2),
            }

    return {
        "total_findings": len(all_findings),
        "confirmed": status_counts["CONFIRMED"],
        "refined": status_counts["REFINED"],
        "rejected": status_counts["REJECTED"],
        "uncertain": status_counts["UNCERTAIN"],
        "estimated_false_positive_rate": round(estimated_fpr * 100, 2),
        "by_severity": by_severity_fp,
    }


def safe_escape(text):
    """安全转义HTML字符，防止XSS和渲染断裂"""
    if text is None:
        return ''
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text)


def sanitize_token_record(rec):
    """安全化token记录，转换所有Path对象为字符串"""
    if rec is None:
        return {}
    if isinstance(rec, str):
        return rec
    if isinstance(rec, dict):
        result = {}
        for k, v in rec.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                result[k] = v
            elif isinstance(v, os.PathLike):
                result[k] = str(v)
            else:
                result[k] = str(v) if v is not None else ''
        return result
    result = {}
    for attr in ['provider', 'model', 'prompt_tokens', 'completion_tokens', 'total_tokens',
                 'duration', 'success', 'cached', 'timestamp', 'prompt', 'response',
                 'agent_name', 'file_path']:
        if hasattr(rec, attr):
            v = getattr(rec, attr)
            if isinstance(v, (str, int, float, bool)) or v is None:
                result[attr] = v
            elif isinstance(v, os.PathLike):
                result[attr] = str(v)
            else:
                result[attr] = str(v) if v is not None else ''
        else:
            result[attr] = ''
    return result


class BaseReportGenerator(ABC):
    """报告生成器基类"""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()

    @abstractmethod
    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成报告

        Args:
            results: 扫描结果列表
            output_path: 输出路径

        Returns:
            报告文件路径
        """
        pass

    @property
    @abstractmethod
    def format(self) -> str:
        """报告格式"""
        pass


class JSONReportGenerator(BaseReportGenerator):
    """JSON 报告生成器"""

    @property
    def format(self) -> str:
        return "json"

    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成 JSON 报告"""
        processed_results = []
        for r in results:
            result_dict = r.to_dict()
            for finding in result_dict.get("findings", []):
                rule_id = finding.get("rule_id", "") or ""
                category = classify_rule(rule_id)
                finding["category"] = category.value
            processed_results.append(result_dict)

        data = {
            "results": processed_results,
            "summary": self._generate_summary(results),
        }

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return str(output_file)

    def _generate_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成摘要

        APTS-RP-008: 漏洞覆盖率统计
        APTS-RP-006: 误报率统计
        """
        total_findings = sum(len(r.findings) for r in results)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        source_counts = {}

        for result in results:
            for finding in result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                metadata = getattr(finding, 'metadata', {})
                if isinstance(metadata, dict):
                    source = metadata.get('source', 'ai')
                else:
                    source = 'ai'
                source_counts[source] = source_counts.get(source, 0) + 1

        total_files = sum(r.metadata.get('total_files', 1) for r in results)

        tool_statistics = None
        for result in results:
            if hasattr(result, 'metadata') and 'tool_statistics' in result.metadata:
                tool_statistics = result.metadata['tool_statistics']
                break

        all_findings = [f for r in results for f in r.findings]
        classified = _classify_findings(all_findings)
        category_statistics = _generate_category_statistics(classified)

        apts_coverage = _calculate_apts_coverage_statistics(all_findings)
        apts_fpr = _calculate_apts_false_positive_rate(all_findings)

        return {
            "total_scans": total_files,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "source_counts": source_counts,
            "tool_statistics": tool_statistics,
            "category_statistics": category_statistics,
            "apts_coverage": apts_coverage,
            "apts_false_positive_rate": apts_fpr,
        }


class HTMLReportGenerator(BaseReportGenerator):
    """HTML 报告生成器"""

    @property
    def format(self) -> str:
        return "html"

    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成 HTML 报告"""
        html_content = self._generate_html(results)

        output_file = Path(output_path)
        if output_file.suffix != ".html":
            output_file = output_file / "report.html"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(output_file)

    def _get_security_status(self, summary):
        """获取安全状态"""
        total_findings = summary["total_findings"]
        critical = summary["severity_counts"].get("critical", 0)
        high = summary["severity_counts"].get("high", 0)
        medium = summary["severity_counts"].get("medium", 0)
        
        if total_findings == 0:
            return "safe", "安全状态良好"
        elif critical > 0:
            return "critical", "严重安全风险"
        elif high > 0:
            return "high", "高安全风险"
        elif medium > 0:
            return "medium", "中等安全风险"
        else:
            return "low", "低安全风险"

    def _get_scan_duration(self, results):
        """获取扫描总时长"""
        total_duration = 0
        for result in results:
            total_duration += result.duration
        return round(total_duration, 2)

    def _generate_html(self, results: List[ScanResult]) -> str:
        """生成 HTML 内容"""
        summary = self._generate_summary(results)
        status, status_text = self._get_security_status(summary)
        total_duration = self._get_scan_duration(results)

        # 收集调试日志
        debug_logs = []
        token_records = []
        for result in results:
            if hasattr(result, 'debug_logs') and result.debug_logs:
                debug_logs.extend(result.debug_logs)
            if hasattr(result, 'metadata') and 'debug_logs' in result.metadata:
                debug_logs.extend(result.metadata['debug_logs'])
            if hasattr(result, 'token_records') and result.token_records:
                token_records.extend(result.token_records)

        # 限制调试日志和 Token 记录数量，并截断过长内容
        def truncate_log(log: str) -> str:
            if len(log) > MAX_LOG_LENGTH:
                return log[:MAX_LOG_LENGTH] + "...[已截断]"
            return log

        def truncate_response(resp: str) -> str:
            if len(resp) > MAX_RESPONSE_LENGTH:
                return resp[:MAX_RESPONSE_LENGTH] + "\n...[响应已截断]"
            return resp

        debug_logs = [safe_escape(truncate_log(log)) for log in debug_logs]
        if len(debug_logs) > MAX_DEBUG_LOGS:
            debug_logs = debug_logs[-MAX_DEBUG_LOGS:]

        def sanitize_and_truncate_record(rec):
            sanitized = sanitize_token_record(rec)
            if 'prompt' in sanitized and sanitized['prompt']:
                sanitized['prompt'] = safe_escape(truncate_response(sanitized['prompt']))
            if 'response' in sanitized and sanitized['response']:
                sanitized['response'] = safe_escape(truncate_response(sanitized['response']))
            return sanitized

        token_records = [sanitize_and_truncate_record(rec) for rec in token_records]
        if len(token_records) > MAX_TOKEN_RECORDS:
            token_records = token_records[-MAX_TOKEN_RECORDS:]

        print(f"[DEBUG] 调试日志数量限制: {len(debug_logs)}/{MAX_DEBUG_LOGS}, 令牌记录数量限制: {len(token_records)}/{MAX_TOKEN_RECORDS}")

        all_findings = [f for r in results for f in r.findings]
        categorized_findings = _classify_findings(all_findings)

        # 加载模板文件
        template_path = Path(__file__).parent / "templates" / "builtin" / "html" / "default.html"
        print(f"[DEBUG] 报告模板路径: {template_path}, 存在: {'是' if template_path.exists() else '否'}")
        if not template_path.exists():
            # 如果模板文件不存在，使用默认模板
            return self._generate_default_html(results, summary, status, status_text, total_duration)

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template_content = f.read()

            if JINJA_AVAILABLE:
                from jinja2 import Environment, BaseLoader
                from src.core.engine import Severity

                def sev(value):
                    if isinstance(value, Severity):
                        return value.value
                    return str(value)

                def sort_by_severity(findings):
                    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
                    def get_severity_key(f):
                        sev_str = f.get('severity', 'info')
                        sev_str = sev_str.lower().split('.')[-1]
                        return severity_order.get(sev_str, 5)
                    return sorted(findings, key=get_severity_key)

                env = Environment(loader=BaseLoader())
                env.filters['sev'] = sev
                env.filters['sort_by_severity'] = sort_by_severity
                template = env.from_string(template_content)

                processed_results = []
                finding_index = 0
                for result in results:
                    processed_result = {
                        'target': str(result.target) if isinstance(result.target, os.PathLike) else result.target,
                        'status': result.status.value if hasattr(result.status, 'value') else str(result.status),
                        'findings': [],
                        'duration': result.duration,
                        'metadata': result.metadata,
                        'debug_logs': result.debug_logs if hasattr(result, 'debug_logs') else [],
                        'token_records': result.token_records if hasattr(result, 'token_records') else [],
                    }
                    for finding in result.findings:
                        finding_index += 1
                        metadata = finding.metadata if hasattr(finding, 'metadata') else {}
                        should_include, status, needs_review = self._should_include_finding(finding, metadata)

                        if not should_include:
                            print(f"[DEBUG] 跳过已拒绝漏洞: {getattr(finding, 'rule_name', finding.rule_id)}")
                            finding_index -= 1
                            continue

                        rule_id = getattr(finding, 'rule_id', '') or ''
                        category = classify_rule(rule_id)
                        processed_finding = {
                            'index': finding_index,
                            'rule_id': safe_escape(finding.rule_id),
                            'rule_name': safe_escape(finding.rule_name),
                            'description': safe_escape(finding.description),
                            'severity': finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity),
                            'status': status,
                            'needs_review': needs_review,
                            'category': category.value,
                            'location': {
                                'file': safe_escape(finding.location.file if hasattr(finding.location, 'file') else str(finding.location)),
                                'line': finding.location.line if hasattr(finding.location, 'line') else 0,
                                'column': finding.location.column if hasattr(finding.location, 'column') else 0,
                                'end_line': finding.location.end_line if hasattr(finding.location, 'end_line') else 0,
                                'end_column': finding.location.end_column if hasattr(finding.location, 'end_column') else 0,
                            },
                            'confidence': finding.confidence,
                            'message': safe_escape(finding.message),
                            'code_snippet': safe_escape(finding.code_snippet),
                            'fix_suggestion': safe_escape(finding.fix_suggestion),
                            'references': finding.references,
                            'metadata': metadata,
                            'evidence': metadata.get('evidence', []) if isinstance(metadata, dict) else [],
                            'code_context': finding.code_context.to_dict() if hasattr(finding, 'code_context') and finding.code_context else None,
                        }

                        if needs_review:
                            print(f"[DEBUG] 标记为需要审查的待定漏洞: {getattr(finding, 'rule_name', finding.rule_id)}, 置信度: {getattr(finding, 'confidence', 0)}, 证据数: {len(metadata.get('evidence', []))}")

                        if hasattr(finding, 'files') and finding.files:
                            processed_finding['files'] = finding.files
                            processed_finding['is_multi_file'] = True
                            processed_finding['snippet_count'] = len(finding.files)
                        else:
                            processed_finding['files'] = [finding.location.file if hasattr(finding.location, 'file') else str(finding.location)]
                            processed_finding['is_multi_file'] = False
                            processed_finding['snippet_count'] = 1

                        if hasattr(finding, 'snippets') and finding.snippets:
                            processed_finding['snippets'] = {k: safe_escape(v) for k, v in finding.snippets.items()}
                        else:
                            processed_finding['snippets'] = {finding.location.file if hasattr(finding.location, 'file') else str(finding.location): safe_escape(finding.code_snippet)}

                        if hasattr(finding, 'chain') and finding.chain:
                            processed_finding['chain'] = [
                                {
                                    'file_path': safe_escape(getattr(step, 'file_path', step.get('file_path', ''))),
                                    'line': getattr(step, 'line', step.get('line', 0)),
                                    'description': safe_escape(getattr(step, 'description', step.get('description', ''))),
                                    'code_snippet': safe_escape(getattr(step, 'code_snippet', step.get('code_snippet', ''))),
                                }
                                for step in finding.chain
                            ]
                            mermaid_lines = ['flowchart LR']
                            for i, step in enumerate(finding.chain):
                                node_id = f'N{i + 1}'
                                file_name = getattr(step, 'file_path', step.get('file_path', ''))
                                if '/' in file_name:
                                    file_name = file_name.split('/')[-1]
                                line_num = getattr(step, 'line', step.get('line', 0))
                                node_label = f'{file_name}:{line_num}' if line_num else file_name
                                mermaid_lines.append(f'    {node_id}[{node_label}]')
                                if i > 0:
                                    prev_node_id = f'N{i}'
                                    mermaid_lines.append(f'    {prev_node_id} --> {node_id}')
                            processed_finding['mermaid_graph'] = '\n'.join(mermaid_lines)
                        else:
                            processed_finding['chain'] = []
                        existing_line_match_status = metadata.get('line_match_status', '') if isinstance(metadata, dict) else ''
                        if existing_line_match_status:
                            processed_finding['line_match_status'] = existing_line_match_status
                            processed_finding['verified_line'] = -1
                        elif LINENUMBER_VALIDATOR_AVAILABLE:
                            file_content = metadata.get('file_content', '') if isinstance(metadata, dict) else ''
                            if not file_content:
                                try:
                                    file_path = finding.location.file if hasattr(finding.location, 'file') else None
                                    if file_path and Path(file_path).exists():
                                        file_content = Path(file_path).read_text(encoding='utf-8', errors='ignore')
                                except Exception:
                                    pass
                            if file_content:
                                try:
                                    validator = LineNumberValidator()
                                    vuln_data = {
                                        'location': str(finding.location),
                                        'evidence': metadata.get('evidence', []) if isinstance(metadata, dict) else [],
                                        'rule_name': getattr(finding, 'rule_name', '') or metadata.get('rule_name', '') if isinstance(metadata, dict) else '',
                                        'description': getattr(finding, 'description', '') or metadata.get('description', '') if isinstance(metadata, dict) else '',
                                    }
                                    validated = validator.validate_location(vuln_data, file_content)
                                    processed_finding['line_match_status'] = validated.get('line_match_status', LineMatchStatus.UNVERIFIED.value if LineMatchStatus else 'UNVERIFIED')
                                    processed_finding['verified_line'] = validated.get('verified_line', -1)
                                    if validated.get('code_snippet'):
                                        processed_finding['code_snippet'] = validated.get('code_snippet')
                                    elif 'ai_reported_line' in validated:
                                        processed_finding['ai_reported_line'] = validated.get('ai_reported_line', -1)
                                except Exception:
                                    processed_finding['line_match_status'] = LineMatchStatus.UNVERIFIED.value if LineMatchStatus else 'UNVERIFIED'
                                    processed_finding['verified_line'] = -1
                            else:
                                processed_finding['line_match_status'] = LineMatchStatus.UNVERIFIED.value if LineMatchStatus else 'UNVERIFIED'
                                processed_finding['verified_line'] = -1
                        processed_result['findings'].append(processed_finding)
                    processed_results.append(processed_result)

                html = template.render(
                    summary=summary,
                    results=processed_results,
                    status=status,
                    status_text=status_text,
                    total_duration=total_duration,
                    debug_logs=debug_logs,
                    token_records=token_records,
                    categorized_findings=categorized_findings,
                    getattr=getattr,
                    hasattr=hasattr
                )
            else:
                # 简单的字符串替换（如果没有 Jinja2）
                html = template_content
                html = html.replace("{{ status }}", status)
                html = html.replace("{{ status_text }}", status_text)
                html = html.replace("{{ summary.total_scans }}", str(summary["total_scans"]))
                html = html.replace("{{ summary.total_findings }}", str(summary["total_findings"]))
                html = html.replace("{{ total_duration }}", str(total_duration))
                html = html.replace("{{ summary.severity_counts.critical }}", str(summary["severity_counts"].get("critical", 0)))
                html = html.replace("{{ summary.severity_counts.high }}", str(summary["severity_counts"].get("high", 0)))
                html = html.replace("{{ summary.severity_counts.medium }}", str(summary["severity_counts"].get("medium", 0)))
                html = html.replace("{{ summary.severity_counts.low }}", str(summary["severity_counts"].get("low", 0)))
                html = html.replace("{{ summary.severity_counts.info }}", str(summary["severity_counts"].get("info", 0)))

            return html
        except Exception as e:
            print(f"[WARN] 模板渲染失败: {e}, 尝试使用备用方案")
            try:
                import re
                if 'template_content' not in dir():
                    return self._generate_default_html(results, summary, status, status_text, total_duration)
                html = template_content
                html = re.sub(r'\{\{.*?\}\}', '', html)
                html = self._apply_simple_replacements(html, summary, status, status_text, total_duration)
                return html
            except Exception as fallback_error:
                print(f"[WARN] 备用方案也失败: {fallback_error}, 使用默认模板")
                return self._generate_default_html(results, summary, status, status_text, total_duration)

    def _apply_simple_replacements(self, html: str, summary: Dict, status: str, status_text: str, total_duration: float) -> str:
        """对模板进行简单的变量替换"""
        html = html.replace("{{ status }}", status)
        html = html.replace("{{ status_text }}", status_text)
        html = html.replace("{{ summary.total_scans }}", str(summary["total_scans"]))
        html = html.replace("{{ summary.total_findings }}", str(summary["total_findings"]))
        html = html.replace("{{ total_duration }}", str(total_duration))
        html = html.replace("{{ summary.severity_counts.critical }}", str(summary["severity_counts"].get("critical", 0)))
        html = html.replace("{{ summary.severity_counts.high }}", str(summary["severity_counts"].get("high", 0)))
        html = html.replace("{{ summary.severity_counts.medium }}", str(summary["severity_counts"].get("medium", 0)))
        html = html.replace("{{ summary.severity_counts.low }}", str(summary["severity_counts"].get("low", 0)))
        html = html.replace("{{ summary.severity_counts.info }}", str(summary["severity_counts"].get("info", 0)))
        return html

    def _generate_default_html(self, results, summary, status, status_text, total_duration):
        """生成默认 HTML 内容（当模板文件不存在或渲染失败时使用）"""
        # 简单的默认 HTML 模板
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HOS-LS 安全扫描报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; text-align: center; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; }}
        .severity-critical {{ border-left: 4px solid #dc3545; background-color: #f8d7da; }}
        .severity-high {{ border-left: 4px solid #fd7e14; background-color: #fff3cd; }}
        .severity-medium {{ border-left: 4px solid #ffc107; background-color: #fff3cd; }}
        .severity-low {{ border-left: 4px solid #17a2b8; background-color: #d1ecf1; }}
        .severity-info {{ border-left: 4px solid #6c757d; background-color: #e2e3e5; }}
    </style>
</head>
<body>
    <h1>HOS-LS 安全扫描报告</h1>
    <div class="summary">
        <h2>扫描摘要</h2>
        <p>扫描文件数: {summary["total_scans"]}</p>
        <p>发现问题数: {summary["total_findings"]}</p>
        <p>安全状态: {status_text}</p>
    </div>
    <h2>详细发现</h2>
    """

        for result in results:
            for finding in result.findings:
                # 确保使用正确的字段
                location = getattr(finding, 'location', 'unknown')
                if isinstance(location, dict):
                    location = location.get('file', 'unknown')
                
                description = getattr(finding, 'description', getattr(finding, 'message', '无描述'))
                
                # 处理修复建议
                fix_suggestion = getattr(finding, 'fix_suggestion', '')
                fix_suggestion_html = f"<p><strong>修复建议:</strong> {fix_suggestion}</p>" if fix_suggestion else ""
                
                html += f"""
    <div class="finding severity-{finding.severity.value}">
        <h3>{finding.rule_name} ({finding.rule_id})</h3>
        <p><strong>位置:</strong> {location}</p>
        <p><strong>描述:</strong> {description}</p>
        {fix_suggestion_html}
    </div>
                """

        html += """
</body>
</html>
        """

        return html



    def _generate_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成摘要

        APTS-RP-008: 漏洞覆盖率统计
        APTS-RP-006: 误报率统计
        """
        total_findings = sum(len(r.findings) for r in results)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        source_counts = {}

        for result in results:
            for finding in result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                metadata = getattr(finding, 'metadata', {})
                if isinstance(metadata, dict):
                    source = metadata.get('source', 'ai')
                else:
                    source = 'ai'
                source_counts[source] = source_counts.get(source, 0) + 1

        total_files = sum(r.metadata.get('total_files', 1) for r in results)

        tool_statistics = None
        for result in results:
            if hasattr(result, 'metadata') and 'tool_statistics' in result.metadata:
                tool_statistics = result.metadata['tool_statistics']
                break

        all_findings = [f for r in results for f in r.findings]
        classified = _classify_findings(all_findings)
        category_statistics = _generate_category_statistics(classified)

        apts_coverage = _calculate_apts_coverage_statistics(all_findings)
        apts_fpr = _calculate_apts_false_positive_rate(all_findings)

        return {
            "total_scans": total_files,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "source_counts": source_counts,
            "tool_statistics": tool_statistics,
            "category_statistics": category_statistics,
            "apts_coverage": apts_coverage,
            "apts_false_positive_rate": apts_fpr,
        }

    def _should_include_finding(self, finding, metadata: dict = None) -> tuple:
        """判断漏洞是否应该包含在报告中

        Returns:
            tuple: (should_include: bool, status: str, needs_review: bool)
        """
        if metadata is None:
            metadata = {}

        status = metadata.get('status', 'UNCERTAIN')
        confidence = getattr(finding, 'confidence', 0) or metadata.get('confidence', 0)
        evidence = metadata.get('evidence', [])
        evidence_count = len(evidence) if evidence else 0

        needs_review = False

        if status == 'CONFIRMED':
            return True, status, False
        elif status == 'REFINED':
            return True, status, False
        elif status == 'REJECTED':
            return False, status, False
        elif status == 'UNCERTAIN':
            if confidence >= 0.7 or evidence_count >= 2:
                return True, status, False
            else:
                needs_review = True
                return True, status, True
        else:
            needs_review = True
            return True, status, True


class MarkdownReportGenerator(BaseReportGenerator):
    """Markdown 报告生成器"""

    @property
    def format(self) -> str:
        return "markdown"

    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成 Markdown 报告"""
        md_content = self._generate_markdown(results)

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md_content)

        return str(output_file)

    def _generate_markdown(self, results: List[ScanResult]) -> str:
        """生成 Markdown 内容"""
        summary = self._generate_summary(results)

        md = f"""# HOS-LS 安全扫描报告

## 摘要

- 扫描文件数: {summary["total_scans"]}
- 发现问题数: {summary["total_findings"]}

### 严重级别分布

| 严重级别 | 数量 |
|---------|------|
| 严重 | {summary["severity_counts"].get("critical", 0)} |
| 高 | {summary["severity_counts"].get("high", 0)} |
| 中 | {summary["severity_counts"].get("medium", 0)} |
| 低 | {summary["severity_counts"].get("low", 0)} |
| 信息 | {summary["severity_counts"].get("info", 0)} |

## 详细发现

"""

        for result in results:
            for finding in result.findings:
                md += self._generate_finding_markdown(finding)

        # 添加攻击链路分析结果
        for result in results:
            if hasattr(result, 'metadata') and 'attack_chain' in result.metadata:
                attack_chain = result.metadata['attack_chain']
                md += """
## 攻击链路分析

### 分析摘要

```
{summary}
```

**总体风险评分:** {risk_score:.2f}

### 高风险攻击路径

{paths}

""".format(
                    summary=attack_chain['summary'],
                    risk_score=attack_chain['risk_score'],
                    paths='\n'.join([f"- {i+1}. {path.description} (风险: {path.risk_score:.2f})" for i, path in enumerate(attack_chain['paths'][:5])])
                )

        return md

    def _generate_finding_markdown(self, finding) -> str:
        """生成单个发现的 Markdown"""
        severity = finding.severity.value
        
        metadata = getattr(finding, 'metadata', {})
        if isinstance(metadata, dict):
            source = metadata.get('source', 'ai')
        else:
            source = 'ai'
        
        location_str = str(finding.location)
        if LINENUMBER_VALIDATOR_AVAILABLE and isinstance(metadata, dict):
            file_content = metadata.get('file_content', '')
            if file_content:
                try:
                    validator = LineNumberValidator()
                    vuln_data = {
                        'location': str(finding.location),
                        'evidence': metadata.get('evidence', []),
                    }
                    validated = validator.validate_location(vuln_data, file_content)
                    match_status = validated.get('line_match_status', 'UNVERIFIED')
                    verified_line = validated.get('verified_line', -1)
                    ai_reported_line = validated.get('ai_reported_line', -1)
                    
                    if match_status == LineMatchStatus.EXACT.value:
                        location_str = f"{finding.location} ✓"
                    elif match_status == LineMatchStatus.ADJUSTED.value and verified_line > 0 and ai_reported_line > 0:
                        location_str = f"{finding.location} (已校正，原报告: {ai_reported_line})"
                    elif match_status == LineMatchStatus.UNVERIFIED.value:
                        location_str = f"{finding.location} ⚠️ [未验证]"
                except Exception:
                    location_str = f"{finding.location} ⚠️ [验证失败]"
        
        poc_md = ""
        if hasattr(finding, 'poc') and finding.poc:
            poc_md = f"""
**漏洞利用 (POC)**: 
```
{finding.poc}
```
"""
        
        fix_md = ""
        if hasattr(finding, 'fix_suggestion') and finding.fix_suggestion:
            fix_md = f"""
**修复建议**: {finding.fix_suggestion}
"""
        
        code_md = ""
        if hasattr(finding, 'code_snippet') and finding.code_snippet:
            code_md = f"""
```
{finding.code_snippet}
```
"""
        
        return f"""
### {finding.rule_name} ({finding.rule_id})

- **严重级别**: {severity}
- **来源**: {source}
- **位置**: {location_str}
- **描述**: {finding.message}
- **置信度**: {finding.confidence}
{code_md}
{poc_md}
{fix_md}

"""

    def _generate_summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成摘要

        APTS-RP-008: 漏洞覆盖率统计
        APTS-RP-006: 误报率统计
        """
        total_findings = sum(len(r.findings) for r in results)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        source_counts = {}

        for result in results:
            for finding in result.findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                metadata = getattr(finding, 'metadata', {})
                if isinstance(metadata, dict):
                    source = metadata.get('source', 'ai')
                else:
                    source = 'ai'
                source_counts[source] = source_counts.get(source, 0) + 1

        total_files = sum(r.metadata.get('total_files', 1) for r in results)

        tool_statistics = None
        for result in results:
            if hasattr(result, 'metadata') and 'tool_statistics' in result.metadata:
                tool_statistics = result.metadata['tool_statistics']
                break

        all_findings = [f for r in results for f in r.findings]
        classified = _classify_findings(all_findings)
        category_statistics = _generate_category_statistics(classified)

        apts_coverage = _calculate_apts_coverage_statistics(all_findings)
        apts_fpr = _calculate_apts_false_positive_rate(all_findings)

        return {
            "total_scans": total_files,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "source_counts": source_counts,
            "tool_statistics": tool_statistics,
            "category_statistics": category_statistics,
            "apts_coverage": apts_coverage,
            "apts_false_positive_rate": apts_fpr,
        }


class SARIFReportGenerator(BaseReportGenerator):
    """SARIF 报告生成器"""

    @property
    def format(self) -> str:
        return "sarif"

    def generate(self, results: List[ScanResult], output_path: str) -> str:
        """生成 SARIF 报告"""
        sarif_content = self._generate_sarif(results)

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif_content, f, indent=2, ensure_ascii=False)

        return str(output_file)

    def _generate_sarif(self, results: List[ScanResult]) -> Dict[str, Any]:
        """生成 SARIF 内容"""
        runs = []

        for result in results:
            run = {
                "tool": {
                    "driver": {
                        "name": "HOS-LS",
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": []
            }

            # 添加结果
            for finding in result.findings:
                run["results"].append({
                    "ruleId": finding.rule_id,
                    "message": {
                        "text": finding.message
                    },
                    "severity": finding.severity.value,
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.location.file
                            },
                            "region": {
                                "startLine": finding.location.line if finding.location.line > 0 else 1
                            }
                        }
                    }]
                })

            runs.append(run)

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs
        }


class ReportGenerator:
    """报告生成器工厂"""

    _generators: Dict[str, type] = {
        "json": JSONReportGenerator,
        "html": HTMLReportGenerator,
        "markdown": MarkdownReportGenerator,
        "sarif": SARIFReportGenerator,
    }

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()

    def generate(
        self,
        results: List[ScanResult],
        output_path: str,
        format: Optional[str] = None,
    ) -> str:
        """生成报告

        Args:
            results: 扫描结果列表
            output_path: 输出路径
            format: 报告格式，如果为 None 则使用配置中的格式

        Returns:
            报告文件路径
        """
        fmt = format or self.config.report.format

        generator_class = self._generators.get(fmt)
        if not generator_class:
            raise ValueError(f"不支持的报告格式: {fmt}")

        generator = generator_class(self.config)
        return generator.generate(results, output_path)

    def register_generator(
        self,
        format: str,
        generator_class: type,
    ) -> None:
        """注册报告生成器

        Args:
            format: 报告格式
            generator_class: 生成器类
        """
        self._generators[format] = generator_class

    def list_formats(self) -> List[str]:
        """列出支持的格式"""
        return list(self._generators.keys())
