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
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

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


# 加固建议类型列表 - 这些发现语义定义不明确，不应与真正的漏洞混在一起显示
HARDENING_ADVICE_KEYWORDS = [
    '业务逻辑', '异常处理', '错误处理', '输入验证', '未校验', '金额未校验',
    '属性注入', 'mass assignment', '敏感异常',
    '加密功能未实现', 'encryption', '加密',
    'ip跳过', 'ip bypass', '请求头伪造', '请求头欺骗', 'header spoof',
]


def _is_hardening_advice(finding) -> bool:
    """判断一个发现是否属于"加固建议"类别
    
    加固建议是指语义定义不明确的发现，如"业务逻辑缺陷"、"异常处理不当"等，
    它们不是真正的安全漏洞，而是代码质量/健壮性建议。
    
    Args:
        finding: 发现对象
        
    Returns:
        如果是加固建议则返回 True
    """
    rule_name = str(getattr(finding, 'rule_name', '') or '').lower()
    description = str(getattr(finding, 'description', '') or '').lower()
    rule_id = str(getattr(finding, 'rule_id', '') or '').lower()
    
    combined = f'{rule_name} {description} {rule_id}'
    for keyword in HARDENING_ADVICE_KEYWORDS:
        if keyword.lower() in combined:
            return True
    return False


def _classify_findings(findings: List[Any]) -> Dict[str, Any]:
    """分类发现结果

    Args:
        findings: 发现列表

    Returns:
        包含 port_related_findings, general_static_findings, special_scan_findings,
        hardening_advice_findings 的字典
    """
    port_related_findings = []
    general_static_findings = []
    special_scan_findings: Dict[str, List] = {area: [] for area in SPECIAL_SCAN_AREAS}
    hardening_advice_findings = []

    for finding in findings:
        # 首先检查是否属于加固建议
        if _is_hardening_advice(finding):
            hardening_advice_findings.append(finding)
            continue
            
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
        "hardening_advice_findings": hardening_advice_findings,
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

    误报率计算逻辑：
    - AI分析发现的基准误报率为15%（纯AI分析存在固有不确定性）
    - 低置信度（<0.6）的发现增加10%误报率
    - 未验证/待人工复核的发现增加15%误报率
    - 使用占位符标题（UNVERIFIED_RISK等）的发现增加20%误报率

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
    placeholder_titles = ['UNVERIFIED_RISK', 'UNKNOWN', 'GENERIC', 'PLACEHOLDER', 'UNVERIFIED', 'SUSPICIOUS_PATTERN']

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
            severity_fpr[severity_str] = {"total": 0, "false_positive": 0, "weighted_fp": 0.0}

        severity_fpr[severity_str]["total"] += 1

        fp_rates_by_status = {
            'CONFIRMED': 0.02,
            'REFINED': 0.15,
            'UNCERTAIN': 0.45,
            'REJECTED': 0.95,
        }

        fp_probability = fp_rates_by_status.get(status_upper, 0.45)

        confidence = getattr(finding, 'confidence', 0.5) or metadata.get('confidence', 0.5)
        if status_upper in ['UNCERTAIN'] and confidence < 0.6:
            fp_probability += 0.10

        if status_upper == "REFINED":
            severity_fpr[severity_str]["false_positive"] += 1

        title = getattr(finding, 'title', '') or getattr(finding, 'vulnerability', '') or ''
        if any(ph in title.upper() for ph in placeholder_titles):
            fp_probability += 0.20

        severity_fpr[severity_str]["weighted_fp"] += fp_probability

    # 计算总体误报率（使用加权平均）
    total_weighted_fp = sum(counts["weighted_fp"] for counts in severity_fpr.values())
    estimated_fpr = total_weighted_fp / len(all_findings) if all_findings else 0.0

    # 限制在合理范围内（10%-40%对于AI分析）
    estimated_fpr = max(0.10, min(0.40, estimated_fpr))

    by_severity_fp = {}
    for sev, counts in severity_fpr.items():
        if counts["total"] > 0:
            sev_fpr = counts["weighted_fp"] / counts["total"]
            by_severity_fp[sev] = {
                "total": counts["total"],
                "estimated_fp": round(counts["weighted_fp"]),
                "estimated_fpr": round(sev_fpr * 100, 2),
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
        self.confidence_threshold = 0.60
        if hasattr(self.config, 'get'):
            self.confidence_threshold = self.config.get('confidence_threshold', 0.60)
        elif hasattr(self.config, 'confidence_threshold'):
            self.confidence_threshold = getattr(self.config, 'confidence_threshold', 0.60)
        self._filtered_count = 0

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
            "confidence_filter_note": getattr(self, '_filtered_count', 0),
            "executive_summary": self._build_executive_summary(all_findings),
        }

    def _build_executive_summary(self, findings: List[Any]) -> Dict[str, Any]:
        """构建执行摘要

        自动识别最关键 3 个风险，提供攻击链视角的风险评估。
        """
        severity_weights = {'critical': 4.0, 'high': 3.0, 'medium': 1.5, 'low': 0.5, 'info': 0.1}

        scored_findings = []
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
            confidence = getattr(f, 'confidence', 0.5) or 0.5
            metadata = getattr(f, 'metadata', {}) or {}
            cross_verified = metadata.get('cross_verified', False) if isinstance(metadata, dict) else False
            cross_boost = 0.5 if cross_verified else 0.0

            sources = metadata.get('sources', []) if isinstance(metadata, dict) else []
            source_boost = min(0.5, len(sources) * 0.15) if isinstance(sources, list) else 0.0

            exploitability = 1.0 if sev in ('critical', 'high') else 0.6 if sev == 'medium' else 0.3

            risk_score = severity_weights.get(sev, 0.1) * confidence * exploitability + cross_boost + source_boost
            scored_findings.append({
                'finding': f,
                'risk_score': risk_score,
                'severity': sev,
                'confidence': confidence,
                'cross_verified': cross_verified,
                'sources': sources if isinstance(sources, list) else [],
            })

        scored_findings.sort(key=lambda x: x['risk_score'], reverse=True)
        top_3 = scored_findings[:3]

        top_risks = []
        for item in top_3:
            f = item['finding']
            rule_name = getattr(f, 'rule_name', getattr(f, 'rule_id', 'Unknown'))
            location_file = ''
            location_line = 0
            if hasattr(f, 'location'):
                location_file = str(getattr(f.location, 'file', ''))
                location_line = getattr(f.location, 'line', 0)
            else:
                location_file = str(getattr(f, 'file', ''))
                location_line = getattr(f, 'line', 0)

            attack_vector = self._infer_attack_vector(f)
            impact_summary = self._infer_impact(f)

            top_risks.append({
                'risk_score': round(item['risk_score'], 2),
                'rule_name': rule_name,
                'rule_id': getattr(f, 'rule_id', ''),
                'severity': item['severity'],
                'confidence': item['confidence'],
                'cross_verified': item['cross_verified'],
                'sources': item['sources'],
                'location_file': location_file,
                'location_line': location_line,
                'attack_vector': attack_vector,
                'impact_summary': impact_summary,
                'description': getattr(f, 'description', '')[:200],
            })

        critical_count = sum(1 for x in scored_findings if x['severity'] == 'critical')
        high_count = sum(1 for x in scored_findings if x['severity'] == 'high')
        medium_count = sum(1 for x in scored_findings if x['severity'] == 'medium')
        total_scored = len(scored_findings)

        if critical_count > 0:
            overall_status = 'critical'
            status_text = '严重风险：发现可立即利用的严重漏洞'
        elif high_count > 0:
            overall_status = 'high'
            status_text = '高风险：发现需要优先处理的高危漏洞'
        elif medium_count > 0:
            overall_status = 'medium'
            status_text = '中等风险：建议尽快修复中等严重性漏洞'
        elif total_scored > 0:
            overall_status = 'low'
            status_text = '低风险：仅发现低严重性问题'
        else:
            overall_status = 'safe'
            status_text = '安全状态良好，未发现显著漏洞'

        attack_chain_hint = ''
        if critical_count >= 2:
            attack_chain_hint = '多个严重漏洞可能形成攻击链，建议优先评估组合利用风险。'
        elif high_count >= 3:
            attack_chain_hint = '多个高危漏洞存在，攻击者可能通过组合利用实现权限提升。'

        return {
            'top_risks': top_risks,
            'overall_status': overall_status,
            'status_text': status_text,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'total_findings': total_scored,
            'attack_chain_hint': attack_chain_hint,
        }

    def _infer_attack_vector(self, finding) -> str:
        """推断攻击向量"""
        rule_name = (getattr(finding, 'rule_name', '') or '').lower()
        rule_id = (getattr(finding, 'rule_id', '') or '').lower()
        description = (getattr(finding, 'description', '') or '').lower()

        if 'sql' in rule_name or 'injection' in rule_name or 'cwe-89' in rule_id:
            return '攻击者通过可控输入（参数、表单、头部）注入恶意 SQL 片段，绕过认证或提取敏感数据'
        if 'xss' in rule_name or 'cwe-79' in rule_id:
            return '攻击者注入恶意脚本到可被其他用户查看的输出中，劫持会话或窃取 Cookie'
        if 'hardcod' in rule_name or 'credential' in rule_name or 'secret' in rule_name or 'password' in rule_name or 'token' in rule_name:
            return '攻击者通过反编译、代码搜索或泄露仓库获取硬编码凭证，直接访问受限资源'
        if 'deserial' in rule_name or 'cwe-502' in rule_id:
            return '攻击者构造恶意序列化对象，在反解析过程中执行任意代码'
        if 'path' in rule_name and ('traversal' in rule_name or 'directory' in rule_name) or 'cwe-22' in rule_id:
            return '攻击者通过 ../ 等路径操作访问系统文件目录之外的敏感文件'
        if 'ssrf' in rule_name or 'cwe-918' in rule_id:
            return '攻击者操控 URL 参数发起内网请求，探测和攻击内部服务'
        if 'csrf' in rule_name or 'cwe-352' in rule_id:
            return '攻击者构造恶意页面诱导已认证用户发起非预期请求'
        if 'rce' in rule_name or 'command' in rule_name or 'cwe-78' in rule_id:
            return '攻击者通过注入操作系统命令或代码片段，在服务器上执行任意命令'
        if 'xxe' in rule_name or 'cwe-611' in rule_id:
            return '攻击者在 XML 中构造恶意 DTD/ENTITY，读取服务器文件或发起 SSRF'
        if 'ldap' in rule_name or 'cwe-90' in rule_id:
            return '攻击者注入 LDAP 过滤器操作符，绕过认证或提取目录数据'
        if 'open.redirect' in rule_name or 'cwe-601' in rule_id:
            return '攻击者构造恶意跳转 URL，将用户引导至钓鱼网站'
        if 'crypto' in rule_name or 'cipher' in rule_name or 'encrypt' in rule_name:
            return '攻击者利用弱加密算法破解加密数据，或实施中间人攻击'
        if 'rate.limit' in rule_name or 'brute' in rule_name or 'cwe-307' in rule_id:
            return '攻击者通过自动化工具高频请求，暴力破解凭据或消耗系统资源'
        if 'cors' in rule_name or 'cwe-942' in rule_id:
            return '攻击者利用宽松 CORS 策略跨域读取敏感 API 响应'

        return f'攻击者利用 {getattr(finding, "rule_name", "未知")} 漏洞进行未授权操作'

    def _infer_impact(self, finding) -> str:
        """推断影响描述"""
        sev = (getattr(finding.severity, 'value', '') or str(finding.severity)).lower()
        rule_name = (getattr(finding, 'rule_name', '') or '').lower()

        if sev in ('critical', 'high'):
            if 'sql' in rule_name or 'injection' in rule_name:
                return '可能导致数据泄露、权限绕过、数据篡改，甚至远程代码执行'
            if 'hardcod' in rule_name or 'credential' in rule_name:
                return '可能导致数据库、云存储或第三方服务被直接访问'
            if 'rce' in rule_name or 'command' in rule_name:
                return '可能导致服务器完全被控制，数据被窃取或篡改'
            if 'deserial' in rule_name:
                return '可能导致远程代码执行，服务器被完全控制'
            return '可能导致敏感数据泄露、权限提升或服务中断'
        if sev == 'medium':
            return '可能导致部分信息泄露或功能异常，建议尽快修复'
        return '影响范围有限，但仍建议修复以符合安全最佳实践'


# ============================================================
# 修复建议动态生成 - 完全由 AI 生成，无硬编码模板
# ============================================================

# 漏洞类型关键词到 OWASP Cheat Sheet 的映射（用于动态兜底）
_VULN_KEYWORD_TO_OWASP = {
    'sql': 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    'xss': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    'csrf': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
    'command': 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
    'exec': 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
    'rce': 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
    'path': 'https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html',
    'traversal': 'https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html',
    'ssrf': 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
    'deserializ': 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
    'hardcod': 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    'credential': 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    'secret': 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    'password': 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
    'crypto': 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
    'cipher': 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
    'encrypt': 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
    'md5': 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
    'sha1': 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
    'redirect': 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
    'ldap': 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
    'xxe': 'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
    'rate.limit': 'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
    'brute': 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
    'auth': 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
    'permission': 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
    'cors': 'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html',
}

# 漏洞类型关键词到通用修复步骤的映射（用于动态兜底）
_VULN_KEYWORD_TO_GENERIC_STEPS = {
    'sql': ['使用参数化查询替代字符串拼接', '禁止使用 f-string/concat 拼接 SQL', '应用最小数据库权限原则'],
    'xss': ['对输出到 HTML 的内容进行上下文感知编码', '启用 Content-Security-Policy 响应头', '设置 Cookie 的 HttpOnly 和 Secure 标志'],
    'csrf': ['启用框架内置 CSRF 保护', '使用 Synchronizer Token Pattern 或 Double Submit Cookie', '确保 GET 请求不修改任何状态'],
    'command': ['使用 ProcessBuilder 将命令和参数作为独立数组传递', '禁止使用 shell=True', '对用户输入进行白名单验证'],
    'exec': ['使用 ProcessBuilder 将命令和参数作为独立数组传递', '禁止使用 shell=True', '对用户输入进行白名单验证'],
    'rce': ['禁止将用户输入传递给代码执行函数', '使用安全的替代 API', '实施输入白名单验证'],
    'path': ['使用 getCanonicalPath() 规范化路径', '验证规范化后的路径是否在允许的目录内', '使用白名单限制可访问的文件类型'],
    'traversal': ['使用 getCanonicalPath() 规范化路径', '验证规范化后的路径是否在允许的目录内', '使用白名单限制可访问的文件类型'],
    'ssrf': ['实施 URL 白名单验证', '阻止访问内网 IP 段和云元数据地址', '限制允许的协议仅为 http/https'],
    'deserializ': ['避免对不可信数据进行 Java 原生反序列化', '使用白名单验证反序列化类', '考虑使用 JSON/XML 等安全序列化格式'],
    'hardcod': ['移除所有硬编码的密码、API 密钥和 Token', '使用环境变量或密钥管理服务', '启用密钥轮换策略'],
    'credential': ['将凭证移至安全的密钥管理系统', '使用环境变量或 Vault 等密钥管理服务', '启用密钥轮换策略'],
    'secret': ['将密钥移至安全的密钥管理系统', '禁止硬编码在代码或配置中', '使用 .gitignore 防止密钥文件被提交'],
    'password': ['使用 BCrypt/Argon2 存储密码', '禁止明文存储或弱哈希', '实施密码复杂度要求'],
    'crypto': ['使用现代加密算法替代已被破解的弱算法', '密码存储使用 BCrypt/PBKDF2/Argon2', '数据加密使用 AES-256-GCM'],
    'cipher': ['使用现代加密算法替代已被破解的弱算法', '避免使用 ECB 模式', '数据加密使用 AES-256-GCM'],
    'encrypt': ['使用现代加密算法替代已被破解的弱算法', '密码存储使用 BCrypt/PBKDF2/Argon2', '数据加密使用 AES-256-GCM'],
    'md5': ['停止使用 MD5 作为哈希算法', '密码存储使用 BCrypt/Argon2', '文件校验使用 SHA-256 或更高'],
    'sha1': ['停止使用 SHA1 作为哈希算法', '签名使用 SHA-256 或更高', '密码存储使用 BCrypt/Argon2'],
    'redirect': ['实施重定向 URL 白名单', '避免使用用户输入直接作为重定向目标', '使用间接引用映射'],
    'ldap': ['使用 LDAP 转义库处理用户输入', '实施输入白名单验证', '使用参数化 LDAP 查询'],
    'xxe': ['启用 XMLConstants.FEATURE_SECURE_PROCESSING', '禁用 DOCTYPE 声明', '禁用外部实体加载'],
    'rate.limit': ['实施请求频率限制', '使用滑动窗口或令牌桶算法', '实施账户锁定策略'],
    'brute': ['实施登录尝试次数限制', '使用账户锁定策略', '启用多因素认证'],
    'auth': ['确保所有敏感端点都配置了认证和授权', '验证 JWT 签名并检查算法', '实施基于角色的访问控制'],
    'permission': ['实施基于角色的访问控制', '对水平/垂直越权进行显式检查', '使用最小权限原则'],
}


def _extract_pentest_data(results) -> Dict[str, Any]:
    """从扫描结果中提取渗透测试数据（AI工具计划和POC执行链）

    Args:
        results: ScanResult 列表

    Returns:
        包含 tool_plans 和 poc_chains 的字典
    """
    tool_plans: List[Dict[str, Any]] = []
    poc_chains: List[Dict[str, Any]] = []

    for result in results:
        meta = getattr(result, 'metadata', {}) or {}
        if not isinstance(meta, dict):
            continue

        # 提取 AI 工具调用计划
        tool_plan = meta.get('tool_plan')
        if tool_plan:
            if isinstance(tool_plan, dict):
                tool_plans.append({
                    'target': getattr(result, 'target', 'unknown'),
                    'target_type': tool_plan.get('target_type', 'unknown'),
                    'reasoning': tool_plan.get('reasoning', ''),
                    'tool_plan': tool_plan.get('tool_plan', []),
                })
            elif isinstance(tool_plan, list):
                tool_plans.append({
                    'target': getattr(result, 'target', 'unknown'),
                    'target_type': 'unknown',
                    'reasoning': '',
                    'tool_plan': tool_plan,
                })

        # 提取 POC 执行链
        poc_data = meta.get('poc_results') or meta.get('poc_chain')
        if poc_data:
            if isinstance(poc_data, dict):
                steps = poc_data.get('steps', poc_data.get('execution_order', []))
                poc_chains.append({
                    'target': getattr(result, 'target', 'unknown'),
                    'overall_strategy': poc_data.get('overall_strategy', ''),
                    'steps': steps if isinstance(steps, list) else [],
                    'metadata': poc_data.get('metadata', {}),
                })
            elif isinstance(poc_data, list):
                poc_chains.append({
                    'target': getattr(result, 'target', 'unknown'),
                    'overall_strategy': '',
                    'steps': poc_data,
                    'metadata': {},
                })

    return {
        'tool_plans': tool_plans,
        'poc_chains': poc_chains,
    }


def _build_dynamic_fallback_fix(vuln_type: str, rule_name: str = '', rule_id: str = '') -> Dict[str, Any]:
    """根据漏洞关键词动态生成基本修复指引（兜底机制）
    
    当 AI 未返回修复建议时，基于 vuln_type、rule_name、rule_id 中的关键词
    匹配 OWASP 参考链接和通用修复步骤。
    
    Args:
        vuln_type: 漏洞类型字符串
        rule_name: 规则名称
        rule_id: 规则 ID
        
    Returns:
        修复建议字典
    """
    combined = f"{vuln_type} {rule_name} {rule_id}".lower()
    
    matched_owasp = ''
    matched_steps = []
    
    for keyword, owasp_link in _VULN_KEYWORD_TO_OWASP.items():
        if keyword.lower() in combined:
            matched_owasp = owasp_link
            matched_steps = _VULN_KEYWORD_TO_GENERIC_STEPS.get(keyword, [])
            break
    
    if matched_steps:
        return {
            'summary': f'根据安全最佳实践审查并修复 {vuln_type or rule_name} 问题。',
            'fix_example': '',
            'fix_steps': matched_steps + ['参考 OWASP 相关修复指南', '实施修复后进行安全测试'],
            'owasp_link': matched_owasp,
            'impact_scope': '具体影响范围需根据代码上下文进一步评估',
            'is_ai_generated': False,
        }
    
    return {
        'summary': f'根据安全最佳实践审查并修复 {vuln_type or rule_name} 问题。',
        'fix_example': '',
        'fix_steps': ['审查代码中的安全缺陷', '参考 OWASP 相关修复指南', '实施修复后进行安全测试'],
        'owasp_link': 'https://owasp.org/www-project-top-ten/',
        'impact_scope': '具体影响范围需根据代码上下文进一步评估',
        'is_ai_generated': False,
    }


def _generate_fix_suggestion(vuln_type: str, rule_name: str = '', rule_id: str = '', metadata: dict = None) -> Dict[str, Any]:
    """根据 AI 分析结果生成修复建议
    
    策略：优先使用 AI 生成的个性化修复建议；如果 AI 未返回修复建议，
    则基于漏洞类型关键词动态生成基本修复指引。
    
    Args:
        vuln_type: 漏洞类型字符串
        rule_name: 规则名称
        rule_id: 规则 ID
        metadata: 元数据字典（可能包含 AI 生成的修复建议）
        
    Returns:
        修复建议字典，包含 summary, fix_example, fix_steps, owasp_link, impact_scope
    """
    # 第一优先：使用 AI 生成的个性化修复建议
    if metadata and isinstance(metadata, dict):
        ai_summary = metadata.get('fix_summary') or metadata.get('fix_suggestion') or metadata.get('remediation')
        ai_example = metadata.get('fix_example') or metadata.get('fix_code') or metadata.get('remediation_code')
        ai_steps = metadata.get('fix_steps') or metadata.get('remediation_steps')
        
        if ai_summary or ai_example:
            return {
                'summary': ai_summary or '参考下方修复代码示例进行安全加固。',
                'fix_example': ai_example or '',
                'fix_steps': ai_steps if isinstance(ai_steps, list) else ['参考 AI 生成的修复建议实施修复', '修复后进行安全测试验证'],
                'owasp_link': metadata.get('owasp_reference', '') or _build_owasp_link_from_cwe(metadata),
                'impact_scope': metadata.get('impact_scope') or metadata.get('impact') or '具体影响范围需根据代码上下文进一步评估',
                'is_ai_generated': True,
            }
    
    # 兜底：动态生成基本修复指引（无硬编码模板）
    return _build_dynamic_fallback_fix(vuln_type, rule_name, rule_id)


def _build_owasp_link_from_cwe(metadata: dict) -> str:
    """根据CWE ID构建OWASP参考链接"""
    cwe_id = metadata.get('cwe_id') or metadata.get('cwe') or ''
    if not cwe_id:
        return ''
    
    # 提取CWE编号
    import re
    match = re.search(r'CWE[-:]?(\d+)', str(cwe_id), re.IGNORECASE)
    if match:
        num = match.group(1)
        return f'https://cwe.mitre.org/data/definitions/{num}.html'
    return ''


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

    def normalize_vuln_type(self, vuln_type: str) -> str:
        """将相似的漏洞类型归一化为统一的类别名称"""
        vuln_lower = vuln_type.lower()
        
        # CSRF相关
        if any(kw in vuln_lower for kw in ['csrf', '跨站请求伪造']):
            return 'CSRF防护缺失'
        
        # Actuator相关
        if any(kw in vuln_lower for kw in ['actuator', '端点暴露', 'endpoint']):
            return 'Actuator端点暴露'
        
        # 密码/凭证相关
        if any(kw in vuln_lower for kw in ['密码', 'password', '硬编码凭证', '默认密码', 'credential']):
            return '硬编码凭证'
        
        # SQL注入相关
        if any(kw in vuln_lower for kw in ['sql', '注入', 'mybatis']):
            return 'SQL注入'
        
        # 输入验证相关
        if any(kw in vuln_lower for kw in ['输入验证', '参数校验', 'validation']):
            return '输入验证缺失'
        
        # 令牌相关
        if any(kw in vuln_lower for kw in ['token', '令牌']):
            return '令牌安全'
        
        # 授权相关
        if any(kw in vuln_lower for kw in ['授权', '权限', 'auth', 'permission']):
            return '授权缺失'
        
        # Redis相关
        if any(kw in vuln_lower for kw in ['redis', 'keys']):
            return '缓存安全风险'
        
        # 异步异常处理
        if any(kw in vuln_lower for kw in ['async', 'future', 'exception', '线程']):
            return '异常处理缺失'
        
        return vuln_type

    def _calculate_risk_score(self, finding: Dict) -> float:
        severity_weights = {'critical': 4.0, 'high': 3.0, 'medium': 1.5, 'low': 0.5, 'info': 0.1}
        exploitability_map = {'critical': 1.0, 'high': 1.0, 'medium': 0.6, 'low': 0.3, 'info': 0.1}
        sev_str = finding.get('severity', 'info').lower().split('.')[-1]
        severity_weight = severity_weights.get(sev_str, 0.1)
        confidence = finding.get('confidence', 0.5) or 0.5
        exploitability = exploitability_map.get(sev_str, 0.3)
        return round(severity_weight * confidence * exploitability, 4)

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
                env.globals.update(dict=type({}), len=len, range=range, str=str, int=int, float=float)
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
                            processed_finding['files'] = [str(f) if hasattr(f, '__fspath__') else f for f in finding.files]
                            processed_finding['is_multi_file'] = True
                            processed_finding['snippet_count'] = len(finding.files)
                        else:
                            location_file = finding.location.file if hasattr(finding.location, 'file') else None
                            processed_finding['files'] = [str(location_file) if location_file else '']
                            processed_finding['is_multi_file'] = False
                            processed_finding['snippet_count'] = 1

                        if hasattr(finding, 'snippets') and finding.snippets:
                            processed_finding['snippets'] = {str(k): safe_escape(v) for k, v in finding.snippets.items()}
                        else:
                            location_file = finding.location.file if hasattr(finding.location, 'file') else None
                            processed_finding['snippets'] = {str(location_file) if location_file else '': safe_escape(finding.code_snippet)}

                        if hasattr(finding, 'chain') and finding.chain:
                            processed_finding['chain'] = [
                                {
                                    'file_path': safe_escape(str(getattr(step, 'file_path', step.get('file_path', '')))),
                                    'line': getattr(step, 'line', step.get('line', 0)),
                                    'description': safe_escape(getattr(step, 'description', step.get('description', ''))),
                                    'code_snippet': safe_escape(getattr(step, 'code_snippet', step.get('code_snippet', ''))),
                                }
                                for step in finding.chain
                            ]
                            mermaid_lines = ['flowchart LR']
                            for i, step in enumerate(finding.chain):
                                node_id = f'N{i + 1}'
                                file_path_raw = str(getattr(step, 'file_path', step.get('file_path', '')))
                                file_name = Path(file_path_raw).name if file_path_raw else file_path_raw
                                line_num = getattr(step, 'line', step.get('line', 0))
                                node_label = f'{file_name}:{line_num}' if line_num else file_name
                                mermaid_lines.append(f'    {node_id}[{node_label}]')
                                if i > 0:
                                    prev_node_id = f'N{i}'
                                    mermaid_lines.append(f'    {prev_node_id} --> {node_id}')
                            processed_finding['mermaid_graph'] = '\n'.join(mermaid_lines)
                        else:
                            processed_finding['chain'] = []

                        enhanced_description = self._build_enhanced_finding_description(finding, metadata)
                        processed_finding['enhanced_description'] = safe_escape(enhanced_description)

                        code_context = None
                        if hasattr(finding, 'code_context') and finding.code_context:
                            code_context = finding.code_context.to_dict()
                        else:
                            code_context = self._extract_code_context_from_file(finding, context_lines=5)
                        processed_finding['code_context'] = code_context

                        enhanced_recommendation = self._generate_enhanced_recommendation(processed_finding)
                        processed_finding['enhanced_recommendation'] = enhanced_recommendation

                        # 生成可操作的修复建议（基于漏洞类型映射）
                        vuln_type_str = metadata.get('vuln_type', '') if isinstance(metadata, dict) else ''
                        fix_suggestion_data = _generate_fix_suggestion(
                            vuln_type=vuln_type_str,
                            rule_name=getattr(finding, 'rule_name', '') or '',
                            rule_id=getattr(finding, 'rule_id', '') or '',
                            metadata=metadata,
                        )
                        processed_finding['fix_suggestion_data'] = fix_suggestion_data
                        
                        # 调试：如果是CSRF相关漏洞，打印详细信息
                        rule_id_check = str(rule_id).lower()
                        rule_name_check = str(getattr(finding, 'rule_name', '')).lower()
                        if 'csrf' in rule_id_check or 'csrf' in rule_name_check:
                            print(f"[CSRF_DEBUG] ========== CSRF漏洞详细信息 ==========")
                            print(f"[CSRF_DEBUG] 原始finding.rule_id: {getattr(finding, 'rule_id', 'N/A')}")
                            print(f"[CSRF_DEBUG] 原始finding.rule_name: {getattr(finding, 'rule_name', 'N/A')}")
                            print(f"[CSRF_DEBUG] processed_finding['rule_id']: {processed_finding['rule_id']}")
                            print(f"[CSRF_DEBUG] processed_finding['rule_name']: {processed_finding['rule_name']}")
                            print(f"[CSRF_DEBUG] processed_finding['metadata']键列表: {list(processed_finding['metadata'].keys()) if isinstance(processed_finding.get('metadata'), dict) else 'N/A'}")
                            print(f"[CSRF_DEBUG] processed_finding['metadata'].get('vuln_type'): {processed_finding.get('metadata', {}).get('vuln_type', 'N/A') if isinstance(processed_finding.get('metadata'), dict) else 'N/A'}")
                            print(f"[CSRF_DEBUG] enhanced_recommendation结果: {enhanced_recommendation}")
                            print(f"[CSRF_DEBUG] ======================================")

                        processed_finding['evidence_chain'] = {
                            'entry_point': {
                                'description': '用户输入入口点',
                                'location': str(finding.location.file) if hasattr(finding.location, 'file') else str(finding.location),
                                'code': finding.code_snippet,
                            },
                            'propagation_path': [
                                {
                                    'step': 1,
                                    'description': '数据从入口点传播到漏洞触发点',
                                    'location': str(finding.location.file) if hasattr(finding.location, 'file') else str(finding.location),
                                    'code': finding.code_snippet,
                                }
                            ],
                            'sink': {
                                'description': '漏洞触发点',
                                'location': str(finding.location.file) if hasattr(finding.location, 'file') else str(finding.location),
                                'code': finding.code_snippet,
                            },
                            'exploitability': {
                                'can_be_exploited': str(finding.severity.value if hasattr(finding.severity, 'value') else finding.severity).upper() in ('CRITICAL', 'HIGH'),
                                'prerequisites': self._get_exploit_prerequisites(finding),
                                'difficulty': self._get_exploit_difficulty(finding),
                                'lateral_impact': self._get_lateral_impact(finding),
                            },
                        }

                        framework_mitigation = self._build_framework_mitigation_info(finding, metadata)
                        if framework_mitigation:
                            processed_finding['framework_mitigation'] = framework_mitigation

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

                        # 提取漏洞利用路径
                        processed_finding['exploit_path'] = self._extract_exploit_path(processed_finding)

                        processed_result['findings'].append(processed_finding)
                    processed_results.append(processed_result)

                # 默认启用去重，避免双倍发现问题
                all_processed_findings = []
                result_finding_maps = []
                for pr in processed_results:
                    result_finding_maps.append(pr['findings'])
                    all_processed_findings.extend(pr['findings'])

                deduplicated = self._deduplicate_findings_for_report(all_processed_findings)

                for pr in processed_results:
                    pr['findings'] = []

                for finding in deduplicated:
                    for pr_idx, pr in enumerate(processed_results):
                        pr_file = str(pr.get('target', '')).lower()
                        finding_file = str(finding.get('location', {}).get('file', '') or '').lower()
                        if pr_file in finding_file or finding_file in pr_file or not pr.get('target', ''):
                            pr['findings'].append(finding)
                            break

                final_findings_count = sum(len(pr['findings']) for pr in processed_results)
                print(f"[DEBUG] 发现去重: 原始 {len(all_processed_findings)} -> 去重后 {final_findings_count}")

                # 更新 summary 统计以匹配去重后的实际数量
                summary['total_findings'] = final_findings_count
                
                # 重新计算 severity_counts
                new_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for finding in deduplicated:
                    sev = str(finding.get('severity', 'info')).lower().split('.')[-1]
                    if sev in new_severity_counts:
                        new_severity_counts[sev] += 1
                    else:
                        new_severity_counts['info'] += 1
                summary['severity_counts'] = new_severity_counts
                
                # 重新计算 source_counts
                new_source_counts = {}
                for finding in deduplicated:
                    metadata = finding.get('metadata', {}) or {}
                    source = metadata.get('source', 'ai') if isinstance(metadata, dict) else 'ai'
                    new_source_counts[source] = new_source_counts.get(source, 0) + 1
                summary['source_counts'] = new_source_counts

                all_processed_findings_for_sort = []
                for pr in processed_results:
                    all_processed_findings_for_sort.extend(pr['findings'])

                for finding in all_processed_findings_for_sort:
                    finding['risk_score'] = self._calculate_risk_score(finding)

                all_processed_findings_for_sort.sort(key=lambda f: f.get('risk_score', 0), reverse=True)

                for i, finding in enumerate(all_processed_findings_for_sort):
                    if i < 5:
                        finding['priority_fix'] = True
                    else:
                        finding['priority_fix'] = False

                vulnerability_type_counts = {}
                unique_vuln_types = set()
                for finding in all_processed_findings_for_sort:
                    vuln_type = finding.get('rule_name', 'Unknown')
                    normalized_type = self.normalize_vuln_type(vuln_type)
                    finding['normalized_vuln_type'] = normalized_type
                    unique_vuln_types.add(normalized_type)
                    vulnerability_type_counts[normalized_type] = vulnerability_type_counts.get(normalized_type, 0) + 1
                
                sorted_vuln_types = sorted(unique_vuln_types)

                sorted_by_risk = {}
                for pr in processed_results:
                    pr_target = str(pr.get('target', '')).lower()  # 统一转换为小写以处理Windows路径大小写不一致问题
                    pr_findings = [f for f in all_processed_findings_for_sort
                                   if pr_target in str(f.get('location', {}).get('file', '')).lower()
                                   or str(f.get('location', {}).get('file', '')).lower() in pr_target
                                   or not pr.get('target', '')]
                    sorted_by_risk[id(pr)] = pr_findings

                for pr in processed_results:
                    pr['findings'] = sorted_by_risk.get(id(pr), [])

                # 去重后重新分类，确保加固建议分页准确
                all_findings_for_classification = []
                for pr in processed_results:
                    all_findings_for_classification.extend(pr['findings'])
                
                # 将字典形式的发现转换为类对象，以便 _classify_findings 可以处理
                class FindingProxy:
                    def __init__(self, d):
                        self.__dict__.update(d)
                
                proxy_findings = [FindingProxy(f) for f in all_findings_for_classification]
                categorized_findings = _classify_findings(proxy_findings)

                # 构建扫描配置元数据
                scan_config_info = {
                    'pure_ai': getattr(self.config, 'pure_ai', False),
                    'test_mode': getattr(self.config, 'test_mode', False),
                    'test_file_count': getattr(self.config, 'test_file_count', 0) if getattr(self.config, 'test_mode', False) else 0,
                    'max_files': getattr(self.config, 'max_files', 0),
                    'ai_provider': getattr(getattr(self.config, 'ai', None), 'provider', 'unknown') if hasattr(self.config, 'ai') else 'unknown',
                    'ai_model': getattr(getattr(self.config, 'ai', None), 'model', 'unknown') if hasattr(self.config, 'ai') else 'unknown',
                    'confidence_threshold': getattr(self.config, 'confidence_threshold', 0.60),
                }

                # 生成异常统计摘要
                anomaly_summary = {
                    'total_anomalies': 0,
                    'truncation_count': 0,
                    'total_rescans': 0,
                    'partial_analysis_count': 0,
                    'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                }

                # 提取渗透测试数据（AI工具计划和POC执行链）
                pentest_data = _extract_pentest_data(results)

                html = template.render(
                    summary=summary,
                    results=processed_results,
                    status=status,
                    status_text=status_text,
                    total_duration=total_duration,
                    debug_logs=debug_logs,
                    token_records=token_records,
                    categorized_findings=categorized_findings,
                    hardening_advice_findings=categorized_findings.get('hardening_advice_findings', []),
                    hardening_advice_count=len(categorized_findings.get('hardening_advice_findings', [])),
                    anomaly_summary=anomaly_summary,
                    executive_summary=summary.get('executive_summary', {}),
                    vulnerability_type_counts=vulnerability_type_counts,
                    unique_vuln_types=sorted_vuln_types,
                    scan_config=scan_config_info,
                    pentest_tool_plans=pentest_data['tool_plans'],
                    pentest_poc_chains=pentest_data['poc_chains'],
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
            print(f"[WARN] 模板渲染失败: {e}, 使用备用HTML报告")
            return self._generate_fallback_html(results, summary, status, status_text, total_duration)

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

    def _generate_fallback_html(self, results, summary, status, status_text, total_duration):
        """生成备用完整HTML报告（当模板渲染失败时使用）"""
        severity_counts = summary.get("severity_counts", {})
        tool_statistics = summary.get("tool_statistics")

        # 按文件分组发现
        findings_by_file: Dict[str, list] = {}
        for result in results:
            for finding in result.findings:
                loc = getattr(finding, 'location', None)
                if isinstance(loc, dict):
                    file_path = str(loc.get('file', 'unknown'))
                elif hasattr(loc, 'file'):
                    file_path = str(loc.file)
                else:
                    file_path = str(loc) if loc else 'unknown'
                if file_path not in findings_by_file:
                    findings_by_file[file_path] = []
                findings_by_file[file_path].append(finding)

        findings_rows = ""
        for file_path, file_findings in findings_by_file.items():
            file_display = os.path.basename(file_path) if file_path != 'unknown' else file_path
            for f in file_findings:
                sev = getattr(f.severity, 'value', str(f.severity)) if hasattr(f, 'severity') else 'info'
                rule_name = safe_escape(getattr(f, 'rule_name', ''))
                rule_id = safe_escape(getattr(f, 'rule_id', ''))
                desc = safe_escape(getattr(f, 'description', getattr(f, 'message', '无描述')))
                fix = safe_escape(getattr(f, 'fix_suggestion', ''))
                fix_html = f"<td>{fix}</td>" if fix else "<td>-</td>"
                confidence = getattr(f, 'confidence', 0) or 0
                findings_rows += f"""    <tr class="severity-{sev}">
        <td>{rule_name}</td>
        <td><code>{rule_id}</code></td>
        <td>{sev.upper()}</td>
        <td>{confidence:.2f}</td>
        <td>{file_display}</td>
        <td>{desc}</td>
        {fix_html}
    </tr>
"""

        config_info = ""
        if hasattr(self, 'config') and self.config:
            pure_ai = getattr(self.config, 'pure_ai', False)
            ai_provider = getattr(getattr(self.config, 'ai', None), 'provider', 'unknown') if hasattr(self.config, 'ai') else 'unknown'
            ai_model = getattr(getattr(self.config, 'ai', None), 'model', 'unknown') if hasattr(self.config, 'ai') else 'unknown'
            conf_threshold = getattr(self.config, 'confidence_threshold', 0.60)
            config_info = f"""    <tr><td>AI 提供商</td><td>{safe_escape(ai_provider)}</td></tr>
    <tr><td>AI 模型</td><td>{safe_escape(ai_model)}</td></tr>
    <tr><td>置信度阈值</td><td>{conf_threshold}</td></tr>
    <tr><td>纯AI模式</td><td>{"是" if pure_ai else "否"}</td></tr>
"""

        tool_info = ""
        if tool_statistics and isinstance(tool_statistics, dict):
            for k, v in tool_statistics.items():
                tool_info += f'    <tr><td>{safe_escape(str(k))}</td><td>{safe_escape(str(v))}</td></tr>\n'

        color_map = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8',
            'info': '#6c757d',
        }

        status_colors = {
            'safe': '#28a745',
            'low': '#17a2b8',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545',
        }
        status_color = status_colors.get(status, '#6c757d')

        html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HOS-LS 安全扫描报告</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #333; line-height: 1.6; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ text-align: center; color: #2c3e50; margin-bottom: 10px; font-size: 28px; }}
        h2 {{ color: #2c3e50; margin: 20px 0 10px; border-bottom: 2px solid #3498db; padding-bottom: 5px; }}
        .status-banner {{ text-align: center; padding: 15px; border-radius: 8px; margin-bottom: 20px; color: #fff; font-size: 20px; font-weight: bold; background: {status_color}; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th {{ background: #3498db; color: #fff; padding: 10px 12px; text-align: left; font-weight: 600; }}
        td {{ padding: 8px 12px; border-bottom: 1px solid #eee; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover {{ background: #f8f9fa; }}
        .severity-critical {{ border-left: 4px solid {color_map['critical']}; }}
        .severity-high {{ border-left: 4px solid {color_map['high']}; }}
        .severity-medium {{ border-left: 4px solid {color_map['medium']}; }}
        .severity-low {{ border-left: 4px solid {color_map['low']}; }}
        .severity-info {{ border-left: 4px solid {color_map['info']}; }}
        .card {{ background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .stat {{ text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }}
        .stat .num {{ font-size: 32px; font-weight: bold; color: #2c3e50; }}
        .stat .label {{ font-size: 13px; color: #666; margin-top: 5px; }}
        code {{ background: #f1f1f1; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
        .footer {{ text-align: center; color: #999; margin-top: 30px; font-size: 12px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>HOS-LS 安全扫描报告</h1>
    <div class="status-banner">{safe_escape(status_text)}</div>

    <div class="grid">
        <div class="stat"><div class="num">{summary.get("total_scans", 0)}</div><div class="label">扫描文件数</div></div>
        <div class="stat"><div class="num">{summary.get("total_findings", 0)}</div><div class="label">发现问题数</div></div>
        <div class="stat"><div class="num">{severity_counts.get("critical", 0)}</div><div class="label">严重</div></div>
        <div class="stat"><div class="num">{severity_counts.get("high", 0)}</div><div class="label">高危</div></div>
        <div class="stat"><div class="num">{severity_counts.get("medium", 0)}</div><div class="label">中危</div></div>
        <div class="stat"><div class="num">{severity_counts.get("low", 0)}</div><div class="label">低危</div></div>
        <div class="stat"><div class="num">{severity_counts.get("info", 0)}</div><div class="label">信息</div></div>
    </div>

    <div class="card">
        <h2>扫描摘要</h2>
        <table>
            <tr><th>项目</th><th>值</th></tr>
            <tr><td>扫描文件数</td><td>{summary.get("total_scans", 0)}</td></tr>
            <tr><td>发现问题数</td><td>{summary.get("total_findings", 0)}</td></tr>
            <tr><td>扫描耗时</td><td>{total_duration} 秒</td></tr>
            <tr><td>安全状态</td><td>{safe_escape(status_text)}</td></tr>
            {config_info}
            {tool_info}
        </table>
    </div>

    <div class="card">
        <h2>发现列表（按文件分组，共 {len(findings_by_file)} 个文件）</h2>
        <table>
            <thead>
                <tr>
                    <th>规则名称</th>
                    <th>规则ID</th>
                    <th>严重级别</th>
                    <th>置信度</th>
                    <th>文件</th>
                    <th>描述</th>
                    <th>修复建议</th>
                </tr>
            </thead>
            <tbody>
{findings_rows}
            </tbody>
        </table>
    </div>

    <div class="footer">HOS-LS 安全扫描报告 | 生成时间: {self._now_str()}</div>
</div>
</body>
</html>"""
        return html

    def _now_str(self) -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _generate_default_html(self, results, summary, status, status_text, total_duration):
        """生成默认 HTML 内容（当模板文件不存在时使用，委托到 _generate_fallback_html）"""
        return self._generate_fallback_html(results, summary, status, status_text, total_duration)



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
            "confidence_filter_note": getattr(self, '_filtered_count', 0),
        }

    def _is_placeholder_finding(self, finding) -> bool:
        placeholder_titles = [
            'UNVERIFIED_RISK', 'UNKNOWN', 'GENERIC', 'PLACEHOLDER',
            'UNVERIFIED', 'SUSPICIOUS_PATTERN', 'POTENTIAL_ISSUE',
            'UNNAMED_VULNERABILITY', 'TBD', 'TODO', 'NEEDS_REVIEW',
        ]
        title = getattr(finding, 'title', '') or getattr(finding, 'rule_name', '') or getattr(finding, 'vulnerability', '') or ''
        title_upper = str(title).upper()
        return any(ph in title_upper for ph in placeholder_titles)

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
        code_snippet = str(getattr(finding, 'code_snippet', '') or '')

        needs_review = False

        if self.config.precision_mode:
            if confidence < 0.85:
                return False, 'FILTERED_PRECISION', False
            if evidence_count < 2:
                return False, 'FILTERED_PRECISION', False
            if not code_snippet or len(code_snippet.strip()) <= 10:
                return False, 'FILTERED_PRECISION', False
            if self._is_placeholder_finding(finding):
                return False, 'FILTERED_PLACEHOLDER', False

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

    def _deduplicate_findings_for_report(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """对报告中的发现进行去重合并

        合并规则：同文件、同行号范围（±3行）、同CWE类型的发现合并为一项。
        保留最高严重级别和最高置信度，并在 merge_note 中标注合并数量。

        Args:
            findings: 处理后的发现列表（字典形式）

        Returns:
            去重合并后的发现列表
        """
        if not findings:
            return []

        severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

        def get_severity_value(sev_str: str) -> int:
            sev_lower = str(sev_str).lower().split('.')[-1]
            return severity_rank.get(sev_lower, 5)

        def get_cwe_type(finding: Dict[str, Any]) -> str:
            metadata = finding.get('metadata', {}) or {}
            cwe_ids = metadata.get('cwe_ids', []) or metadata.get('cwe_id', '') or ''
            if isinstance(cwe_ids, list):
                cwe_str = ','.join(sorted(set(str(c) for c in cwe_ids)))
                if cwe_str:
                    return cwe_str
            elif isinstance(cwe_ids, str) and cwe_ids.strip():
                return cwe_ids
            # 回退: 使用 rule_name 的 hash 值作为去重标识
            rule_name = finding.get('rule_name', '') or ''
            if rule_name:
                return f'rule:{hash(rule_name) & 0xFFFFFFFF}'
            return ''

        def get_line_range(finding: Dict[str, Any]) -> Tuple[int, int]:
            location = finding.get('location', {}) or {}
            line = location.get('line', 0) or 0
            end_line = location.get('end_line', 0) or line
            if end_line < line:
                end_line = line
            return (line, end_line)

        def lines_overlap(range1: Tuple[int, int], range2: Tuple[int, int], tolerance: int = 3) -> bool:
            start1, end1 = range1
            start2, end2 = range2
            return (start1 - tolerance) <= end2 and (start2 - tolerance) <= end1

        def file_paths_match(path1: str, path2: str) -> bool:
            p1 = str(path1).strip()
            p2 = str(path2).strip()
            if not p1 or not p2:
                return False
            return p1 == p2

        merged = []
        used_indices = set()

        for i, finding in enumerate(findings):
            if i in used_indices:
                continue

            finding_file = finding.get('location', {}).get('file', '') or ''
            finding_line_range = get_line_range(finding)
            finding_cwe = get_cwe_type(finding)

            group = [finding]
            used_indices.add(i)

            for j in range(i + 1, len(findings)):
                if j in used_indices:
                    continue

                other = findings[j]
                other_file = other.get('location', {}).get('file', '') or ''
                other_line_range = get_line_range(other)
                other_cwe = get_cwe_type(other)

                if (file_paths_match(finding_file, other_file)
                        and lines_overlap(finding_line_range, other_line_range, tolerance=3)
                        and finding_cwe == other_cwe):
                    group.append(other)
                    used_indices.add(j)

            if len(group) == 1:
                merged.append(finding)
            else:
                representative = group[0]
                max_severity_value = get_severity_value(representative.get('severity', 'info'))
                max_confidence = float(representative.get('confidence', 0) or 0)
                max_severity_str = representative.get('severity', 'info')
                merged_evidence = list(representative.get('evidence', []) or [])

                for g in group[1:]:
                    g_sev_value = get_severity_value(g.get('severity', 'info'))
                    g_confidence = float(g.get('confidence', 0) or 0)

                    if g_sev_value < max_severity_value:
                        max_severity_value = g_sev_value
                        max_severity_str = g.get('severity', 'info')

                    if g_confidence > max_confidence:
                        max_confidence = g_confidence

                    g_evidence = g.get('evidence', []) or []
                    for ev in g_evidence:
                        if ev not in merged_evidence:
                            merged_evidence.append(ev)

                representative['severity'] = max_severity_str
                representative['confidence'] = max_confidence
                representative['evidence'] = merged_evidence
                representative['merge_note'] = f"已合并 {len(group)} 个相同位置的发现"
                representative['_merged_from'] = len(group)
                merged.append(representative)

        return merged

    def _build_framework_mitigation_info(self, finding: Dict, metadata: Dict) -> Optional[Dict]:
        """构建框架缓解措施信息"""
        if not isinstance(metadata, dict):
            return None

        framework_ctx = metadata.get("framework_context", [])
        sec_annotations = metadata.get("security_annotations", [])
        mitigation_desc = metadata.get("mitigation_description", "")
        original_sev = metadata.get("original_severity", "")
        mitigated_sev = metadata.get("mitigated_severity", "")
        attack_diff = metadata.get("attack_difficulty_score", 0.0)
        protection_layers = metadata.get("protection_layers", 0)

        if not framework_ctx and not sec_annotations and not mitigation_desc:
            return None

        return {
            "has_mitigation": True,
            "framework_context": framework_ctx,
            "security_annotations": sec_annotations,
            "mitigation_description": mitigation_desc,
            "original_severity": original_sev,
            "mitigated_severity": mitigated_sev,
            "severity_downgraded": original_sev != mitigated_sev if original_sev and mitigated_sev else False,
            "attack_difficulty_score": attack_diff,
            "protection_layers": protection_layers,
        }

    def _get_exploit_prerequisites(self, finding: Dict) -> List[str]:
        """获取利用前置条件"""
        severity = getattr(finding, 'severity', '')
        severity_str = severity.value if hasattr(severity, 'value') else str(severity)
        vuln_type = getattr(finding, 'rule_id', '') or ''
        metadata = getattr(finding, 'metadata', {}) or {}
        if isinstance(metadata, dict):
            vuln_type = metadata.get('vuln_type', vuln_type)

        prerequisites = []

        if 'sql' in vuln_type.lower():
            prerequisites.append('可控制的SQL参数输入')
            prerequisites.append('数据库服务可访问')
        elif 'password' in vuln_type.lower() or 'secret' in vuln_type.lower():
            prerequisites.append('配置文件或代码访问权限')
        elif 'exec' in vuln_type.lower() or 'command' in vuln_type.lower():
            prerequisites.append('可控制的外部输入')
            prerequisites.append('系统命令执行权限')
        elif 'xss' in vuln_type.lower():
            prerequisites.append('用户可输入数据')
            prerequisites.append('未过滤的HTML输出')

        if not prerequisites:
            prerequisites.append('漏洞相关代码路径可访问')

        return prerequisites

    def _get_exploit_difficulty(self, finding: Dict) -> str:
        """评估利用难度"""
        confidence = getattr(finding, 'confidence', 0.5) or 0.5
        severity = getattr(finding, 'severity', '')
        severity_str = (severity.value if hasattr(severity, 'value') else str(severity)).upper()

        if severity_str in ('CRITICAL',) and confidence > 0.7:
            return 'easy'
        elif severity_str in ('HIGH', 'MEDIUM') and confidence > 0.5:
            return 'medium'
        else:
            return 'hard'

    def _get_lateral_impact(self, finding: Dict) -> str:
        """评估横向影响"""
        vuln_type = getattr(finding, 'rule_id', '') or ''
        metadata = getattr(finding, 'metadata', {}) or {}
        if isinstance(metadata, dict):
            vuln_type = metadata.get('vuln_type', vuln_type)

        if 'sql' in vuln_type.lower():
            return '可能导致数据泄露、数据篡改'
        elif 'password' in vuln_type.lower() or 'secret' in vuln_type.lower():
            return '可能导致凭证泄露、权限提升'
        elif 'exec' in vuln_type.lower() or 'command' in vuln_type.lower():
            return '可能导致系统完全控制'
        elif 'xss' in vuln_type.lower():
            return '可能导致会话劫持、钓鱼攻击'
        else:
            return '可能导致安全风险'

    def _build_enhanced_finding_description(self, finding: Any, metadata: dict = None) -> str:
        """构建结构化发现描述

        格式:
        【问题类型】SQL注入漏洞
        【受影响位置】UserController.java:42
        【风险说明】攻击者可通过构造恶意SQL语句获取数据库完全控制权，导致数据泄露或篡改
        【详细说明】使用${}拼接SQL参数，存在注入风险

        Args:
            finding: 发现对象
            metadata: 元数据字典

        Returns:
            结构化的描述字符串
        """
        if metadata is None:
            metadata = getattr(finding, 'metadata', {}) or {}

        rule_id = getattr(finding, 'rule_id', '') or ''
        rule_name = getattr(finding, 'rule_name', '') or ''
        original_desc = getattr(finding, 'description', '') or getattr(finding, 'message', '') or ''

        location_file = ''
        location_line = 0
        loc = getattr(finding, 'location', None)
        if loc:
            if hasattr(loc, 'file'):
                location_file = str(loc.file)
            elif isinstance(loc, dict):
                location_file = str(loc.get('file', ''))
            else:
                location_file = str(loc)
            if hasattr(loc, 'line'):
                location_line = loc.line
            elif isinstance(loc, dict):
                location_line = loc.get('line', 0)

        severity = getattr(finding, 'severity', '')
        severity_str = (severity.value if hasattr(severity, 'value') else str(severity)).upper()

        vuln_type_map = {
            'SQL': ('SQL注入漏洞', '原理(Why): 未经验证的用户输入被直接拼接到SQL语句中，破坏了SQL语句的语义结构。攻击者可通过单引号/双引号/注释符(--,#)闭合原有语句，注入额外SQL逻辑。攻击向量: 登录表单、搜索框、URL参数、HTTP Header、Cookie等任何可达数据库的输入点。影响: 数据泄露(读取整表)、数据篡改(UPDATE/DELETE)、绕过认证(OR 1=1)、文件读写(LOAD_FILE/INTO OUTFILE)、远程命令执行(xp_cmdshell/udf)。'),
            'XSS': ('跨站脚本(XSS)漏洞', '原理(Why): 未对用户输入进行HTML编码就直接输出到页面，浏览器将恶意内容作为可执行脚本解析。类型: 反射型(通过URL参数注入立即触发)、存储型(恶意脚本持久化到数据库随页面展示触发)、DOM型(JavaScript动态修改DOM导致执行)。攻击向量: 评论区、用户名、个人资料、搜索框、URL参数。影响: 窃取Cookie/Session Token、执行钓鱼攻击、劫持用户会话、修改页面内容、重定向到恶意站点、键盘记录。'),
            'COMMAND_INJECTION': ('命令注入漏洞', '原理(Why): 用户输入未经过滤直接传递给系统命令解释器(sh/bash/cmd/powershell)。攻击者可通过管道符(|)、分号(;)、反引号(`)、$()等分隔符注入额外命令。攻击向量: 文件名参数、IP地址参数、搜索关键词、系统管理接口。影响: 远程代码执行(RCE)、反弹Shell获取系统控制权、读取任意文件、提权到root/system、横向移动入侵内网。'),
            'PATH_TRAVERSAL': ('路径遍历漏洞', '原理(Why): 使用../序列跳转到父目录，绕过应用程序的目录限制。攻击者通过URL编码(%2e%2e%2f)、双重编码、空字节(%00)绕过简单过滤。攻击向量: 文件下载参数、文件上传路径、日志查看路径、模板加载、图片加载。影响: 读取/etc/passwd或Windows SAM文件、获取Web配置文件中的数据库凭证、读取源代码泄露业务逻辑、下载敏感文档。'),
            'SSRF': ('服务端请求伪造(SSRF)漏洞', '原理(Why): 服务器作为代理转发用户控制的URL请求，绕过了客户端IP限制。攻击者利用服务器的信任关系访问内网资源。攻击向量: URL预览功能、图片加载/缩略图生成、Webhook回调、文件导入(从URL)、PDF生成器。影响: 访问云平台元数据(AWS 169.254.169.254获取IAM凭证)、扫描内网端口、访问未授权的Redis/Memcached、绕过防火墙访问内部API。'),
            'DESERIALIZATION': ('不安全反序列化漏洞', '原理(Why): 反序列化过程中自动调用对象的readObject()/__wakeup()等魔术方法，触发恶意构造的Gadget Chain链式调用。攻击者精心构造序列化数据使反序列化执行任意代码。攻击向量: HTTP请求体(JSON/XML/Java Serialized)、Redis缓存数据、消息队列(RabbitMQ/Kafka)、Cookie/Session存储、RMI/JMX调用。影响: 远程代码执行(RCE)、完全控制系统、部署后门、数据窃取、横向移动。'),
            'HARDCODED_SECRET': ('硬编码密钥漏洞', '原理(Why): 密钥/密码/Token以明文形式硬编码在源代码或配置文件中。任何有代码仓库访问权限的人(包括离职员工、开源贡献者)均可获取。攻击向量: Git/GitHub公开仓库扫描、代码审计、反编译JAR/APK、IDE历史、备份文件泄露。自动化工具: truffleHog、git-secrets、gitleaks。影响: 数据库入侵、API滥用产生费用、云服务资源被盗用(EC2/S3)、供应链攻击。'),
            'WEAK_CRYPTO': ('弱加密算法漏洞', '原理(Why): 使用已被密码学界确认不安全的算法。MD5存在碰撞攻击(Slenvto攻击)、SHA1已被Google实际破解(SHAttered)、DES密钥仅56位可在数小时内暴力破解、RC4存在统计偏差攻击。攻击向量: 彩虹表破解哈希值、中间人攻击解密TLS通信(弱密码套件)、离线暴力破解、生日攻击。影响: 密码批量泄露、通信内容被窃听、Session Token伪造、数字签名伪造。'),
            'CSRF': ('跨站请求伪造(CSRF)漏洞', '原理(Why): 利用浏览器自动携带Cookie的机制，在用户已登录状态下，通过恶意页面/链接发起状态修改请求。服务器无法区分请求是否由用户自愿发起。攻击向量: 恶意网站中的隐藏表单自动提交、img标签触发GET请求、邮件/社交媒体中的恶意链接、Iframe内嵌表单。影响: 未经授权的资金转账、修改密码/邮箱锁定账户、删除数据、创建管理员账户、执行任意状态修改操作。'),
            'OPEN_REDIRECT': ('开放重定向漏洞', '原理(Why): 应用未验证重定向目标URL的合法性，直接使用用户输入作为跳转地址。攻击者构造指向钓鱼网站的链接利用受害者对原域名的信任。攻击向量: 登录后的redirect参数、退出登录跳转、OAuth回调URL、短链接服务、错误页面跳转。影响: 结合社会工程学窃取用户凭证(OAuth Token钓鱼)、绕过域名白名单限制、传播恶意软件、品牌信任度损害。'),
            'LDAP_INJECTION': ('LDAP注入漏洞', '原理(Why): 用户输入未经转义直接拼接到LDAP过滤器中，攻击者可注入通配符(*)或逻辑运算符(|、&)修改查询逻辑。攻击向量: 登录表单的用户名/密码字段、搜索功能、联系人查询、目录浏览接口。影响: 绕过身份验证(注入*通配符)、遍历整个目录结构、获取用户列表及属性(邮箱/电话/职位)、提升权限(修改用户属性)、拒绝服务(构造复杂查询)。'),
            'XXE': ('XML外部实体(XXE)漏洞', '原理(Why): XML解析器默认启用外部实体解析，攻击者在DTD中定义引用本地文件或内网资源的实体。当解析器处理XML时自动加载这些资源并可能返回内容。攻击向量: 文件上传(XML/SVG/DOCX/Excel等格式)、SOAP API调用、RSS订阅解析、SAML认证消息、自定义XML接口。影响: 读取/etc/passwd或Windows系统文件、内网端口扫描、SSRF攻击内网服务、拒绝服务(Billion Laughs指数膨胀攻击)、文件写入(如果支持参数实体)。'),
            'RATE_LIMIT': ('缺少速率限制', '原理(Why): API端点未设置请求频率限制或限制过于宽松，攻击者可使用自动化工具高速发起请求而不被阻止。攻击向量: 登录接口(暴力破解密码)、短信验证码接口(短信轰炸产生费用)、密码重置接口(枚举Token)、搜索接口(资源耗尽)、注册接口(批量创建垃圾账户)。影响: 账户被破解、短信费用激增(每分钟数十条)、服务不可用(DoS)、垃圾数据污染数据库、爬虫大量抓取数据。'),
            'AUTH_BYPASS': ('认证绕过漏洞', '原理(Why): 认证逻辑存在设计缺陷或实现错误，使攻击者可绕过正常认证流程。常见原因: JWT签名算法未验证(al:none攻击)、权限检查条件可被短路、默认凭证未修改、会话管理漏洞、越权访问控制缺失。攻击向量: 修改JWT Header中alg为none并删除签名、删除Authorization头测试默认行为、使用默认admin/admin登录、直接访问未受保护的API端点、参数污染绕过检查。影响: 直接获取管理员权限、访问所有用户数据、修改系统配置、执行特权操作、完全绕过安全控制。'),
        }

        issue_type = rule_name
        risk_desc = ''
        for keyword, (type_name, risk) in vuln_type_map.items():
            if keyword in rule_id.upper() or keyword in rule_name.upper():
                issue_type = type_name
                risk_desc = risk
                break

        if not risk_desc:
            risk_descriptions = {
                'CRITICAL': '攻击者可直接利用此漏洞获取系统完全控制权，造成不可逆的严重损害',
                'HIGH': '攻击者可利用此漏洞获取敏感数据或部分系统权限，造成重大安全风险',
                'MEDIUM': '在特定条件下可被利用，可能导致信息泄露或服务异常',
                'LOW': '风险较低，但仍建议修复以防止潜在的安全隐患',
                'INFO': '信息性发现，用于提示潜在的代码质量问题',
            }
            risk_desc = risk_descriptions.get(severity_str, '存在安全风险，建议进一步评估')

        exploit_section = ''
        if severity_str in ('CRITICAL', 'HIGH'):
            exploit_guides = {
                "SQL": "利用方法: 1) 在输入参数中注入单引号测试报错 2) 使用UNION SELECT提取数据库版本/表名/列名 3) 使用LOAD_FILE()读取服务器文件 4) 使用INTO OUTFILE写入WebShell",
                "XSS": "利用方法: 1) 在输入中注入恶意script标签测试反射型 2) 提交包含恶意脚本的评论/用户名测试存储型 3) 使用BeEF框架劫持用户会话",
                "COMMAND_INJECTION": "利用方法: 1) 在参数后添加;whoami测试命令执行 2) 使用管道符连接nc反弹shell 3) 使用命令替换符下载执行远程脚本",
                "PATH_TRAVERSAL": "利用方法: 1) 使用../../../../etc/passwd测试Linux路径遍历 2) 使用反斜杠序列测试Windows路径 3) 使用URL编码绕过简单过滤",
                "SSRF": "利用方法: 1) 使用云元数据URL获取AWS凭证 2) 使用localhost访问内网Redis 3) 使用file协议读取本地文件",
                "DESERIALIZATION": "利用方法: 1) 使用ysoserial生成CommonsCollections Gadget链 2) 使用marshalsec生成Java反序列化payload 3) 通过HTTP请求头/Body/Cookie注入恶意序列化对象",
                "HARDCODED_SECRET": "利用方法: 1) 直接在源码中搜索password/secret/api_key关键字 2) 使用truffleHog/git-leaks扫描Git历史 3) 提取凭证后尝试登录数据库/API/云服务",
                "WEAK_CRYPTO": "利用方法: 1) 使用在线彩虹表破解哈希 2) 使用hashcat暴力破解弱哈希 3) 使用已知明文攻击破解DES加密",
                "CSRF": "利用方法: 1) 构造恶意HTML页面包含隐藏表单自动提交 2) 使用img标签触发GET请求 3) 结合XSS绕过CSRF Token",
                "LDAP_INJECTION": "利用方法: 1) 在用户名中注入通配符绕过认证 2) 使用逻辑运算符构造永真条件 3) 注入objectClass遍历目录",
                "XXE": "利用方法: 1) 在XML中定义外部实体引用读取本地文件 2) 使用外部实体发起SSRF攻击 3) Billion Laughs攻击导致DoS",
                "RATE_LIMIT": "利用方法: 1) 使用Burp Intruder/Hydra进行密码爆破 2) 使用Python脚本循环请求短信接口 3) 使用slowloris工具发起慢速DoS攻击",
                "AUTH_BYPASS": "利用方法: 1) 修改JWT Header中alg为none并删除签名 2) 删除请求中的Authorization头测试默认行为 3) 使用默认凭证尝试登录",
            }

            matched_exploit = ""
            for keyword, guide in exploit_guides.items():
                if keyword in rule_id.upper() or keyword in rule_name.upper():
                    matched_exploit = guide
                    break

            if matched_exploit:
                exploit_section = f"\n【利用方法】{matched_exploit}"

        file_display = Path(location_file).name if location_file else '未知文件'
        location_str = f"{file_display}:{location_line}" if location_line > 0 else file_display

        enhanced_parts = [
            f"【问题类型】{issue_type}",
            f"【受影响位置】{location_str}",
            f"【风险说明】{risk_desc}",
        ]

        if exploit_section:
            enhanced_parts.append(exploit_section)

        if original_desc and original_desc not in [rule_name, rule_id] and original_desc not in risk_desc:
            enhanced_parts.append(f"【详细说明】{original_desc}")

        confidence = getattr(finding, 'confidence', 0)
        if confidence > 0:
            enhanced_parts.append(f"【置信度】{confidence:.0%}")

        evidence = metadata.get('evidence', []) if isinstance(metadata, dict) else []
        if evidence:
            enhanced_parts.append(f"【证据数量】{len(evidence)} 条")

        return '\n'.join(enhanced_parts)

    def _extract_code_context_from_file(self, finding: Any, context_lines: int = 5) -> Optional[dict]:
        """从文件中提取漏洞代码上下文（前后N行）

        提取范围：漏洞行前后各5行代码，包含行号信息和漏洞行高亮标记。

        Args:
            finding: 发现对象
            context_lines: 上下文行数（默认5行）

        Returns:
            包含以下字段的字典：
            - context_before: 漏洞行之前的代码行列表
            - vulnerable_line: 漏洞行代码
            - context_after: 漏洞行之后的代码行列表
            - line_number: 漏洞行号
            - file_path: 文件路径
            - total_lines: 文件总行数
            - highlighted_vulnerable_line: 带高亮标记的漏洞行（用于模板渲染）
            如果无法读取文件则返回 None
        """
        loc = getattr(finding, 'location', None)
        if not loc:
            return None

        if hasattr(loc, 'file'):
            file_path = loc.file
        elif isinstance(loc, dict):
            file_path = loc.get('file')
        else:
            file_path = str(loc)

        if not file_path or not Path(str(file_path)).exists():
            return None

        target_line = 0
        if hasattr(loc, 'line'):
            target_line = loc.line
        elif isinstance(loc, dict):
            target_line = loc.get('line', 0)

        if target_line <= 0:
            return None

        try:
            file_path_str = str(file_path)
            with open(file_path_str, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()

            total_lines = len(all_lines)
            if target_line > total_lines:
                return None

            start_idx = max(0, target_line - context_lines - 1)
            end_idx = min(total_lines, target_line + context_lines)

            context_before = []
            for i in range(start_idx, target_line - 1):
                context_before.append({
                    'line_number': i + 1,
                    'content': all_lines[i].rstrip('\n\r'),
                })

            vulnerable_line_content = all_lines[target_line - 1].rstrip('\n\r') if target_line <= total_lines else ''
            
            context_after = []
            for i in range(target_line, end_idx):
                context_after.append({
                    'line_number': i + 1,
                    'content': all_lines[i].rstrip('\n\r'),
                })

            return {
                'context_before': context_before,
                'vulnerable_line': vulnerable_line_content,
                'context_after': context_after,
                'line_number': target_line,
                'file_path': file_path_str,
                'total_lines': total_lines,
                'highlighted_vulnerable_line': f'[VULN] {vulnerable_line_content}',
            }
        except Exception:
            return None

    def _generate_enhanced_recommendation(self, finding: Dict) -> Dict:
        """生成增强版修复建议（带具体代码示例）

        根据漏洞类型生成针对性的修复建议，包含：
        - 文字说明
        - 修复前代码示例（标注问题）
        - 修复后代码示例（标注修复方法）
        - 参考资料链接
        - 修复优先级

        Args:
            finding: 处理后的发现字典

        Returns:
            增强版修复建议字典
        """

        
        # finding 是字典，使用 .get() 而不是 getattr()
        severity = finding.get('severity', '') if isinstance(finding, dict) else getattr(finding, 'severity', '')
        severity_str = (severity.value if hasattr(severity, 'value') else str(severity)).upper()
        vuln_type = finding.get('rule_id', '') if isinstance(finding, dict) else getattr(finding, 'rule_id', '') or ''
        rule_name = finding.get('rule_name', '') if isinstance(finding, dict) else getattr(finding, 'rule_name', '') or ''
        metadata = finding.get('metadata', {}) if isinstance(finding, dict) else getattr(finding, 'metadata', {}) or {}
        if isinstance(metadata, dict):
            vuln_type = metadata.get('vuln_type', vuln_type)
        if not vuln_type or len(vuln_type) < 3:
            vuln_type = rule_name



        fix_suggestion = getattr(finding, 'fix_suggestion', '') or getattr(finding, 'remediation', '') or '进行安全修复'

        rec = {
            'recommendation': fix_suggestion,
            'code_example_before': '',
            'code_example_after': '',
            'reference': '',
            'priority': 'urgent' if severity_str in ('CRITICAL',) else 'high' if severity_str in ('HIGH',) else 'medium' if severity_str in ('MEDIUM',) else 'low',
            'fix_steps': [],
        }

        vuln_lower = (vuln_type + ' ' + rule_name).lower()
        
        # 中文漏洞类型到英文关键词的映射扩展
        cn_to_en_map = {
            # SQL注入类
            'sql注入': 'sql', 'sql注入风险': 'sql', 'mybatis': 'mybatis',
            # 敏感信息泄露
            '硬编码': 'password', '密码': 'password', '密钥': 'secret', '敏感字段': 'secret',
            'api密钥': 'secret', 'api_key': 'secret',
            # 命令注入
            '命令注入': 'exec', '命令执行': 'exec', '远程命令': 'exec', 'rce': 'exec',
            # XSS
            'xss': 'xss', '跨站脚本': 'xss', '反射型xss': 'xss', '存储型xss': 'xss',
            # 路径穿越
            '路径穿越': 'path', '路径遍历': 'path', '目录遍历': 'path', '任意文件': 'path',
            '文件上传': 'path', '文件读取': 'path', '任意文件上传': 'path',
            # 反序列化
            '反序列化': 'deserializ', '不安全反序列化': 'deserializ', 'java反序列化': 'deserializ',
            'fastjson': 'deserializ', 'jackson': 'deserializ', 'objectinputstream': 'deserializ',
            # SSRF
            'ssrf': 'ssrf', '服务端请求伪造': 'ssrf',
            # 加密/哈希
            '弱加密': 'crypto', '弱哈希': 'crypto', 'md5': 'crypto', 'sha1': 'crypto',
            'des': 'crypto', '3des': 'crypto', '填充模式不安全': 'crypto',
            '不安全随机': 'crypto', '弱随机': 'crypto', '加密算法': 'crypto',
            '算法未白名单': 'crypto',
            # CSRF
            'csrf': 'csrf', '跨站请求伪造': 'csrf',
            # LDAP注入
            'ldap': 'ldap',
            # XXE
            'xxe': 'xxe', 'xml外部实体': 'xxe', 'xml注入': 'xxe',
            # 重定向
            '重定向': 'redirect', '开放重定向': 'redirect', '未验证重定向': 'redirect',
            '跳转': 'redirect',
            # Actuator/端点
            'actuator': 'actuator', '端点暴露': 'actuator', '管理端点': 'endpoint',
            # 授权/认证
            '未授权': 'auth', '未授权访问': 'auth', '越权': 'auth', '权限': 'permission',
            '认证': 'auth', '绕过认证': 'auth', '租户上下文篡改': 'auth',
            '不安全的直接对象引用': 'auth', 'idor': 'auth',
            # Redis
            'redis': 'redis', '阻塞': 'redis', 'keys命令': 'redis',
            # Token/JWT
            'token': 'token', 'jwt': 'token', '令牌': 'token',
            # 输入验证
            '输入验证': 'input_validation', '输入验证缺失': 'input_validation',
            '未校验': 'input_validation', '金额未校验': 'input_validation',
            '属性注入': 'mass_assignment', 'mass assignment': 'mass_assignment',
            # 异常处理
            '异常处理': 'exception', '异常处理不当': 'exception', '敏感异常': 'exception',
            # 业务逻辑
            '业务逻辑': 'business_logic', '业务逻辑缺陷': 'business_logic',
        }
        
        # 将中文漏洞类型映射为英文关键词，追加到 vuln_lower
        extra_keywords = []
        for cn_key, en_val in cn_to_en_map.items():
            if cn_key in vuln_lower:
                extra_keywords.append(en_val)
        if extra_keywords:
            vuln_lower = vuln_lower + ' ' + ' '.join(extra_keywords)
        


        if 'mybatis' in vuln_lower or 'sql' in vuln_lower:
            rec['code_example_before'] = '''@Select("SELECT * FROM users WHERE id = ${id}")
public User getUserById(String id);  // 危险: 使用${}直接拼接SQL参数'''
            rec['code_example_after'] = '''@Select("SELECT * FROM users WHERE id = #{id}")
public User getUserById(String id);  // 安全: 使用#{}预编译参数，防止SQL注入'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '将 ${} 替换为 #{} 使用预编译参数',
                '避免使用 ${table} 动态表名，改用白名单验证',
                '对排序字段使用 MyBatis 的 <choose> 标签',
            ]
        elif 'password' in vuln_lower or 'secret' in vuln_lower:
            rec['code_example_before'] = '''// application.properties
spring.datasource.password=hardcoded_secret_123  // 危险: 硬编码密钥

// 或 Java 代码中
String apiKey = "sk-1234567890abcdef";  // 危险: 硬编码API密钥'''
            rec['code_example_after'] = '''// application.properties
spring.datasource.password=${DB_PASSWORD}  // 安全: 从环境变量读取

// 或 Java 代码中
String apiKey = System.getenv("API_KEY");  // 安全: 使用环境变量'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '移除所有硬编码的密码和密钥',
                '使用环境变量或密钥管理服务(如Vault、AWS Secrets Manager)',
                '启用密钥轮换策略',
                '使用 @Value("${DB_PASSWORD}") 或 @ConfigurationProperties 注入',
            ]
        elif 'exec' in vuln_lower or 'command' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 直接拼接用户输入到系统命令
Process process = Runtime.getRuntime().exec("cmd /c " + userInput);'''
            rec['code_example_after'] = '''// 安全: 使用 ProcessBuilder 参数化命令
ProcessBuilder pb = new ProcessBuilder("cmd", "/c", userInput);
pb.redirectErrorStream(true);
Process process = pb.start();'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '避免使用 Runtime.exec(String)，改用 ProcessBuilder',
                '使用参数化命令，将命令和参数分开',
                '对用户输入进行白名单验证',
                '使用 SecurityManager 限制命令执行权限',
            ]
        elif 'xss' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 直接输出用户输入到HTML
response.getWriter().println("<div>" + userInput + "</div>");

// 或在 JSP 中
<%= request.getParameter("name") %>'''
            rec['code_example_after'] = '''// 安全: 使用 HTML 转义
response.getWriter().println("<div>" + Encode.forHtml(userInput) + "</div>");

// 或在 JSP 中使用 JSTL
<c:out value="${param.name}" />'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '使用 OWASP Java Encoder 进行HTML转义',
                '在 JSP 中使用 <c:out> 代替 <%= %>',
                '对属性值使用 Encode.forHtmlAttribute()',
                '对URL使用 Encode.forUriComponent()',
            ]
        elif 'path' in vuln_lower or 'traversal' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 直接拼接用户输入到文件路径
File file = new File(baseDir + "/" + userInput);
InputStream is = new FileInputStream(file);'''
            rec['code_example_after'] = '''// 安全: 规范化路径并验证
File file = new File(baseDir, userInput).getCanonicalFile();
if (!file.getPath().startsWith(new File(baseDir).getCanonicalPath())) {
    throw new SecurityException("非法路径访问");
}
InputStream is = new FileInputStream(file);'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '使用 getCanonicalFile() 规范化路径',
                '验证规范化后的路径是否在允许的目录内',
                '使用白名单限制可访问的文件类型',
                '避免使用用户输入直接构造文件路径',
            ]
        elif 'deserializ' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 直接反序列化不可信数据
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();'''
            rec['code_example_after'] = '''// 安全: 使用白名单验证反序列化
ObjectInputStream ois = new ValidatingObjectInputStream(inputStream);
ois.accept(MySafeClass.class, AnotherSafeClass.class);
Object obj = ois.readObject();'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '使用 ValidatingObjectInputStream 进行白名单验证',
                '考虑使用 JSON/XML 等安全序列化格式',
                '实现 readObject() 方法进行输入验证',
                '使用 SerialKiller 或 NotSoSerial 等安全库',
            ]
        elif 'ssrf' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 未验证用户提供的URL
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();'''
            rec['code_example_after'] = '''// 安全: 验证URL白名单
if (!isAllowedUrl(userInput)) {
    throw new SecurityException("不允许访问该URL");
}
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '实现URL白名单验证',
                '阻止访问内网IP(127.0.0.1, 10.x, 192.168.x等)',
                '使用 HttpURLConnection.setFollowRedirects(false)',
                '限制允许的协议仅为 http/https',
            ]
        elif 'crypto' in vuln_lower or 'cipher' in vuln_lower or 'weak' in vuln_lower:
            rec['code_example_before'] = '''// 不安全：使用已被破解的弱算法
MessageDigest md = MessageDigest.getInstance("MD5");
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
// 无算法校验，允许任意 algorithm 参数'''
            rec['code_example_after'] = '''// 安全：使用 BCrypt（密码存储，至少 12 轮）
String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));

// 安全：使用 PBKDF2WithHmacSHA256（密码存储）
SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
SecretKey key = factory.generateSecret(spec);

// 安全：使用 AES-256-GCM（数据加密，必须配合随机 IV）
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

// 安全：在 encrypt/decrypt 方法中校验算法
private static final Set<String> BLOCKED = Set.of(
    "DES/ECB/PKCS5Padding", "AES/ECB/PKCS5Padding", "RC4", "MD5", "SHA1"
);'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '在 encrypt/decrypt 方法中增加算法白名单校验，拒绝不安全算法',
                '密码存储使用 BCrypt/PBKDF2/Argon2（至少 12 轮）',
                '数据加密使用 AES-256-GCM（必须配合随机 IV/nonce）',
                '密钥长度要求：AES ≥ 256 位、RSA ≥ 2048 位、ECC ≥ 256 位',
                '避免使用 MD5/SHA1/DES/3DES/RC4/AES-ECB',
                '定期更新加密算法和密钥轮换策略',
            ]
        elif 'csrf' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 无CSRF保护的POST端点
@PostMapping("/transfer")
public void transferMoney(@RequestParam String to, @RequestParam double amount) {
    // 处理转账
}'''
            rec['code_example_after'] = '''// 安全: 启用CSRF保护(Spring Security默认已开启)
@PostMapping("/transfer")
public void transferMoney(@RequestParam String to, @RequestParam double amount) {
    // 处理转账
}

// 确保 Spring Security 配置中启用 CSRF
http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '确保 Spring Security CSRF 保护已启用',
                '使用 Synchronizer Token Pattern',
                '对敏感操作添加 Double Submit Cookie',
                '验证 Referer/Origin 头',
            ]
        elif 'ldap' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 直接拼接用户输入到LDAP查询
String filter = "(uid=" + userInput + ")";
NamingEnumeration results = ctx.search(baseDN, filter);'''
            rec['code_example_after'] = '''// 安全: 使用LDAP转义
String escapedInput = StringEscapeUtils.escapeLdap(userInput);
String filter = "(uid=" + escapedInput + ")";
NamingEnumeration results = ctx.search(baseDN, filter);'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '使用 Apache Commons Text 的 StringEscapeUtils.escapeLdap()',
                '对用户输入进行LDAP元字符转义',
                '使用参数化LDAP查询',
                '实施最小权限LDAP绑定',
            ]
        elif 'xxe' in vuln_lower or 'xml' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 未禁用XXE的XML解析
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlInput)));'''
            rec['code_example_after'] = '''// 安全: 禁用XXE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder db = dbf.newDocumentBuilder();'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '启用 FEATURE_SECURE_PROCESSING',
                '禁用 DOCTYPE 声明',
                '禁用外部实体解析',
                '考虑使用 JSON 替代 XML',
            ]
        elif 'redirect' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 未验证的重定向
String url = request.getParameter("url");
response.sendRedirect(url);  // 攻击者可构造恶意重定向到钓鱼网站'''
            rec['code_example_after'] = '''// 安全: 验证重定向URL
String url = request.getParameter("url");
if (isAllowedRedirectUrl(url)) {
    response.sendRedirect(url);
} else {
    response.sendRedirect("/default");
}'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '实现URL白名单验证',
                '使用间接引用映射(如redirect_id=1映射到真实URL)',
                '避免直接将用户输入传递给重定向函数',
                '在安全注解中记录重定向验证逻辑',
            ]
        elif 'actuator' in vuln_lower or '端点暴露' in vuln_lower or 'endpoint' in vuln_lower:
            rec['code_example_before'] = '''// application.properties
# 危险: 暴露所有 Actuator 端点
management.endpoints.web.exposure.include=*
management.endpoint.health.show-details=always'''
            rec['code_example_after'] = '''// application.properties
# 安全: 仅暴露必要的端点
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=when_authorized
# 添加访问控制
spring.security.enabled=true'''
            rec['reference'] = 'https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security'
            rec['fix_steps'] = [
                '仅暴露必要的 Actuator 端点(如 health, info)',
                '禁止使用 * 暴露所有端点',
                '为敏感端点(如 env, beans)配置访问控制',
                '使用 Spring Security 保护 Actuator 端点',
                '禁用生产环境不必要的端点',
            ]
        elif '授权' in vuln_lower or 'auth' in vuln_lower or 'permission' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 缺少授权检查的端点
@GetMapping("/admin/users")
public List<User> getAllUsers() {
    return userService.findAll();  // 任何用户都可访问
}'''
            rec['code_example_after'] = '''// 安全: 添加授权注解
@GetMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public List<User> getAllUsers() {
    return userService.findAll();
}

// 或在 Spring Security 配置中
http.authorizeRequests()
    .antMatchers("/admin/**").hasRole("ADMIN");'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '在所有敏感端点添加 @PreAuthorize 或 @Secured 注解',
                '配置 Spring Security 的 URL 级别访问控制',
                '实现基于角色的访问控制(RBAC)',
                '对方法级别添加权限验证',
                '记录未授权访问尝试的日志',
            ]
        elif 'redis' in vuln_lower or 'keys' in vuln_lower or '阻塞' in vuln_lower:
            rec['code_example_before'] = '''// 危险: 在 Redis 中使用阻塞命令
Jedis jedis = pool.getResource();
jedis.keys("*");  // 危险: 在大数据集上阻塞Redis
jedis.flushall();  // 危险: 清空所有数据'''
            rec['code_example_after'] = '''// 安全: 使用 SCAN 代替 KEYS
Jedis jedis = pool.getResource();
String cursor = ScanParams.SCAN_POINTER_START;
ScanParams params = new ScanParams().match("prefix:*").count(100);
do {
    ScanResult<String> result = jedis.scan(cursor, params);
    cursor = result.getCursor();
    for (String key : result.getResult()) {
        // 处理key
    }
} while (!cursor.equals(ScanParams.SCAN_POINTER_START));'''
            rec['reference'] = 'https://redis.io/commands/scan/'
            rec['fix_steps'] = [
                '使用 SCAN 命令代替 KEYS 命令',
                '避免在生产环境使用 FLUSHALL/FLUSHDB',
                '对 Redis 操作设置超时时间',
                '使用连接池管理 Redis 连接',
                '监控 Redis 慢查询日志',
            ]
        elif 'token' in vuln_lower or '令牌' in vuln_lower:
            rec['code_example_before'] = '''// 危险: JWT Token 安全缺陷
String token = Jwts.builder()
    .setSubject(username)
    .signWith(SignatureAlgorithm.HS256, "secret")  // 危险: 弱密钥
    .compact();  // 危险: 无过期时间

// 或验证时
Jwts.parser().setSigningKey("secret").parseClaimsJws(token);'''
            rec['code_example_after'] = '''// 安全: 正确的 JWT 实现
String token = Jwts.builder()
    .setSubject(username)
    .setIssuedAt(new Date())
    .setExpiration(new Date(System.currentTimeMillis() + 3600000))  // 1小时过期
    .signWith(SignatureAlgorithm.RS256, privateKey)  // 使用非对称加密
    .compact();

// 验证时
Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html'
            rec['fix_steps'] = [
                '使用强密钥(至少256位)或非对称加密(RS256)',
                '设置合理的 Token 过期时间',
                '在 Token 中包含 issuedAt 和 expiration 声明',
                '使用 HTTPS 传输 Token',
                '实现 Token 黑名单机制以支持注销',
                '不要在 Token 中存储敏感信息',
            ]
        else:
            rec['code_example_before'] = f'''// 当前代码存在 {vuln_type or "安全"} 风险
// 请检查以下安全点:
// 1. 输入验证和输出编码
// 2. 身份认证和授权
// 3. 敏感数据保护'''
            rec['code_example_after'] = '''// 建议: 
// 1. 添加输入验证(白名单验证)
// 2. 使用参数化查询/命令
// 3. 实施最小权限原则
// 4. 记录安全日志'''
            rec['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'
            rec['fix_steps'] = [
                '审查代码中的输入验证逻辑',
                '使用参数化查询防止注入',
                '实施最小权限原则',
                '添加安全日志和监控',
            ]

        return rec

    def _extract_exploit_path(self, finding: Dict) -> List[Dict]:
        """提取漏洞利用路径（数据流路径）

        从发现的元数据中提取入口点 → 处理 → 受影响资源 的数据流路径。

        Args:
            finding: 处理后的发现字典

        Returns:
            路径步骤列表，每项包含 {label, file, line, role}
            role: 'entry' | 'process' | 'sink'
        """
        if not isinstance(finding, dict):
            return []

        metadata = finding.get('metadata', {}) or {}
        path_steps = []

        # 1. 检查是否已有明确的 exploit_path / data_flow_path
        exploit_path = metadata.get('exploit_path') or metadata.get('data_flow_path')
        if exploit_path and isinstance(exploit_path, list):
            for step in exploit_path:
                if isinstance(step, dict):
                    path_steps.append({
                        'label': step.get('label', step.get('description', '')),
                        'file': step.get('file', ''),
                        'line': step.get('line', 0),
                        'role': step.get('role', 'process'),
                    })
            if path_steps:
                return path_steps

        # 2. 从 evidence 中提取路径
        evidence = metadata.get('evidence', []) or []
        if evidence and isinstance(evidence, list):
            for i, ev in enumerate(evidence):
                if isinstance(ev, dict):
                    ev_location = ev.get('location', ev.get('file', ''))
                    ev_line = ev.get('line', 0)
                    ev_reason = ev.get('reason', ev.get('description', ''))

                    role = 'process'
                    if i == 0:
                        role = 'entry'
                    elif i == len(evidence) - 1:
                        role = 'sink'

                    path_steps.append({
                        'label': ev_reason if ev_reason else f'步骤 {i+1}',
                        'file': ev_location,
                        'line': ev_line,
                        'role': role,
                    })

        # 3. 从 chain 中提取路径
        chain = finding.get('chain', [])
        if chain and not path_steps:
            for i, step in enumerate(chain):
                if isinstance(step, dict):
                    role = 'process'
                    if i == 0:
                        role = 'entry'
                    elif i == len(chain) - 1:
                        role = 'sink'
                    path_steps.append({
                        'label': step.get('description', ''),
                        'file': step.get('file_path', ''),
                        'line': step.get('line', 0),
                        'role': role,
                    })

        # 4. 回退：基于 finding 自身位置构建简单路径
        if not path_steps:
            loc = finding.get('location', {}) or {}
            file_path = loc.get('file', '')
            line_num = loc.get('line', 0)
            rule_name = finding.get('rule_name', '')
            severity = finding.get('severity', 'medium')

            # 根据严重性判断是否可被利用
            is_exploitable = str(severity).lower() in ('critical', 'high')

            if is_exploitable:
                path_steps = [
                    {'label': '外部输入', 'file': '', 'line': 0, 'role': 'entry'},
                    {'label': rule_name, 'file': file_path, 'line': line_num, 'role': 'process'},
                    {'label': '受影响资源', 'file': file_path, 'line': line_num, 'role': 'sink'},
                ]
            elif file_path:
                path_steps = [
                    {'label': '入口点', 'file': '', 'line': 0, 'role': 'entry'},
                    {'label': rule_name, 'file': file_path, 'line': line_num, 'role': 'sink'},
                ]

        return path_steps


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
                        location_str = f"{finding.location} [OK]"
                    elif match_status == LineMatchStatus.ADJUSTED.value and verified_line > 0 and ai_reported_line > 0:
                        location_str = f"{finding.location} (已校正，原报告: {ai_reported_line})"
                    elif match_status == LineMatchStatus.UNVERIFIED.value:
                        location_str = f"{finding.location} [WARN] [未验证]"
                except Exception:
                    location_str = f"{finding.location} [WARN] [验证失败]"
        
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
        
        mitigation_md = ""
        if metadata and isinstance(metadata, dict):
            fw_mitigation = self._build_framework_mitigation_info(finding, metadata)
            if fw_mitigation and fw_mitigation.get("has_mitigation"):
                mitigation_md = "\n**【框架缓解措施】**\n"
                if fw_mitigation.get("security_annotations"):
                    mitigation_md += f"- 检测到安全注解: {', '.join(fw_mitigation['security_annotations'])}\n"
                if fw_mitigation.get("mitigation_description"):
                    mitigation_md += f"- 缓解说明: {fw_mitigation['mitigation_description']}\n"
                if fw_mitigation.get("severity_downgraded"):
                    mitigation_md += f"- 严重级别已调整: {fw_mitigation['original_severity'].upper()} → {fw_mitigation['mitigated_severity'].upper()}\n"
                if fw_mitigation.get("attack_difficulty_score", 0) > 0:
                    mitigation_md += f"- 攻击难度评分: {fw_mitigation['attack_difficulty_score']:.2f} (0=易, 1=难)\n"
                if fw_mitigation.get("protection_layers", 0) > 0:
                    mitigation_md += f"- 保护层数: {fw_mitigation['protection_layers']}\n"
        
        return f"""
### {finding.rule_name} ({finding.rule_id})

- **严重级别**: {severity}
- **来源**: {source}
- **位置**: {location_str}
- **描述**: {finding.message}
- **置信度**: {finding.confidence}
{code_md}
{poc_md}
{mitigation_md}
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
        self.confidence_threshold = 0.60
        if hasattr(self.config, 'get'):
            self.confidence_threshold = self.config.get('confidence_threshold', 0.60)
        elif hasattr(self.config, 'confidence_threshold'):
            self.confidence_threshold = getattr(self.config, 'confidence_threshold', 0.60)

    def generate(
        self,
        results: Union[List[ScanResult], ScanResult],
        output_path: str,
        format: Optional[str] = None,
    ) -> str:
        """生成报告

        Args:
            results: 扫描结果列表或单个ScanResult对象
            output_path: 输出路径
            format: 报告格式，如果为 None 则使用配置中的格式

        Returns:
            报告文件路径
        """
        # 支持单个ScanResult对象，自动包装为列表
        if isinstance(results, ScanResult):
            results = [results]
        elif not isinstance(results, list):
            # 尝试转换为列表
            results = [results]

        fmt = format or self.config.report.format

        generator_class = self._generators.get(fmt)
        if not generator_class:
            raise ValueError(f"不支持的报告格式: {fmt}")

        generator = generator_class(self.config)
        generator.confidence_threshold = self.confidence_threshold

        filtered_results = self._filter_findings_by_confidence(results)
        self._filtered_count = len([
            f for r in results for f in r.findings
        ]) - len([
            f for r in filtered_results for f in r.findings
        ])

        return generator.generate(filtered_results, output_path)

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

    def _filter_findings_by_confidence(self, results: List[ScanResult]) -> List[ScanResult]:
        """按置信度过滤发现

        过滤掉置信度低于阈值的发现，但保护高原始置信度不被框架缓解逻辑错误降级。
        当漏洞定位行号为 0 或无效时，大幅降低置信度并过滤不显示。

        Args:
            results: 扫描结果列表

        Returns:
            过滤后的扫描结果列表
        """
        filtered_results = []
        
        for result in results:
            filtered_findings = []
            
            for finding in result.findings:
                confidence = getattr(finding, 'confidence', 0)
                metadata = getattr(finding, 'metadata', {}) or {}
                
                original_confidence = metadata.get('original_confidence', confidence)
                
                location_line = 0
                if hasattr(finding, 'location'):
                    location_line = getattr(finding.location, 'line', 0) or 0
                
                if location_line <= 0:
                    confidence = min(confidence, 0.1)
                    finding.confidence = confidence
                    if 'metadata' not in finding.__dict__:
                        finding.metadata = metadata
                    finding.metadata['line_number_invalid'] = True
                    finding.metadata['confidence_penalized'] = True
                    # 行号未定位的低置信度发现直接过滤掉，不显示在报告中
                    if confidence >= self.confidence_threshold and original_confidence >= self.confidence_threshold:
                        filtered_findings.append(finding)
                    continue
                
                if confidence < self.confidence_threshold:
                    if original_confidence >= self.confidence_threshold:
                        finding.confidence = original_confidence
                        filtered_findings.append(finding)
                else:
                    filtered_findings.append(finding)
            
            from copy import deepcopy
            filtered_result = deepcopy(result)
            filtered_result.findings = filtered_findings
            filtered_results.append(filtered_result)
        
        return filtered_results

    def list_formats(self) -> List[str]:
        """列出支持的格式"""
        return list(self._generators.keys())
