"""漏洞发现处理模块

提供去重、合并、保护验证源和格式转换功能。
从 scanner.py 中提取，供 SecurityScanner 调用。
"""

from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


def deduplicate_findings(findings: List) -> List:
    """去重发现的问题

    基于 (rule_id, file_path, line_number, code_snippet) 进行去重

    Args:
        findings: 发现的问题列表

    Returns:
        去重后的问题列表
    """
    seen = set()
    unique_findings = []

    for finding in findings:
        file_path = getattr(finding.location, "file", "")
        line = getattr(finding.location, "line", 0)
        rule_id = finding.rule_id
        code_snippet = finding.code_snippet[:50] if finding.code_snippet else ""

        key = (rule_id, file_path, line, code_snippet)

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings


def merge_duplicate_findings(findings: List) -> List:
    """合并重复发现，相同规则ID和文件优先使用更高级别

    Args:
        findings: 发现的问题列表

    Returns:
        合并后的问题列表
    """
    seen = {}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def get_severity_level(severity):
        if hasattr(severity, "value"):
            sev_str = severity.value.lower()
        elif hasattr(severity, "name"):
            sev_str = severity.name.lower()
        else:
            sev_str = str(severity).lower()
        return severity_order.get(sev_str, 999)

    def get_metadata(finding) -> dict:
        metadata = getattr(finding, "metadata", None)
        if metadata is None:
            return {}
        if isinstance(metadata, dict):
            return metadata
        return {}

    for finding in findings:
        rule_id = finding.rule_id
        file_path = (
            getattr(finding.location, "file", "") if hasattr(finding, "location") else ""
        )
        key = (rule_id, file_path)

        current_level = get_severity_level(finding.severity)
        metadata = get_metadata(finding)
        is_verified = metadata.get("verified", False)

        if key not in seen:
            seen[key] = (finding, current_level)
        else:
            existing_finding, existing_level = seen[key]
            existing_metadata = get_metadata(existing_finding)
            existing_verified = existing_metadata.get("verified", False)

            if is_verified and not existing_verified:
                seen[key] = (finding, current_level)
            elif is_verified == existing_verified:
                if current_level < existing_level:
                    seen[key] = (finding, current_level)

    return [f for f, _ in seen.values()]


def protect_verified_sources(findings: List) -> List:
    """保护已验证来源的发现不被覆盖

    config_scanner 和 code_vuln_scanner 的发现是已知的、可复现的安全风险。
    这些发现使用自己确定的严重级别，不应该被 AI 分析器的判定覆盖。

    Args:
        findings: 合并后的发现列表

    Returns:
        处理后的发现列表
    """
    verified_sources = {"config_scanner", "code_vuln_scanner"}
    verified_findings = {}

    def get_metadata_source(finding) -> str:
        metadata = getattr(finding, "metadata", None)
        if metadata is None:
            return ""
        if isinstance(metadata, dict):
            return str(metadata.get("source", ""))
        return ""

    def get_metadata(finding) -> dict:
        metadata = getattr(finding, "metadata", None)
        if metadata is None:
            return {}
        if isinstance(metadata, dict):
            return metadata
        return {}

    for f in findings:
        source = get_metadata_source(f)
        if source in verified_sources:
            key = (f.rule_id, getattr(f.location, "file", "") if hasattr(f, "location") else "")
            if key not in verified_findings:
                verified_findings[key] = f

    if not verified_findings:
        return findings

    result = []
    for f in findings:
        source = get_metadata_source(f)
        key = (f.rule_id, getattr(f.location, "file", "") if hasattr(f, "location") else "")

        if key in verified_findings and source not in verified_sources:
            result.append(verified_findings[key])
        else:
            result.append(f)

    return result


def convert_to_finding(issue) -> Optional[Any]:
    """将分析问题转换为标准 Finding 对象

    Args:
        issue: 分析问题对象

    Returns:
        标准 Finding 对象
    """
    try:
        from src.core.engine import Finding, Location, Severity

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        if hasattr(issue, "severity"):
            severity_str = getattr(issue, "severity", "medium").lower()
        elif isinstance(issue, dict) and "severity" in issue:
            severity_str = str(issue["severity"]).lower()
        else:
            severity_str = "medium"
        severity = severity_map.get(severity_str, Severity.MEDIUM)

        if hasattr(issue, "description"):
            description = getattr(issue, "description", "").strip()
        elif isinstance(issue, dict) and "description" in issue:
            description = str(issue["description"]).strip()
        else:
            description = ""

        if hasattr(issue, "rule_name"):
            rule_name = getattr(issue, "rule_name", "Unknown Issue").strip()
        elif isinstance(issue, dict) and "rule_name" in issue:
            rule_name = str(issue["rule_name"]).strip()
        else:
            if hasattr(issue, "rule_id"):
                rule_id = getattr(issue, "rule_id", "").strip()
            elif isinstance(issue, dict) and "rule_id" in issue:
                rule_id = str(issue["rule_id"]).strip()
            else:
                rule_id = ""

            rule_name_map = {
                "AST-DANGEROUS-FUNCTION": "危险函数调用",
                "AST-SENSITIVE-PARAM": "敏感参数缺少类型注解",
                "AST-MISSING-DOCSTRING": "函数缺少文档字符串",
                "AST-MISSING-CLASS-DOCSTRING": "类缺少文档字符串",
                "AST-WILDCARD-IMPORT": "通配符导入",
                "AST-DANGEROUS-MODULE": "危险模块导入",
                "AST-SENSITIVE-VARIABLE": "敏感变量定义",
                "AST-HARDCODED-SECRET": "硬编码敏感信息",
                "AST-CONSTANT-CONDITION": "常量条件",
                "AST-INFINITE-LOOP": "可能的无限循环",
                "AST-EMPTY-EXCEPT": "空的异常处理块",
                "AST-GENERIC-EXCEPTION": "通用异常",
                "AST-RETURN-SENSITIVE": "返回敏感信息",
                "AST-SQL-INJECTION": "SQL 注入风险",
                "AST-XSS": "XSS 风险",
                "AST-COMMAND-INJECTION": "命令注入风险",
                "AST-SENSITIVE-ATTRIBUTE": "类中存在敏感属性",
            }

            rule_name = rule_name_map.get(rule_id, "未知问题")

        if hasattr(issue, "code_snippet"):
            code_snippet = getattr(issue, "code_snippet", "").strip()
        elif isinstance(issue, dict) and "code_snippet" in issue:
            code_snippet = str(issue["code_snippet"]).strip()
        else:
            code_snippet = ""

        if hasattr(issue, "fix_suggestion"):
            fix_suggestion = getattr(issue, "fix_suggestion", "").strip()
        elif isinstance(issue, dict) and "fix_suggestion" in issue:
            fix_suggestion = str(issue["fix_suggestion"]).strip()
        else:
            fix_suggestion = ""

        if hasattr(issue, "location"):
            location_dict = issue.location if isinstance(issue.location, dict) else {}
        elif isinstance(issue, dict) and "location" in issue:
            location_dict = issue["location"] if isinstance(issue["location"], dict) else {}
        else:
            location_dict = {}

        if hasattr(issue, "file_path"):
            file_path = getattr(issue, "file_path", "")
        elif isinstance(issue, dict) and "file_path" in issue:
            file_path = issue["file_path"]
        elif "file" in location_dict:
            file_path = location_dict["file"]
        else:
            file_path = ""

        location = Location(
            file=file_path,
            line=location_dict.get("line", 0),
            column=location_dict.get("column", 0),
            end_line=location_dict.get("end_line", 0),
            end_column=location_dict.get("end_column", 0),
        )

        if hasattr(issue, "rule_id"):
            rule_id = getattr(issue, "rule_id", "UNKNOWN")
        elif isinstance(issue, dict) and "rule_id" in issue:
            rule_id = issue["rule_id"]
        else:
            rule_id = "UNKNOWN"

        if hasattr(issue, "confidence"):
            confidence = getattr(issue, "confidence", 0.5)
        elif isinstance(issue, dict) and "confidence" in issue:
            confidence = issue["confidence"]
        else:
            confidence = 0.5

        if hasattr(issue, "references"):
            references = getattr(issue, "references", [])
        elif isinstance(issue, dict) and "references" in issue:
            references = issue["references"]
        else:
            references = []

        metadata: dict = {}
        if hasattr(issue, "metadata"):
            metadata = getattr(issue, "metadata", {})
        elif isinstance(issue, dict) and "metadata" in issue:
            metadata = issue["metadata"]

        if hasattr(issue, "exploit_status"):
            metadata["exploit_status"] = getattr(issue, "exploit_status", "possible")
        elif isinstance(issue, dict) and "exploit_status" in issue:
            metadata["exploit_status"] = issue["exploit_status"]

        finding = Finding(
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            severity=severity,
            location=location,
            confidence=confidence,
            message=description,
            code_snippet=code_snippet,
            fix_suggestion=fix_suggestion,
            references=references,
            metadata=metadata,
        )

        return finding
    except Exception:
        return None
