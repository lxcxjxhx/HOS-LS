"""安全日志记录缺陷检测规则

基于 OWASP Top 10 2021 A09 - Security Logging Failures，检测安全事件日志记录的缺陷。
包括缺失安全事件日志、审计追踪不足和敏感数据泄露等问题。
"""

import re
from typing import Any, Dict, List, Optional, Union, Set
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class MissingSecurityEventLoggingRule(BaseRule):
    """A09-001: 缺失安全事件日志检测

    检测缺少安全事件日志记录的敏感操作，如登录、注销、权限变更等。

    OWASP Top 10 2021: A09:2021
    AISVS reference: v1.0-C8.1.1
    CWE: CWE-778 (Insufficient Logging)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="A09-001",
            name="Missing Security Event Logging",
            description="检测敏感操作缺少安全事件日志记录，包括登录、注销、权限变更、账户锁定等。参考: OWASP Top 10 2021 A09:2021",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-778",
            references=[
                "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                "https://cwe.mitre.org/data/definitions/778.html",
                "https://aisvs.owasp.org/",
            ],
            tags=["owasp", "logging", "security-events", "audit"],
            owasp_category="A09:2021",
        )
        super().__init__(metadata, config)

        self._sensitive_operations = [
            r"login\s*\(",
            r"logout\s*\(",
            r"sign_in\s*\(",
            r"sign_out\s*\(",
            r"authenticate\s*\(",
            r"change_password\s*\(",
            r"reset_password\s*\(",
            r"update_password\s*\(",
            r"change_email\s*\(",
            r"update_email\s*\(",
            r"change_phone\s*\(",
            r"update_phone\s*\(",
            r"delete_account\s*\(",
            r"remove_account\s*\(",
            r"activate_account\s*\(",
            r"deactivate_account\s*\(",
            r"lock_account\s*\(",
            r"unlock_account\s*\(",
            r"grant_permission\s*\(",
            r"revoke_permission\s*\(",
            r"add_role\s*\(",
            r"remove_role\s*\(",
            r"make_admin\s*\(",
            r"remove_admin\s*\(",
            r"session\.create",
            r"session\.destroy",
            r"session\.invalidate",
            r"token\.create",
            r"token\.revoke",
        ]

        self._logging_patterns = [
            r"log\.",
            r"logger\.",
            r"logging\.",
            r"audit",
            r"event\.log",
            r"security_log",
            r"log_event",
            r"record_event",
            r"write_log",
            r"log_handler",
            r"FileHandler",
            r"SysLogHandler",
            r"logging\.info",
            r"logging\.warning",
            r"logging\.error",
            r"logging\.critical",
        ]

        self._sensitive_operation_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._sensitive_operations
        ]
        self._logging_pattern = re.compile(
            r"|".join(self._logging_patterns), re.IGNORECASE
        )

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行缺失安全事件日志检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
        results = []

        if isinstance(target, Path):
            try:
                content = target.read_text(encoding="utf-8")
            except Exception:
                return results
            file_path = str(target)
        elif isinstance(target, str):
            content = target
            file_path = "<string>"
        elif isinstance(target, dict):
            content = target.get("content", "")
            file_path = target.get("file_path", "<unknown>")
        else:
            return results

        lines = content.split("\n")

        for pattern in self._sensitive_operation_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")

                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()

                if not self._has_logging(content, match.start(), match.end()):
                    result = RuleResult(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        passed=False,
                        message=f"检测到敏感操作缺少安全事件日志: {match.group()}",
                        severity=self.metadata.severity,
                        confidence=0.85,
                        location={
                            "file": file_path,
                            "line": line_num,
                            "column": col_num,
                        },
                        code_snippet=code_snippet,
                        fix_suggestion="在敏感操作前后添加安全事件日志记录，包括操作类型、执行用户、时间戳和结果。",
                        references=self.metadata.references,
                    )
                    results.append(result)

        return results

    def _has_logging(self, content: str, start: int, end: int) -> bool:
        """检查是否有日志记录

        Args:
            content: 文件内容
            start: 匹配开始位置
            end: 匹配结束位置

        Returns:
            是否有日志记录
        """
        context_window = 300
        search_start = max(0, start - context_window)
        search_end = min(len(content), end + context_window)
        context = content[search_start:search_end]

        if self._logging_pattern.search(context):
            return True

        return False


class InsufficientAuditTrailRule(BaseRule):
    """A09-002: 审计追踪不足检测

    检测缺少完整审计追踪的问题，包括日志不完整、缺少关键字段等。

    OWASP Top 10 2021: A09:2021
    CWE: CWE-779 (Insufficient Audit)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="A09-002",
            name="Insufficient Audit Trail",
            description="检测审计日志缺少必要字段或信息不完整，如缺少时间戳、用户ID、IP地址等关键信息。参考: OWASP Top 10 2021 A09:2021",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-779",
            references=[
                "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                "https://cwe.mitre.org/data/definitions/779.html",
            ],
            tags=["owasp", "audit", "logging", "traceability"],
            owasp_category="A09:2021",
        )
        super().__init__(metadata, config)

        self._incomplete_log_patterns = [
            (
                re.compile(
                    r"log\.(?:info|warning|error|debug)\s*\(\s*[\"'][^\"']*[\"']\s*\)",
                    re.IGNORECASE
                ),
                "日志记录缺少结构化字段（用户ID、时间戳、IP地址等）"
            ),
            (
                re.compile(
                    r"logger\.(?:info|warning|error|debug)\s*\(\s*[\"'][^\"']*[\"']\s*(?:,\s*\{[^}]*\})?\s*\)",
                    re.IGNORECASE
                ),
                "日志记录可能缺少关键审计字段"
            ),
        ]

        self._required_audit_fields = [
            r"timestamp",
            r"datetime",
            r"time\.time\(\)",
            r"date",
            r"user[_\[]i?[d]",
            r"user_id",
            r"username",
            r"ip",
            r"ip_address",
            r"request\.remote_addr",
            r"request\.ip",
            r"session[_\[]i?[d]",
            r"session_id",
            r"action",
            r"operation",
            r"event",
            r"result",
            r"status",
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行审计追踪不足检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
        results = []

        if isinstance(target, Path):
            try:
                content = target.read_text(encoding="utf-8")
            except Exception:
                return results
            file_path = str(target)
        elif isinstance(target, str):
            content = target
            file_path = "<string>"
        elif isinstance(target, dict):
            content = target.get("content", "")
            file_path = target.get("file_path", "<unknown>")
        else:
            return results

        lines = content.split("\n")

        for pattern, description in self._incomplete_log_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")

                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()

                if not self._has_required_fields(content, match.start(), match.end()):
                    result = RuleResult(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        passed=False,
                        message=f"检测到审计日志不完整: {description}",
                        severity=self.metadata.severity,
                        confidence=0.75,
                        location={
                            "file": file_path,
                            "line": line_num,
                            "column": col_num,
                        },
                        code_snippet=code_snippet,
                        fix_suggestion="确保审计日志包含所有必要字段：时间戳、用户ID、IP地址、会话ID、操作类型、操作结果等。",
                        references=self.metadata.references,
                    )
                    results.append(result)

        return results

    def _has_required_fields(self, content: str, start: int, end: int) -> bool:
        """检查是否有所需的审计字段

        Args:
            content: 文件内容
            start: 匹配开始位置
            end: 匹配结束位置

        Returns:
            是否有所需字段
        """
        context_window = 500
        search_start = max(0, start - context_window)
        search_end = min(len(content), end + context_window)
        context = content[search_start:search_end]

        found_fields = 0
        for field_pattern in self._required_audit_fields:
            if re.search(field_pattern, content, re.IGNORECASE):
                found_fields += 1

        return found_fields >= 3


class SensitiveDataInLogsRule(BaseRule):
    """A09-003: 敏感数据在日志中暴露检测

    检测将敏感数据写入日志的不安全行为，如密码、密钥、令牌、信用卡号等。

    OWASP Top 10 2021: A09:2021
    CWE: CWE-532 (Information Exposure Through Log)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="A09-003",
            name="Sensitive Data in Logs",
            description="检测敏感数据被写入日志的安全问题，包括密码、API密钥、令牌、信用卡号、社会安全号等。参考: OWASP Top 10 2021 A09:2021",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-532",
            references=[
                "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                "https://cwe.mitre.org/data/definitions/532.html",
            ],
            tags=["owasp", "logging", "sensitive-data", "pii"],
            owasp_category="A09:2021",
        )
        super().__init__(metadata, config)

        self._sensitive_data_patterns = [
            r"password",
            r"passwd",
            r"pwd",
            r"secret",
            r"api[_\s]?key",
            r"apikey",
            r"api_secret",
            r"access[_\s]?token",
            r"refresh[_\s]?token",
            r"auth[_\s]?token",
            r"bearer",
            r"authorization",
            r"credential",
            r"private[_\s]?key",
            r"social[_\s]?security",
            r"ssn",
            r"credit[_\s]?card",
            r"card[_\s]?number",
            r"cvv",
            r"pin",
            r"bank[_\s]?account",
            r"account[_\s]?number",
            r"routing[_\s]?number",
            r"tax[_\s]?id",
            r"passport",
            r"driver[_\s]?license",
            r"jwt",
            r"session[_\s]?key",
        ]

        self._logging_patterns = [
            r"log\.",
            r"logger\.",
            r"logging\.",
            r"print\s*\(",
            r"console\.log",
            r"syslog",
            r"audit",
            r"event\.log",
        ]

        self._dangerous_patterns = [
            (
                re.compile(
                    r"(?:" + "|".join(self._logging_patterns) + r")" +
                    r"[a-z]*\s*\([^)]*(?:" + "|".join(self._sensitive_data_patterns) + r")[^)]*\)",
                    re.IGNORECASE | re.DOTALL
                ),
                "日志记录包含敏感数据"
            ),
            (
                re.compile(
                    r"(?:log|logger|logging)\.(?:info|warn|error|debug|info|warning)\s*\(\s*f?[\"'][^\"']*" +
                    r"(?:" + "|".join(self._sensitive_data_patterns) + r")[^\"']*[\"']",
                    re.IGNORECASE
                ),
                "f-string/格式化字符串日志包含敏感数据"
            ),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行敏感数据在日志中暴露检测

        Args:
            target: 检查目标（文件路径、代码内容或 AST 节点）

        Returns:
            规则执行结果列表
        """
        results = []

        if isinstance(target, Path):
            try:
                content = target.read_text(encoding="utf-8")
            except Exception:
                return results
            file_path = str(target)
        elif isinstance(target, str):
            content = target
            file_path = "<string>"
        elif isinstance(target, dict):
            content = target.get("content", "")
            file_path = target.get("file_path", "<unknown>")
        else:
            return results

        lines = content.split("\n")

        for pattern, description in self._dangerous_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                col_num = match.start() - content[: match.start()].rfind("\n")

                if line_num <= len(lines):
                    code_snippet = lines[line_num - 1].strip()
                else:
                    code_snippet = match.group()

                result = RuleResult(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    passed=False,
                    message=f"检测到敏感数据在日志中暴露: {description}",
                    severity=self.metadata.severity,
                    confidence=0.9,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion="不要在日志中记录敏感数据。对必须记录的敏感数据进行脱敏处理（如只记录前三位后三位）。",
                    references=self.metadata.references,
                )
                results.append(result)

        return results


__all__ = [
    "MissingSecurityEventLoggingRule",
    "InsufficientAuditTrailRule",
    "SensitiveDataInLogsRule",
]