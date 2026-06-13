"""不安全设计检测规则

基于 OWASP Top 10 2021 A04 - Insecure Design，检测代码中潜在的不安全设计缺陷。
包括 IDOR、业务逻辑漏洞和竞态条件检测。
"""

import re
from typing import Any, Dict, List, Optional, Union, Set
from pathlib import Path

from src.rules.base import BaseRule, RuleCategory, RuleMetadata, RuleResult, RuleSeverity


class IDORRule(BaseRule):
    """A04-001: 不安全的直接对象引用 (IDOR) 检测

    检测缺少访问控制验证的直接对象引用，攻击者可能绕过授权访问其他用户资源。

    OWASP Top 10 2021: A04:2021
    AISVS reference: v1.0-C7.1.1
    CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="A04-001",
            name="Insecure Direct Object Reference (IDOR)",
            description="检测缺少访问控制验证的直接对象引用。攻击者可能通过修改 ID 参数访问其他用户的数据。参考: OWASP Top 10 2021 A04:2021",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-639",
            references=[
                "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                "https://cwe.mitre.org/data/definitions/639.html",
                "https://aisvs.owasp.org/",
            ],
            tags=["owasp", "idor", "access-control", "insecure-design"],
            owasp_category="A04:2021",
        )
        super().__init__(metadata, config)

        self._user_input_object_patterns = [
            r"request\.[a-zA-Z_]+",
            r"request\.args",
            r"request\.json",
            r"request\.form",
            r"request\.data",
            r"request\.values",
            r"params\[",
            r"args\[",
            r"form\[",
            r"json\[",
            r"body\[",
            r"query\[",
            r"sys\.argv",
            r"os\.environ",
            r"\b\w+_[iI]d\b",
            r"\buser_[a-zA-Z_]+\b",
            r"\bid\b",
            r"\buid\b",
            r"\b\w+_[iI]d\b",
        ]

        self._object_access_patterns = [
            r"\.get\s*\(",
            r"\.find\s*\(",
            r"\.filter\s*\(",
            r"\.query\s*\(",
            r"\.fetch\s*\(",
            r"\.select\s*\(",
            r"cursor\.execute",
            r"db\.find",
            r"db\.findOne",
            r"Model\.findById",
            r"Model\.findOne",
            r"collection\.find",
            r"collection\.findOne",
            r"table\.select",
            r"session\.get",
            r"cache\.get",
        ]

        self._auth_check_patterns = [
            r"is_authenticated",
            r"check_permission",
            r"verify_access",
            r"authorize",
            r"has_permission",
            r"check_ownership",
            r"verify_ownership",
            r"validate_access",
            r"can_access",
            r"check_authorization",
            r"@login_required",
            r"@require_auth",
            r"@authenticated",
            r"if\s+user\.id\s*==",
            r"if\s+user_id\s*==",
            r"if\s+request\.user",
        ]

        self._dangerous_patterns = [
            (
                re.compile(
                    r"(?:" + "|".join(self._user_input_object_patterns) + r")" +
                    r"(?:\s*,\s*" + "|".join(self._user_input_object_patterns) + r")*" +
                    r"\s*(?:=>|:|\))\s*(?:" + "|".join(self._object_access_patterns) + r")",
                    re.IGNORECASE
                ),
                "用户输入直接作为对象查询参数，无访问控制验证"
            ),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行 IDOR 检测

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

                if not self._has_authorization_check(content, match.start(), match.end()):
                    result = RuleResult(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        passed=False,
                        message=f"检测到潜在的 IDOR 漏洞: {description}",
                        severity=self.metadata.severity,
                        confidence=0.8,
                        location={
                            "file": file_path,
                            "line": line_num,
                            "column": col_num,
                        },
                        code_snippet=code_snippet,
                        fix_suggestion="在执行对象访问前添加访问控制验证，确保用户有权访问请求的资源。使用间接引用或服务端会话验证。",
                        references=self.metadata.references,
                    )
                    results.append(result)

        return results

    def _has_authorization_check(self, content: str, start: int, end: int) -> bool:
        """检查是否有授权检查

        Args:
            content: 文件内容
            start: 匹配开始位置
            end: 匹配结束位置

        Returns:
            是否有授权检查
        """
        context_window = 500
        search_start = max(0, start - context_window)
        search_end = min(len(content), end + context_window)
        context = content[search_start:search_end]

        for auth_pattern in self._auth_check_patterns:
            if re.search(auth_pattern, context, re.IGNORECASE):
                return True

        return False


class BusinessLogicFlawRule(BaseRule):
    """A04-002: 业务逻辑缺陷检测

    检测常见的业务逻辑安全缺陷，如越权操作、负值绕过、时间检验绕过等。

    OWASP Top 10 2021: A04:2021
    CWE: CWE-841 (Workflow Enforcement)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="A04-002",
            name="Business Logic Flaw",
            description="检测常见的业务逻辑安全缺陷，包括越权操作、价格/数量绕过、时间检验绕过等。参考: OWASP Top 10 2021 A04:2021",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-841",
            references=[
                "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                "https://cwe.mitre.org/data/definitions/841.html",
            ],
            tags=["owasp", "business-logic", "insecure-design"],
            owasp_category="A04:2021",
        )
        super().__init__(metadata, config)

        self._flaw_patterns = [
            (
                re.compile(
                    r"(?:price|amount|quantity|discount|coupon|rate|fee)\s*=\s*" +
                    r"(?:request\.[a-zA-Z_]+|params\[|args\[|form\[|json\[|[a-zA-Z_]+)",
                    re.IGNORECASE
                ),
                "业务关键字段直接使用用户输入"
            ),
            (
                re.compile(
                    r"if\s*\(\s*[a-zA-Z_]+\s*[<>]=\s*0\s*\)\s*\{?\s*return",
                    re.IGNORECASE
                ),
                "仅检验负值，缺少上限验证"
            ),
            (
                re.compile(
                    r"(?:discount|coupon|reward|points)\s*\.\s*apply" +
                    r"(?:(?!\.validate|\.check)[^;])*request",
                    re.IGNORECASE | re.DOTALL
                ),
                "优惠/积分应用缺少服务端验证"
            ),
            (
                re.compile(
                    r"timestamp\s*[<>]=\s*(?:time\.time\(\)|datetime\.now\(\))",
                    re.IGNORECASE
                ),
                "时间戳比较可能被客户端篡改"
            ),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行业务逻辑缺陷检测

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

        for pattern, description in self._flaw_patterns:
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
                    message=f"检测到潜在的业务逻辑缺陷: {description}",
                    severity=self.metadata.severity,
                    confidence=0.75,
                    location={
                        "file": file_path,
                        "line": line_num,
                        "column": col_num,
                    },
                    code_snippet=code_snippet,
                    fix_suggestion="在服务端实现完整的业务逻辑验证，确保关键操作在服务器端执行，不依赖客户端数据。",
                    references=self.metadata.references,
                )
                results.append(result)

        return results


class RaceConditionRule(BaseRule):
    """A04-003: 竞态条件检测

    检测可能导致竞态条件的并发访问模式，如检查时间到使用时间 (TOCTOU) 漏洞。

    OWASP Top 10 2021: A04:2021
    CWE: CWE-362 (Race Condition)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        metadata = RuleMetadata(
            id="A04-003",
            name="Race Condition (TOCTOU)",
            description="检测可能导致竞态条件的并发访问模式，包括检查时间到使用时间 (TOCTOU) 漏洞。参考: OWASP Top 10 2021 A04:2021",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.AI_SECURITY,
            language="*",
            version="1.0.0",
            author="HOS-LS Team",
            cwe="CWE-362",
            references=[
                "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                "https://cwe.mitre.org/data/definitions/362.html",
            ],
            tags=["owasp", "race-condition", "toctou", "insecure-design"],
            owasp_category="A04:2021",
        )
        super().__init__(metadata, config)

        self._toctou_patterns = [
            (
                re.compile(
                    r"(?:if|while|assert)\s*\([^)]*file_exists|os\.path\.exists|" +
                    r"is_file|is_dir|exists|stat|get_status",
                    re.IGNORECASE
                ),
                r"(?:open|read|write|execute|chmod|chown|delete|remove|unlink)\s*\(",
                "文件存在性检查与使用之间存在竞态窗口"
            ),
            (
                re.compile(
                    r"(?:if|while|assert)\s*\([^)]*lock|acquire|semaphore|mutex",
                    re.IGNORECASE
                ),
                r"(?:unlock|release|exit|return)\s*\(",
                "锁检查后释放前存在竞态窗口"
            ),
            (
                re.compile(
                    r"(?:balance|stock|quantity|count|available)\s*[<>]=",
                    re.IGNORECASE
                ),
                r"(?:balance|stock|quantity|count|available)\s*[+\-]=",
                "余额/库存检查与修改之间存在竞态窗口"
            ),
        ]

    def check(self, target: Union[str, Path, Dict[str, Any]]) -> List[RuleResult]:
        """执行竞态条件检测

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

        for pattern_tuple in self._toctou_patterns:
            if len(pattern_tuple) == 3:
                check_pattern, use_pattern, description = pattern_tuple
                for check_match in check_pattern.finditer(content):
                    check_end = check_match.end()
                    search_area = content[check_end:check_end + 500]
                    if use_pattern.search(search_area):
                        line_num = content[: check_match.start()].count("\n") + 1
                        col_num = check_match.start() - content[: check_match.start()].rfind("\n")

                        if line_num <= len(lines):
                            code_snippet = lines[line_num - 1].strip()
                        else:
                            code_snippet = check_match.group()

                        result = RuleResult(
                            rule_id=self.metadata.id,
                            rule_name=self.metadata.name,
                            passed=False,
                            message=f"检测到潜在的竞态条件: {description}",
                            severity=self.metadata.severity,
                            confidence=0.7,
                            location={
                                "file": file_path,
                                "line": line_num,
                                "column": col_num,
                            },
                            code_snippet=code_snippet,
                            fix_suggestion="使用原子操作或锁机制确保检查和使用操作的原子性，或使用事务/数据库约束。",
                            references=self.metadata.references,
                        )
                        results.append(result)

        return results


__all__ = [
    "IDORRule",
    "BusinessLogicFlawRule",
    "RaceConditionRule",
]