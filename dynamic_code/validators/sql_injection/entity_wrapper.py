"""EntityWrapper 安全验证器

EntityWrapper 由 MyBatis-Plus 提供，是安全的 SQL 封装。
只有当 ew.sqlSegment 被用户输入直接污染时才构成漏洞。
"""

import re
from typing import List, Dict, Any, Optional

from src.analyzers.verification.interfaces import (
    Validator,
    VulnContext,
    ValidationResult,
    create_false_positive_result,
    create_valid_result,
    create_uncertain_result,
)


class EntityWrapperSafeValidator(Validator):
    """EntityWrapper 安全验证器

    EntityWrapper 由 MyBatis-Plus 提供，是安全的封装。
    只有当 ew.sqlSegment 被用户输入污染时才构成漏洞。
    """

    @property
    def name(self) -> str:
        return "entity_wrapper_safe"

    @property
    def vuln_types(self) -> List[str]:
        return ["sql_injection", "entity_wrapper"]

    @property
    def description(self) -> str:
        return "检测 EntityWrapper 是否安全封装"

    @property
    def confidence_level(self) -> str:
        return "medium"

    def check_applicability(self, context: VulnContext) -> bool:
        code_lower = context.code_snippet.lower()
        return (
            "ew" in context.code_snippet or
            "entitywrapper" in code_lower or
            "ew.sqlsegment" in code_lower or
            "wrapper.sqlsegment" in code_lower
        )

    def validate(self, context: VulnContext) -> ValidationResult:
        code_snippet = context.code_snippet
        code_lower = code_snippet.lower()

        is_safe, evidence = self._check_entity_wrapper_safety(code_snippet, code_lower)

        if is_safe:
            return create_false_positive_result(
                reason="EntityWrapper 被框架安全封装使用，不构成SQL注入",
                confidence=0.9,
                evidence=evidence
            )

        is_dangerous, danger_evidence = self._check_dangerous_usage(
            code_snippet,
            code_lower
        )

        if is_dangerous:
            return create_valid_result(
                reason="检测到 EntityWrapper sqlSegment 被用户输入直接拼接，存在SQL注入风险",
                confidence=0.8,
                evidence=danger_evidence
            )

        return create_uncertain_result(
            reason="检测到 EntityWrapper 使用，但无法确定是否存在用户输入污染",
            confidence=0.5,
            evidence=evidence
        )

    def _check_entity_wrapper_safety(
        self,
        code_snippet: str,
        code_lower: str
    ) -> tuple[bool, Dict[str, Any]]:
        safe_patterns = [
            r'ew\.where\(',
            r'ew\.orderBy\(',
            r'ew\.select\(',
            r'ew\.in\(',
            r'ew\.eq\(',
            r'ew\.ne\(',
            r'ew\.gt\(',
            r'ew\.lt\(',
            r'ew\.like\(',
            r'ew\.between\(',
            r'QueryWrapper\s*<',
            r'EntityWrapper\s*<',
            r'\.sqlSegment\(\s*\)',
        ]

        for pattern in safe_patterns:
            if re.search(pattern, code_lower):
                return True, {
                    "type": "safe_framework_usage",
                    "matched_pattern": pattern
                }

        dangerous_patterns = [
            r'ew\.sqlSegment\s*\+\s*["\']',
            r'ew\.sqlSegment\s*\+\s*\w+',
            r'String\.format.*sqlSegment',
            r'"select.*" \+ .*sqlSegment',
            r"'select.*' + .*sqlSegment",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, code_lower):
                return False, {
                    "type": "potentially_dangerous",
                    "matched_pattern": pattern
                }

        return True, {
            "type": "standard_entity_wrapper",
            "note": "使用标准 EntityWrapper 方法"
        }

    def _check_dangerous_usage(
        self,
        code_snippet: str,
        code_lower: str
    ) -> tuple[bool, Dict[str, Any]]:
        dangerous_concat_patterns = [
            r'sqlSegment\s*\+\s*["\'][^"\']*$',
            r'sqlSegment\s*\+\s*\w+\s*\+\s*["\']',
            r'\+\s*request\.',
            r'\+\s*param\.',
            r'\+\s*userInput',
            r'\+\s*user\.',
            r'\+\s*httpServletRequest',
        ]

        for pattern in dangerous_concat_patterns:
            if re.search(pattern, code_lower):
                return True, {
                    "type": "dangerous_concat",
                    "pattern": pattern,
                    "reason": "sqlSegment 被直接拼接了外部输入"
                }

        string_format_patterns = [
            r'String\.format\([^)]*sqlSegment',
            r'"select.*%s.*"\s*.*%.*sqlSegment',
        ]

        for pattern in string_format_patterns:
            if re.search(pattern, code_lower):
                return True, {
                    "type": "dangerous_format",
                    "pattern": pattern,
                    "reason": "使用 String.format 直接格式化 sqlSegment"
                }

        return False, {}
