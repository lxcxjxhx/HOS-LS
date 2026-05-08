"""字符串拼接 SQL 注入验证器

检测 "SELECT ... WHERE " + variable + " = ..." 等字符串拼接模式。
这种模式直接将用户输入拼接到 SQL 语句中，极易造成 SQL 注入。
"""

import re
from typing import List, Dict, Any, Optional, Tuple

from src.analyzers.verification.interfaces import (
    Validator,
    VulnContext,
    ValidationResult,
    create_false_positive_result,
    create_valid_result,
    create_uncertain_result,
)


class StringConcatSqlValidator(Validator):
    """字符串拼接 SQL 注入验证器

    检测 "SELECT ... WHERE " + variable + " = ..." 模式
    """

    SQL_KEYWORDS = [
        "SELECT", "INSERT", "UPDATE", "DELETE",
        "DROP", "TRUNCATE", "ALTER", "CREATE",
        "FROM", "WHERE", "JOIN", "UNION"
    ]

    @property
    def name(self) -> str:
        return "string_concat_sql"

    @property
    def vuln_types(self) -> List[str]:
        return ["sql_injection", "string_concat"]

    @property
    def description(self) -> str:
        return "检测字符串拼接 SQL 注入"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        code_lower = context.code_snippet.lower()

        has_sql_keyword = any(
            keyword.lower() in code_lower
            for keyword in self.SQL_KEYWORDS
        )

        has_concat_pattern = self._has_string_concat_pattern(context.code_snippet)

        return has_sql_keyword and has_concat_pattern

    def _has_string_concat_pattern(self, code_snippet: str) -> bool:
        concat_patterns = [
            r'["\'].*?["\']\s*\+',          # "string" +
            r'\+\s*["\'][^"\']*["\']',      # + "string"
            r'\w+\s*\+\s*\w+',               # var + var
            r'\.append\s*\(',                # .append(
            r'StringBuilder',               # StringBuilder
            r'StringBuffer',                # StringBuffer
        ]

        for pattern in concat_patterns:
            if re.search(pattern, code_snippet):
                return True

        return False

    def validate(self, context: VulnContext) -> ValidationResult:
        code_snippet = context.code_snippet

        is_safe, evidence = self._check_safety(code_snippet)

        if is_safe:
            return create_false_positive_result(
                reason="检测到字符串拼接但使用了参数化查询或安全API",
                confidence=0.9,
                evidence=evidence
            )

        concat_details = self._analyze_concat_details(code_snippet)

        if concat_details["is_user_input_involved"]:
            return create_valid_result(
                reason=f"检测到 SQL 字符串拼接，用户输入 {concat_details['input_vars']} 直接参与拼接，存在SQL注入风险",
                confidence=0.9,
                evidence=concat_details
            )

        return create_uncertain_result(
            reason="检测到 SQL 字符串拼接，但无法确定是否有用户输入参与",
            confidence=0.6,
            evidence=concat_details
        )

    def _check_safety(self, code_snippet: str) -> Tuple[bool, Dict[str, Any]]:
        safe_patterns = [
            r'PreparedStatement',
            r'prepareStatement\s*\(',
            r'\?\s*\)',                      # JDBC parameter placeholder
            r'jdbc\.template',
            r'mybatis.*#\{',                 # MyBatis #{} is safe
            r'namedParameterJdbcTemplate',
            r'SqlParameterSource',
            r'BeanPropertySqlParameterSource',
        ]

        for pattern in safe_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return True, {
                    "type": "safe_api",
                    "matched_pattern": pattern
                }

        return False, {}

    def _analyze_concat_details(
        self,
        code_snippet: str
    ) -> Dict[str, Any]:
        details: Dict[str, Any] = {
            "is_user_input_involved": False,
            "input_vars": [],
            "concat_positions": [],
            "sql_keywords_found": []
        }

        details["sql_keywords_found"] = [
            kw for kw in self.SQL_KEYWORDS
            if kw in code_snippet.upper()
        ]

        user_input_patterns = [
            r'request\.get',
            r'@RequestParam',
            r'@RequestBody',
            r'@PathVariable',
            r'HttpServletRequest',
            r'RequestFacade',
            r'userInput',
            r'user\.',
            r'param\.get',
            r'args\[',
            r'\.query\(',
            r'\.param\(',
        ]

        for pattern in user_input_patterns:
            matches = re.findall(pattern, code_snippet, re.IGNORECASE)
            if matches:
                details["is_user_input_involved"] = True
                details["input_vars"].extend(matches)

        string_var_pattern = r'["\'].*?["\']\s*\+\s*(\w+)|(\w+)\s*\+\s*["\'].*?["\']'
        for match in re.finditer(string_var_pattern, code_snippet):
            var = match.group(1) or match.group(2)
            if var and var not in details["input_vars"]:
                if not any(kw.upper() in var.upper() for kw in self.SQL_KEYWORDS):
                    details["concat_positions"].append({
                        "var": var,
                        "position": match.start()
                    })

        potential_user_vars = [
            "username", "password", "email", "name", "id",
            "userId", "user_id", "account", "phone", "address",
            "search", "query", "keyword", "filter", "sort",
            "page", "size", "limit", "offset", "token", "key"
        ]

        for pos in details["concat_positions"]:
            var_lower = pos["var"].lower()
            for user_var in potential_user_vars:
                if user_var in var_lower:
                    details["is_user_input_involved"] = True
                    if pos["var"] not in details["input_vars"]:
                        details["input_vars"].append(pos["var"])

        return details
