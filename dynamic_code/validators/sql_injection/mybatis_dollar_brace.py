"""MyBatis ${} SQL 注入验证器

检测 MyBatis XML 或注解中使用的 ${} 字符串拼接是否可被SQL注入。
${} 会直接替换为参数值，而 #{} 会使用预编译的占位符。
"""

import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.analyzers.verification.interfaces import (
    Validator,
    VulnContext,
    ValidationResult,
    create_false_positive_result,
    create_valid_result,
    create_uncertain_result,
)


class MybatisDollarBraceValidator(Validator):
    """MyBatis ${} SQL注入验证器

    检查规则：
    1. 提取 ${} 中的参数名
    2. 查找服务层调用
    3. 检查参数是否硬编码
    4. 如果硬编码返回误报
    """

    @property
    def name(self) -> str:
        return "mybatis_dollar_brace"

    @property
    def vuln_types(self) -> List[str]:
        return ["sql_injection", "mybatis_dollar_brace"]

    @property
    def description(self) -> str:
        return "检测 MyBatis ${} 拼接是否可被SQL注入"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        return "${" in context.code_snippet

    def validate(self, context: VulnContext) -> ValidationResult:
        code_snippet = context.code_snippet

        dollar_brace_params = self._extract_dollar_brace_params(code_snippet)
        if not dollar_brace_params:
            return create_uncertain_result(
                reason="未找到 ${} 参数",
                confidence=0.5
            )

        is_hardcoded, evidence = self._check_hardcoded_params(
            dollar_brace_params,
            code_snippet,
            context
        )

        if is_hardcoded:
            return create_false_positive_result(
                reason=f"参数 {dollar_brace_params} 被硬编码，不构成SQL注入风险",
                confidence=0.95,
                evidence=evidence
            )

        caller_info = self._find_service_layer_caller(context)

        if caller_info:
            evidence["caller"] = caller_info
            return create_valid_result(
                reason=f"检测到 ${dollar_brace_params} 使用了非硬编码参数，可能存在SQL注入风险",
                confidence=0.85,
                evidence=evidence
            )

        return create_uncertain_result(
            reason=f"检测到 ${dollar_brace_params}，但无法确定参数来源，建议人工审核",
            confidence=0.6
        )

    def _extract_dollar_brace_params(self, code_snippet: str) -> List[str]:
        pattern = r'\$\{([^}]+)\}'
        matches = re.findall(pattern, code_snippet)
        return list(set(matches))

    def _check_hardcoded_params(
        self,
        params: List[str],
        code_snippet: str,
        context: VulnContext
    ) -> tuple[bool, Dict[str, Any]]:
        for param in params:
            hardcoded_regex = rf'\$\{{[^}}]*["\'][^"\']*{re.escape(param)}[^"\']*["\'][^}}]*\}}'
            if re.search(hardcoded_regex, code_snippet):
                return True, {
                    "param": param,
                    "type": "hardcoded_string",
                    "matched_pattern": f"${{'value'{param}'value'}}"
                }

        hardcoded_sql_keywords = [
            "1=1", "1 OR 1", "' OR '1", '" OR "1',
            "DROP TABLE", "DELETE FROM",
        ]

        code_lower = code_snippet.lower()
        for keyword in hardcoded_sql_keywords:
            if keyword.lower() in code_lower:
                dollar_brace_content = re.findall(r'\$\{([^}]+)\}', code_snippet)
                for param in dollar_brace_content:
                    if param.lower() not in keyword.lower():
                        return True, {
                            "param": param,
                            "type": "hardcoded_sql_injection_keyword",
                            "matched_value": keyword
                        }

        return False, {"params_checked": params}

    def _find_service_layer_caller(
        self,
        context: VulnContext
    ) -> Optional[Dict[str, Any]]:
        caller_info = {}

        if hasattr(context, 'metadata') and context.metadata:
            caller = context.metadata.get('caller') or context.metadata.get('service_method')
            if caller:
                caller_info["method"] = caller
                caller_info["source"] = "metadata"

        if not caller_info and context.file_path:
            mapper_file = Path(context.file_path)
            if mapper_file.exists():
                content = mapper_file.read_text(encoding='utf-8', errors='ignore')
                lines = content.split('\n')

                if context.line_number > 0 and context.line_number <= len(lines):
                    nearby_lines = lines[max(0, context.line_number - 20):context.line_number]
                    for line in reversed(nearby_lines):
                        service_match = re.search(
                            r'(?:@Select|@Update|@Insert|@Delete|Map\s*)\s*\([',
                            line
                        )
                        if service_match:
                            caller_info["source"] = "mybatis_annotation"
                            break

        return caller_info if caller_info else None
