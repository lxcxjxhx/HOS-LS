import re
from typing import List
from src.analyzers.verification.interfaces import Validator, ValidationResult, VulnContext, create_uncertain_result


class SpelInjectionValidator(Validator):
    """
    SpEL 表达式注入验证器

    检查规则：
    1. 检测 SpelExpressionParser 或 ExpressionParser 的使用
    2. 检测用户输入是否进入表达式
    3. 如果表达式来自硬编码或不可控源，标记为误报
    """

    @property
    def name(self) -> str:
        return "spel_injection"

    @property
    def vuln_types(self) -> List[str]:
        return ["spel", "spel_injection", "expression_injection"]

    @property
    def description(self) -> str:
        return "检测 SpEL 表达式注入漏洞"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        code = context.code_snippet
        spel_patterns = [
            "SpelExpressionParser",
            "ExpressionParser",
            "SpelExpression",
            "SpelExpressionParser",
        ]
        return any(pattern in code for pattern in spel_patterns)

    def validate(self, context: VulnContext) -> ValidationResult:
        code = context.code_snippet

        if not self.check_applicability(context):
            return create_uncertain_result(
                "此验证器不适用于当前代码上下文",
                confidence=0.3
            )

        if self._is_hardcoded_expression(code):
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.9,
                reason="表达式来自硬编码字符串，不可控，不是漏洞",
                evidence={"hardcoded": True}
            )

        if self._has_user_input_to_expression(code):
            return ValidationResult(
                is_valid=True,
                is_false_positive=False,
                confidence=0.85,
                reason="用户输入进入 SpEL 表达式，存在注入风险",
                evidence={"user_input": True}
            )

        if self._is_safe_spel_usage(code):
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.85,
                reason="SpEL 用于安全场景（配置解析/模板），无用户输入",
                evidence={"safe_usage": True}
            )

        return create_uncertain_result(
            "无法确定 SpEL 表达式是否可控，需人工复核",
            confidence=0.5
        )

    def _is_hardcoded_expression(self, code_snippet: str) -> bool:
        """检查表达式是否来自硬编码"""
        hardcoded_patterns = [
            r'="[^"]*"',
            r"'[^']*'",
            r'"[^"]*\.SPEL[^"]*"',
            r'"[^"]*\|[^"]*"',
        ]
        for pattern in hardcoded_patterns:
            if re.search(pattern, code_snippet):
                if 'request' not in code_snippet.lower() and 'param' not in code_snippet.lower():
                    return True
        return False

    def _has_user_input_to_expression(self, code_snippet: str) -> bool:
        """检查用户输入是否进入表达式"""
        user_input_patterns = [
            r'request\.get',
            r'@RequestParam',
            r'@RequestBody',
            r'@PathVariable',
            r'@RequestHeader',
            r'param\[',
            r'request\[',
            r'getHeader',
            r'getQueryString',
            r'getParameter',
        ]
        expression_usage_patterns = [
            r'\.getValue\s*\(',
            r'\.setValue\s*\(',
            r'\.evaluate\s*\(',
            r'\.parseExpression\s*\(',
            r'\.getExpression\s*\(',
        ]

        has_user_input = any(re.search(p, code_snippet, re.IGNORECASE) for p in user_input_patterns)
        has_expression_usage = any(re.search(p, code_snippet) for p in expression_usage_patterns)

        return has_user_input and has_expression_usage

    def _is_safe_spel_usage(self, code_snippet: str) -> bool:
        """检查是否用于安全场景"""
        safe_patterns = [
            r'ApplicationContext',
            r'Environment',
            r'@Value',
            r'\.resolvePlaceholders\s*\(',
            r'\.getProperty\s*\(',
        ]
        return any(re.search(p, code_snippet) for p in safe_patterns)

    def _is_only_import(self, code_snippet: str) -> bool:
        """检查是否只是 import 语句"""
        lines = code_snippet.split('\n')
        has_import = False
        has_usage = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('import') and ('spel' in stripped.lower() or 'expression' in stripped.lower()):
                has_import = True
            if 'SpelExpressionParser' in stripped or 'ExpressionParser' in stripped:
                if not stripped.startswith('import') and not stripped.startswith('*') and not stripped.startswith('//'):
                    has_usage = True

        return has_import and not has_usage
