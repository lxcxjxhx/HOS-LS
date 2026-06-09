from typing import List
from src.analyzers.verification.interfaces import Validator, VulnContext, ValidationResult


class CsrfDisabledValidator(Validator):
    """
    CSRF 禁用验证器

    检测 .csrf().disable() 配置
    只有当没有其他 CSRF 防护时才构成漏洞
    """

    @property
    def name(self) -> str:
        return "csrf_disabled"

    @property
    def vuln_types(self) -> List[str]:
        return ["auth_bypass", "csrf"]

    @property
    def description(self) -> str:
        return "检测 CSRF 保护是否被禁用"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        return ".csrf()" in context.code_snippet or "csrf" in context.code_snippet.lower()

    def validate(self, context: VulnContext) -> ValidationResult:
        code = context.code_snippet

        if ".disable()" not in code and "disable()" not in code:
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.95,
                reason="CSRF 配置存在但未调用 .disable()，未被禁用",
                evidence={"code_snippet": code}
            )

        csrf_disable_patterns = [
            ".csrf().disable()",
            "csrf().disable()",
            ".csrf().disable(true)",
            "csrf().disable(true)",
        ]

        is_csrf_disabled = any(pattern in code for pattern in csrf_disable_patterns)

        if not is_csrf_disabled:
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.9,
                reason="检测到 csrf 相关配置但未实际禁用",
                evidence={"code_snippet": code}
            )

        other_csrf_protection_patterns = [
            "csrfToken",
            "csrf_token",
            "CsrfToken",
            "_csrf",
            "X-CSRF-Token",
            "X-XSRF-TOKEN",
            "xsrf",
            "@Csrf ",
            "csrfIgnored",
        ]

        has_other_protection = any(
            pattern in code.lower() for pattern in other_csrf_protection_patterns
        )

        if has_other_protection:
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.85,
                reason="检测到其他 CSRF 防护措施（如 CSRF Token），禁用可能是有意为之",
                evidence={"code_snippet": code}
            )

        file_path_lower = context.file_path.lower()
        yaml_or_properties = any(
            ext in file_path_lower for ext in [".yaml", ".yml", ".properties", ".toml"]
        )

        if yaml_or_properties:
            if "csrf" in code.lower() and "disable" in code.lower():
                return ValidationResult(
                    is_valid=True,
                    is_false_positive=False,
                    confidence=0.9,
                    reason="配置文件中明确禁用 CSRF 保护，可能导致 CSRF 攻击",
                    evidence={
                        "code_snippet": code,
                        "file_path": context.file_path,
                        "line_number": context.line_number
                    }
                )

        return ValidationResult(
            is_valid=True,
            is_false_positive=False,
            confidence=0.85,
            reason="检测到 .csrf().disable() 配置且无其他 CSRF 防护措施，存在 CSRF 漏洞风险",
            evidence={
                "code_snippet": code,
                "file_path": context.file_path,
                "line_number": context.line_number
            },
            verification_steps=[
                "1. 确认应用是否处理敏感操作（表单提交、API调用等）",
                "2. 检查是否实现了 CSRF Token 机制",
                "3. 验证 SameSite Cookie 配置",
                "4. 确认自定义 CSRF 防护的存在"
            ]
        )
