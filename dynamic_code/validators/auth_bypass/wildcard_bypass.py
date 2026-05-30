from typing import List
from src.analyzers.verification.interfaces import Validator, VulnContext, ValidationResult


class WildcardBypassValidator(Validator):
    """
    通配符权限绕过验证器

    检测 release-urls: /** 配置导致的认证绕过
    """

    CRITICAL_WILDCARD_PATTERNS = [
        (r"release-urls\s*:\s*\*\*", "release-urls 配置为 /** (全放行)"),
        (r"release-urls\s*:\s*\/\*\*", "release-urls 配置为 /** (全放行)"),
        (r"release\.urls\s*=\s*\*\*", "release.urls 配置为 /** (全放行)"),
        (r"release\.urls\s*=\s*\"\/\*\*\"", "release.urls 配置为 /** (全放行)"),
        (r"release-urls\s*=\s*\[.*\*\*.*\]", "release-urls 数组包含 /** 通配符"),
    ]

    SENSITIVE_CONTEXT_PATTERNS = [
        "admin",
        "user",
        "api",
        "phone",
        "oauth",
        "account",
        "password",
        "payment",
        "order",
        "transaction",
        "sensitive",
        "private",
        "profile",
    ]

    @property
    def name(self) -> str:
        return "wildcard_bypass"

    @property
    def vuln_types(self) -> List[str]:
        return ["auth_bypass", "authorization", "wildcard"]

    @property
    def description(self) -> str:
        return "检测通配符 /** 导致的全放行"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        code_lower = context.code_snippet.lower()
        return (
            "/**" in context.code_snippet
            or "release-urls" in code_lower
            or "release.urls" in code_lower
        )

    def validate(self, context: VulnContext) -> ValidationResult:
        code = context.code_snippet

        matched_patterns = []
        for pattern, description in self.CRITICAL_WILDCARD_PATTERNS:
            import re

            if re.search(pattern, code, re.IGNORECASE):
                matched_patterns.append(description)

        if not matched_patterns:
            if "/**" in code:
                import re

                if re.search(r"[\"']\s*/\*\*\s*[\"']", code):
                    matched_patterns.append("路径通配符 /** 出现在字符串中")

        if not matched_patterns:
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.9,
                reason="检测到 /** 通配符但不是 release-urls 全放行配置",
                evidence={"code_snippet": code}
            )

        file_path_lower = context.file_path.lower()
        is_yaml_config = any(ext in file_path_lower for ext in [".yaml", ".yml", ".toml", ".properties"])

        has_sensitive_context = False
        code_lower = code.lower()
        for pattern in self.SENSITIVE_CONTEXT_PATTERNS:
            if pattern in code_lower:
                has_sensitive_context = True
                break

        if has_sensitive_context:
            confidence = 0.95
            reason = (
                f"检测到严重的认证绕过配置: {', '.join(matched_patterns)}。"
                f"该配置可能放行了包含敏感上下文的端点。"
            )
        else:
            confidence = 0.9
            reason = (
                f"检测到危险的通配符配置: {', '.join(matched_patterns)}。"
                f"/** 通配符会匹配所有路径，可能导致未授权访问。"
            )

        evidence = {
            "code_snippet": code,
            "file_path": context.file_path,
            "line_number": context.line_number,
            "matched_patterns": matched_patterns,
        }

        if is_yaml_config:
            evidence["config_type"] = "yaml"
        else:
            evidence["config_type"] = "unknown"

        return ValidationResult(
            is_valid=True,
            is_false_positive=False,
            confidence=confidence,
            reason=reason,
            evidence=evidence,
            verification_steps=[
                "1. 确认 release-urls /** 配置的用途和范围",
                "2. 检查 /** 覆盖的路径是否包含需要认证的资源",
                "3. 验证认证配置的其他部分是否存在",
                "4. 建议：限制 release-urls 到具体路径而非 /**",
                "5. 确认是否为测试环境或特殊用途的配置"
            ]
        )
