from typing import List
from src.analyzers.verification.interfaces import Validator, VulnContext, ValidationResult


class PermitAllValidator(Validator):
    """
    permitAll 配置验证器

    检测 permitAll() 配置是否包含敏感端点
    """

    SENSITIVE_PATTERNS = [
        "/admin",
        "/admin/**",
        "/phone",
        "/phone/**",
        "/oauth",
        "/oauth/**",
        "/api/admin",
        "/api/admin/**",
        "/api/phone",
        "/api/phone/**",
        "/user/**",
        "/account/**",
        "/password",
        "/secure",
        "/management",
        "/console",
        "/actuator",
        "/actuator/**",
        "/api/v1/admin",
        "/api/v2/admin",
        "/management/**",
        "/console/**",
        "/swagger",
        "/swagger-ui",
        "/v3/api-docs",
        "/fineract",
        "/fineract/**",
    ]

    @property
    def name(self) -> str:
        return "permit_all"

    @property
    def vuln_types(self) -> List[str]:
        return ["auth_bypass", "authorization"]

    @property
    def description(self) -> str:
        return "检测 permitAll 是否包含敏感路径"

    @property
    def confidence_level(self) -> str:
        return "medium"

    def check_applicability(self, context: VulnContext) -> bool:
        return "permitAll" in context.code_snippet or "permitAll()" in context.code_snippet

    def validate(self, context: VulnContext) -> ValidationResult:
        code = context.code_snippet

        if "permitAll" not in code and "permitAll()" not in code:
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.95,
                reason="代码中不包含 permitAll 配置",
                evidence={"code_snippet": code}
            )

        matched_sensitive_paths = []
        code_lower = code.lower()

        for pattern in self.SENSITIVE_PATTERNS:
            pattern_lower = pattern.lower()
            if pattern_lower.strip("/") in code_lower or pattern_lower in code_lower:
                matched_sensitive_paths.append(pattern)

        if not matched_sensitive_paths:
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.7,
                reason="permitAll 配置存在但未匹配到明显敏感的路径",
                evidence={"code_snippet": code}
            )

        severity_score = 0.0
        critical_patterns = ["/admin", "/oauth", "/phone/**", "/actuator", "/console"]
        high_patterns = ["/management", "/user/**", "/account/**", "/password"]

        for path in matched_sensitive_paths:
            if any(cp in path for cp in critical_patterns):
                severity_score += 0.4
            elif any(hp in path for hp in high_patterns):
                severity_score += 0.2

        severity_score = min(severity_score, 1.0)

        if severity_score >= 0.4:
            confidence = 0.9
            reason = f"permitAll 配置包含敏感路径: {', '.join(matched_sensitive_paths)}，存在严重授权绕过风险"
        elif severity_score >= 0.2:
            confidence = 0.75
            reason = f"permitAll 配置包含较敏感路径: {', '.join(matched_sensitive_paths)}，存在授权绕过风险"
        else:
            confidence = 0.65
            reason = f"permitAll 配置包含可能敏感的路径: {', '.join(matched_sensitive_paths)}"

        return ValidationResult(
            is_valid=True,
            is_false_positive=False,
            confidence=confidence,
            reason=reason,
            evidence={
                "code_snippet": code,
                "file_path": context.file_path,
                "line_number": context.line_number,
                "matched_paths": matched_sensitive_paths,
                "severity_score": severity_score
            },
            verification_steps=[
                "1. 确认 permitAll 匹配的路径是否包含敏感操作",
                "2. 检查该端点是否需要认证（如用户数据、权限操作）",
                "3. 验证是否有其他安全层保护（如 IP 白名单）",
                "4. 评估绕过后可能造成的危害程度"
            ]
        )
