from typing import List
from src.analyzers.verification.interfaces import Validator, ValidationResult, VulnContext, create_uncertain_result


class URLControllableValidator(Validator):
    """
    URL 可控性 SSRF 验证器

    检查规则：
    1. 检测 URL 参数是否来自用户输入
    2. 检查是否存在 URL 验证
    3. 评估 SSRF 风险
    """

    @property
    def name(self) -> str:
        return "url_controllable"

    @property
    def vuln_types(self) -> List[str]:
        return ["ssrf", "url_controllable"]

    @property
    def description(self) -> str:
        return "检测 URL 参数可控性导致的 SSRF"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        url_patterns = ["URL(", "new URL(", "HttpClient", "WebClient", "getForObject", "postForObject"]
        return any(pattern in context.code_snippet for pattern in url_patterns)

    def validate(self, context: VulnContext) -> ValidationResult:
        if not self.check_applicability(context):
            return create_uncertain_result(
                "此验证器不适用于当前代码上下文",
                confidence=0.3
            )

        if self._has_url_validation(context.code_snippet):
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.8,
                reason="检测到 URL 验证机制",
                evidence={"validation_found": True}
            )

        if self._is_param_from_user(context.code_snippet):
            return ValidationResult(
                is_valid=True,
                is_false_positive=False,
                confidence=0.85,
                reason="URL 参数来自用户输入，存在 SSRF 风险",
                evidence={"user_controlled": True}
            )

        return create_uncertain_result(
            "无法确定参数来源，需人工复核",
            confidence=0.5
        )

    def _has_url_validation(self, code_snippet: str) -> bool:
        validation_patterns = [
            "urlValidator",
            "URLValidator",
            "Patterns.matches",
            "whitelist",
            "ALLOW_LIST",
            "allowedHosts",
            "InetAddress.isReachable",
            "!url.startsWith(\"http",
        ]
        return any(pattern in code_snippet for pattern in validation_patterns)

    def _is_param_from_user(self, code_snippet: str) -> bool:
        input_patterns = [
            "@RequestParam",
            "@RequestBody",
            "@PathVariable",
            "request.getParameter",
            "request.getQueryString",
            "@Value",
        ]
        return any(pattern in code_snippet for pattern in input_patterns)
