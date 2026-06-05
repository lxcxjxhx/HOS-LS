from typing import List
from src.analyzers.verification.interfaces import Validator, ValidationResult, VulnContext, create_uncertain_result


class RestTemplateSSRFValidator(Validator):
    """
    RestTemplate SSRF 验证器

    检查规则：
    1. 检测 RestTemplate 的 URL 可控性
    2. 检查是否存在 URL 验证
    3. 评估内网资源访问风险
    """

    @property
    def name(self) -> str:
        return "resttemplate_ssrf"

    @property
    def vuln_types(self) -> List[str]:
        return ["ssrf", "resttemplate_ssrf"]

    @property
    def description(self) -> str:
        return "检测 RestTemplate URL 可控性导致的 SSRF"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        return "RestTemplate" in context.code_snippet or "restTemplate" in context.code_snippet

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
                confidence=0.85,
                reason="检测到 URL 验证机制",
                evidence={"validation_found": True}
            )

        if self._is_url_from_user_input(context.code_snippet):
            return ValidationResult(
                is_valid=True,
                is_false_positive=False,
                confidence=0.8,
                reason="URL 来自用户输入，可能存在 SSRF",
                evidence={"user_input": True}
            )

        if self._is_localhost_or_internal(context.code_snippet):
            return ValidationResult(
                is_valid=True,
                is_false_positive=False,
                confidence=0.75,
                reason="检测到本地或内网地址访问",
                evidence={"internal_access": True}
            )

        return create_uncertain_result(
            "无法确定 URL 来源，需人工复核",
            confidence=0.5
        )

    def _has_url_validation(self, code_snippet: str) -> bool:
        validation_patterns = [
            "urlValidator",
            "URLValidator",
            "Uri.isAbsolute()",
            "!url.startsWith",
            "whitelist",
            "ALLOW_LIST",
            "allowedHosts",
        ]
        return any(pattern in code_snippet for pattern in validation_patterns)

    def _is_url_from_user_input(self, code_snippet: str) -> bool:
        input_patterns = [
            "@RequestParam",
            "@RequestBody",
            "@PathVariable",
            "request.getParameter",
            "request.getQueryString",
            "request.getHeader",
        ]
        return any(pattern in code_snippet for pattern in input_patterns)

    def _is_localhost_or_internal(self, code_snippet: str) -> bool:
        internal_patterns = [
            "localhost",
            "127.0.0.1",
            "169.254.169.254",
            "metadata.google.internal",
            "internal.",
            "metadata.aws",
        ]
        return any(pattern in code_snippet.lower() for pattern in internal_patterns)
