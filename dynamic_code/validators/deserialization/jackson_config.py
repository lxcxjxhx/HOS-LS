import re
from typing import List
from src.analyzers.verification.interfaces import Validator, ValidationResult, VulnContext, create_uncertain_result


class JacksonConfigValidator(Validator):
    """
    Jackson 反序列化配置验证器

    检查规则：
    1. 检测 Jackson ObjectMapper 配置
    2. 检查是否启用了不安全的配置
    3. 区分 import 语句和实际注解使用
    4. import 语句不算漏洞，只有实际使用 @JsonTypeInfo 才算
    """

    @property
    def name(self) -> str:
        return "jackson_config"

    @property
    def vuln_types(self) -> List[str]:
        return ["deserialization", "jackson"]

    @property
    def description(self) -> str:
        return "检测 Jackson 反序列化不安全配置"

    @property
    def confidence_level(self) -> str:
        return "medium"

    def check_applicability(self, context: VulnContext) -> bool:
        return "ObjectMapper" in context.code_snippet or "jackson" in context.code_snippet.lower()

    def validate(self, context: VulnContext) -> ValidationResult:
        code = context.code_snippet

        if not self.check_applicability(context):
            return create_uncertain_result(
                "此验证器不适用于当前代码上下文",
                confidence=0.3
            )

        if self._is_only_import(code):
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.95,
                reason="仅检测到 Jackson import 语句，未实际使用，不构成漏洞",
                evidence={"import_only": True, "reason": "import语句不是实际使用"}
            )

        if self._has_safe_config(code):
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.85,
                reason="检测到安全的 Jackson 配置（DefaultTyping已禁用或使用安全类型验证）",
                evidence={"safe_config": True}
            )

        if self._has_unsafe_config(code):
            return ValidationResult(
                is_valid=True,
                is_false_positive=False,
                confidence=0.9,
                reason="检测到不安全的 Jackson 反序列化配置（启用了危险的DefaultTyping）",
                evidence={"unsafe_config": True}
            )

        return create_uncertain_result(
            "无法确定 Jackson 配置安全性，需人工复核",
            confidence=0.5
        )

    def _is_only_import(self, code_snippet: str) -> bool:
        """检查是否只是 import 语句，没有实际使用"""
        lines = code_snippet.split('\n')
        has_import = False
        has_usage = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('import') and 'jackson' in stripped.lower():
                has_import = True
            if '@JsonTypeInfo' in stripped and not stripped.startswith('*') and not stripped.startswith('//'):
                has_usage = True
            if 'JsonTypeInfo.As.' in stripped or 'JsonTypeInfo.TYPE.' in stripped:
                has_usage = True

        return has_import and not has_usage

    def _has_safe_config(self, code_snippet: str) -> bool:
        safe_patterns = [
            "setDefaultTypingDisabled",
            "DefaultTyping.DISABLED",
            "activateDefaultTyping",
            "ObjectMapper.DefaultTyping",
            "PolymorphicTypeValidator",
            ".disabled()",
        ]
        return any(pattern in code_snippet for pattern in safe_patterns)

    def _has_unsafe_config(self, code_snippet: str) -> bool:
        unsafe_patterns = [
            "DefaultTyping.NON_FINAL",
            "DefaultTyping.OBJECT_AND_NON_CONCREETS",
            "JsonTypeInfo.As.PROPERTY",
            "enableDefaultTyping",
            "DefaultTyping.EVERYTHING",
        ]

        for pattern in unsafe_patterns:
            if pattern in code_snippet:
                return True

        if re.search(r'@JsonTypeInfo\s*\(', code_snippet):
            if not self._is_only_import(code_snippet):
                return True

        return False

    def _is_annotation_usage(self, code_snippet: str) -> bool:
        """检测 @JsonTypeInfo 是否作为注解实际使用"""
        return bool(re.search(r'@JsonTypeInfo\s*\(', code_snippet))
