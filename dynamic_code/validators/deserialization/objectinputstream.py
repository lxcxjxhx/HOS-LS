import re
from typing import List
from src.analyzers.verification.interfaces import Validator, ValidationResult, VulnContext, create_uncertain_result


class ObjectInputStreamValidator(Validator):
    """
    ObjectInputStream 反序列化验证器

    检查规则：
    1. 检测 ObjectInputStream 的实际使用（非仅 import）
    2. 检查是否有输入验证
    3. 检查是否来自不可信源
    4. 评估反序列化风险
    """

    @property
    def name(self) -> str:
        return "objectinputstream"

    @property
    def vuln_types(self) -> List[str]:
        return ["deserialization", "objectinputstream", "java_deserialization"]

    @property
    def description(self) -> str:
        return "检测 ObjectInputStream 不安全反序列化"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        code = context.code_snippet
        return self._has_actual_objectinputstream_usage(code)

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
                reason="仅检测到 ObjectInputStream import 语句，未实际使用，不构成漏洞",
                evidence={"import_only": True}
            )

        if self._has_safe_deserialization(code):
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.85,
                reason="检测到安全的反序列化配置或验证机制",
                evidence={"safe_deserialization": True}
            )

        if self._is_from_untrusted_source(code):
            return ValidationResult(
                is_valid=True,
                is_false_positive=False,
                confidence=0.9,
                reason="来自不可信源的直接反序列化，存在安全风险",
                evidence={"untrusted_source": True}
            )

        if self._has_type_validation(code):
            return ValidationResult(
                is_valid=False,
                is_false_positive=True,
                confidence=0.8,
                reason="检测到类型验证或过滤机制",
                evidence={"type_validation": True}
            )

        return create_uncertain_result(
            "无法确定反序列化来源，需人工复核",
            confidence=0.5
        )

    def _has_actual_objectinputstream_usage(self, code_snippet: str) -> bool:
        """检查是否有 ObjectInputStream 的实际使用"""
        lines = code_snippet.split('\n')
        has_actual_usage = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('import'):
                continue
            if stripped.startswith('*') or stripped.startswith('//'):
                continue
            if 'ObjectInputStream' in stripped and ('new ObjectInputStream' in stripped or '.readObject' in stripped):
                has_actual_usage = True
                break
            if re.search(r'ObjectInputStream\s+\w+\s*=', stripped):
                has_actual_usage = True
                break

        return has_actual_usage

    def _is_only_import(self, code_snippet: str) -> bool:
        """检查是否只是 import 语句"""
        lines = code_snippet.split('\n')
        has_import = False
        has_usage = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('import') and 'ObjectInputStream' in stripped:
                has_import = True
            if not stripped.startswith('import') and not stripped.startswith('*') and not stripped.startswith('//'):
                if 'ObjectInputStream' in stripped:
                    has_usage = True

        return has_import and not has_usage

    def _has_safe_deserialization(self, code_snippet: str) -> bool:
        """检查是否有安全的反序列化配置"""
        safe_patterns = [
            r'setAllowedClasses',
            r'ObjectInputStream\s*\(.*validat',
            r'validateBeforeWrite',
            r'ObjectInputStream.*filter',
            r'setMixInResolver',
        ]
        return any(re.search(p, code_snippet, re.IGNORECASE) for p in safe_patterns)

    def _has_type_validation(self, code_snippet: str) -> bool:
        """检查是否有类型验证"""
        validation_patterns = [
            "ClassResolver",
            "PolymorphicTypeValidator",
            "setObjectValidator",
            "validateBeforeWrite",
            "TypeValidator",
        ]
        return any(pattern in code_snippet for pattern in validation_patterns)

    def _is_from_untrusted_source(self, code_snippet: str) -> bool:
        """检查是否来自不可信源（用户输入）"""
        untrusted_patterns = [
            r'request\.getInputStream',
            r'request\.getReader',
            r'socket\.getInputStream',
            r'connection\.getInputStream',
            r'ServletInputStream',
            r'@RequestBody',
            r'@RequestParam',
            r'@PathVariable',
            r'request\.getParameter',
            r'request\.getQueryString',
        ]
        return any(re.search(p, code_snippet, re.IGNORECASE) for p in untrusted_patterns)
