import re
from typing import List

from src.analyzers.verification.interfaces import (
    Validator,
    VulnContext,
    ValidationResult,
    create_valid_result,
    create_false_positive_result,
    create_uncertain_result,
)


class ConfigStoredValidator(Validator):
    """
    配置文件凭证验证器

    检测 application.yml, application.properties 中的凭证配置
    这类配置是常见的做法，误报率较低
    """

    INSECURE_PATTERNS = [
        r'password:\s*["\']?[^${\s][^"\']*["\']?',
        r'password\s*=\s*[^${\s][^"\']*',
        r'secret:\s*["\']?[^${\s][^"\']*["\']?',
        r'secret\s*=\s*[^${\s][^"\']*',
        r'api[_-]?key:\s*["\']?[^${\s][^"\']*["\']?',
        r'api[_-]?key\s*=\s*[^${\s][^"\']*',
    ]

    ACCEPTABLE_PATTERNS = [
        r'password:\s*["\']?\$\{.*\}["\']?',
        r'password\s*=\s*["\']?\$\{.*\}["\']?',
        r'password:\s*["\']?\s*["\']?',
        r'password\s*=\s*["\']?\s*["\']?',
        r'password:\s*#.*',
        r'password\s*=#.*',
        r'password:\s*\{\{.*\}\}',
        r'password\s*=\{\{.*\}\}',
        r'from\s+environment',
        r'from\s+config[_-]?center',
        r'from\s+vault',
        r'from\s+secrets?\s*manager',
        r'datasource\.password',
        r'spring\.datasource\.password',
        r'jdbc\.password',
    ]

    @property
    def name(self) -> str:
        return "config_stored"

    @property
    def vuln_types(self) -> List[str]:
        return ["secrets", "config", "yaml_config"]

    @property
    def description(self) -> str:
        return "检测配置文件中的凭证"

    @property
    def confidence_level(self) -> str:
        return "medium"

    def check_applicability(self, context: VulnContext) -> bool:
        if not context.file_path:
            return False

        config_extensions = ('.yml', '.yaml', '.properties')
        return context.file_path.endswith(config_extensions)

    def validate(self, context: VulnContext) -> ValidationResult:
        if not self.check_applicability(context):
            return create_uncertain_result(
                reason="不是配置文件，不适用此验证器",
                confidence=0.3
            )

        code = context.code_snippet

        for acceptable_pattern in self.ACCEPTABLE_PATTERNS:
            if re.search(acceptable_pattern, code, re.IGNORECASE):
                return create_false_positive_result(
                    reason="检测到凭证配置但使用了安全引用方式（环境变量/配置中心占位符）",
                    confidence=0.9,
                    evidence={
                        "code_snippet": code[:200],
                        "file": context.file_path,
                        "line": context.line_number
                    }
                )

        for insecure_pattern in self.INSECURE_PATTERNS:
            if re.search(insecure_pattern, code, re.IGNORECASE):
                return create_valid_result(
                    reason="配置文件中发现明文凭证配置",
                    confidence=0.7,
                    evidence={
                        "code_snippet": code[:200],
                        "file": context.file_path,
                        "line": context.line_number,
                        "pattern_matched": insecure_pattern
                    }
                )

        if any(keyword in code.lower() for keyword in ['password', 'secret', 'key', 'token']):
            return create_false_positive_result(
                reason="配置文件中的凭证配置可能是安全引用方式",
                confidence=0.6,
                evidence={
                    "code_snippet": code[:200],
                    "file": context.file_path,
                    "line": context.line_number
                }
            )

        return create_uncertain_result(
            reason="无法确定配置文件中的凭证安全性",
            confidence=0.4,
            evidence={
                "code_snippet": code[:200],
                "file": context.file_path,
                "line": context.line_number
            }
        )

    def verify(self, context: dict) -> dict:
        """兼容 DynamicLoader 的 verify 方法"""
        vuln_context = VulnContext(
            file_path=context.get('file_path', ''),
            line_number=context.get('line_number', 0),
            code_snippet=context.get('code_snippet', ''),
            vuln_type=context.get('vuln_type', ''),
            project_root=context.get('project_root', ''),
            finding_id=context.get('finding_id'),
            metadata=context.get('metadata')
        )

        result = self.validate(vuln_context)

        return {
            'is_valid': result.is_valid,
            'is_false_positive': result.is_false_positive,
            'confidence': result.confidence,
            'reason': result.reason,
            'evidence': result.evidence,
            'poc_script': result.poc_script,
            'verification_steps': result.verification_steps
        }
