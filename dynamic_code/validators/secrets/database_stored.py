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


class DatabaseStoredValidator(Validator):
    """
    数据库配置中心凭证验证器

    检测存储在数据库中的凭证配置（如 Nacos 配置中心）
    这类配置是常见的企业做法
    """

    CONFIG_CENTER_PATTERNS = [
        r'nacos',
        r'apollo',
        r'consul',
        r'etcd',
        r'zookeeper',
        r'config[_-]?center',
        r'configuration[_-]?center',
    ]

    INSERT_PATTERNS = [
        r'INSERT\s+INTO\s+\w*[Cc]onfig',
        r'INSERT\s+INTO\s+\w*[Pp]roperty',
        r'INSERT\s+INTO\s+\w*[Ss]ecret',
        r'INSERT\s+INTO\s+\w*[Cc]redential',
        r'UPDATE\s+\w*[Cc]onfig',
        r'UPDATE\s+\w*[Pp]roperty',
        r'UPDATE\s+\w*[Ss]ecret',
        r'UPDATE\s+\w*[Cc]redential',
    ]

    SENSITIVE_VALUE_PATTERNS = [
        r'password["\']?\s*:\s*["\']?[^${\s][^"\']*',
        r'secret["\']?\s*:\s*["\']?[^${\s][^"\']*',
        r'password["\']?\s*=\s*[^${\s][^"\']*',
        r'secret["\']?\s*=\s*[^${\s][^"\']*',
    ]

    SAFE_VALUE_PATTERNS = [
        r'password["\']?\s*:\s*["\']?\$\{.*\}',
        r'secret["\']?\s*:\s*["\']?\$\{.*\}',
        r'password["\']?\s*=\s*["\']?\$\{.*\}',
        r'secret["\']?\s*=\s*["\']?\$\{.*\}',
        r'password["\']?\s*:\s*["\']?\s*["\']?$',
        r'secret["\']?\s*:\s*["\']?\s*["\']?$',
    ]

    @property
    def name(self) -> str:
        return "database_stored"

    @property
    def vuln_types(self) -> List[str]:
        return ["secrets", "database", "nacos"]

    @property
    def description(self) -> str:
        return "检测数据库配置中心存储的凭证"

    @property
    def confidence_level(self) -> str:
        return "low"

    def check_applicability(self, context: VulnContext) -> bool:
        if not context.file_path:
            return False

        if not context.file_path.endswith('.sql'):
            return False

        code_lower = context.code_snippet.lower() if context.code_snippet else ''

        has_config_keyword = any(
            pattern in code_lower
            for pattern in ['password', 'secret', 'key', 'nacos', 'config']
        )

        if not has_config_keyword:
            return False

        return True

    def validate(self, context: VulnContext) -> ValidationResult:
        if not self.check_applicability(context):
            return create_uncertain_result(
                reason="不是数据库配置中心的 SQL，不适用此验证器",
                confidence=0.3
            )

        code = context.code_snippet
        code_lower = code.lower()

        is_config_center = any(
            re.search(pattern, code_lower, re.IGNORECASE)
            for pattern in self.CONFIG_CENTER_PATTERNS
        )

        is_mutation = any(
            re.search(pattern, code, re.IGNORECASE)
            for pattern in self.INSERT_PATTERNS
        )

        if not (is_config_center or is_mutation):
            return create_uncertain_result(
                reason="SQL 文件中未检测到配置中心相关操作",
                confidence=0.3,
                evidence={
                    "code_snippet": code[:200],
                    "file": context.file_path,
                    "line": context.line_number
                }
            )

        for safe_pattern in self.SAFE_VALUE_PATTERNS:
            if re.search(safe_pattern, code, re.IGNORECASE):
                return create_false_positive_result(
                    reason="数据库配置中心使用占位符引用外部配置源（环境变量/密钥服务），这是安全的做法",
                    confidence=0.95,
                    evidence={
                        "code_snippet": code[:200],
                        "file": context.file_path,
                        "line": context.line_number
                    }
                )

        for insecure_pattern in self.SENSITIVE_VALUE_PATTERNS:
            if re.search(insecure_pattern, code, re.IGNORECASE):
                return create_valid_result(
                    reason="数据库配置中心存储了明文凭证，建议使用环境变量引用或加密存储",
                    confidence=0.6,
                    evidence={
                        "code_snippet": code[:200],
                        "file": context.file_path,
                        "line": context.line_number,
                        "pattern_matched": insecure_pattern
                    }
                )

        if is_config_center and is_mutation:
            return create_false_positive_result(
                reason="数据库配置中心（Nacos/Apollo等）是企业级配置管理常见做法，通常配合访问控制使用",
                confidence=0.8,
                evidence={
                    "code_snippet": code[:200],
                    "file": context.file_path,
                    "line": context.line_number
                }
            )

        return create_uncertain_result(
            reason="无法确定数据库配置中心凭证的安全性",
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
