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


class CodeHardcodedValidator(Validator):
    """
    代码硬编码凭证验证器

    检测 Java 代码中的硬编码密码、密钥等
    如：private String password = "xxx";
    """

    HARDCODE_PATTERNS = [
        r'password\s*=\s*["\'].*["\']',
        r'secret\s*=\s*["\'].*["\']',
        r'api[_-]?key\s*=\s*["\'].*["\']',
        r'token\s*=\s*["\'].*["\']',
        r'credential\s*=\s*["\'].*["\']',
        r'private\s+(?:static\s+)?(?:final\s+)?String\s+\w*[Pp]assword\s*=',
        r'private\s+(?:static\s+)?(?:final\s+)?String\s+\w*[Ss]ecret\s*=',
        r'private\s+(?:static\s+)?(?:final\s+)?String\s+\w*[Tt]oken\s*=',
        r'private\s+(?:static\s+)?(?:final\s+)?String\s+\w*[Kk]ey\s*=',
        r'private\s+(?:static\s+)?(?:final\s+)?String\s+\w*[Cc]redential\s*=',
    ]

    SAFE_PATTERNS = [
        r'System\.getenv\s*\(',
        r'System\.getProperty\s*\(',
        r'@Value\s*\(',
        r'\$\{',
        r'password\s*=\s*["\'].*\$\{.*\}',
        r'password\s*=\s*env\[',
        r'password\s*=\s*System',
        r'from\s+environment',
        r'from\s+config',
        r'from\s+vault',
        r'from\s+secrets?\s+manager',
    ]

    @property
    def name(self) -> str:
        return "code_hardcoded"

    @property
    def vuln_types(self) -> List[str]:
        return ["secrets", "hardcoded", "credentials"]

    @property
    def description(self) -> str:
        return "检测代码中的硬编码凭证"

    @property
    def confidence_level(self) -> str:
        return "high"

    def check_applicability(self, context: VulnContext) -> bool:
        if not context.code_snippet:
            return False

        code_lower = context.code_snippet.lower()
        keywords = ['password', 'secret', 'key', 'token', 'credential']

        if not any(keyword in code_lower for keyword in keywords):
            return False

        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, context.code_snippet, re.IGNORECASE):
                return False

        return True

    def validate(self, context: VulnContext) -> ValidationResult:
        if not self.check_applicability(context):
            return create_uncertain_result(
                reason="代码片段不包含硬编码凭证模式",
                confidence=0.3
            )

        code = context.code_snippet

        is_hardcoded = False
        evidence_matches = []

        for pattern in self.HARDCODE_PATTERNS:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                is_hardcoded = True
                evidence_matches.extend(matches)

        if not is_hardcoded:
            return create_false_positive_result(
                reason="检测到凭证相关关键词但未发现真正的硬编码模式",
                confidence=0.7,
                evidence={"code_snippet": code[:200]}
            )

        if any(re.search(pattern, code, re.IGNORECASE) for pattern in self.SAFE_PATTERNS):
            return create_false_positive_result(
                reason="检测到凭证但来自外部配置源（环境变量/配置中心/密钥服务）",
                confidence=0.85,
                evidence={
                    "code_snippet": code[:200],
                    "matches": evidence_matches
                }
            )

        return create_valid_result(
            reason="发现代码硬编码凭证，这是不安全的做法",
            confidence=0.9,
            evidence={
                "code_snippet": code[:200],
                "matches": evidence_matches,
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
