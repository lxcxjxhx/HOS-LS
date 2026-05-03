import re
from dataclasses import dataclass, field
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class FallbackResult:
    is_vulnerable: bool
    confidence: float
    findings: List[dict]
    method: str
    summary: str


class FallbackAnalyzer:
    DANGEROUS_SQL_PATTERNS = [
        r'execute\s*\([^)]*\+',
        r'executeQuery\s*\([^)]*\+',
        r'executeUpdate\s*\([^)]*\+',
        r'createStatement\s*\([^)]*\+',
        r'"\s*\+\s*.*(?:SELECT|INSERT|UPDATE|DELETE)',
        r'"\s*f["\']\s*%.*(?:SELECT|INSERT|UPDATE|DELETE)',
        r'\%(?:s|d).*?(?:SELECT|INSERT|UPDATE|DELETE)',
        r'\$\{.*?\}',
    ]

    DANGEROUS_COMMAND_PATTERNS = [
        r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\([^)]*\+',
        r'ProcessBuilder\s*\(.*?\+\)',
        r'child_process\s*\.\s*exec\s*\([^)]*\+',
        r'child_process\s*\.\s*execSync\s*\([^)]*\+',
        r'os\s*\.\s*system\s*\([^)]*\+',
        r'os\s*\.\s*popen\s*\([^)]*\+',
        r'subprocess\s*\.\s*call\s*\([^)]*\+',
        r'subprocess\s*\.\s*run\s*\([^)]*\+',
    ]

    DANGEROUS_PATH_PATTERNS = [
        r'(?:open|read|write|FileInputStream|FileOutputStream)\s*\([^)]*\+',
        r'Paths\s*\.\s*get\s*\([^)]*\+',
        r'Path\s*\.\s*of\s*\([^)]*\+',
        r'File\s*\([^)]*\+',
        r'readFileSync\s*\([^)]*\+',
        r'writeFileSync\s*\([^)]*\+',
        r'\+\s*["\'][^"\']*\.\.[/\\]',
    ]

    DANGEROUS_XSS_PATTERNS = [
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'document\s*\.\s*write\s*\(',
        r'\.html\s*\(.*?\)',
        r'v-html\s*=',
        r'dangerouslySetInnerHTML',
        r'\{\s*__html\s*\}',
    ]

    DANGEROUS_DESERIALIZATION_PATTERNS = [
        r'ObjectInputStream\s*\.\s*readObject\s*\(',
        r'pickle\s*\.\s*loads\s*\(',
        r'yaml\s*\.\s*load\s*\(',
        r'yaml\s*\.\s*unsafe_load\s*\(',
        r'json\s*\.\s*loads?\s*\(',
        r'un serialize\s*\(',
        r'XStream\s*\(\s*\)\s*\.fromXML',
    ]

    def __init__(self):
        logger.info("FallbackAnalyzer initialized with static sink patterns")

    def analyze(self, code: str, language: str, vuln_type: str) -> FallbackResult:
        logger.debug(f"Analyzing {vuln_type} for language {language}")

        if vuln_type == "sql_injection":
            return self._static_sql_analysis(code, language)
        elif vuln_type == "command_injection":
            return self._static_command_analysis(code, language)
        elif vuln_type == "path_traversal":
            return self._static_path_analysis(code, language)
        elif vuln_type == "xss":
            return self._static_xss_analysis(code, language)
        elif vuln_type == "deserialization":
            return self._static_deserialization_analysis(code, language)
        else:
            logger.warning(f"Unknown vuln_type: {vuln_type}")
            return FallbackResult(
                is_vulnerable=False,
                confidence=0.5,
                findings=[],
                method="static_analysis_fallback",
                summary=f"Unknown vulnerability type: {vuln_type}"
            )

    def _static_sql_analysis(self, code: str, language: str) -> FallbackResult:
        findings = []
        for pattern in self.DANGEROUS_SQL_PATTERNS:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "line": self._get_line_number(code, match.start())
                })

        if findings:
            logger.warning(f"SQL injection patterns detected: {len(findings)} findings")
            return FallbackResult(
                is_vulnerable=True,
                confidence=0.7,
                findings=findings,
                method="static_analysis_fallback",
                summary=f"Detected {len(findings)} potential SQL injection patterns"
            )

        return FallbackResult(
            is_vulnerable=False,
            confidence=0.9,
            findings=[],
            method="static_analysis_fallback",
            summary="No SQL injection patterns detected"
        )

    def _static_command_analysis(self, code: str, language: str) -> FallbackResult:
        findings = []
        for pattern in self.DANGEROUS_COMMAND_PATTERNS:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "line": self._get_line_number(code, match.start())
                })

        if findings:
            logger.warning(f"Command injection patterns detected: {len(findings)} findings")
            return FallbackResult(
                is_vulnerable=True,
                confidence=0.7,
                findings=findings,
                method="static_analysis_fallback",
                summary=f"Detected {len(findings)} potential command injection patterns"
            )

        return FallbackResult(
            is_vulnerable=False,
            confidence=0.9,
            findings=[],
            method="static_analysis_fallback",
            summary="No command injection patterns detected"
        )

    def _static_path_analysis(self, code: str, language: str) -> FallbackResult:
        findings = []
        for pattern in self.DANGEROUS_PATH_PATTERNS:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "line": self._get_line_number(code, match.start())
                })

        if findings:
            logger.warning(f"Path traversal patterns detected: {len(findings)} findings")
            return FallbackResult(
                is_vulnerable=True,
                confidence=0.7,
                findings=findings,
                method="static_analysis_fallback",
                summary=f"Detected {len(findings)} potential path traversal patterns"
            )

        return FallbackResult(
            is_vulnerable=False,
            confidence=0.9,
            findings=[],
            method="static_analysis_fallback",
            summary="No path traversal patterns detected"
        )

    def _static_xss_analysis(self, code: str, language: str) -> FallbackResult:
        findings = []
        for pattern in self.DANGEROUS_XSS_PATTERNS:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "line": self._get_line_number(code, match.start())
                })

        if findings:
            logger.warning(f"XSS patterns detected: {len(findings)} findings")
            return FallbackResult(
                is_vulnerable=True,
                confidence=0.7,
                findings=findings,
                method="static_analysis_fallback",
                summary=f"Detected {len(findings)} potential XSS patterns"
            )

        return FallbackResult(
            is_vulnerable=False,
            confidence=0.9,
            findings=[],
            method="static_analysis_fallback",
            summary="No XSS patterns detected"
        )

    def _static_deserialization_analysis(self, code: str, language: str) -> FallbackResult:
        findings = []
        for pattern in self.DANGEROUS_DESERIALIZATION_PATTERNS:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "line": self._get_line_number(code, match.start())
                })

        if findings:
            logger.warning(f"Deserialization patterns detected: {len(findings)} findings")
            return FallbackResult(
                is_vulnerable=True,
                confidence=0.7,
                findings=findings,
                method="static_analysis_fallback",
                summary=f"Detected {len(findings)} potential insecure deserialization patterns"
            )

        return FallbackResult(
            is_vulnerable=False,
            confidence=0.9,
            findings=[],
            method="static_analysis_fallback",
            summary="No insecure deserialization patterns detected"
        )

    def _get_line_number(self, code: str, position: int) -> int:
        return code[:position].count('\n') + 1
