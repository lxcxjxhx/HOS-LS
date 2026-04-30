"""漏洞验证模块

提供漏洞可利用性验证功能。
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.attack.fuzzer import Fuzzer


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """漏洞验证结果"""

    is_exploitable: bool
    confidence: float
    poc: str
    bypass_method: str
    reason: str
    sink_reachable: bool = True
    sanitization_present: bool = False
    sanitization_bypassable: bool = False


class VulnerabilityValidator:
    """漏洞可利用性验证器

    验证漏洞是否可被实际利用，检查数据流路径和防护措施。
    """

    SQL_SINKS = [
        "execute(", "cursor.execute", "executemany(",
        "raw(", "query(", "select(", "insert(", "update(", "delete(",
    ]

    SQL_SANITIZATIONS = [
        "params=", "bindparam", "?", "%s", ":param",
        "cursor.execute(sql, (", "executemany(sql,",
    ]

    XSS_SINKS = [
        "innerHTML", "outerHTML", "document.write", "write(",
        "render_template_string", "dangerouslySetInnerHTML",
        "|safe", "Markup(", "{{", "{%",
    ]

    XSS_SANITIZATIONS = [
        "escape(", "html.escape", "sanitize", "DOMPurify",
        "bleach.clean", "markupsafe.escape", "|e", "|escape",
        "textContent", "innerText",
    ]

    CMD_SINKS = [
        "os.system", "os.popen", "subprocess.call", "subprocess.run",
        "subprocess.Popen", "subprocess.exec", "eval(", "exec(",
        "exec_file(", "spawn(", "make_server(",
    ]

    CMD_SANITIZATIONS = [
        "shell=False", "shlex.quote", "validateschema",
        "allowed_commands", "whitelist",
    ]

    PATH_SINKS = [
        "open(", "read(", "write(", "send_file(",
        "os.path.join", "Path(", "file(", "upload(",
    ]

    PATH_SANITIZATIONS = [
        "os.path.abspath", "os.path.realpath", "resolve()",
        "startswith(", "in safe_", "validate_path",
    ]

    def __init__(self) -> None:
        self.fuzzer = Fuzzer()
        logger.info("VulnerabilityValidator initialized with Fuzzer integration")

    def validate_sql_injection(
        self, code_snippet: str, context: Dict
    ) -> ValidationResult:
        """验证 SQL 注入可利用性

        Args:
            code_snippet: 代码片段
            context: 包含 source、sink、dataflow 等信息的上下文

        Returns:
            验证结果
        """
        logger.debug(f"Validating SQL injection in: {code_snippet[:100]}")

        sink_reachable, sink_info = self._check_sink_reachable(
            code_snippet, self.SQL_SINKS, "SQL"
        )

        if not sink_reachable:
            return ValidationResult(
                is_exploitable=False,
                confidence=0.0,
                poc="",
                bypass_method="",
                reason="SQL sink not found or not reachable",
                sink_reachable=False,
            )

        sanitization_present, sanitization_info = self._check_sanitization(
            code_snippet, self.SQL_SANITIZATIONS, "SQL"
        )

        sanitization_bypassable = False
        bypass_method = ""

        if sanitization_present:
            sanitization_bypassable, bypass_method = self._check_sanitization_bypass(
                code_snippet, context, "sql"
            )
            if not sanitization_bypassable:
                return ValidationResult(
                    is_exploitable=False,
                    confidence=0.2,
                    poc="",
                    bypass_method="",
                    reason=f"Sanitization present and not bypassable: {sanitization_info}",
                    sink_reachable=True,
                    sanitization_present=True,
                    sanitization_bypassable=False,
                )

        poc_payload = self._generate_sql_poc(context)

        if sanitization_bypassable:
            confidence = 0.75
            reason = f"Sink reachable with bypassable sanitization: {sanitization_info}"
        elif sanitization_present:
            confidence = 0.3
            reason = "Sanitization present, low confidence"
        else:
            confidence = 0.9
            reason = "Direct SQL sink reachable without sanitization"

        logger.info(f"SQL injection validation: exploitable={confidence > 0.5}, confidence={confidence}")

        return ValidationResult(
            is_exploitable=confidence > 0.5,
            confidence=confidence,
            poc=poc_payload,
            bypass_method=bypass_method,
            reason=reason,
            sink_reachable=True,
            sanitization_present=sanitization_present,
            sanitization_bypassable=sanitization_bypassable,
        )

    def validate_xss(
        self, code_snippet: str, context: Dict
    ) -> ValidationResult:
        """验证 XSS 可利用性

        Args:
            code_snippet: 代码片段
            context: 包含 source、sink、dataflow 等信息的上下文

        Returns:
            验证结果
        """
        logger.debug(f"Validating XSS in: {code_snippet[:100]}")

        sink_reachable, sink_info = self._check_sink_reachable(
            code_snippet, self.XSS_SINKS, "XSS"
        )

        if not sink_reachable:
            return ValidationResult(
                is_exploitable=False,
                confidence=0.0,
                poc="",
                bypass_method="",
                reason="XSS sink not found or not reachable",
                sink_reachable=False,
            )

        sanitization_present, sanitization_info = self._check_sanitization(
            code_snippet, self.XSS_SANITIZATIONS, "XSS"
        )

        sanitization_bypassable = False
        bypass_method = ""

        if sanitization_present:
            sanitization_bypassable, bypass_method = self._check_sanitization_bypass(
                code_snippet, context, "xss"
            )
            if not sanitization_bypassable:
                return ValidationResult(
                    is_exploitable=False,
                    confidence=0.2,
                    poc="",
                    bypass_method="",
                    reason=f"Sanitization present and not bypassable: {sanitization_info}",
                    sink_reachable=True,
                    sanitization_present=True,
                    sanitization_bypassable=False,
                )

        poc_payload = self._generate_xss_poc(context)

        if sanitization_bypassable:
            confidence = 0.8
            reason = f"XSS sink reachable with bypassable sanitization: {sanitization_info}"
        elif sanitization_present:
            confidence = 0.25
            reason = "XSS sanitization present, low confidence"
        else:
            confidence = 0.9
            reason = "Direct XSS sink reachable without sanitization"

        logger.info(f"XSS validation: exploitable={confidence > 0.5}, confidence={confidence}")

        return ValidationResult(
            is_exploitable=confidence > 0.5,
            confidence=confidence,
            poc=poc_payload,
            bypass_method=bypass_method,
            reason=reason,
            sink_reachable=True,
            sanitization_present=sanitization_present,
            sanitization_bypassable=sanitization_bypassable,
        )

    def validate_command_injection(
        self, code_snippet: str, context: Dict
    ) -> ValidationResult:
        """验证命令注入可利用性

        Args:
            code_snippet: 代码片段
            context: 包含 source、sink、dataflow 等信息的上下文

        Returns:
            验证结果
        """
        logger.debug(f"Validating command injection in: {code_snippet[:100]}")

        sink_reachable, sink_info = self._check_sink_reachable(
            code_snippet, self.CMD_SINKS, "Command"
        )

        if not sink_reachable:
            return ValidationResult(
                is_exploitable=False,
                confidence=0.0,
                poc="",
                bypass_method="",
                reason="Command sink not found or not reachable",
                sink_reachable=False,
            )

        sanitization_present, sanitization_info = self._check_sanitization(
            code_snippet, self.CMD_SANITIZATIONS, "Command"
        )

        has_shell_true = "shell=True" in code_snippet

        sanitization_bypassable = False
        bypass_method = ""

        if sanitization_present:
            if has_shell_true:
                sanitization_bypassable = True
                bypass_method = "shell=True overrides sanitization"
        elif has_shell_true:
            sanitization_bypassable = True
            bypass_method = "shell=True allows command injection"

        if sanitization_present and not sanitization_bypassable:
            return ValidationResult(
                is_exploitable=False,
                confidence=0.2,
                poc="",
                bypass_method="",
                reason=f"Sanitization present and not bypassable: {sanitization_info}",
                sink_reachable=True,
                sanitization_present=True,
                sanitization_bypassable=False,
            )

        poc_payload = self._generate_cmd_poc(context)

        if sanitization_bypassable:
            confidence = 0.95
            reason = f"Command injection via {bypass_method}"
        else:
            confidence = 0.85
            reason = "Command sink reachable without shell execution"

        logger.info(f"Command injection validation: exploitable={confidence > 0.5}, confidence={confidence}")

        return ValidationResult(
            is_exploitable=confidence > 0.5,
            confidence=confidence,
            poc=poc_payload,
            bypass_method=bypass_method,
            reason=reason,
            sink_reachable=True,
            sanitization_present=sanitization_present,
            sanitization_bypassable=sanitization_bypassable,
        )

    def validate_path_traversal(
        self, code_snippet: str, context: Dict
    ) -> ValidationResult:
        """验证路径遍历可利用性

        Args:
            code_snippet: 代码片段
            context: 包含 source、sink、dataflow 等信息的上下文

        Returns:
            验证结果
        """
        logger.debug(f"Validating path traversal in: {code_snippet[:100]}")

        sink_reachable, sink_info = self._check_sink_reachable(
            code_snippet, self.PATH_SINKS, "Path"
        )

        if not sink_reachable:
            return ValidationResult(
                is_exploitable=False,
                confidence=0.0,
                poc="",
                bypass_method="",
                reason="Path operation sink not found or not reachable",
                sink_reachable=False,
            )

        sanitization_present, sanitization_info = self._check_sanitization(
            code_snippet, self.PATH_SANITIZATIONS, "Path"
        )

        sanitization_bypassable = False
        bypass_method = ""

        if sanitization_present:
            sanitization_bypassable, bypass_method = self._check_sanitization_bypass(
                code_snippet, context, "path"
            )
            if not sanitization_bypassable:
                return ValidationResult(
                    is_exploitable=False,
                    confidence=0.2,
                    poc="",
                    bypass_method="",
                    reason=f"Sanitization present and not bypassable: {sanitization_info}",
                    sink_reachable=True,
                    sanitization_present=True,
                    sanitization_bypassable=False,
                )

        poc_payload = self._generate_path_poc(context)

        if sanitization_bypassable:
            confidence = 0.8
            reason = f"Path traversal with bypass: {bypass_method}"
        elif sanitization_present:
            confidence = 0.3
            reason = "Path validation present, low confidence"
        else:
            confidence = 0.85
            reason = "Direct path operation without validation"

        logger.info(f"Path traversal validation: exploitable={confidence > 0.5}, confidence={confidence}")

        return ValidationResult(
            is_exploitable=confidence > 0.5,
            confidence=confidence,
            poc=poc_payload,
            bypass_method=bypass_method,
            reason=reason,
            sink_reachable=True,
            sanitization_present=sanitization_present,
            sanitization_bypassable=sanitization_bypassable,
        )

    def validate_all(self, findings: List[Dict]) -> List[ValidationResult]:
        """验证所有发现

        Args:
            findings: 漏洞发现列表，每个发现包含 type, code_snippet, context 等

        Returns:
            验证结果列表
        """
        logger.info(f"Validating {len(findings)} findings")
        results = []

        for finding in findings:
            finding_type = finding.get("type", "UNKNOWN")
            code_snippet = finding.get("code_snippet", finding.get("code", ""))
            context = finding.get("context", {})

            logger.debug(f"Validating finding type: {finding_type}")

            if finding_type == "SQL_INJECTION":
                result = self.validate_sql_injection(code_snippet, context)
            elif finding_type == "XSS":
                result = self.validate_xss(code_snippet, context)
            elif finding_type == "COMMAND_INJECTION":
                result = self.validate_command_injection(code_snippet, context)
            elif finding_type == "PATH_TRAVERSAL":
                result = self.validate_path_traversal(code_snippet, context)
            else:
                logger.warning(f"Unknown finding type: {finding_type}")
                result = ValidationResult(
                    is_exploitable=False,
                    confidence=0.0,
                    poc="",
                    bypass_method="",
                    reason=f"Unknown vulnerability type: {finding_type}",
                )

            results.append(result)

        logger.info(f"Validation complete: {sum(1 for r in results if r.is_exploitable)} exploitable")
        return results

    def _check_sink_reachable(
        self, code_snippet: str, sinks: List[str], sink_type: str
    ) -> Tuple[bool, str]:
        """检查危险 sink 是否可达

        Args:
            code_snippet: 代码片段
            sinks: sink 模式列表
            sink_type: sink 类型名称

        Returns:
            (是否可达, 匹配的sink信息)
        """
        for sink in sinks:
            if sink in code_snippet:
                logger.debug(f"Found {sink_type} sink: {sink}")
                return True, sink
        return False, ""

    def _check_sanitization(
        self, code_snippet: str, sanitizations: List[str], san_type: str
    ) -> Tuple[bool, str]:
        """检查是否存在安全防护

        Args:
            code_snippet: 代码片段
            sanitizations: 防护模式列表
            san_type: 防护类型名称

        Returns:
            (是否存在防护, 匹配的防护信息)
        """
        for san in sanitizations:
            if san in code_snippet:
                logger.debug(f"Found {san_type} sanitization: {san}")
                return True, san
        return False, ""

    def _check_sanitization_bypass(
        self, code_snippet: str, context: Dict, vuln_type: str
    ) -> Tuple[bool, str]:
        """检查安全防护是否可绕过

        Args:
            code_snippet: 代码片段
            context: 漏洞上下文
            vuln_type: 漏洞类型

        Returns:
            (是否可绕过, 绕过方法)
        """
        if vuln_type == "sql":
            if self._check_sql_bypass(code_snippet, context):
                return True, "SQL syntax bypass (comments, UNION, etc.)"

        elif vuln_type == "xss":
            if self._check_xss_bypass(code_snippet, context):
                return True, "XSS filter bypass (encoding, case variation, etc.)"

        elif vuln_type == "path":
            if self._check_path_bypass(code_snippet, context):
                return True, "Path traversal bypass (double encoding, null byte, etc.)"

        return False, ""

    def _check_sql_bypass(self, code_snippet: str, context: Dict) -> bool:
        """检查 SQL 过滤是否可绕过"""
        bypass_patterns = [
            r"'\s*OR\s*'1'\s*=\s*'1",
            r"'\s*OR\s*1\s*=\s*1",
            r"'\s*--",
            r"'\s*#",
            r"UNION\s+(ALL\s+)?SELECT",
            r"EXEC\s*\(",
            r";\s*DROP\s+",
            r";\s*DELETE\s+",
        ]
        for pattern in bypass_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return True
        return False

    def _check_xss_bypass(self, code_snippet: str, context: Dict) -> bool:
        """检查 XSS 过滤是否可绕过"""
        bypass_patterns = [
            r"<script",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<img[^>]+onerror",
            r"<svg[^>]+onload",
            r"<iframe",
            r"data:text/html",
        ]
        for pattern in bypass_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return True
        return False

    def _check_path_bypass(self, code_snippet: str, context: Dict) -> bool:
        """检查路径验证是否可绕过"""
        bypass_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e",
            r"\.\.%2f",
            r"\.\.%5c",
            r"\.\.%c0%af",
            r"\.\.%c1%9c",
        ]
        for pattern in bypass_patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return True
        return False

    def _generate_sql_poc(self, context: Dict) -> str:
        """生成 SQL 注入 PoC

        Args:
            context: 漏洞上下文

        Returns:
            PoC 载荷字符串
        """
        payload = self.fuzzer.generate_random_payload("sql")
        mutated = self.fuzzer.generate_mutated_payload(payload.payload, "encoding")
        if mutated:
            return mutated[0]
        return payload.payload

    def _generate_xss_poc(self, context: Dict) -> str:
        """生成 XSS PoC

        Args:
            context: 漏洞上下文

        Returns:
            PoC 载荷字符串
        """
        payload = self.fuzzer.generate_random_payload("xss")
        mutated = self.fuzzer.generate_mutated_payload(payload.payload, "encoding")
        if mutated:
            return mutated[0]
        return payload.payload

    def _generate_cmd_poc(self, context: Dict) -> str:
        """生成命令注入 PoC

        Args:
            context: 漏洞上下文

        Returns:
            PoC 载荷字符串
        """
        payload = self.fuzzer.generate_random_payload("cmd")
        return payload.payload

    def _generate_path_poc(self, context: Dict) -> str:
        """生成路径遍历 PoC

        Args:
            context: 漏洞上下文

        Returns:
            PoC 载荷字符串
        """
        payload = self.fuzzer.generate_random_payload("path")
        mutated = self.fuzzer.generate_mutated_payload(payload.payload, "encoding")
        if mutated:
            return mutated[0]
        return payload.payload


def get_vulnerability_validator() -> VulnerabilityValidator:
    """获取漏洞验证器单例

    Returns:
        VulnerabilityValidator 实例
    """
    return VulnerabilityValidator()
