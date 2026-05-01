"""漏洞推理引擎

基于 CWE 和代码模式进行漏洞推理
"""
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class VulnerabilityInference:
    """漏洞推理结果"""
    cwe_id: str
    vulnerability_type: str
    confidence: float
    sink_function: str
    source_function: Optional[str]
    exploit_pattern: str
    language: str
    severity: str
    location: str
    evidence: List[str]
    recommendation: str


class ReasoningEngine:
    """漏洞推理引擎"""

    CWE_DEFINITIONS = {
        "CWE-89": {
            "name": "SQL Injection",
            "severity": "CRITICAL",
            "description": "SQL命令中引入用户输入而未适当清理",
            "sink_functions": [
                "cursor.execute", "cursor.executemany", "connection.execute",
                "execute", "executemany", "query", "raw", "session.execute",
                "${", "#{", "${", "#{",
            ],
            "exploit_patterns": ["string_concatenation", "format_string", "string_template", "direct_interpolation"]
        },
        "CWE-79": {
            "name": "Cross-site Scripting (XSS)",
            "severity": "HIGH",
            "description": "网页中包含未适当清理的用户输入",
            "sink_functions": [
                "innerHTML", "outerHTML", "insertAdjacentHTML",
                "document.write", "eval", "setTimeout", "setInterval",
                "html()", "text()", "append()", "prepend()",
            ],
            "exploit_patterns": ["innerHTML_assignment", "document_write", "eval_input", "direct_output"]
        },
        "CWE-22": {
            "name": "Path Traversal",
            "severity": "HIGH",
            "description": "文件路径中引入用户输入而未适当验证",
            "sink_functions": [
                "open", "file", "File", "readFile", "readFileSync",
                "createReadStream", "readFile", "fopen", "fread",
                "new File(", "File(", "Path(", "Paths.get(",
            ],
            "exploit_patterns": ["path_concatenation", "path_join", "user_input_path", "dynamic_path"]
        },
        "CWE-259": {
            "name": "Hard-coded Password",
            "severity": "CRITICAL",
            "description": "代码中包含硬编码密码",
            "sink_functions": ["password", "passwd", "pwd", "secret", "credential"],
            "exploit_patterns": ["hardcoded_string", "literal_value", "constant_assignment"]
        },
        "CWE-321": {
            "name": "Hard-coded Cryptographic Key",
            "severity": "HIGH",
            "description": "代码中包含硬编码加密密钥",
            "sink_functions": ["key", "secret", "encrypt", "decrypt", "crypto"],
            "exploit_patterns": ["hardcoded_string", "literal_value", "constant_assignment"]
        },
        "CWE-352": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "severity": "MEDIUM",
            "description": "Web应用未验证请求来源",
            "sink_functions": ["csrf", "token", "verify", "check", "validate"],
            "exploit_patterns": ["missing_token", "no_verification", "unsafe_request"]
        },
        "CWE-601": {
            "name": "Open Redirect",
            "severity": "MEDIUM",
            "description": "应用将用户输入用于重定向URL而未验证",
            "sink_functions": ["redirect", "forward", "sendRedirect", "location", "href"],
            "exploit_patterns": ["user_input_redirect", "unvalidated_redirect", "dynamic_url"]
        },
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "severity": "HIGH",
            "description": "应用从用户输入获取URL而未适当验证",
            "sink_functions": ["fetch", "request", "get", "post", "curl", "http", "urlopen"],
            "exploit_patterns": ["user_input_url", "dynamic_url", "unvalidated_request"]
        },
    }

    LANGUAGE_PATTERNS = {
        "python": {
            "sql_sinks": ["cursor.execute(", "cursor.executemany(", "connection.execute(", "execute(", "executemany("],
            "command_sinks": ["os.system(", "subprocess.", "eval(", "exec(", "os.popen("],
            "file_sinks": ["open(", "os.open(", "io.open(", "pathlib.Path("],
            "source_patterns": ["request.args", "request.form", "request.json", "input(", "sys.argv"],
        },
        "java": {
            "sql_sinks": ["Statement.execute", "PreparedStatement.", "Session.createQuery", "entityManager.", "JdbcTemplate."],
            "command_sinks": ["Runtime.exec(", "ProcessBuilder(", "System.exec("],
            "file_sinks": ["new File(", "Files.readAllBytes(", "FileInputStream.", "FileReader("],
            "source_patterns": ["request.getParameter", "request.getHeader", "@RequestParam", "@PathVariable"],
        },
        "javascript": {
            "xss_sinks": ["innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(", "new Function("],
            "sql_sinks": ["mysql.query", "pg.query", "mongodb.collection.", "sequelize.query"],
            "command_sinks": ["child_process.exec", "child_process.spawn", "eval(", "vm.runInContext("],
            "file_sinks": ["fs.readFile", "fs.writeFile", "fs.createReadStream"],
            "source_patterns": ["req.query", "req.body", "req.params", "req.headers"],
        },
    }

    def __init__(self):
        self.cwe_definitions = self.CWE_DEFINITIONS
        self.language_patterns = self.LANGUAGE_PATTERNS

    def infer_vulnerability(
        self,
        code_snippet: str,
        language: str,
        location: str = ""
    ) -> Optional[VulnerabilityInference]:
        """推理漏洞

        Args:
            code_snippet: 代码片段
            language: 编程语言
            location: 代码位置

        Returns:
            漏洞推理结果
        """
        for cwe_id, cwe_def in self.cwe_definitions.items():
            for sink_func in cwe_def["sink_functions"]:
                if sink_func in code_snippet:
                    confidence = self._calculate_confidence(
                        code_snippet, language, sink_func, cwe_def["exploit_patterns"]
                    )
                    if confidence >= 0.5:
                        exploit_pattern = self._detect_exploit_pattern(
                            code_snippet, cwe_def["exploit_patterns"]
                        )
                        return VulnerabilityInference(
                            cwe_id=cwe_id,
                            vulnerability_type=cwe_def["name"],
                            confidence=confidence,
                            sink_function=sink_func,
                            source_function=self._detect_source_function(code_snippet, language),
                            exploit_pattern=exploit_pattern,
                            language=language,
                            severity=cwe_def["severity"],
                            location=location,
                            evidence=[code_snippet[:200]],
                            recommendation=self._generate_recommendation(cwe_id, cwe_def["name"])
                        )
        return None

    def infer_sql_injection(
        self,
        code_snippet: str,
        language: str,
        location: str = ""
    ) -> Optional[VulnerabilityInference]:
        """专门推理 SQL 注入漏洞

        Args:
            code_snippet: 代码片段
            language: 编程语言
            location: 代码位置

        Returns:
            SQL 注入漏洞推理结果
        """
        cwe_def = self.cwe_definitions.get("CWE-89", {})
        if not cwe_def:
            return None

        sql_indicators = [
            "execute", "query", "SELECT", "INSERT", "UPDATE", "DELETE",
            "WHERE", "FROM", "JOIN", "${", "#{",
        ]

        has_sql = any(indicator in code_snippet.upper() for indicator in sql_indicators if len(indicator) > 2)
        has_dynamic = "${" in code_snippet or "#{ " in code_snippet or "+ " in code_snippet

        if has_sql and has_dynamic:
            confidence = 0.9
            exploit_pattern = "string_concatenation"
            sink_func = "cursor.execute"

            if "${" in code_snippet:
                confidence = 0.95
                exploit_pattern = "mybatis_interpolation"
                sink_func = "${"

            return VulnerabilityInference(
                cwe_id="CWE-89",
                vulnerability_type=cwe_def["name"],
                confidence=confidence,
                sink_function=sink_func,
                source_function=self._detect_source_function(code_snippet, language),
                exploit_pattern=exploit_pattern,
                language=language,
                severity=cwe_def["severity"],
                location=location,
                evidence=[code_snippet[:200]],
                recommendation=self._generate_recommendation("CWE-89", cwe_def["name"])
            )

        return None

    def infer_xss(
        self,
        code_snippet: str,
        language: str,
        location: str = ""
    ) -> Optional[VulnerabilityInference]:
        """专门推理 XSS 漏洞

        Args:
            code_snippet: 代码片段
            language: 编程语言
            location: 代码位置

        Returns:
            XSS 漏洞推理结果
        """
        cwe_def = self.cwe_definitions.get("CWE-79", {})
        if not cwe_def:
            return None

        xss_sinks = ["innerHTML", "outerHTML", "document.write", "html(", "text(", "append("]
        has_sink = any(sink in code_snippet for sink in xss_sinks)
        has_user_input = self._detect_source_function(code_snippet, language) is not None

        if has_sink and has_user_input:
            return VulnerabilityInference(
                cwe_id="CWE-79",
                vulnerability_type=cwe_def["name"],
                confidence=0.85,
                sink_function=next(sink for sink in xss_sinks if sink in code_snippet),
                source_function=self._detect_source_function(code_snippet, language),
                exploit_pattern="innerHTML_assignment",
                language=language,
                severity=cwe_def["severity"],
                location=location,
                evidence=[code_snippet[:200]],
                recommendation=self._generate_recommendation("CWE-79", cwe_def["name"])
            )

        return None

    def infer_path_traversal(
        self,
        code_snippet: str,
        language: str,
        location: str = ""
    ) -> Optional[VulnerabilityInference]:
        """专门推理路径遍历漏洞

        Args:
            code_snippet: 代码片段
            language: 编程语言
            location: 代码位置

        Returns:
            路径遍历漏洞推理结果
        """
        cwe_def = self.cwe_definitions.get("CWE-22", {})
        if not cwe_def:
            return None

        file_sinks = ["new File(", "File(", "open(", "readFile(", "createReadStream("]
        has_sink = any(sink in code_snippet for sink in file_sinks)
        has_concatenation = "+ " in code_snippet or "../" in code_snippet or ".." in code_snippet

        if has_sink and has_concatenation:
            return VulnerabilityInference(
                cwe_id="CWE-22",
                vulnerability_type=cwe_def["name"],
                confidence=0.8,
                sink_function=next(sink for sink in file_sinks if sink in code_snippet),
                source_function=self._detect_source_function(code_snippet, language),
                exploit_pattern="path_concatenation",
                language=language,
                severity=cwe_def["severity"],
                location=location,
                evidence=[code_snippet[:200]],
                recommendation=self._generate_recommendation("CWE-22", cwe_def["name"])
            )

        return None

    def batch_infer(
        self,
        code_snippets: List[Tuple[str, str, str]]
    ) -> List[VulnerabilityInference]:
        """批量推理漏洞

        Args:
            code_snippets: [(code_snippet, language, location), ...]

        Returns:
            漏洞推理结果列表
        """
        results = []
        for code, language, location in code_snippets:
            inferred = self.infer_vulnerability(code, language, location)
            if inferred:
                results.append(inferred)
        return results

    def _calculate_confidence(
        self,
        code_snippet: str,
        language: str,
        sink_function: str,
        exploit_patterns: List[str]
    ) -> float:
        """计算漏洞置信度"""
        confidence = 0.5

        if any(pattern in code_snippet for pattern in exploit_patterns):
            confidence += 0.2

        if self._detect_source_function(code_snippet, language):
            confidence += 0.15

        if len(code_snippet) > 50:
            confidence += 0.1

        if "${" in code_snippet or "#{" in code_snippet:
            confidence = min(confidence + 0.15, 0.98)

        if ".." in code_snippet or "../" in code_snippet:
            confidence = min(confidence + 0.1, 0.95)

        return min(confidence, 0.99)

    def _detect_exploit_pattern(self, code_snippet: str, patterns: List[str]) -> str:
        """检测利用模式"""
        for pattern in patterns:
            if pattern in code_snippet:
                return pattern
        return "unknown"

    def _detect_source_function(self, code_snippet: str, language: str) -> Optional[str]:
        """检测输入源函数"""
        if language not in self.language_patterns:
            return None

        source_patterns = self.language_patterns[language].get("source_patterns", [])
        for pattern in source_patterns:
            if pattern in code_snippet:
                return pattern

        if "request" in code_snippet.lower() or "input" in code_snippet.lower():
            return "user_input"

        return None

    def _generate_recommendation(self, cwe_id: str, vulnerability_type: str) -> str:
        """生成修复建议"""
        recommendations = {
            "CWE-89": "使用参数化查询（PreparedStatement）替代字符串拼接；避免使用 ${} 和 #{ } 直接拼接SQL",
            "CWE-79": "对用户输入进行 HTML 转义；使用 text() 而非 html() 方法；避免使用 eval() 处理用户输入",
            "CWE-22": "对用户输入进行路径规范化（realpath）；验证输入路径在允许范围内；避免直接拼接用户输入到文件路径",
            "CWE-259": "使用环境变量或配置中心存储密码；避免在代码中硬编码凭证",
            "CWE-321": "使用安全的随机数生成器创建密钥；将密钥存储在环境变量或密钥管理服务中",
            "CWE-352": "实现 CSRF Token 验证；检查 Referer/Origin 请求头",
            "CWE-601": "验证重定向 URL 在允许的域名列表内；避免直接使用用户输入作为重定向目标",
            "CWE-918": "验证用户输入的 URL 是否指向内部资源；使用 safelist 验证 URL 域名",
        }
        return recommendations.get(cwe_id, f"请修复 {vulnerability_type} 漏洞")

    def get_cwe_info(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """获取 CWE 信息"""
        return self.cwe_definitions.get(cwe_id)

    def list_supported_cwe(self) -> List[str]:
        """列出支持的 CWE"""
        return list(self.cwe_definitions.keys())
