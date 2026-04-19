"""漏洞验证模块

提供漏洞验证功能。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ValidationResult:
    """验证结果"""
    
    finding_id: str
    is_valid: bool
    confidence: float
    evidence: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class VulnerabilityValidator:
    """漏洞验证器
    
    验证发现的漏洞是否真实存在。
    """
    
    def __init__(self) -> None:
        self.validators = {
            "SQL_INJECTION": self._validate_sql_injection,
            "XSS": self._validate_xss,
            "COMMAND_INJECTION": self._validate_command_injection,
            "PATH_TRAVERSAL": self._validate_path_traversal,
            "SSRF": self._validate_ssrf,
            "PROMPT_INJECTION": self._validate_prompt_injection,
        }
    
    def validate(
        self,
        finding: Dict[str, Any],
        code_context: Optional[str] = None,
    ) -> ValidationResult:
        """验证漏洞
        
        Args:
            finding: 漏洞发现
            code_context: 代码上下文
            
        Returns:
            验证结果
        """
        finding_type = finding.get("type", finding.get("rule_id", "UNKNOWN"))
        
        validator = self.validators.get(finding_type)
        if validator:
            return validator(finding, code_context)
        
        # 默认验证
        return ValidationResult(
            finding_id=finding.get("id", "unknown"),
            is_valid=True,
            confidence=finding.get("confidence", 0.5),
            evidence="无法验证，使用原始置信度",
        )
    
    def _validate_sql_injection(
        self, finding: Dict[str, Any], code_context: Optional[str]
    ) -> ValidationResult:
        """验证 SQL 注入"""
        evidence = []
        reproduction_steps = []
        
        if code_context:
            # 检查是否存在用户输入
            user_input_patterns = [
                "request.", "input(", "args.", "params.",
                "$_GET", "$_POST", "req.body",
            ]
            has_user_input = any(
                pattern in code_context for pattern in user_input_patterns
            )
            
            # 检查是否存在 SQL 操作
            sql_patterns = [
                "execute(", "cursor.execute", "raw(",
                "SELECT", "INSERT", "UPDATE", "DELETE",
            ]
            has_sql = any(
                pattern in code_context.upper() for pattern in sql_patterns
            )
            
            # 检查是否存在参数化查询
            parameterized_patterns = [
                "?", "%s", ":param", "params=", "bindparam",
            ]
            has_parameterized = any(
                pattern in code_context for pattern in parameterized_patterns
            )
            
            if has_user_input and has_sql:
                if has_parameterized:
                    evidence.append("使用了参数化查询，风险较低")
                    confidence = 0.3
                else:
                    evidence.append("存在用户输入直接拼接到 SQL 的情况")
                    confidence = 0.9
                
                reproduction_steps = [
                    "1. 识别用户输入点",
                    "2. 构造 SQL 注入载荷",
                    "3. 观察数据库响应",
                ]
            else:
                confidence = 0.2
                evidence.append("未发现明显的 SQL 注入路径")
        else:
            confidence = finding.get("confidence", 0.5)
        
        return ValidationResult(
            finding_id=finding.get("id", "sql_injection"),
            is_valid=confidence > 0.5,
            confidence=confidence,
            evidence="; ".join(evidence),
            reproduction_steps=reproduction_steps,
        )
    
    def _validate_xss(
        self, finding: Dict[str, Any], code_context: Optional[str]
    ) -> ValidationResult:
        """验证 XSS"""
        evidence = []
        reproduction_steps = []
        
        if code_context:
            # 检查是否存在输出点
            output_patterns = [
                "innerHTML", "document.write", "render_template_string",
                "dangerouslySetInnerHTML", "|safe", "Markup",
            ]
            has_output = any(pattern in code_context for pattern in output_patterns)
            
            # 检查是否存在转义
            escape_patterns = [
                "escape(", "html.escape", "sanitize", "DOMPurify",
                "bleach.clean", "markupsafe.escape",
            ]
            has_escape = any(pattern in code_context for pattern in escape_patterns)
            
            if has_output:
                if has_escape:
                    evidence.append("存在输出转义，风险较低")
                    confidence = 0.3
                else:
                    evidence.append("存在未转义的输出点")
                    confidence = 0.85
                
                reproduction_steps = [
                    "1. 识别输出点",
                    "2. 注入 XSS 载荷",
                    "3. 检查是否执行脚本",
                ]
            else:
                confidence = 0.2
                evidence.append("未发现明显的 XSS 输出点")
        else:
            confidence = finding.get("confidence", 0.5)
        
        return ValidationResult(
            finding_id=finding.get("id", "xss"),
            is_valid=confidence > 0.5,
            confidence=confidence,
            evidence="; ".join(evidence),
            reproduction_steps=reproduction_steps,
        )
    
    def _validate_command_injection(
        self, finding: Dict[str, Any], code_context: Optional[str]
    ) -> ValidationResult:
        """验证命令注入"""
        evidence = []
        reproduction_steps = []
        
        if code_context:
            # 检查是否存在危险函数
            dangerous_functions = [
                "os.system", "subprocess.call", "subprocess.run",
                "subprocess.Popen", "eval(", "exec(",
            ]
            has_dangerous = any(
                func in code_context for func in dangerous_functions
            )
            
            # 检查是否存在 shell=True
            has_shell_true = "shell=True" in code_context
            
            if has_dangerous:
                if has_shell_true:
                    evidence.append("使用 shell=True，风险极高")
                    confidence = 0.95
                else:
                    evidence.append("存在危险函数调用")
                    confidence = 0.8
                
                reproduction_steps = [
                    "1. 识别命令执行点",
                    "2. 注入命令分隔符",
                    "3. 执行任意命令",
                ]
            else:
                confidence = 0.2
                evidence.append("未发现明显的命令注入点")
        else:
            confidence = finding.get("confidence", 0.5)
        
        return ValidationResult(
            finding_id=finding.get("id", "command_injection"),
            is_valid=confidence > 0.5,
            confidence=confidence,
            evidence="; ".join(evidence),
            reproduction_steps=reproduction_steps,
        )
    
    def _validate_path_traversal(
        self, finding: Dict[str, Any], code_context: Optional[str]
    ) -> ValidationResult:
        """验证路径遍历"""
        evidence = []
        reproduction_steps = []
        
        if code_context:
            # 检查是否存在文件操作
            file_operations = [
                "open(", "read(", "write(", "send_file(",
                "os.path.join", "Path(",
            ]
            has_file_op = any(op in code_context for op in file_operations)
            
            # 检查是否存在路径验证
            validation_patterns = [
                "os.path.abspath", "os.path.realpath", "resolve()",
                "startswith", "in safe_paths",
            ]
            has_validation = any(
                pattern in code_context for pattern in validation_patterns
            )
            
            if has_file_op:
                if has_validation:
                    evidence.append("存在路径验证，风险较低")
                    confidence = 0.3
                else:
                    evidence.append("存在未验证的文件路径操作")
                    confidence = 0.8
                
                reproduction_steps = [
                    "1. 识别文件路径输入点",
                    "2. 注入路径遍历载荷",
                    "3. 访问敏感文件",
                ]
            else:
                confidence = 0.2
                evidence.append("未发现明显的路径遍历点")
        else:
            confidence = finding.get("confidence", 0.5)
        
        return ValidationResult(
            finding_id=finding.get("id", "path_traversal"),
            is_valid=confidence > 0.5,
            confidence=confidence,
            evidence="; ".join(evidence),
            reproduction_steps=reproduction_steps,
        )
    
    def _validate_ssrf(
        self, finding: Dict[str, Any], code_context: Optional[str]
    ) -> ValidationResult:
        """验证 SSRF"""
        evidence = []
        reproduction_steps = []
        
        if code_context:
            # 检查是否存在 HTTP 请求
            http_patterns = [
                "requests.get", "requests.post", "urllib.request",
                "httpx.get", "httpx.post", "aiohttp",
            ]
            has_http = any(pattern in code_context for pattern in http_patterns)
            
            # 检查是否存在 URL 验证
            validation_patterns = [
                "allowed_hosts", "whitelist", "startswith",
                "in allowed", "validate_url",
            ]
            has_validation = any(
                pattern in code_context for pattern in validation_patterns
            )
            
            if has_http:
                if has_validation:
                    evidence.append("存在 URL 验证，风险较低")
                    confidence = 0.3
                else:
                    evidence.append("存在未验证的 HTTP 请求")
                    confidence = 0.8
                
                reproduction_steps = [
                    "1. 识别 URL 输入点",
                    "2. 注入内网地址",
                    "3. 访问内部服务",
                ]
            else:
                confidence = 0.2
                evidence.append("未发现明显的 SSRF 点")
        else:
            confidence = finding.get("confidence", 0.5)
        
        return ValidationResult(
            finding_id=finding.get("id", "ssrf"),
            is_valid=confidence > 0.5,
            confidence=confidence,
            evidence="; ".join(evidence),
            reproduction_steps=reproduction_steps,
        )
    
    def _validate_prompt_injection(
        self, finding: Dict[str, Any], code_context: Optional[str]
    ) -> ValidationResult:
        """验证 Prompt 注入"""
        evidence = []
        reproduction_steps = []
        
        if code_context:
            # 检查是否存在 prompt 构建
            prompt_patterns = [
                "prompt", "system_prompt", "messages",
                "format(", "f'", 'f"',
            ]
            has_prompt = any(pattern in code_context for pattern in prompt_patterns)
            
            # 检查是否存在输入验证
            validation_patterns = [
                "sanitize", "escape", "validate",
                "allowed_chars", "max_length",
            ]
            has_validation = any(
                pattern in code_context for pattern in validation_patterns
            )
            
            if has_prompt:
                if has_validation:
                    evidence.append("存在输入验证，风险较低")
                    confidence = 0.4
                else:
                    evidence.append("存在未验证的 prompt 构建")
                    confidence = 0.85
                
                reproduction_steps = [
                    "1. 识别 prompt 构建点",
                    "2. 注入指令覆盖载荷",
                    "3. 观察 AI 响应变化",
                ]
            else:
                confidence = 0.2
                evidence.append("未发现明显的 Prompt 注入点")
        else:
            confidence = finding.get("confidence", 0.5)
        
        return ValidationResult(
            finding_id=finding.get("id", "prompt_injection"),
            is_valid=confidence > 0.5,
            confidence=confidence,
            evidence="; ".join(evidence),
            reproduction_steps=reproduction_steps,
        )
