"""结果转换模块

将原始 Pipeline 输出转换为标准 VulnerabilityFinding 列表。
从 PureAIAnalyzer 中提取的工具方法集合。
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.ai.models import VulnerabilityFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


# 高危风险类型列表
HIGH_RISK_TYPES: Set[str] = {
    "CSRF", "csrf", "Cross-Site Request Forgery",
    "authentication", "Authentication", "认证",
    "authorization", "Authorization", "授权",
    "Privilege", "privilege", "越权",
    "token", "Token", "session", "Session", "令牌", "会话",
    "JWT", "OAuth", "OIDC", "SAML",
    "credential", "Credential", "凭证", "密码", "password", "Password",
    "IDOR", "idor", "访问控制", "access control",
    "SQL injection", "SQL注入", "sql injection", "SQL Injection",
    "XSS", "xss", "Cross-Site Scripting", "跨站脚本",
    "RCE", "rce", "Remote Code Execution", "命令执行",
    "SSRF", "ssrf", "Server-Side Request Forgery",
    "deserialize", "Deserialize", "反序列化", "serialization", "Serialization",
    "path traversal", "Path Traversal", "路径穿越",
    "directory traversal", "file inclusion", "File Inclusion", "文件包含",
    "LFI", "RFI",
    "XXE", "xxe", "XML External Entity",
    "SSTI", "ssti", "Server-Side Template Injection",
    "Race Condition", "race condition", "竞态条件",
    "Heap Inspection", "heap inspection",
    "Type Confusion", "type confusion",
}


class ResultConverter:
    """结果转换器 — 将 Pipeline 原始输出转换为标准化发现列表。

    包含从 PureAIAnalyzer 提取的纯工具方法集合。
    需要接收外部依赖（ai_model, client, nvd_adapter, debug_logs）作为参数或回调。
    """

    def __init__(
        self,
        config=None,
        ai_model=None,
        client=None,
        nvd_adapter=None,
        debug_logs: Optional[List[str]] = None,
    ):
        self.config = config
        self.ai_model = ai_model
        self.client = client
        self.nvd_adapter = nvd_adapter
        self.debug_logs = debug_logs or []

    def _verify_code_pattern_in_file(
        self, file_path: str, line_num: int, pattern_keywords: List[str]
    ) -> bool:
        """验证代码模式是否在指定行附近存在

        Args:
            file_path: 文件路径
            line_num: 行号
            pattern_keywords: 需要验证的关键词列表

        Returns:
            模式是否匹配
        """
        if not pattern_keywords:
            return True
        try:
            code_snippet = self._extract_code_at_line(file_path, line_num, context_lines=3)
            if not code_snippet:
                return False
            code_upper = code_snippet.upper()
            return any(kw.upper() in code_upper for kw in pattern_keywords)
        except Exception:
            return False

    def _translate_snake_case_name(self, snake_name: str) -> str:
        """将蛇形命名（snake_case）翻译为中文

        Args:
            snake_name: 蛇形命名（如 csrf_disabled）

        Returns:
            中文翻译（如 CSRF保护被禁用）
        """
        words = snake_name.split("_")
        if len(words) < 2:
            return snake_name

        # 蛇形命名关键词映射
        word_mapping = {
            "csr": "CSRF",
            "xss": "XSS",
            "sql": "SQL",
            "rce": "远程代码执行",
            "ssr": "SSRF",
            "xxe": "XXE",
            "cors": "CORS",
            "jwt": "JWT",
            "token": "令牌",
            "disabled": "被禁用",
            "disable": "禁用",
            "enabled": "被启用",
            "enable": "启用",
            "bypass": "绕过",
            "leakage": "泄露",
            "leak": "泄露",
            "exposure": "暴露",
            "hardcoded": "硬编码",
            "hard": "硬编码",
            "encoded": "编码",
            "missing": "缺失",
            "weak": "弱",
            "insecure": "不安全",
            "unauthorized": "未授权",
            "permit": "允许",
            "all": "所有",
            "url": "URL",
            "path": "路径",
            "exception": "异常",
            "unhandled": "未处理",
            "transport": "传输",
            "clickjack": "点击劫持",
            "frame": "框架",
            "options": "选项",
            "config": "配置",
            "configuration": "配置",
            "auth": "认证",
            "password": "密码",
            "credential": "凭据",
            "secret": "密钥",
            "api": "API",
            "key": "密钥",
            "data": "数据",
            "sensitive": "敏感",
            "information": "信息",
            "disclosure": "泄露",
            "injection": "注入",
            "upload": "上传",
            "file": "文件",
            "command": "命令",
            "redirect": "重定向",
            "open": "开放",
            "deserialization": "反序列化",
            "serialization": "序列化",
            "debug": "调试",
            "mode": "模式",
            "error": "错误",
            "handling": "处理",
            "stack": "堆栈",
            "trace": "跟踪",
            "session": "会话",
            "storage": "存储",
            "local": "本地",
            "best": "最佳",
            "practice": "实践",
            "code": "代码",
            "smell": "规范问题",
            "pattern": "模式",
            "suspicious": "可疑",
            "security": "安全",
            "misconfiguration": "配置错误",
            "setting": "设置",
            "swagger": "Swagger文档",
            "value": "值",
            "object": "对象",
            "user": "用户",
            "complete": "完整",
            "full": "完整",
            "refresh": "刷新",
            "scope": "作用域",
            "protection": "保护",
            "cache": "缓存",
            "log": "日志",
            "print": "打印",
            "output": "输出",
            "input": "输入",
            "validation": "验证",
            "sanitize": "清洗",
            "encoding": "编码",
            "escaping": "转义",
        }

        # 特殊组合映射
        special_combinations = {
            "csrf_disabled": "CSRF保护被禁用",
            "csrf_protection_disabled": "CSRF保护被禁用",
            "permit_all_url_bypass": "允许所有URL绕过安全检查",
            "token_transport_leakage": "令牌传输过程中泄露",
            "unhandled_exception": "未处理的异常",
            "x_frame_options_missing": "X-Frame-Options响应头缺失",
            "clickjacking_risk": "点击劫持风险",
            "hardcoded_credential": "硬编码凭据",
            "hardcoded_password": "硬编码密码",
            "hardcoded_secret": "硬编码密钥",
            "hardcoded_api_key": "硬编码API密钥",
            "sensitive_data_exposure": "敏感数据泄露",
            "information_disclosure": "信息泄露",
            "weak_encryption": "弱加密算法",
            "insecure_configuration": "不安全配置",
            "debug_mode_enabled": "调试模式被启用",
            "error_handling_issue": "错误处理问题",
            "stack_trace_disclosure": "堆栈跟踪泄露",
            "cors_misconfiguration": "CORS配置错误",
            "missing_authentication": "缺少认证",
            "missing_authorization": "缺少授权",
            "session_fixation": "会话固定攻击",
            "open_redirect": "开放重定向",
            "sql_injection": "SQL注入",
            "command_injection": "命令注入",
            "path_traversal": "路径遍历",
            "file_upload_vulnerability": "文件上传漏洞",
            "deserialization_vulnerability": "反序列化漏洞",
            "xxe_vulnerability": "XXE漏洞",
            "ssrf_vulnerability": "SSRF漏洞",
            "xss_reflected": "反射型XSS",
            "xss_stored": "存储型XSS",
            "xss_dom": "DOM型XSS",
            "swagger_exposure": "Swagger文档暴露",
            "api_doc_exposure": "API文档暴露",
            "refresh_scope_risk": "RefreshScope风险",
            "configuration_binding_risk": "配置绑定风险",
        }

        # 先检查特殊组合映射
        full_snake = snake_name.lower()
        if full_snake in special_combinations:
            return special_combinations[full_snake]

        # 逐个单词翻译并组合
        translated_parts = []
        for word in words:
            word_lower = word.lower()
            if word_lower in word_mapping:
                translated_parts.append(word_mapping[word_lower])
            else:
                # 保留原始单词
                translated_parts.append(word)

        # 如果有任何部分未翻译，返回原始名称
        if any(p.isalpha() for p in translated_parts if isinstance(p, str)):
            # 仍有英文单词未翻译
            return snake_name

        return "".join(translated_parts)

    async def _translate_vulnerability_name_ai_async(self, vulnerability: str) -> str:
        """使用真正的AI进行漏洞名称翻译（异步版本）

        通过AI模型将英文漏洞名称翻译为中文，结合NVD CVE数据库上下文。

        Args:
            vulnerability: 原始漏洞名称（英文）

        Returns:
            中文漏洞名称
        """
        if not vulnerability:
            return "未知漏洞"

        # nvd_context = ""
        if self.nvd_adapter and self.nvd_adapter.is_available():
            try:
                keywords = [vulnerability]
                cwe_results = self.nvd_adapter.match_cwe(keywords, limit=1)
                if cwe_results and len(cwe_results) > 0:
                    # cwe_info = cwe_results[0]
                    # nvd_context = cwe_info.get("cwe_description", "")
                    pass
            except Exception as e:
                logger.debug(f"静默异常: {type(e).__name__}: {e}")

        prompt = """你是一个安全漏洞专家。请将以下漏洞名称翻译为中文。

漏洞名称: {vulnerability}
{f'相关NVD描述: {nvd_context}' if nvd_context else ''}

要求:
1. 只输出中文翻译，不要解释，不要添加任何额外内容
2. 使用安全领域的标准术语
3. 如果无法翻译或无法确定，返回原名称
4. 翻译要准确、简洁、专业

中文翻译:"""

        try:
            if not self.client:
                return self._normalize_vulnerability_name(vulnerability)

            from src.ai.models import AIRequest

            ai_request = AIRequest(
                prompt=prompt, model=self.ai_model, temperature=0.1, max_tokens=100
            )
            response = await self.client.generate(ai_request)
            translation = str(response.content).strip()
            if translation and translation != vulnerability:
                return translation
            return self._normalize_vulnerability_name(vulnerability)
        except Exception as e:
            logger.debug(f"AI翻译失败，使用fallback: {e}")
            return self._normalize_vulnerability_name(vulnerability)

    def _extract_code_at_line(self, file_path: str, line_num: int, context_lines: int = 2) -> str:
        """提取指定行及其上下文的代码

        Args:
            file_path: 文件路径
            line_num: 行号（1-based）
            context_lines: 上下文行数

        Returns:
            代码片段
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return ""
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                if line_num <= 0 or line_num > len(lines):
                    return ""
                start = max(0, line_num - context_lines)
                end = min(len(lines), line_num + context_lines + 1)
                return "".join(lines[start:end])
        except Exception:
            return ""

    def _validate_finding_location(
        self, finding: Dict[str, Any], file_path_context: str
    ) -> Dict[str, Any]:
        """验证漏洞发现的位置和代码是否真实存在

        Args:
            finding: 漏洞发现
            file_path_context: 文件路径上下文

        Returns:
            验证结果，包含 is_valid, reason, verified_line 等信息
        """
        location = finding.get("location", "")
        if not location:
            return {"is_valid": False, "reason": "位置信息为空"}

        # 解析位置：可能是 "文件名:行号" 或 "完整路径:行号" 格式
        file_name = ""
        line_num = 0

        if isinstance(location, str) and ":" in location:
            parts = location.rsplit(":", 1)
            if len(parts) == 2:
                potential_drive = parts[0]
                potential_line = parts[1]
                if len(potential_drive) == 1 and potential_drive.isalpha():
                    file_name = (
                        potential_drive + ":" + potential_line.rsplit(":", 1)[0]
                        if ":" in potential_line
                        else location
                    )
                    try:
                        line_num = int(potential_line.rsplit(":", 1)[-1])
                    except ValueError:
                        line_num = 0
                else:
                    file_name = parts[0]
                    try:
                        line_num = int(parts[1])
                    except ValueError:
                        return {"is_valid": False, "reason": f"行号无效: {parts[1]}"}
        elif isinstance(location, dict):
            file_name = location.get("file", "")
            line_num = location.get("line", 0)

        # 确定要检查的文件路径
        check_file = file_name if file_name else file_path_context
        if check_file and not Path(check_file).is_absolute():
            # 如果是相对路径，尝试相对于原始文件目录
            if file_path_context:
                base_dir = str(Path(file_path_context).parent)
                check_file = str(Path(base_dir) / check_file)

        # 检查行号是否存在
        if line_num > 0 and check_file:
            if not self._line_exists_in_file(check_file, line_num):
                return {
                    "is_valid": False,
                    "reason": f"声称的位置 {check_file}:{line_num} 行不存在或文件无法读取",
                    "file": check_file,
                    "line": line_num,
                }

            # 如果发现中有 code_snippet，验证关键词是否在代码中
            code_snippet = finding.get("code_snippet", "")
            if code_snippet:
                # 提取关键词（过滤掉常见的非代码词）
                keywords = [kw.strip() for kw in code_snippet.split() if len(kw) > 3]
                suspicious_keywords = ["EXAMPLE", "SAMPLE", "TEST", "DEMO", "FIXME", "TODO", "XXX"]
                meaningful_keywords = [
                    kw for kw in keywords if kw.upper() not in suspicious_keywords
                ]
                if meaningful_keywords:
                    if not self._verify_code_pattern_in_file(
                        check_file, line_num, meaningful_keywords[:5]
                    ):
                        return {
                            "is_valid": False,
                            "reason": "声称的问题代码模式在指定位置附近未找到匹配",
                            "file": check_file,
                            "line": line_num,
                        }

        return {"is_valid": True, "reason": "位置验证通过", "file": check_file, "line": line_num}

    def _line_exists_in_file(self, file_path: str, line_num: int) -> bool:
        """验证指定行号是否在文件真实存在

        Args:
            file_path: 文件路径
            line_num: 行号

        Returns:
            行号是否有效
        """
        if not file_path or line_num <= 0:
            return False
        try:
            path = Path(file_path)
            if not path.exists():
                return False
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                return 0 < line_num <= len(lines)
        except Exception:
            return False

    def _contains_chinese(self, text: str) -> bool:
        """检查文本是否包含中文字符"""
        for char in text:
            if "\u4e00" <= char <= "\u9fff":
                return True
        return False

    def _normalize_vulnerability_name(self, vulnerability: str) -> str:
        """将英文漏洞名称翻译为中文

        Args:
            vulnerability: 原始漏洞名称（可能是英文或中文）

        Returns:
            中文漏洞名称
        """
        if not vulnerability:
            return "未知漏洞"

        vuln_upper = vulnerability.upper()
        vuln_lower = vulnerability.lower()

        mapping = {
            "SQL INJECTION": "SQL注入",
            "SQL_INJECTION": "SQL注入",
            "SQLINJECTION": "SQL注入",
            "SQL": "SQL注入",
            "XSS": "跨站脚本攻击",
            "CROSS-SITE SCRIPTING": "跨站脚本攻击",
            "CROSS SITE SCRIPTING": "跨站脚本攻击",
            "CSRF": "跨站请求伪造",
            "CROSS-SITE REQUEST FORGERY": "跨站请求伪造",
            "CROSS SITE REQUEST FORGERY": "跨站请求伪造",
            "SSRF": "服务器端请求伪造",
            "SERVER-SIDE REQUEST FORGERY": "服务器端请求伪造",
            "PATH TRAVERSAL": "路径遍历",
            "PATH_TRAVERSAL": "路径遍历",
            "DIRECTORY TRAVERSAL": "目录遍历",
            "COMMAND INJECTION": "命令注入",
            "COMMAND_INJECTION": "命令注入",
            "RCE": "远程代码执行",
            "REMOTE CODE EXECUTION": "远程代码执行",
            "XXE": "XML外部实体注入",
            "LFI": "本地文件包含",
            "LOCAL FILE INCLUSION": "本地文件包含",
            "RFI": "远程文件包含",
            "REMOTE FILE INCLUSION": "远程文件包含",
            "IDOR": "越权访问",
            "INSECURE DIRECT OBJECT REFERENCE": "越权访问",
            "SSTI": "服务器端模板注入",
            "SERVER SIDE TEMPLATE INJECTION": "服务器端模板注入",
            "SENSITIVE DATA EXPOSURE": "敏感数据泄露",
            "DATA EXPOSURE": "敏感数据泄露",
            "INFORMATION DISCLOSURE": "信息泄露",
            "WEAK CRYPTOGRAPHY": "弱加密算法",
            "WEAK ENCRYPTION": "弱加密算法",
            "INSECURE ENCRYPTION": "不安全加密",
            "HARDCODED CREDENTIAL": "硬编码凭据",
            "HARDCODED PASSWORD": "硬编码密码",
            "HARDCODED SECRET": "硬编码密钥",
            "HARDCODED API KEY": "硬编码API密钥",
            "JWT VULNERABILITY": "JWT安全漏洞",
            "JWT": "令牌安全漏洞",
            "TOKEN": "令牌安全漏洞",
            "BEARER TOKEN": "令牌安全漏洞",
            "CORS MISCONFIGURATION": "CORS配置不当",
            "CORS": "跨域资源共享配置不当",
            "DESERIALIZATION": "反序列化漏洞",
            "INSECURE DESERIALIZATION": "不安全反序列化",
            "OPEN REDIRECT": "开放重定向",
            "UNVALIDATED REDIRECT": "未验证重定向",
            "BUFFER OVERFLOW": "缓冲区溢出",
            "PRINTF FORMAT STRING": "格式化字符串漏洞",
            "PATH DEPENDENCY": "路径依赖风险",
            "HARDCODED PATH": "硬编码路径",
            "CREDENTIAL": "凭据安全风险",
            "PASSWORD": "密码安全风险",
            "SECRET": "密钥安全风险",
            "APIKEY": "API密钥安全风险",
            "FRAME OPTIONS": "X-Frame-Options配置问题",
            "X-FRAME-OPTIONS": "X-Frame-Options配置问题",
            "CSRF PROTECTION": "CSRF保护缺失",
            "CSRF PROTECTION DISABLED": "CSRF保护被禁用",
            "AUTHORIZATION": "授权问题",
            "UNAUTHORIZED": "未授权访问",
            "AUTHORIZATION BYPASS": "授权绕过",
            "AUTHENTICATION": "认证问题",
            "WEAK AUTHENTICATION": "弱认证",
            "SESSION": "会话管理问题",
            "SESSION FIXATION": "会话固定",
            "REMOTE TOKEN SERVICE": "远程令牌服务风险",
            "REMOTETOKENSERVICES": "远程令牌服务风险",
            "SWAGGER": "Swagger文档暴露",
            "API DOCUMENTATION": "API文档暴露",
            "DEBUG MODE": "调试模式启用",
            "DEBUG": "调试信息泄露",
            "ERROR HANDLING": "错误处理问题",
            "STACK TRACE": "堆栈跟踪泄露",
            "XML INJECTION": "XML注入",
            "JSON INJECTION": "JSON注入",
            "CLICKJACKING": "点击劫持",
            "MIME SNIFFING": "MIME类型嗅探",
            "DOM XSS": "DOM型跨站脚本",
            "STORAGE": "存储安全风险",
            "LOCAL STORAGE": "本地存储风险",
            "SESSION STORAGE": "会话存储风险",
            "BEST PRACTICE": "最佳实践违规",
            "CODE SMELL": "代码规范问题",
            "CONFIGURATION": "配置问题",
            "MISCONFIGURATION": "配置错误",
            "INSECURE CONFIGURATION": "不安全配置",
            "SUSPICIOUS PATTERN": "可疑模式",
            "SUSPICIOUS_PATTERN": "可疑模式",
            "SUSPICIOUS": "可疑模式",
            "PATTERN": "模式",
            "WEAK SECURITY SIGNAL": "弱安全信号",
            "WEAK_SECURITY_SIGNAL": "弱安全信号",
            "WEAK_SIGNAL": "弱安全信号",
            "SECURITY MISCONFIGURATION": "安全配置错误",
            "INSECURE SETTING": "不安全设置",
            "INSECURE CONFIG": "不安全配置",
            "SECURITY CONFIG": "安全配置",
            "HARDCODED": "硬编码",
            "HARDCODED VALUE": "硬编码值",
            "HARDCODED CONFIG": "硬编码配置",
        }

        if vuln_upper in mapping:
            return mapping[vuln_upper]

        keyword_mappings = [
            (["SQL", "INJECT"], "SQL注入"),
            (["INJECTION"], "注入漏洞"),
            (["XSS", "CROSS SITE", "CROSS-SITE"], "跨站脚本攻击"),
            (["CSRF", "CROSS SITE REQUEST", "CROSS-SITE REQUEST"], "跨站请求伪造"),
            (["SSRF", "SERVER SIDE REQUEST"], "服务器端请求伪造"),
            (["PATH", "TRAVERSAL"], "路径遍历"),
            (["COMMAND", "INJECT", "EXEC"], "命令注入/远程代码执行"),
            (["RCE", "REMOTE CODE"], "远程代码执行"),
            (["XXE", "XML EXTERNAL"], "XML外部实体注入"),
            (["LFI", "LOCAL FILE"], "本地文件包含"),
            (["RFI", "REMOTE FILE"], "远程文件包含"),
            (["IDOR", "DIRECT OBJECT"], "越权访问"),
            (["SSTI", "TEMPLATE INJECTION"], "服务器端模板注入"),
            (["SENSITIVE", "DATA", "EXPOSURE"], "敏感数据泄露"),
            (["WEAK", "CRYPTO", "ENCRYPT"], "弱加密算法"),
            (["HARDCODED", "CREDENTIAL", "PASSWORD", "SECRET", "API"], "硬编码凭据"),
            (["JWT", "TOKEN", "BEARER"], "令牌安全漏洞"),
            (["CORS", "CROSS ORIGIN"], "跨域资源配置不当"),
            (["DESERIALIZ"], "反序列化漏洞"),
            (["OPEN REDIRECT", "UNVALIDATED REDIRECT"], "开放重定向"),
            (["BUFFER OVERFLOW"], "缓冲区溢出"),
            (["FORMAT STRING"], "格式化字符串漏洞"),
            (["PATH DEPENDENCY", "HARDCODED PATH"], "硬编码路径风险"),
            (["FRAME OPTIONS", "X-FRAME"], "X-Frame-Options配置问题"),
            (["CSRF PROTECTION DISABLED", "CSRF DISABLED"], "CSRF保护被禁用"),
            (["UNAUTHORIZED", "AUTHZ BYPASS"], "未授权访问"),
            (["AUTHENTICATION"], "认证问题"),
            (["SESSION FIXATION"], "会话固定攻击"),
            (["REMOTE TOKEN", "REMOTETOKEN"], "远程令牌服务风险"),
            (["SWAGGER", "API DOC"], "API文档暴露"),
            (["DEBUG MODE", "DEBUG"], "调试模式启用"),
            (["ERROR HANDLING", "STACK TRACE"], "错误处理问题"),
            (["XML INJECTION"], "XML注入"),
            (["JSON INJECTION"], "JSON注入"),
            (["CLICKJACKING"], "点击劫持"),
            (["MIME SNIFF"], "MIME类型嗅探"),
            (["DOM XSS"], "DOM型跨站脚本"),
            (["LOCAL STORAGE", "SESSION STORAGE"], "本地存储风险"),
            (["BEST PRACTICE", "CODE SMELL"], "代码规范问题"),
            (["CONFIGURATION", "MISCONFIGURATION"], "配置问题"),
            (["REFINED", "REJECTED", "UNCERTAIN"], "待确认风险"),
            (["RISK", "SIGNAL"], "风险信号"),
            (["SUSPICIOUS", "PATTERN"], "可疑模式"),
            (["WEAK", "SECURITY", "SIGNAL"], "弱安全信号"),
            (["SECURITY", "MISCONFIGURATION"], "安全配置错误"),
            (["HARDCODED", "VALUE"], "硬编码值"),
            (["HARDCODED", "CONFIG"], "硬编码配置"),
            (["INSECURE", "SETTING"], "不安全设置"),
            (["INSECURE", "CONFIG"], "不安全配置"),
        ]

        for keywords, chinese in keyword_mappings:
            if all(kw in vuln_upper or kw.lower() in vuln_lower for kw in keywords if len(kw) > 3):
                return chinese

        # 处理蛇形命名（snake_case）：拆分为单词并逐个翻译
        if "_" in vulnerability and not self._contains_chinese(vulnerability):
            snake_case_translation = self._translate_snake_case_name(vulnerability)
            if snake_case_translation and snake_case_translation != vulnerability:
                return snake_case_translation

        if any(
            term in vuln_upper
            for term in [
                "VULNERABILITY",
                "VULN",
                "ISSUE",
                "PROBLEM",
                "RISK",
                "WEAK",
                "INSECURE",
                "MISSING",
                "WITHOUT",
            ]
        ):
            if vulnerability.endswith("相关安全风险"):
                return vulnerability
            if any(
                term in vuln_upper for term in ["UNVERIFIED", "UNKNOWN", "GENERIC", "PLACEHOLDER"]
            ):
                return vulnerability
            return f"{vulnerability}相关安全风险"

        return vulnerability

    def _extract_location_from_evidence(
        self, finding: Dict[str, Any], file_path_context: str
    ) -> str:
        """从evidence中提取位置信息

        Args:
            finding: 发现数据
            file_path_context: 文件路径上下文

        Returns:
            提取的位置字符串
        """
        evidence = finding.get("evidence", [])
        if not evidence:
            return file_path_context

        if isinstance(evidence, list):
            for ev in evidence:
                if isinstance(ev, dict):
                    loc = ev.get("location", "")
                    if loc and loc not in ("N/A", "Unknown", "", None):
                        if isinstance(loc, (int, float)):
                            return f"{Path(file_path_context).name}:{int(loc)}"
                        if ":" in str(loc) and str(loc).count(":") >= 2:
                            return str(loc)
                        if ":" in str(loc):
                            parts = str(loc).rsplit(":", 1)
                            if len(parts) == 2 and parts[0].endswith(
                                (".java", ".py", ".js", ".ts", ".go", ".rb")
                            ):
                                return str(loc)
                        return f"{Path(file_path_context).name}:{loc}"
        elif isinstance(evidence, dict):
            loc = evidence.get("location", "")
            if loc and loc not in ("N/A", "Unknown", "", None):
                if ":" in str(loc) and str(loc).count(":") >= 2:
                    return str(loc)
                return f"{Path(file_path_context).name}:{loc}"

        return file_path_context

    def _is_high_risk_type(self, title: str) -> bool:
        """检查是否为高危风险类型

        Args:
            title: 风险标题

        Returns:
            是否为高危风险
        """
        if not title:
            return False
        title_lower = title.lower()
        for pattern in self.HIGH_RISK_TYPES:
            if pattern in title_lower:
                return True
        return False

    def _generate_detailed_description(self, vulnerability: str, finding: Dict[str, Any]) -> str:
        """根据漏洞类型生成详细的中文描述

        Args:
            vulnerability: 漏洞名称
            finding: 漏洞发现数据

        Returns:
            详细的中文描述
        """
        vuln_upper = vulnerability.upper()
        evidence_list = finding.get("evidence", [])
        # evidence_text = ""  # noqa: F841 - 保留用于后续扩展
        if evidence_list and isinstance(evidence_list, list):
            # evidence_text = " ".join(
            #     [
            #         e.get("reason", e.get("description", "")) if isinstance(e, dict) else str(e)
            #         for e in evidence_list[:3]
            #     ]
            # )
            pass

        # combined = f"{vuln_upper} {evidence_text.upper()}"

        if "SQL" in vuln_upper or "INJECT" in vuln_upper:
            return "SQL注入漏洞：攻击者可通过在用户输入中注入恶意SQL语句来操作数据库，可能导致敏感数据泄露、数据篡改或服务器沦陷。常见于使用字符串拼接构建SQL查询的场景。"
        elif (
            "UNAUTHORIZED" in vuln_upper
            or "ACCESS" in vuln_upper
            or "未授权" in vulnerability
            or "越权" in vulnerability
        ):
            return "未授权访问/越权漏洞：应用程序未对用户操作权限进行充分验证，导致低权限用户可执行高权限操作或访问他人资源。可能导致数据泄露、账户劫持或业务逻辑被恶意利用。"
        elif "XSS" in vuln_upper or "跨站脚本" in vulnerability:
            return "跨站脚本(XSS)漏洞：攻击者可在页面中注入恶意JavaScript代码，窃取用户Cookie、会话令牌或劫持用户操作。常见于未对用户输入进行HTML编码就输出到页面的场景。"
        elif "CSRF" in vuln_upper or "跨站请求伪造" in vulnerability:
            return "跨站请求伪造(CSRF)漏洞：攻击者诱骗已登录用户在不知情的情况下发起恶意请求，可导致账户设置被修改、密码被更改等敏感操作被执行。"
        elif "PATH" in vuln_upper and (
            "TRAVERSAL" in vuln_upper or "遍历" in vulnerability or "路径" in vulnerability
        ):
            return "路径遍历漏洞：应用程序对用户提供的文件路径未进行充分验证，攻击者可通过构造 '../' 等特殊字符序列访问服务器上的敏感文件。"
        elif "COMMAND" in vuln_upper or "RCE" in vuln_upper or "命令注入" in vulnerability:
            return "命令注入/远程代码执行漏洞：应用程序将用户输入传递给系统命令执行函数，攻击者可通过构造恶意命令在服务器上执行任意代码，获取服务器完全控制权。"
        elif (
            "CREDENTIAL" in vuln_upper
            or "PASSWORD" in vuln_upper
            or "SECRET" in vuln_upper
            or "KEY" in vuln_upper
            or "凭据" in vulnerability
            or "密码" in vulnerability
        ):
            return "硬编码凭据风险：代码中包含硬编码的敏感凭据（如密码、API密钥、加密密钥），可能被源码泄露或通过代码审查被发现，造成严重安全风险。建议使用环境变量或密钥管理系统存储敏感信息。"
        elif (
            "SENSITIVE" in vuln_upper
            or "DATA EXPOSURE" in vuln_upper
            or "暴露" in vulnerability
            or "泄露" in vulnerability
        ):
            return "敏感数据泄露：应用程序在响应、日志或令牌中暴露了不应公开的敏感信息（如用户密码、身份证号、银行卡号等），违反数据保护合规要求。"
        elif "JWT" in vuln_upper or "TOKEN" in vuln_upper or "令牌" in vulnerability:
            return "令牌安全配置问题：令牌的生成、验证或存储存在安全缺陷，可能被伪造、窃取或重放，导致会话劫持或身份冒充。"
        elif "SSRF" in vuln_upper or "服务端请求伪造" in vulnerability:
            return "服务端请求伪造(SSRF)漏洞：应用程序从用户指定URL获取资源时未进行充分验证，攻击者可利用此漏洞访问内网服务、读取本地文件或探测内网结构。"
        elif "DESERIALIZ" in vuln_upper or "反序列化" in vulnerability:
            return "不安全的反序列化漏洞：应用程序反序列化来自不可信源的数据，攻击者可通过构造恶意序列化对象执行任意代码或进行拒绝服务攻击。"
        elif (
            "WEAK" in vuln_upper
            or "ENCRYPT" in vuln_upper
            or "加密" in vulnerability
            or "CRYPTO" in vuln_upper
        ):
            return "弱加密算法风险：使用了存在已知攻击方法或密钥长度不足的加密算法（如MD5、SHA1、DES等），攻击者可能破解敏感数据。"
        elif "CORS" in vuln_upper or "跨域" in vulnerability:
            return "CORS配置不当：跨域资源共享(CORS)策略配置过于宽松，允许任意来源的跨域请求，可能导致敏感API被恶意网站调用。"
        elif "UPLOAD" in vuln_upper or "上传" in vulnerability:
            return "文件上传漏洞：应用程序对用户上传文件的类型、内容和大小缺乏充分验证，攻击者可上传恶意文件（如WebShell）并执行任意代码。"
        elif "REDIS" in vuln_upper or "CACHE" in vuln_upper or "缓存" in vulnerability:
            return "缓存安全配置问题：缓存机制未进行适当的访问控制或数据隔离，不同用户/租户的数据可能发生混淆，导致信息泄露。"
        elif (
            "HARDCODED" in vuln_upper
            or "硬编码" in vulnerability
            or "RESOURCE" in vuln_upper
            or "路径" in vulnerability
            or "配置" in vulnerability
        ):
            if "PATH" in vuln_upper or "路径" in vulnerability:
                return "硬编码路径风险：代码中包含硬编码的文件路径或资源路径，可能导致在不同环境或部署配置下出现路径错误，降低系统的可移植性和配置灵活性。"
            elif (
                "CREDENTIAL" in vuln_upper
                or "PASSWORD" in vuln_upper
                or "SECRET" in vuln_upper
                or "KEY" in vuln_upper
            ):
                return "硬编码凭据风险：代码中包含硬编码的敏感凭据（如密码、API密钥、加密密钥），可能被源码泄露或通过代码审查被发现，造成严重安全风险。建议使用环境变量或密钥管理系统存储敏感信息。"
            else:
                return "硬编码配置风险：代码中包含硬编码的配置值，降低了系统的可配置性和可维护性。建议将配置外部化到配置文件或环境变量中。"
        else:
            evidence = (
                finding.get("evidence_chain_summary", "")
                or finding.get("reason", "")
                or finding.get("description", "")
            )
            if evidence and len(evidence) > 20:
                return f"安全风险：{evidence[:150]}..."
            if (
                "evidence" in finding
                and isinstance(finding["evidence"], list)
                and len(finding["evidence"]) > 0
            ):
                ev = finding["evidence"][0]
                if isinstance(ev, dict):
                    reason = ev.get("reason", ev.get("description", ""))
                    if reason and len(reason) > 15:
                        return f"发现可疑代码模式：{reason[:100]}..."
            return f"发现{vulnerability}相关安全风险，建议根据详细代码上下文进行人工复核确认。"

    HIGH_RISK_TYPES = [
        "sql",
        "sql注入",
        "sql injection",
        "sqli",
        "xss",
        "cross-site",
        "跨站脚本",
        "csrf",
        "cross-site request",
        "认证",
        "authentication",
        "auth bypass",
        "认证绕过",
        "授权",
        "authorization",
        "越权",
        "权限",
        "session",
        "会话",
        "敏感信息",
        "sensitive",
        "password",
        "secret",
        "token",
        "注入",
        "injection",
        "文件上传",
        "file upload",
        "路径遍历",
        "path traversal",
        "directory traversal",
        "命令执行",
        "command execution",
        "rce",
        "远程代码执行",
        "remote code execution",
        "xxe",
        "xml external entity",
        "反序列化",
        "deserialization",
        "serialization",
        "cors",
        "跨域",
        "ssl",
        "tls",
        "证书",
        "中间人",
        "mitm",
    ]

    def _calculate_evidence_confidence(self, evidence: Any) -> float:
        """计算证据列表的动态置信度

        Args:
            evidence: 证据列表

        Returns:
            动态置信度（0.0-1.0），基于证据质量和数量计算
        """
        logger.debug("AI 动态置信度引导已添加")
        if not evidence:
            return 0.0

        if isinstance(evidence, list):
            if len(evidence) == 0:
                return 0.0

            evidence_count = len(evidence)
            evidence_quality_score = 0.0
            context_completeness = 0.0
            attack_path_clarity = 0.0
            confidence_values = []

            for item in evidence:
                if isinstance(item, dict):
                    item_confidence = item.get("confidence", 0.5)
                    if isinstance(item_confidence, (int, float)):
                        evidence_quality_score += item_confidence
                        confidence_values.append(float(item_confidence))

                    code_snippet = item.get("code_snippet", "")
                    location = item.get("location", "")
                    reason = item.get("reason", "")

                    if code_snippet and len(code_snippet) > 10:
                        context_completeness += 0.15
                    if location and location not in ("N/A", "Unknown", "", None):
                        context_completeness += 0.1
                    if reason and len(reason) > 20:
                        attack_path_clarity += 0.15

            evidence_quality_avg = (
                evidence_quality_score / evidence_count if evidence_count > 0 else 0.0
            )

            if evidence_count <= 3:
                base_confidence = 0.3
            elif evidence_count <= 6:
                base_confidence = 0.5
            else:
                base_confidence = 0.7

            context_completeness = min(context_completeness, 0.3)
            attack_path_clarity = min(attack_path_clarity, 0.3)

            dynamic_confidence = (
                base_confidence * 0.4
                + evidence_quality_avg * 0.3
                + context_completeness
                + attack_path_clarity
            )

            confidence_dispersion = self._calculate_confidence_dispersion(confidence_values)
            if confidence_dispersion < 0.05 and evidence_quality_avg > 0.7:
                dynamic_confidence *= 0.85

            return min(max(dynamic_confidence, 0.0), 0.95)

        if isinstance(evidence, dict) and "confidence" in evidence:
            conf = evidence["confidence"]
            if isinstance(conf, (int, float)):
                return float(conf)

        return 0.5

    def normalize_severity(self, severity: str) -> str:
        """确保严重等级合法

        Args:
            severity: 原始严重等级

        Returns:
            合法的严重等级（CRITICAL/HIGH/MEDIUM/LOW/INFO）
        """
        if not severity:
            return "MEDIUM"

        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        normalized = severity.upper().strip()

        if normalized in valid_severities:
            return normalized

        if "critical" in normalized or "严重" in severity:
            return "CRITICAL"
        elif "high" in normalized or "高" in severity:
            return "HIGH"
        elif "medium" in normalized or "中" in severity:
            return "MEDIUM"
        elif "low" in normalized or "低" in severity:
            return "LOW"
        elif "info" in normalized or "信息" in severity:
            return "INFO"

        logger.debug(f"[normalize_severity] 未知严重等级 '{severity}'，使用默认 '中'")
        return "MEDIUM"

    def _merge_verification_results(self, risk: Dict[str, Any]) -> Dict[str, Any]:
        """合并验证结果到风险决策

        如果验证决策为CONFIRMED但裁决为其他状态，覆盖裁决

        Args:
            risk: 风险字典

        Returns:
            修改后的风险字典
        """
        verification_decision = risk.get("verification_decision", "")
        signal_state = risk.get("signal_state", "NEW")
        reason = risk.get("reason", "")

        if verification_decision == "CONFIRMED" and signal_state != "CONFIRMED":
            logger.debug(
                f"验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}, 采用验证决策"
            )
            self.debug_logs.append(
                f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}"
            )
            risk["signal_state"] = "CONFIRMED"
            risk["status"] = "CONFIRMED"
            risk["verification_override"] = True
            risk["override_reason"] = f"验证决策: {verification_decision}, 原因: {reason}"
            self.debug_logs.append(f"[DEBUG] 覆盖原因: {reason}")

        elif verification_decision == "REFINED" and signal_state not in ["CONFIRMED", "REFINED"]:
            logger.debug(
                f"验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}, 采用验证决策"
            )
            self.debug_logs.append(
                f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}"
            )
            risk["signal_state"] = "REFINED"
            risk["status"] = "REFINED"
            risk["verification_override"] = True
            risk["override_reason"] = f"验证决策: {verification_decision}, 原因: {reason}"

        elif verification_decision == "REJECTED" and signal_state != "REJECTED":
            logger.debug(
                f"验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}, 采用验证决策"
            )
            self.debug_logs.append(
                f"[DEBUG] 验证覆盖: verification_decision={verification_decision}, signal_state={signal_state}"
            )
            risk["signal_state"] = "REJECTED"
            risk["status"] = "REJECTED"
            risk["verification_override"] = True
            risk["override_reason"] = f"验证决策: {verification_decision}, 原因: {reason}"

        return risk

    def _calculate_confidence_dispersion(self, confidence_values: list) -> float:
        """计算置信度值的分散度（标准差）

        Args:
            confidence_values: 置信度值列表

        Returns:
            标准差（0.0表示完全一致，越大表示越分散）
        """
        if not confidence_values or len(confidence_values) < 2:
            return 0.0

        mean = sum(confidence_values) / len(confidence_values)
        variance = sum((x - mean) ** 2 for x in confidence_values) / len(confidence_values)
        return float(variance**0.5)

    def _check_rejection_completeness(
        self, risk_findings: List[Dict], all_rejected: bool = False
    ) -> List[Dict]:
        """检查拒绝完整性，识别可能的审核失误

        当所有风险都被拒绝时，检查是否存在高危类型被错误拒绝的情况。
        对于高危类型，即使被 REJECTED 也标记为需要人工复核。

        Args:
            risk_findings: 风险发现列表
            all_rejected: 是否所有风险都被拒绝

        Returns:
            修改后的风险发现列表
        """
        if not all_rejected:
            return risk_findings

        modified_count = 0
        for risk in risk_findings:
            title = risk.get("title", risk.get("risk_type", ""))
            verification_decision = risk.get("verification_decision", "")
            signal_state = risk.get("signal_state", "")

            if verification_decision == "REJECTED" and signal_state == "REJECTED":
                if self._is_high_risk_type(title):
                    logger.debug(f"  高危风险类型被拒绝，进入人工复核: {title}")
                    risk["requires_human_review"] = True
                    risk["high_risk_override"] = True
                    risk["status"] = "REFINED"
                    risk["signal_state"] = "REFINED"
                    modified_count += 1

        if modified_count > 0:
            logger.warning(f"  识别出 {modified_count} 个高危类型被错误拒绝，已标记为待人工复核")

        return risk_findings

    def _generate_recommendation(
        self, risk_type: str, severity: str, description: str, evidence: str
    ) -> str:
        """根据风险类型和严重程度生成具体修复建议

        Args:
            risk_type: 风险类型
            severity: 严重程度
            description: 风险描述
            evidence: 证据描述

        Returns:
            具体的修复建议
        """
        risk_upper = risk_type.upper()
        desc_upper = description.upper()
        combined = f"{risk_upper} {desc_upper}"

        high_keywords = [
            "SQL",
            "INJECT",
            "XSS",
            "CSRF",
            "COMMAND",
            "RCE",
            "PRIVILEGE",
            "AUTHENTICATION",
            "CREDENTIAL",
            "SECRET",
            "KEY",
            "PASSWORD",
            "UNSAFE",
            "DESERIALIZ",
            "SSRF",
            "PATH",
            "SENSITIVE",
            "DATA EXPOSURE",
            "JWT",
            "TOKEN",
            "EXPOSURE",
            "REDIS",
            "DENIAL",
            "DOS",
            "SERVICE",
            "ATTACK",
            "SCAN",
        ]
        medium_keywords = [
            "WEAK",
            "DEFAULT",
            "MISSING",
            "HARDCODED",
            "CONFIGURATION",
            "BROKEN",
            "INSECURE",
            "TRAVERSAL",
            "CONTEXT",
            "TENANT",
            "CUSTOM SECURITY",
            "AUTHORIZATION",
            "PERMISSION",
            "越权",
        ]
        low_keywords = ["INFO", "LOGGING", "DEBUG", "REMEDIATION", "BEST", "PRACTICE"]

        if any(kw in combined for kw in high_keywords):
            severity_advice = {
                "CRITICAL": "立即修复",
                "HIGH": "优先修复",
                "MEDIUM": "尽快修复",
                "LOW": "建议修复",
                "INFO": "可选择修复",
            }.get(severity.upper() if severity else "MEDIUM", "建议修复")

            if "HARDCODED" in combined or "硬编码" in combined:
                if (
                    "CREDENTIAL" in combined
                    or "PASSWORD" in combined
                    or "SECRET" in combined
                    or "KEY" in combined
                ):
                    return f"{severity_advice}：将硬编码的凭据移动到安全存储（如环境变量或密钥管理系统），实施凭据轮换策略"
                elif "PATH" in combined or "路径" in combined:
                    return f"{severity_advice}：将硬编码的路径改为从配置文件或环境变量读取，提高可移植性"
                else:
                    return f"{severity_advice}：将硬编码的配置移动到安全存储（如环境变量或配置文件）"
            elif "SQL" in combined or "INJECT" in combined:
                return f"{severity_advice}：使用参数化查询或预编译语句，勿使用字符串拼接SQL"
            elif "XSS" in combined:
                return f"{severity_advice}：对用户输入进行HTML实体编码，设置严格CSP策略"
            elif "CSRF" in combined:
                return f"{severity_advice}：为所有状态修改请求添加CSRF Token验证，使用SameSite Cookie"
            elif "COMMAND" in combined or "RCE" in combined:
                return f"{severity_advice}：避免直接执行用户输入，使用安全的API或白名单验证"
            elif (
                "AUTHENTICATION" in combined
                or "CREDENTIAL" in combined
                or "PASSWORD" in combined
                or "SECRET" in combined
            ):
                return f"{severity_advice}：使用安全的方式存储凭据，实施强密码策略和密钥轮换"
            elif "PRIVILEGE" in combined or "ACCESS" in combined:
                return f"{severity_advice}：实施最小权限原则，使用基于角色的访问控制(RBAC)"
            elif "SSRF" in combined:
                return f"{severity_advice}：建立URL白名单验证，禁用对内部网络的访问"
            elif "PATH" in combined and "TRAVERSAL" in combined:
                return f"{severity_advice}：对用户输入进行路径规范化，使用白名单验证文件路径"
            elif "DESERIALIZ" in combined:
                return f"{severity_advice}：避免反序列化不受信任的数据，使用安全的序列化方案"
            elif (
                "SENSITIVE" in combined
                or "DATA EXPOSURE" in combined
                or "EXPOSURE" in combined
                or "敏感" in description
                or "暴露" in description
            ):
                return f"{severity_advice}：对敏感数据进行脱敏处理，最小化令牌中存储的信息，仅保留必要的用户标识"
            elif "JWT" in combined or "TOKEN" in combined or "令牌" in description:
                return f"{severity_advice}：确保令牌不包含敏感信息，使用令牌加密或签名保护完整性"
            elif (
                "REDIS" in combined
                or "DENIAL" in combined
                or "DOS" in combined
                or "SERVICE" in combined
                or "ATTACK" in combined
                or "SCAN" in combined
                or "服务" in description
                or "拒绝" in description
            ):
                return f"{severity_advice}：优化查询效率，对大键集合使用游标遍历而非一次性加载，限制资源消耗"
            elif (
                "AUTHENTICATION" in combined
                or "CREDENTIAL" in combined
                or "PASSWORD" in combined
                or "SECRET" in combined
            ):
                return f"{severity_advice}：使用安全的方式存储凭据，实施强密码策略和密钥轮换"
            elif (
                "PRIVILEGE" in combined
                or "ACCESS" in combined
                or "AUTHORIZATION" in combined
                or "PERMISSION" in combined
                or "越权" in description
                or "授权" in description
            ):
                return f"{severity_advice}：实施最小权限原则，使用基于角色的访问控制(RBAC)，验证用户操作权限"
            else:
                return f"{severity_advice}：基于代码证据评估后实施相应安全措施"

        elif any(kw in combined for kw in medium_keywords):
            severity_advice = {
                "CRITICAL": "立即修复",
                "HIGH": "优先修复",
                "MEDIUM": "尽快修复",
                "LOW": "建议修复",
                "INFO": "可选择修复",
            }.get(severity.upper() if severity else "LOW", "建议修复")

            if "WEAK" in combined or "DEFAULT" in combined:
                return f"{severity_advice}：替换弱加密算法或默认配置，使用行业标准安全方案"
            elif "MISSING" in combined or "缺失" in description:
                return f"{severity_advice}：添加缺失的安全控制或验证机制"
            elif "HARDCODED" in combined or "硬编码" in description:
                return f"{severity_advice}：将硬编码的配置移动到安全存储（如环境变量或密钥管理系统）"
            elif "CONFIGURATION" in combined or "CONFIG" in combined or "配置" in description:
                return f"{severity_advice}：修正安全配置，遵循安全最佳实践"
            elif (
                "CONTEXT" in combined
                or "TENANT" in combined
                or "上下文" in description
                or "租户" in description
            ):
                return f"{severity_advice}：确保上下文隔离正确实现，验证多线程/异步场景下的上下文传递"
            elif "CUSTOM SECURITY" in combined or "自定义" in description:
                return f"{severity_advice}：审查自定义安全逻辑，进行代码审计和渗透测试"
            elif "不足" in description or "不完整" in description or "INSECURE" in combined:
                return f"{severity_advice}：增强安全控制，确保配置完整和正确"
            else:
                return f"{severity_advice}：基于代码证据评估后实施相应安全措施"

        elif any(kw in combined for kw in low_keywords):
            return "参考最佳实践进行优化，或作为低优先级改进项"

        if description and len(description) > 10:
            return f"根据描述评估: {description[:50]}..."

        return "需要人工复核此风险"
