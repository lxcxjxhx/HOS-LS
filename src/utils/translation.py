"""翻译字典模块

提供安全术语、严重级别、漏洞判定结果的中英文映射。
"""

SEVERITY_MAP = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "CRITICAL": "严重",
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "INFO": "信息"
}

VERDICT_MAP = {
    "confirmed": "确认漏洞",
    "valid": "确认漏洞",
    "refuted": "误报",
    "invalid": "误报",
    "needs_review": "需人工复核",
    "uncertain": "需人工复核",
    "ACCEPT": "确认",
    "REFUTE": "误报",
    "ESCALATE": "需人工复核",
    "UNCERTAIN": "不确定"
}

VULNERABILITY_TITLE_MAP = {
    "SQL Injection": "SQL 注入",
    "sql injection": "SQL 注入",
    "SQL_INJECTION": "SQL 注入",
    "Cross-Site Scripting": "跨站脚本攻击",
    "XSS": "XSS 跨站脚本",
    "xss": "XSS 跨站脚本",
    "Cross-Site Request Forgery": "跨站请求伪造",
    "CSRF": "CSRF 跨站请求伪造",
    "csrf": "CSRF 跨站请求伪造",
    "Command Injection": "命令注入",
    "command injection": "命令注入",
    "COMMAND_INJECTION": "命令注入",
    "Path Traversal": "路径遍历",
    "path traversal": "路径遍历",
    "PATH_TRAVERSAL": "路径遍历",
    "Server-Side Request Forgery": "服务器端请求伪造",
    "SSRF": "SSRF 服务器端请求伪造",
    "ssrf": "SSRF 服务器端请求伪造",
    "Hardcoded Credentials": "硬编码凭证",
    "hardcoded credentials": "硬编码凭证",
    "HARDCODED_CREDENTIALS": "硬编码凭证",
    "Hardcoded Password": "硬编码密码",
    "hardcoded password": "硬编码密码",
    "Insecure Randomness": "不安全的随机数",
    "Weak Cryptography": "弱加密",
    "weak cryptography": "弱加密",
    "Authentication Bypass": "认证绕过",
    "authentication bypass": "认证绕过",
    "Authorization Bypass": "授权绕过",
    "authorization bypass": "授权绕过",
    "Sensitive Data Exposure": "敏感数据泄露",
    "sensitive data exposure": "敏感数据泄露",
    "Missing Authentication": "缺失认证",
    "missing authentication": "缺失认证",
    "Missing Authorization": "缺失授权",
    "missing authorization": "缺失授权",
    "Unvalidated Redirect": "未验证的重定向",
    "unvalidated redirect": "未验证的重定向",
    "Buffer Overflow": "缓冲区溢出",
    "buffer overflow": "缓冲区溢出",
    "Integer Overflow": "整数溢出",
    "integer overflow": "整数溢出",
    "Race Condition": "竞态条件",
    "race condition": "竞态条件",
    "Deserialization": "反序列化漏洞",
    "deserialization": "反序列化漏洞",
    "XXE": "XML 外部实体注入",
    "xxe": "XML 外部实体注入",
    "Template Injection": "模板注入",
    "template injection": "模板注入",
    "LDAP Injection": "LDAP 注入",
    "ldap injection": "LDAP 注入",
    "XML Injection": "XML 注入",
    "xml injection": "XML 注入",
    "Code Injection": "代码注入",
    "code injection": "代码注入",
    "Expression Language Injection": "表达式语言注入",
    "expression language injection": "表达式语言注入"
}

RECOMMENDATION_MAP = {
    "Use parameterized queries": "使用参数化查询",
    "parameterized queries": "使用参数化查询",
    "prepared statements": "使用预编译语句",
    "Use input validation": "进行输入校验",
    "input validation": "输入校验",
    "Sanitize input": "净化输入",
    "sanitize input": "净化输入",
    "Use CSRF token": "使用 CSRF Token",
    "csrf token": "启用 CSRF 防护",
    "Enable CSRF protection": "启用 CSRF 防护",
    "Use secure random": "使用安全随机数",
    "secure random": "安全随机数",
    "Use environment variables": "使用环境变量",
    "environment variables": "环境变量配置",
    "Encrypt data": "加密数据",
    "encrypt data": "数据加密",
    "Use HTTPS": "使用 HTTPS",
    "use https": "使用 HTTPS",
    "Implement authentication": "实现身份验证",
    "authentication": "身份验证",
    "Implement authorization": "实现授权机制",
    "authorization": "授权控制"
}

STATUS_MAP = {
    "VALID": "有效",
    "INVALID": "无效",
    "UNCERTAIN": "不确定"
}

def translate_severity(severity: str) -> str:
    """翻译严重级别

    Args:
        severity: 英文严重级别

    Returns:
        中文严重级别
    """
    return SEVERITY_MAP.get(severity, severity)

def translate_verdict(verdict: str) -> str:
    """翻译判定结果

    Args:
        verdict: 英文判定结果

    Returns:
        中文判定结果
    """
    return VERDICT_MAP.get(verdict, verdict)

def translate_vulnerability_title(title: str) -> str:
    """翻译漏洞名称

    Args:
        title: 英文漏洞名称

    Returns:
        中文或保留原文的漏洞名称
    """
    return VULNERABILITY_TITLE_MAP.get(title, title)

def translate_recommendation(rec: str) -> str:
    """翻译建议

    Args:
        rec: 英文建议

    Returns:
        中文建议
    """
    return RECOMMENDATION_MAP.get(rec, rec)

def format_finding_cn(vuln: dict, lang: str = "zh") -> dict:
    """格式化漏洞输出（中文优先）

    Args:
        vuln: 漏洞字典
        lang: 语言偏好，默认为中文

    Returns:
        格式化后的漏洞字典
    """
    if lang != "zh":
        return vuln

    formatted = vuln.copy()

    if "severity" in formatted:
        formatted["severity_cn"] = translate_severity(formatted["severity"])

    if "vulnerability" in formatted:
        formatted["vulnerability_cn"] = translate_vulnerability_title(formatted["vulnerability"])

    if "status" in formatted:
        formatted["status_cn"] = translate_verdict(formatted["status"])

    if "verdict" in formatted:
        formatted["verdict_cn"] = translate_verdict(formatted["verdict"])

    if "recommendation" in formatted:
        rec = formatted["recommendation"]
        if isinstance(rec, str):
            formatted["recommendation_cn"] = translate_recommendation(rec)
        elif isinstance(rec, list):
            formatted["recommendation_cn"] = [translate_recommendation(r) for r in rec]

    return formatted
