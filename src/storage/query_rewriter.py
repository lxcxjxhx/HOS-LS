"""查询重写器

实现基于语义扩展的查询重写，提高检索的准确性和召回率。
"""

from typing import List, Dict, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class QueryRewriter:
    """查询重写器

    使用语义扩展和规则对查询进行重写，提高检索的准确性和召回率。
    """

    def __init__(self):
        """初始化查询重写器"""
        # 漏洞类型扩展
        self.vulnerability_types = [
            "RCE", "SQL injection", "XSS", "CSRF", "Command injection",
            "Buffer overflow", "Authentication bypass", "Authorization bypass",
            "Injection", "Denial of service", "Information disclosure",
            "Privilege escalation", "Path traversal", "File inclusion",
            "Cross-site request forgery", "Cross-site scripting",
            "Remote code execution", "Server-side request forgery",
            "XML external entity", "Prototype pollution"
        ]
        
        # 安全关键词
        self.security_keywords = [
            "vulnerability", "exploit", "attack", "security", "risk",
            "vulnerable", "exploitable", "compromise", "breach",
            "insecure", "unsafe", "dangerous", "critical",
            "high risk", "medium risk", "low risk"
        ]
        
        # 代码相关关键词
        self.code_keywords = [
            "exec", "system", "eval", "execfile", "compile",
            "__import__", "open", "file", "subprocess", "os.system",
            "input", "raw_input", "request", "params", "query",
            "cookie", "session", "header", "payload", "inject"
        ]
        
        # CVE 相关模式
        self.cve_patterns = [
            r"CVE-\d{4}-\d{4,}"
        ]

    def rewrite_query(self, query: str) -> str:
        """重写查询

        Args:
            query: 原始查询

        Returns:
            重写后的查询
        """
        if not query:
            return query
        
        # 步骤 1: 漏洞类型扩展
        expanded_query = self._expand_vulnerability_types(query)
        
        # 步骤 2: 安全关键词扩展
        expanded_query = self._expand_security_keywords(expanded_query)
        
        # 步骤 3: 代码关键词扩展
        expanded_query = self._expand_code_keywords(expanded_query)
        
        # 步骤 4: 同义词扩展
        expanded_query = self._expand_synonyms(expanded_query)
        
        logger.debug(f"原始查询: {query}")
        logger.debug(f"重写后查询: {expanded_query}")
        
        return expanded_query

    def _expand_vulnerability_types(self, query: str) -> str:
        """扩展漏洞类型

        Args:
            query: 原始查询

        Returns:
            扩展后的查询
        """
        # 检查是否已包含漏洞类型
        contains_vulnerability = any(vuln.lower() in query.lower() for vuln in self.vulnerability_types)
        
        if not contains_vulnerability:
            # 添加常见漏洞类型
            expanded = query + " OR " + " OR ".join(self.vulnerability_types[:10])  # 只添加前10个常见的
            return expanded
        
        return query

    def _expand_security_keywords(self, query: str) -> str:
        """扩展安全关键词

        Args:
            query: 原始查询

        Returns:
            扩展后的查询
        """
        # 检查是否已包含安全关键词
        contains_security = any(keyword.lower() in query.lower() for keyword in self.security_keywords)
        
        if not contains_security:
            # 添加安全关键词
            expanded = query + " OR " + " OR ".join(self.security_keywords[:5])  # 只添加前5个常见的
            return expanded
        
        return query

    def _expand_code_keywords(self, query: str) -> str:
        """扩展代码关键词

        Args:
            query: 原始查询

        Returns:
            扩展后的查询
        """
        # 检查是否已包含代码关键词
        contains_code = any(keyword.lower() in query.lower() for keyword in self.code_keywords)
        
        if not contains_code:
            # 添加代码关键词
            expanded = query + " OR " + " OR ".join(self.code_keywords[:10])  # 只添加前10个常见的
            return expanded
        
        return query

    def _expand_synonyms(self, query: str) -> str:
        """扩展同义词

        Args:
            query: 原始查询

        Returns:
            扩展后的查询
        """
        # 同义词映射
        synonyms = {
            "漏洞": ["安全问题", "安全缺陷", "安全漏洞", "弱点"],
            "攻击": ["入侵", "渗透", "攻击向量", "攻击路径"],
            "代码": ["源码", "程序", "脚本", "代码片段"],
            "注入": ["注入攻击", "代码注入", "命令注入", "SQL注入"],
            "执行": ["命令执行", "代码执行", "远程执行", "执行漏洞"],
            "绕过": ["绕过漏洞", "身份验证绕过", "授权绕过", "访问控制绕过"],
            "泄露": ["信息泄露", "数据泄露", "敏感信息泄露", "隐私泄露"],
            "溢出": ["缓冲区溢出", "栈溢出", "堆溢出", "整数溢出"]
        }
        
        expanded = query
        for keyword, syns in synonyms.items():
            if keyword in query:
                # 添加同义词
                expanded += " OR " + " OR ".join(syns)
                break  # 只添加一组同义词，避免查询过长
        
        return expanded

    def rewrite_with_ast(self, query: str, ast_info: Optional[Dict[str, Any]] = None) -> str:
        """结合 AST 信息重写查询

        Args:
            query: 原始查询
            ast_info: AST 信息

        Returns:
            重写后的查询
        """
        if not ast_info:
            return self.rewrite_query(query)
        
        # 从 AST 中提取信息
        expanded_query = query
        
        # 提取函数调用
        if "functions" in ast_info:
            functions = ast_info["functions"]
            for func in functions:
                if func in self.code_keywords:
                    expanded_query += f" OR {func}"
        
        # 提取变量名
        if "variables" in ast_info:
            variables = ast_info["variables"]
            for var in variables:
                if any(keyword in var.lower() for keyword in ["input", "user", "request", "param"]):
                    expanded_query += f" OR {var}"
        
        # 提取控制流
        if "control_flow" in ast_info:
            control_flow = ast_info["control_flow"]
            for flow in control_flow:
                if flow in ["if", "for", "while", "try", "except"]:
                    expanded_query += f" OR {flow}"
        
        # 调用基本重写
        expanded_query = self.rewrite_query(expanded_query)
        
        return expanded_query

    def get_expansion_stats(self, original_query: str, rewritten_query: str) -> Dict[str, Any]:
        """获取扩展统计信息

        Args:
            original_query: 原始查询
            rewritten_query: 重写后的查询

        Returns:
            统计信息
        """
        original_tokens = set(original_query.lower().split())
        rewritten_tokens = set(rewritten_query.lower().split())
        
        added_tokens = rewritten_tokens - original_tokens
        token_count_increase = len(rewritten_tokens) - len(original_tokens)
        
        return {
            "original_token_count": len(original_tokens),
            "rewritten_token_count": len(rewritten_tokens),
            "token_count_increase": token_count_increase,
            "added_tokens": list(added_tokens)
        }
