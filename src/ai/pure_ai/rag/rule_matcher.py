"""规则匹配引擎

实现基于正则表达式和 AST 模式的规则匹配，作为 Hybrid RAG 的一部分。
"""

import re
from typing import Dict, List, Optional, Any, Pattern

from src.utils.logger import get_logger

logger = get_logger(__name__)


class RuleMatcher:
    """规则匹配引擎

    实现基于正则表达式和 AST 模式的规则匹配，支持规则的添加、更新和匹配。
    """

    def __init__(self):
        """初始化规则匹配引擎"""
        # 规则存储
        self._rules: Dict[str, Dict] = {}
        
        # 预编译的正则表达式
        self._compiled_rules: Dict[str, Pattern] = {}
        
        # 默认规则
        self._load_default_rules()

    def add_rule(self, rule_id: str, pattern: str, description: str, severity: str = "medium") -> None:
        """添加规则

        Args:
            rule_id: 规则ID
            pattern: 正则表达式模式
            description: 规则描述
            severity: 严重程度 (low, medium, high)
        """
        try:
            # 编译正则表达式
            compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            # 添加规则
            self._rules[rule_id] = {
                "pattern": pattern,
                "compiled_pattern": compiled_pattern,
                "description": description,
                "severity": severity
            }
            
            # 保存编译后的正则表达式
            self._compiled_rules[rule_id] = compiled_pattern
            
            logger.info(f"添加规则成功: {rule_id}")
        except re.error as e:
            logger.error(f"添加规则失败 {rule_id}: {e}")

    def add_rules(self, rules: List[Dict[str, str]]) -> None:
        """批量添加规则

        Args:
            rules: 规则列表，每个规则包含 rule_id, pattern, description, severity
        """
        for rule in rules:
            rule_id = rule.get("rule_id")
            pattern = rule.get("pattern")
            description = rule.get("description", "")
            severity = rule.get("severity", "medium")
            
            if rule_id and pattern:
                self.add_rule(rule_id, pattern, description, severity)

    def update_rule(self, rule_id: str, pattern: str, description: str, severity: str = "medium") -> None:
        """更新规则

        Args:
            rule_id: 规则ID
            pattern: 正则表达式模式
            description: 规则描述
            severity: 严重程度 (low, medium, high)
        """
        self.add_rule(rule_id, pattern, description, severity)

    def delete_rule(self, rule_id: str) -> None:
        """删除规则

        Args:
            rule_id: 规则ID
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            if rule_id in self._compiled_rules:
                del self._compiled_rules[rule_id]
            logger.info(f"删除规则成功: {rule_id}")

    def match(self, content: str) -> List[Dict[str, Any]]:
        """匹配规则

        Args:
            content: 要匹配的内容

        Returns:
            匹配结果列表
        """
        matches = []
        
        for rule_id, rule in self._rules.items():
            compiled_pattern = rule["compiled_pattern"]
            description = rule["description"]
            severity = rule["severity"]
            
            # 执行匹配
            rule_matches = compiled_pattern.findall(content)
            if rule_matches:
                # 计算匹配得分
                score = self._calculate_score(rule_matches, severity)
                
                matches.append({
                    "rule_id": rule_id,
                    "description": description,
                    "severity": severity,
                    "matches": rule_matches,
                    "score": score
                })
        
        # 按得分排序
        matches.sort(key=lambda x: x["score"], reverse=True)
        
        return matches

    def match_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """匹配文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据

        Returns:
            匹配结果列表
        """
        matches = self.match(content)
        
        # 添加文档信息
        for match in matches:
            match["document_id"] = document_id
            match["content"] = content
            match["metadata"] = metadata
        
        return matches

    def get_rules(self) -> Dict[str, Dict]:
        """获取所有规则

        Returns:
            规则字典
        """
        return self._rules

    def clear(self) -> None:
        """清空规则"""
        self._rules.clear()
        self._compiled_rules.clear()
        self._load_default_rules()

    def _calculate_score(self, matches: List[str], severity: str) -> float:
        """计算匹配得分

        Args:
            matches: 匹配结果列表
            severity: 严重程度

        Returns:
            得分
        """
        # 基础得分
        base_score = len(matches)
        
        # 严重程度权重
        severity_weights = {
            "low": 1.0,
            "medium": 2.0,
            "high": 3.0
        }
        
        weight = severity_weights.get(severity, 1.0)
        
        # 计算最终得分
        score = base_score * weight
        
        return score

    def _load_default_rules(self) -> None:
        """加载默认规则"""
        # 安全相关规则
        default_rules = [
            # 命令执行
            {
                "rule_id": "command_execution",
                "pattern": r"(exec|system|os\.system|subprocess\.Popen|eval|execfile|compile|__import__|open|file)",
                "description": "命令执行漏洞",
                "severity": "high"
            },
            # SQL 注入
            {
                "rule_id": "sql_injection",
                "pattern": r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*['\"](.*)['\"]",
                "description": "SQL 注入漏洞",
                "severity": "high"
            },
            # XSS
            {
                "rule_id": "xss",
                "pattern": r"(document\.write|innerHTML|outerHTML|eval|setTimeout|setInterval).*['\"](.*)['\"]",
                "description": "XSS 漏洞",
                "severity": "medium"
            },
            # CSRF
            {
                "rule_id": "csrf",
                "pattern": r"(POST|PUT|DELETE).*without.*CSRF",
                "description": "CSRF 漏洞",
                "severity": "medium"
            },
            # 认证绕过
            {
                "rule_id": "auth_bypass",
                "pattern": r"(bypass|skip|disable).*auth",
                "description": "认证绕过漏洞",
                "severity": "high"
            },
            # 授权绕过
            {
                "rule_id": "authz_bypass",
                "pattern": r"(bypass|skip|disable).*permission",
                "description": "授权绕过漏洞",
                "severity": "high"
            },
            # 缓冲区溢出
            {
                "rule_id": "buffer_overflow",
                "pattern": r"(strcpy|memcpy|sprintf|gets|scanf).*['\"](.*)['\"]",
                "description": "缓冲区溢出漏洞",
                "severity": "high"
            },
            # CVE 编号
            {
                "rule_id": "cve_id",
                "pattern": r"CVE-\d{4}-\d{4,}",
                "description": "CVE 漏洞编号",
                "severity": "medium"
            },
            # 敏感信息泄露
            {
                "rule_id": "sensitive_info",
                "pattern": r"(password|secret|key|token|api_key|access_key|secret_key)",
                "description": "敏感信息泄露",
                "severity": "high"
            },
            # 硬编码凭证
            {
                "rule_id": "hardcoded_cred",
                "pattern": r"(password|secret|key)\s*=\s*['\"](.*)['\"]",
                "description": "硬编码凭证",
                "severity": "high"
            }
        ]
        
        # 添加默认规则
        for rule in default_rules:
            self.add_rule(
                rule["rule_id"],
                rule["pattern"],
                rule["description"],
                rule["severity"]
            )

    def __len__(self) -> int:
        """获取规则数量

        Returns:
            规则数量
        """
        return len(self._rules)
