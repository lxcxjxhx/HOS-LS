"""AI 安全检测基础模块

提供 AI 安全检测的通用模式和基类。
"""

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class AISecurityBaseRule(ABC):
    """AI 安全规则基类

    提供 AI 安全检测的通用接口和模式。
    """

    PROMPT_INJECTION_PATTERNS = [
        re.compile(r"(?i)(ignore\s+(previous|all|above)\s+instructions?)", re.IGNORECASE),
        re.compile(r"(?i)(disregard\s+(your|my)\s+(previous|all)\s+instructions?)", re.IGNORECASE),
        re.compile(r"(?i)(forget\s+(everything|all|what)\s+(you|we)\s+(know|said))", re.IGNORECASE),
        re.compile(r"(?i)(new\s+instructions?:)", re.IGNORECASE),
        re.compile(r"(?i)(system\s+prompt\s+(leak|extraction|stealing|hacking))", re.IGNORECASE),
        re.compile(r"(?i)(you\s+are\s+now\s+(a|an)\s+(\w+\s+)?assistant)", re.IGNORECASE),
    ]

    SENSITIVE_DATA_PATTERNS = [
        re.compile(r"(?i)(api\s*key|secret\s*key|private\s*key)", re.IGNORECASE),
        re.compile(r"(?i)(password|passwd|pwd)\s*=", re.IGNORECASE),
        re.compile(r"(?i)(token|auth.*token|bearer)", re.IGNORECASE),
        re.compile(r"(?i)(credit\s*card|card\s*number|cvv)", re.IGNORECASE),
    ]

    MODEL_CONFIDENCE_PATTERNS = [
        re.compile(r"(?i)(uncertain|not\s+sure|don't\s+know)", re.IGNORECASE),
        re.compile(r"(?i)(as\s+an\s+AI|I\s+am\s+not\s+sure)", re.IGNORECASE),
        re.compile(r"(?i)(harmful|inappropriate|illegal)", re.IGNORECASE),
    ]

    def __init__(self):
        self.name = self.__class__.__name__
        self.severity = "HIGH"
        self.category = "AI Security"

    @abstractmethod
    def detect(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检测 AI 安全问题

        Args:
            context: 包含代码上下文的字典

        Returns:
            检测结果列表
        """
        pass

    def match_pattern(self, text: str, patterns: List[re.Pattern]) -> Optional[re.Match]:
        """匹配文本中的模式

        Args:
            text: 待匹配的文本
            patterns: 正则表达式模式列表

        Returns:
            匹配结果，未匹配返回 None
        """
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return match
        return None

    def check_prompt_injection(self, text: str) -> bool:
        """检查提示注入

        Args:
            text: 待检查的文本

        Returns:
            是否存在提示注入风险
        """
        return self.match_pattern(text, self.PROMPT_INJECTION_PATTERNS) is not None

    def check_sensitive_data(self, text: str) -> bool:
        """检查敏感数据泄露

        Args:
            text: 待检查的文本

        Returns:
            是否存在敏感数据
        """
        return self.match_pattern(text, self.SENSITIVE_DATA_PATTERNS) is not None

    def create_finding(self, line_number: int, code: str, message: str,
                       severity: Optional[str] = None) -> Dict[str, Any]:
        """创建检测结果

        Args:
            line_number: 代码行号
            code: 相关代码片段
            message: 问题描述
            severity: 严重程度

        Returns:
            检测结果字典
        """
        return {
            "rule": self.name,
            "severity": severity or self.severity,
            "category": self.category,
            "line": line_number,
            "code": code,
            "message": message,
        }