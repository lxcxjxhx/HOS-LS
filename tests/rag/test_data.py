"""测试数据"""

from src.learning.self_learning import Knowledge, KnowledgeType, Pattern
from datetime import datetime


def get_test_knowledge():
    """获取测试知识"""
    knowledge_list = [
        Knowledge(
            id="test_knowledge_1",
            knowledge_type=KnowledgeType.VULNERABILITY,
            content="SQL注入漏洞是一种常见的Web应用安全漏洞，攻击者通过在输入字段中插入SQL代码来执行未授权的数据库操作。",
            source="test_source",
            confidence=0.9,
            tags=["SQL", "注入", "漏洞"],
            metadata={"severity": "high"}
        ),
        Knowledge(
            id="test_knowledge_2",
            knowledge_type=KnowledgeType.PATTERN,
            content="XSS攻击是一种注入攻击，攻击者将恶意脚本注入到受信任的网站中。",
            source="test_source",
            confidence=0.85,
            tags=["XSS", "注入", "攻击"],
            metadata={"severity": "medium"}
        ),
        Knowledge(
            id="test_knowledge_3",
            knowledge_type=KnowledgeType.RULE,
            content="输入验证是防止注入攻击的有效方法，包括类型检查、长度限制和特殊字符过滤。",
            source="test_source",
            confidence=0.95,
            tags=["防御", "输入验证"],
            metadata={"effectiveness": "high"}
        )
    ]
    return knowledge_list


def get_test_patterns():
    """获取测试模式"""
    pattern_list = [
        Pattern(
            id="test_pattern_1",
            pattern_type="SQL_INJECTION",
            pattern_value="' OR 1=1 --",
            description="SQL注入攻击模式，用于绕过身份验证",
            confidence=0.9,
            occurrence_count=10,
            true_positive_count=8,
            false_positive_count=2,
            metadata={"severity": "high"}
        ),
        Pattern(
            id="test_pattern_2",
            pattern_type="XSS",
            pattern_value="<script>alert('XSS')</script>",
            description="XSS攻击模式，用于执行恶意脚本",
            confidence=0.85,
            occurrence_count=15,
            true_positive_count=12,
            false_positive_count=3,
            metadata={"severity": "medium"}
        )
    ]
    return pattern_list


def get_test_query():
    """获取测试查询"""
    return "SQL注入漏洞的防御方法"
