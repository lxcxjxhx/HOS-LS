"""增强误报过滤测试"""

import pytest
from src.ai.filters.enhanced_filter import EnhancedFindingsFilter, HardExclusionRules


class TestEnhancedFindingsFilter:
    def test_init(self):
        """测试初始化"""
        filter = EnhancedFindingsFilter(
            use_hard_exclusions=True,
            use_ai_filtering=True
        )
        assert filter.use_hard_exclusions is True
        assert filter.use_ai_filtering is True

    def test_hard_exclude(self):
        """测试硬编码排除规则"""
        # 测试 SQL 注入误报
        finding = {
            "rule_id": "SQL_INJECTION",
            "rule_name": "SQL 注入",
            "description": "可能的 SQL 注入漏洞",
            "severity": "high",
            "confidence": 0.8,
            "code_snippet": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "file_path": "test.py"
        }
        
        reason = HardExclusionRules.get_exclusion_reason(finding)
        # 这个发现不应该被排除，因为它是一个有效的 SQL 注入漏洞
        assert reason is None

        # 测试资源泄漏误报
        finding = {
            "rule_id": "RESOURCE_LEAK",
            "rule_name": "资源泄漏",
            "description": "resource leak potential",
            "severity": "medium",
            "confidence": 0.7,
            "code_snippet": "file = open('test.txt')",
            "file_path": "test.py"
        }
        
        reason = HardExclusionRules.get_exclusion_reason(finding)
        # 这个发现应该被排除，因为它是一个资源管理问题，不是安全漏洞
        assert reason is not None

    async def test_filter_findings(self):
        """测试过滤发现"""
        filter = EnhancedFindingsFilter(use_hard_exclusions=True, use_ai_filtering=False)
        
        findings = [
            {
                "rule_id": "RESOURCE_LEAK",
                "rule_name": "资源泄漏",
                "description": "可能的资源泄漏",
                "severity": "medium",
                "confidence": 0.7,
                "code_snippet": "file = open('test.txt')",
                "file_path": "test.py"
            },
            {
                "rule_id": "HARDCODED_SECRET",
                "rule_name": "硬编码密钥",
                "description": "可能的硬编码密钥",
                "severity": "critical",
                "confidence": 0.9,
                "code_snippet": "api_key = 'sk-1234567890abcdef'",
                "file_path": "test.py"
            }
        ]
        
        success, result, stats = await filter.filter_findings(findings, {"file_path": "test.py"})
        assert success is True
        assert len(result["filtered_findings"]) == 1
        assert len(result["excluded_findings"]) == 1
        assert result["filtered_findings"][0]["rule_id"] == "HARDCODED_SECRET"
        assert result["excluded_findings"][0]["finding"]["rule_id"] == "RESOURCE_LEAK"
