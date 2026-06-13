"""Agent流水线构建器测试"""

import pytest
from src.core.chat.pipeline_builder import (
    PipelineBuilder,
    PipelineConfig,
    AgentType,
    AgentNode
)


class TestPipelineBuilder:
    """PipelineBuilder 测试类"""

    @pytest.fixture
    def builder(self):
        """创建流水线构建器实例"""
        return PipelineBuilder()

    def test_parse_chain_flags(self, builder):
        """测试解析链式标志"""
        agents = builder.parse_chain_flags("scan+context+final")

        assert len(agents) == 3
        assert AgentType.SCAN in agents
        assert AgentType.CONTEXT in agents
        assert AgentType.FINAL in agents

        single_chain = builder.parse_chain_flags("risk")
        assert len(single_chain) == 1
        assert AgentType.RISK in single_chain

    def test_expand_macro(self, builder):
        """测试宏展开"""
        full_audit_agents = builder.expand_macro("full-audit")

        assert len(full_audit_agents) > 3
        assert AgentType.SCAN in full_audit_agents
        assert AgentType.FINAL in full_audit_agents
        assert AgentType.REPORT in full_audit_agents

        quick_scan_agents = builder.expand_macro("quick-scan")
        assert AgentType.SCAN in quick_scan_agents
        assert AgentType.CONTEXT in quick_scan_agents
        assert AgentType.FINAL in quick_scan_agents

        with pytest.raises(ValueError, match="Unknown macro"):
            builder.expand_macro("non-existent-macro")

    def test_auto_complete(self, builder):
        """测试自动补全依赖"""
        agents = [AgentType.ATTACK]

        completed = builder.auto_complete(agents)

        assert AgentType.ATTACK in completed
        assert AgentType.VERIFY in completed
        assert AgentType.RISK in completed
        assert AgentType.UNDERSTAND in completed
        assert AgentType.CONTEXT in completed
        assert AgentType.SCAN in completed

        order = completed[:completed.index(AgentType.ATTACK) + 1]
        assert AgentType.SCAN in order
        assert AgentType.CONTEXT in order
        assert AgentType.UNDERSTAND in order
        assert AgentType.RISK in order
        assert AgentType.VERIFY in order
        assert AgentType.ATTACK in order

    def test_cli_to_chat(self, builder):
        """测试CLI到聊天的转换"""
        result = builder.cli_to_chat("--scan+context+final")
        assert "扫描" in result or "context" in result.lower() or "final" in result.lower()

        result = builder.cli_to_chat("--quick-scan")
        assert "快速" in result or "scan" in result.lower()

        result = builder.cli_to_chat("--deep-scan")
        assert "深度" in result or "deep" in result.lower()

        result = builder.cli_to_chat("--full-audit")
        assert "审计" in result or "audit" in result.lower()

    def test_chat_to_cli(self, builder):
        """测试聊天到CLI的转换"""
        result = builder.chat_to_cli("执行扫描")
        assert "scan" in result

        result = builder.chat_to_cli("进行完整审计")
        assert "full-audit" in result

        result = builder.chat_to_cli("快速扫描代码")
        assert "quick-scan" in result

        result = builder.chat_to_cli("深度安全扫描")
        assert "deep-scan" in result

        result = builder.chat_to_cli("")
        assert "scan" in result
