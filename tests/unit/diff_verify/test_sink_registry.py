"""Sink注册表单元测试"""

import pytest
from src.sal.sink_registry import SinkRegistry, SinkDefinition, SinkCategory


class TestSinkRegistry:
    """Sink注册表测试"""
    
    def test_init_default_sinks(self):
        """测试默认Sink初始化"""
        registry = SinkRegistry()
        sinks = registry.get_all()
        
        # 应该有默认Sink
        assert len(sinks) > 0
        
        # 检查是否包含SQL注入Sink
        sql_sinks = registry.get_by_category(SinkCategory.SQL_INJECTION)
        assert len(sql_sinks) > 0
    
    def test_register_custom_sink(self):
        """测试注册自定义Sink"""
        registry = SinkRegistry()
        
        custom_sink = SinkDefinition(
            category=SinkCategory.OTHER,
            name="custom_sink",
            patterns=["custom_func"],
            languages=["python"],
            severity="HIGH",
            description="Custom sink for testing"
        )
        
        registry.register(custom_sink)
        
        # 验证注册成功
        retrieved = registry.get("custom_sink")
        assert retrieved is not None
        assert retrieved.name == "custom_sink"
    
    def test_find_matching_sinks(self):
        """测试查找匹配的Sink"""
        registry = SinkRegistry()
        
        # 测试SQL注入匹配
        matches = registry.find_matching_sinks("execute_query", "python")
        assert len(matches) > 0
        
        # 测试命令注入匹配
        matches = registry.find_matching_sinks("os.system", "python")
        assert len(matches) > 0
    
    def test_is_sink(self):
        """测试Sink检查"""
        registry = SinkRegistry()
        
        # 应该是Sink
        assert registry.is_sink("execute", "python") == True
        assert registry.is_sink("os.system", "python") == True
        
        # 不应该是Sink
        assert registry.is_sink("print", "python") == False
        assert registry.is_sink("calculate_sum", "python") == False
    
    def test_get_by_language(self):
        """测试按语言获取Sink"""
        registry = SinkRegistry()
        
        python_sinks = registry.get_by_language("python")
        assert len(python_sinks) > 0
        
        # 所有返回的Sink应该支持Python
        for sink in python_sinks:
            assert "python" in [l.lower() for l in sink.languages]
    
    def test_export_for_prompt(self):
        """测试导出Prompt格式"""
        registry = SinkRegistry()
        
        prompt_text = registry.export_for_prompt("python")
        assert len(prompt_text) > 0
        assert "高危Sink集合" in prompt_text
    
    def test_sink_matches(self):
        """测试Sink匹配逻辑"""
        sink = SinkDefinition(
            category=SinkCategory.SQL_INJECTION,
            name="test_sink",
            patterns=["execute", "query"],
            languages=["python", "java"],
            severity="HIGH"
        )
        
        # 应该匹配
        assert sink.matches("execute", "python") == True
        assert sink.matches("db_query", "java") == True
        
        # 不应该匹配（语言不对）
        assert sink.matches("execute", "javascript") == False
        
        # 不应该匹配（模式不对）
        assert sink.matches("print", "python") == False
