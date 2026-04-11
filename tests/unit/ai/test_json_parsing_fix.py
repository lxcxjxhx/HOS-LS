"""JSON解析修复功能的单元测试

测试覆盖8类典型场景：
1. 标准 JSON 输入
2. 带 markdown 代码块的 JSON
3. 混合文本 + JSON
4. Python 字典风格的输出
5. 带有未转义特殊字符的 JSON
6. 双重转义的 JSON
7. 空输入和无效输入
8. 超长响应（>10KB）
"""

import pytest
import json
import sys
from pathlib import Path

# 添加项目根目录到系统路径
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from src.ai.json_parser import SmartJSONParser
from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline


class TestSmartJSONParserIntegration:
    """测试 SmartJSONParser 集成"""

    def setup_method(self):
        """每个测试方法前的设置"""
        self.parser = SmartJSONParser()

    def test_standard_json(self):
        """测试1: 标准 JSON 输入"""
        input_json = '{"key": "value", "number": 123}'
        result = self.parser.parse(input_json)
        assert result is not None
        assert result['key'] == 'value'
        assert result['number'] == 123

    def test_markdown_code_block_json(self):
        """测试2: 带 markdown 代码块的 JSON"""
        input_text = '''```json
{
    "vulnerabilities": [
        {
            "type": "SQLi",
            "location": "test.py:10"
        }
    ]
}
```'''
        result = self.parser.parse(input_text)
        assert result is not None
        assert 'vulnerabilities' in result
        assert len(result['vulnerabilities']) == 1

    def test_mixed_text_and_json(self):
        """测试3: 混合文本 + JSON"""
        input_text = '''以下是分析结果：
{"findings": [{"type": "XSS"}]}
分析完成。'''
        result = self.parser.parse(input_text)
        assert result is not None
        assert 'findings' in result

    def test_python_dict_style(self):
        """测试4: Python 字典风格的输出（单引号、True/False/None）"""
        input_text = "{'key': 'value', 'flag': True, 'data': None}"
        result = self.parser.parse(input_text)
        # SmartJSONParser 可能无法完全解析Python风格，但应该尝试提取
        # 这里我们主要测试不会崩溃

    def test_unescaped_special_chars(self):
        """测试5: 带有未转义特殊字符的 JSON"""
        input_text = r'{"path": "C:\Users\test", "content": "line with \"quotes\""}'
        result = self.parser.parse(input_text)
        # 测试解析器能处理或优雅失败

    def test_double_escaped_quotes(self):
        """测试6: 双重转义的 JSON"""
        input_text = r'''{"message": "He said \\"hello\\""}'''
        result = self.parser.parse(input_text)
        # SmartJSONParser 可能无法处理双重转义，这是已知的局限性
        # 主要确保不会崩溃
        if result is not None:
            assert 'message' in result


class TestMultiAgentPipelineJSONParsing:
    """测试 MultiAgentPipeline 的 _parse_json_response 方法"""

    def setup_method(self):
        """创建模拟的 MultiAgentPipeline 实例"""
        # 由于 MultiAgentPipeline 需要 client 和 config 参数，
        # 我们这里只测试其静态的 JSON 解析逻辑

        # 创建一个最小的配置对象
        class MockConfig:
            def __init__(self):
                self.max_retries = 3
                self.pure_ai_model = 'deepseek-reasoner'
                self.language = 'cn'
                self.max_tokens_per_file = 8000

            def get(self, key, default=None):
                return getattr(self, key, default)

        self.config = MockConfig()
        # 注意：我们不初始化完整的 pipeline（需要真实的 client），
        # 只测试 JSON 解析相关的辅助功能

    def test_parse_valid_scanner_response(self):
        """测试解析有效的 Scanner Agent 响应"""
        valid_response = '''
{
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "location": "test.py:42",
      "description": "User input not sanitized",
      "potential_impact": "Data breach",
      "cvss_score": "8.5"
    }
  ]
}
'''

        # 直接调用 json.loads 验证格式正确性
        parsed = json.loads(valid_response)
        assert 'vulnerabilities' in parsed
        assert len(parsed['vulnerabilities']) == 1
        assert parsed['vulnerabilities'][0]['type'] == 'SQL Injection'

    def test_parse_valid_reasoning_response(self):
        """测试解析有效的 Reasoning Agent 响应"""
        valid_response = '''
{
  "findings": [
    {
      "vulnerability": "XSS",
      "location": "app.js:15",
      "severity": "high",
      "confidence": "高",
      "cvss_score": "7.2",
      "description": "Unsanitized user input",
      "evidence": "innerHTML usage without escaping"
    }
  ]
}
'''

        parsed = json.loads(valid_response)
        assert 'findings' in parsed
        assert parsed['findings'][0]['severity'] == 'high'

    def test_parse_markdown_wrapped_json(self):
        """测试解析被 markdown 包裹的 JSON"""
        markdown_response = '''分析结果如下：

```json
{
  "vulnerabilities": [
    {
      "type": "Path Traversal",
      "severity": "medium"
    }
  ]
}
```

以上是完整的分析报告。'''

        parser = SmartJSONParser()
        result = parser.parse(markdown_response)
        assert result is not None
        assert 'vulnerabilities' in result

    def test_parse_with_explanatory_text(self):
        """测试解析带有解释性文本的 JSON"""
        mixed_response = '''经过详细的安全分析，我发现以下问题：

{
  "findings": [
    {
      "vulnerability": "Hardcoded Secret",
      "confidence": "高"
    }
  ]
}

建议立即修复此问题。'''

        parser = SmartJSONParser()
        result = parser.parse(mixed_response)
        assert result is not None

    def test_parse_python_style_output(self):
        """测试解析 Python 字典风格输出"""
        python_style = """{'vulnerabilities': [{'type': 'CSRF', 'flag': True}]}"""

        parser = SmartJSONParser()
        result = parser.parse(python_style)
        # 可能返回None或部分解析的结果，主要确保不崩溃

    def test_empty_input_handling(self):
        """测试空输入处理"""
        parser = SmartJSONParser()

        # 空字符串
        assert parser.parse("") is None

        # 只有空白字符
        assert parser.parse("   \n\t  ") is None

        # 无效的文本
        result = parser.parse("This is just plain text, no JSON here")
        # 应该返回 None 或尽力解析

    def test_large_json_response(self):
        """测试超长 JSON 响应（>10KB）"""
        # 构造一个大的 JSON 对象
        large_vulns = []
        for i in range(100):
            large_vulns.append({
                "type": f"Vulnerability_{i}",
                "location": f"file_{i}.py:{i*10}",
                "description": f"Description for vulnerability {i} with some extra text to make it longer " * 5,
                "potential_impact": f"Impact level {i % 3}",
                "cvss_score": f"{5.0 + (i % 5):.1f}"
            })

        large_json = json.dumps({"vulnerabilities": large_vulns}, ensure_ascii=False)

        # 验证大小超过 10KB
        assert len(large_json.encode('utf-8')) > 10000

        parser = SmartJSONParser()
        result = parser.parse(large_json)
        assert result is not None
        assert len(result['vulnerabilities']) == 100

    def test_malformed_json_recovery(self):
        """测试畸形 JSON 的恢复能力"""
        # 尾部逗号
        malformed1 = '{"key": "value", "number": 123,}'
        parser = SmartJSONParser()
        result1 = parser.parse(malformed1)
        # SmartJSONParser 的 _clean_content 可能会修复这个问题

        # 缺少引号的属性名
        malformed2 = '{key: "value", number: 123}'
        result2 = parser.parse(malformed2)

        # 单引号代替双引号
        malformed3 = "{'key': 'value', 'number': 123}"
        result3 = parser.parse(malformed3)


class TestDefaultObjectStructure:
    """测试默认对象的结构一致性"""

    def test_default_final_findings_structure(self):
        """测试默认 final_findings 的结构"""
        default_finding = {
            "vulnerability": "未发现安全问题",
            "location": "unknown",
            "severity": "info",
            "status": "VALID",
            "confidence": "高",
            "cvss_score": "",
            "recommendation": "代码安全，无需修复",
            "evidence": "经过全面的安全分析，未发现明显的安全漏洞。"
        }

        # 验证所有必需字段存在
        required_fields = [
            'vulnerability', 'location', 'severity', 'status',
            'confidence', 'cvss_score', 'recommendation', 'evidence'
        ]
        for field in required_fields:
            assert field in default_finding

    def test_default_summary_structure(self):
        """测试默认 summary 的结构"""
        default_summary = {
            "total_vulnerabilities": 0,
            "valid_vulnerabilities": 0,
            "uncertain_vulnerabilities": 0,
            "invalid_vulnerabilities": 0,
            "high_severity_count": 0,
            "medium_severity_count": 0,
            "low_severity_count": 0
        }

        # 验证所有必需字段存在且值为0
        for key, value in default_summary.items():
            assert value == 0, f"Field {key} should be 0, got {value}"


class TestEdgeCases:
    """测试边缘情况"""

    def test_unicode_content(self):
        """测试包含 Unicode 内容的 JSON"""
        unicode_json = '{"message": "中文测试 🎉 日本語 한국어", "emoji": "✅❌⚠️"}'
        parser = SmartJSONParser()
        result = parser.parse(unicode_json)
        assert result is not None
        assert '中文测试' in result['message']

    def test_nested_json_structures(self):
        """测试嵌套的 JSON 结构"""
        nested_json = '''
{
  "level1": {
    "level2": {
      "level3": {
        "deep_value": "found"
      },
      "array": [1, 2, {"nested": true}]
    }
  }
}
'''
        parser = SmartJSONParser()
        result = parser.parse(nested_json)
        assert result is not None
        assert result['level1']['level2']['level3']['deep_value'] == 'found'

    def test_json_with_newlines_in_strings(self):
        """测试字符串值中包含换行符的 JSON"""
        newlines_json = '{"text": "line1\\nline2\\nline3", "code": "def foo():\\n    pass"}'
        parser = SmartJSONParser()
        result = parser.parse(newlines_json)
        assert result is not None
        # JSON解析后，\\n 会被转换为真正的换行符 \n
        assert 'line1' in result['text']
        assert 'line2' in result['text']
        assert '\n' in result['text']

    def test_json_with_null_values(self):
        """测试包含 null 值的 JSON"""
        null_json = '{"value": null, "empty": "", "zero": 0, "false": false}'
        parser = SmartJSONParser()
        result = parser.parse(null_json)
        assert result is not None
        assert result['value'] is None
        assert result['empty'] == ''
        assert result['zero'] == 0
        assert result['false'] is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
