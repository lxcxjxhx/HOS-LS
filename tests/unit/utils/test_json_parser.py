"""Utils JSON parser module tests"""

import json
import pytest

from src.utils.json_parser import SmartJSONParser


class TestSmartJSONParser:
    def setup_method(self):
        self.parser = SmartJSONParser()

    def test_parse_valid_json(self):
        content = '{"key": "value", "number": 42}'
        result = self.parser.parse(content)
        assert result is not None
        assert result["key"] == "value"
        assert result["number"] == 42

    def test_parse_json_with_markdown(self):
        content = '''```json
{"key": "value"}
```'''
        result = self.parser.parse(content)
        assert result is not None
        assert result["key"] == "value"

    def test_parse_json_array(self):
        content = '[{"id": 1}, {"id": 2}]'
        result = self.parser.parse(content)
        assert result is not None
        assert len(result) == 2

    def test_parse_json_array_from_markdown(self):
        content = '''```json
[{"id": 1}, {"id": 2}]
```'''
        result = self.parser.parse(content)
        assert result is not None
        assert len(result) == 2

    def test_parse_with_comments(self):
        content = '''{
    // This is a comment
    "key": "value"
}'''
        result = self.parser.parse(content)
        assert result is not None
        assert result["key"] == "value"

    def test_parse_invalid_json(self):
        content = "not json at all"
        result = self.parser.parse(content)
        assert result is None

    def test_parse_empty_content(self):
        result = self.parser.parse("")
        assert result is None

    def test_parse_nested_json(self):
        content = '{"outer": {"inner": {"deep": "value"}}}'
        result = self.parser.parse(content)
        assert result["outer"]["inner"]["deep"] == "value"

    def test_parse_array(self):
        content = '[1, 2, 3]'
        result = self.parser.parse_array(content)
        assert result == [1, 2, 3]

    def test_parse_array_non_array(self):
        content = '{"key": "value"}'
        result = self.parser.parse_array(content)
        assert result is None

    def test_parse_with_fallback_default(self):
        content = "invalid"
        result = self.parser.parse_with_fallback(content, fallback={"default": True})
        assert result == {"default": True}

    def test_parse_with_fallback_valid(self):
        content = '{"key": "value"}'
        result = self.parser.parse_with_fallback(content, fallback={"default": True})
        assert result == {"key": "value"}

    def test_parse_with_fallback_no_default(self):
        content = "invalid"
        result = self.parser.parse_with_fallback(content)
        assert result == {}

    def test_parse_json_with_line_numbers(self):
        content = '''1 {"key": "value"}'''
        result = self.parser.parse(content)
        if result is not None:
            assert result["key"] == "value"

    def test_clean_content(self):
        content = '```json\n{"key": "value"}\n```'
        cleaned = self.parser._clean_content(content)
        assert "```" not in cleaned

    def test_remove_single_line_comments(self):
        content = '{"key": "value" // comment}'
        result = self.parser._remove_comments(content)
        assert "// comment" not in result

    def test_remove_multiline_comments(self):
        content = '{"key": /* comment */ "value"}'
        result = self.parser._remove_comments(content)
        assert "/* comment */" not in result

    def test_parse_json_object_from_code_block(self):
        content = '''Here is the result:
```
{"result": "success"}
```'''
        result = self.parser.parse(content)
        assert result is not None
        assert result["result"] == "success"

    def test_parse_complex_json(self):
        content = json.dumps({
            "scan_results": {
                "findings": [
                    {"rule": "SQL_INJECTION", "severity": "high"},
                    {"rule": "XSS", "severity": "medium"},
                ],
                "total": 2,
                "status": "completed"
            }
        })
        result = self.parser.parse(content)
        assert result is not None
        assert result["scan_results"]["total"] == 2
        assert len(result["scan_results"]["findings"]) == 2
