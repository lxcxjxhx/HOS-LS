"""行号验证器单元测试"""

import pytest
from src.ai.pure_ai.line_number_mapper import LineNumberMapper, LineNumberValidator


class TestLineNumberMapper:
    """LineNumberMapper 单元测试"""

    def test_exact_match_at_reported_line(self):
        """测试精确匹配（代码片段在AI报告行号处匹配）"""
        mapper = LineNumberMapper()
        content = """package com.example;

public class Test {
    private String value;
}"""
        mapper.record_file_snapshot("Test.java", content)

        matched_line, match_status, candidates = mapper.find_matching_line(
            "public class Test {", content, ai_reported_line=3
        )

        assert matched_line == 3
        assert match_status == "EXACT"

    def test_adjusted_match_different_line(self):
        """测试校正匹配（代码片段在其他位置匹配）"""
        mapper = LineNumberMapper()
        content = """package com.example;

public class Test {
    private String value;
}"""
        mapper.record_file_snapshot("Test.java", content)

        matched_line, match_status, candidates = mapper.find_matching_line(
            "private String value;", content, ai_reported_line=10
        )

        assert matched_line == 4
        assert match_status == "ADJUSTED"

    def test_not_found(self):
        """测试无法匹配"""
        mapper = LineNumberMapper()
        content = """package com.example;

public class Test {
}"""
        mapper.record_file_snapshot("Test.java", content)

        matched_line, match_status, candidates = mapper.find_matching_line(
            "non-existent code", content, ai_reported_line=5
        )

        assert match_status == "NOT_FOUND"

    def test_parse_location(self):
        """测试解析location字符串"""
        mapper = LineNumberMapper()

        file_path, line_num = mapper.parse_location("Test.java:25")
        assert file_path == "Test.java"
        assert line_num == 25

        file_path, line_num = mapper.parse_location("path/to/File.java:1-10")
        assert file_path == "path/to/File.java"
        assert line_num == 1

    def test_calculate_line_deviation(self):
        """测试计算行号偏差"""
        mapper = LineNumberMapper()

        deviation = mapper.calculate_line_deviation(25, 29)
        assert deviation == 4

        deviation = mapper.calculate_line_deviation(29, 25)
        assert deviation == 4

    def test_is_within_tolerance(self):
        """测试容忍度检查"""
        mapper = LineNumberMapper()

        assert mapper.is_within_tolerance(0, 0) is True
        assert mapper.is_within_tolerance(1, 0) is False
        assert mapper.is_within_tolerance(3, 5) is True
        assert mapper.is_within_tolerance(6, 5) is False


class TestLineNumberValidator:
    """LineNumberValidator 单元测试（校正优先模式）"""

    def test_exact_match_preserved(self):
        """测试精确匹配 - 漏洞被保留"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper)

        content = """package com.example;

public class Test {
}"""
        validator.record_file_snapshot("Test.java", content)

        result = validator.verify_and_correct(
            "Test.java:1", "package com.example;", tolerance=0
        )

        assert result["line_match_status"] == "EXACT"
        assert result["is_valid"] is True
        assert result["deviation"] == 0
        assert result["warning_message"] is None

    def test_adjusted_match_preserved(self):
        """测试校正匹配 - 漏洞被保留（关键测试）"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper)

        content = """package com.example;

public class Test {
}"""
        validator.record_file_snapshot("Test.java", content)

        result = validator.verify_and_correct(
            "Test.java:10", "public class Test {", tolerance=5
        )

        assert result["line_match_status"] == "ADJUSTED"
        assert result["is_valid"] is True
        assert result["verified_line"] == 3
        assert result["deviation"] == 7

    def test_large_deviation_preserved(self):
        """测试大偏差也被保留 - 不因偏差大而排除（关键测试）"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper, tolerance=3)

        content = """package com.example;

public class Test {
    private String value;
}"""
        validator.record_file_snapshot("Test.java", content)

        result = validator.verify_and_correct(
            "Test.java:20", "private String value;", tolerance=3
        )

        assert result["line_match_status"] == "ADJUSTED"
        assert result["is_valid"] is True
        assert result["verified_line"] == 4
        assert result["deviation"] == 16
        assert result["warning_message"] is not None
        assert "偏差较大" in result["warning_message"]

    def test_not_found_still_preserved(self):
        """测试找不到匹配时漏洞仍被保留"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper)

        content = """package com.example;
"""
        validator.record_file_snapshot("Test.java", content)

        result = validator.verify_and_correct(
            "Test.java:5", "non-existent-code", tolerance=0
        )

        assert result["line_match_status"] == "NOT_FOUND"
        assert result["is_valid"] is True
        assert result["warning_message"] is not None

    def test_no_snippet(self):
        """测试无代码片段"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper)

        content = """package com.example;
"""
        validator.record_file_snapshot("Test.java", content)

        result = validator.verify_and_correct(
            "Test.java:1", None, tolerance=0
        )

        assert result["line_match_status"] == "NO_SNIPPET"
        assert result["is_valid"] is True

    def test_invalid_location(self):
        """测试无效location"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper)

        result = validator.verify_and_correct(
            "", "some code", tolerance=0
        )

        assert result["line_match_status"] == "INVALID_LOCATION"
        assert result["is_valid"] is False

    def test_candidates_provided(self):
        """测试候选行号列表"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper)

        content = """package com.example;

public class Test {
    private String value;
}"""
        validator.record_file_snapshot("Test.java", content)

        result = validator.verify_and_correct(
            "Test.java:20", "public class Test {", tolerance=5
        )

        assert result["candidate_lines"] is not None
        assert len(result["candidate_lines"]) > 0

    def test_ai_hallucination_warning(self):
        """测试AI幻觉警告 - 代码片段不存在时"""
        mapper = LineNumberMapper()
        validator = LineNumberValidator(mapper)

        content = """package com.example;

public class Test {
}"""
        validator.record_file_snapshot("Test.java", content)

        result = validator.verify_and_correct(
            "Test.java:5", "suspicious.malicious.method();", tolerance=0
        )

        assert result["line_match_status"] == "NOT_FOUND"
        assert result["ai_hallucination_warning"] is True
        assert "🚨 AI幻觉警告" in result["warning_message"]
        assert result["is_valid"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
