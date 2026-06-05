"""LineNumberMapper 单元测试"""

import pytest
from src.ai.pure_ai.line_number_mapper import LineNumberMapper, LineNumberValidator


@pytest.fixture
def mapper():
    return LineNumberMapper()


@pytest.fixture
def validator(mapper):
    return LineNumberValidator(mapper)


@pytest.fixture
def sample_java_code():
    return """package com.example;

import java.util.List;

@Service
public class UserService {
    private String password;
    
    public void setUser(String name) {
        this.name = name;
    }
    
    public String getUser(int id) {
        return userRepository.findById(id);
    }
    
    public void dangerousMethod(String input) {
        Runtime.getRuntime().exec(input);
    }
}
"""


@pytest.fixture
def sample_python_code():
    return """import os

def process_data(data):
    result = eval(data)
    return result

def safe_function():
    return "safe"

password = "secret123"
"""


class TestLineNumberMapperInit:
    def test_init(self, mapper):
        assert isinstance(mapper._snapshots, dict)
        assert len(mapper._snapshots) == 0


class TestRecordFileSnapshot:
    def test_record_with_content(self, mapper):
        mapper.record_file_snapshot("test.py", "print('hello')")
        assert "test.py" in mapper._snapshots
        assert mapper._snapshots["test.py"] == "print('hello')"

    def test_record_with_none_content(self, mapper, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')", encoding="utf-8")
        mapper.record_file_snapshot(str(test_file))
        assert str(test_file) in mapper._snapshots

    def test_record_with_nonexistent_file(self, mapper):
        mapper.record_file_snapshot("/nonexistent/file.py")
        assert "/nonexistent/file.py" in mapper._snapshots
        assert mapper._snapshots["/nonexistent/file.py"] == ""


class TestGetFileContent:
    def test_get_existing_content(self, mapper):
        mapper.record_file_snapshot("test.py", "print('hello')")
        content = mapper.get_file_content("test.py")
        assert content == "print('hello')"

    def test_get_nonexistent_file(self, mapper):
        content = mapper.get_file_content("nonexistent.py")
        assert content == ""


class TestParseLocation:
    def test_parse_simple_location(self, mapper):
        file_path, line = mapper.parse_location("test.py:26")
        assert file_path == "test.py"
        assert line == 26

    def test_parse_windows_location(self, mapper):
        file_path, line = mapper.parse_location("C:\\path\\to\\file.java:42")
        assert "file.java" in file_path
        assert line == 42

    def test_parse_range_location(self, mapper):
        file_path, line = mapper.parse_location("test.py:1-24")
        assert file_path == "test.py"
        assert line == 1

    def test_parse_empty_location(self, mapper):
        file_path, line = mapper.parse_location("")
        assert file_path is None
        assert line is None

    def test_parse_none_location(self, mapper):
        file_path, line = mapper.parse_location(None)
        assert file_path is None
        assert line is None

    def test_parse_no_line_number(self, mapper):
        file_path, line = mapper.parse_location("test.py")
        assert file_path == "test.py"
        assert line is None


class TestIsInvalidLocation:
    def test_valid_location(self, mapper):
        assert not mapper.is_invalid_location("test.py:26")

    def test_invalid_line_marker(self, mapper):
        assert mapper.is_invalid_location("test.py:line")
        assert mapper.is_invalid_location("test.py:Line")
        assert mapper.is_invalid_location("test.py:LINE")

    def test_invalid_unknown_marker(self, mapper):
        assert mapper.is_invalid_location("test.py:unknown")
        assert mapper.is_invalid_location("test.py:Unknown")

    def test_invalid_chinese_marker(self, mapper):
        assert mapper.is_invalid_location("test.py:行号未知")
        assert mapper.is_invalid_location("test.py:行号")
        assert mapper.is_invalid_location("test.py:未知")

    def test_empty_location(self, mapper):
        assert mapper.is_invalid_location("")
        assert mapper.is_invalid_location(None)


class TestFindMatchingLine:
    def test_exact_match(self, mapper, sample_python_code):
        snippet = "result = eval(data)"
        line_num, status, candidates = mapper.find_matching_line(
            snippet, sample_python_code, ai_reported_line=4
        )
        assert status == "EXACT"
        assert line_num > 0

    def test_adjusted_match(self, mapper, sample_python_code):
        snippet = "result = eval(data)"
        line_num, status, candidates = mapper.find_matching_line(
            snippet, sample_python_code, ai_reported_line=10
        )
        assert status == "ADJUSTED"
        assert line_num > 0

    def test_not_found_empty_snippet(self, mapper):
        line_num, status, candidates = mapper.find_matching_line(
            "", "some code", ai_reported_line=1
        )
        assert status == "NOT_FOUND"
        assert line_num == -1

    def test_not_found_empty_file(self, mapper):
        line_num, status, candidates = mapper.find_matching_line(
            "some code", "", ai_reported_line=1
        )
        assert status == "NOT_FOUND"
        assert line_num == -1

    def test_not_found_no_match(self, mapper):
        line_num, status, candidates = mapper.find_matching_line(
            "completely_different_code_here", "some other code", ai_reported_line=1
        )
        assert status == "NOT_FOUND"


class TestNormalizeWhitespace:
    def test_normalize_spaces(self, mapper):
        result = mapper._normalize_whitespace("  hello   world  ")
        assert result == "hello world"

    def test_normalize_tabs(self, mapper):
        result = mapper._normalize_whitespace("hello\t\tworld")
        assert result == "hello world"

    def test_normalize_newlines(self, mapper):
        result = mapper._normalize_whitespace("hello\nworld")
        assert result == "hello world"


class TestExtractKeywords:
    def test_extract_function_name(self, mapper):
        keywords = mapper._extract_keywords("def my_function(arg1, arg2):")
        assert "my_function" in keywords

    def test_extract_class_name(self, mapper):
        keywords = mapper._extract_keywords("class MyClass:")
        assert "myclass" in [kw.lower() for kw in keywords]

    def test_extract_variable_name(self, mapper):
        keywords = mapper._extract_keywords("var myVariable = 1;")
        assert "myvariable" in keywords

    def test_extract_keywords_empty(self, mapper):
        keywords = mapper._extract_keywords("")
        assert len(keywords) == 0


class TestEditDistanceSimilarity:
    def test_identical_strings(self, mapper):
        sim = mapper._edit_distance_similarity("hello", "hello")
        assert sim == 1.0

    def test_completely_different(self, mapper):
        sim = mapper._edit_distance_similarity("abc", "xyz")
        assert sim < 1.0

    def test_empty_strings(self, mapper):
        sim = mapper._edit_distance_similarity("", "")
        assert sim == 0.0

    def test_one_empty_string(self, mapper):
        sim = mapper._edit_distance_similarity("hello", "")
        assert sim == 0.0


class TestFuzzySearch:
    def test_fuzzy_search_exact(self, mapper, sample_python_code):
        lines = sample_python_code.split('\n')
        results = mapper._fuzzy_search(
            "result = eval(data)", lines, center_line=4, search_range=5
        )
        assert len(results) > 0

    def test_fuzzy_search_empty_snippet(self, mapper):
        lines = ["line1", "line2"]
        results = mapper._fuzzy_search("", lines, center_line=1, search_range=5)


class TestCalculateLineDeviation:
    def test_deviation_normal(self, mapper):
        dev = mapper.calculate_line_deviation(10, 15)
        assert dev == 5

    def test_deviation_same(self, mapper):
        dev = mapper.calculate_line_deviation(10, 10)
        assert dev == 0

    def test_deviation_negative_input(self, mapper):
        dev = mapper.calculate_line_deviation(-1, 10)
        assert dev == -1

    def test_deviation_zero_input(self, mapper):
        dev = mapper.calculate_line_deviation(0, 10)
        assert dev == -1


class TestIsWithinTolerance:
    def test_within_tolerance(self, mapper):
        assert mapper.is_within_tolerance(3, 5)

    def test_outside_tolerance(self, mapper):
        assert not mapper.is_within_tolerance(10, 5)

    def test_zero_tolerance(self, mapper):
        assert mapper.is_within_tolerance(0, 0)
        assert not mapper.is_within_tolerance(1, 0)


class TestIsValidVulnerabilityLine:
    def test_valid_line(self, mapper):
        is_valid, reason = mapper._is_valid_vulnerability_line(
            "Runtime.getRuntime().exec(input);", 25, 30
        )
        assert is_valid
        assert reason == "VALID"

    def test_empty_line(self, mapper):
        is_valid, reason = mapper._is_valid_vulnerability_line("", 10, 30)
        assert not is_valid
        assert "空行" in reason

    def test_single_line_comment(self, mapper):
        is_valid, reason = mapper._is_valid_vulnerability_line(
            "// this is a comment", 10, 30
        )
        assert not is_valid
        assert "注释" in reason

    def test_package_statement_early_line(self, mapper):
        is_valid, reason = mapper._is_valid_vulnerability_line(
            "package com.example;", 2, 30
        )
        assert not is_valid
        assert "package" in reason

    def test_import_statement_early_line(self, mapper):
        is_valid, reason = mapper._is_valid_vulnerability_line(
            "import java.util.List;", 3, 30
        )
        assert not is_valid
        assert "import" in reason


class TestIsCommentOrImport:
    def test_single_line_comment(self, mapper):
        assert mapper._is_comment_or_import("// comment")

    def test_multi_line_comment_start(self, mapper):
        assert mapper._is_comment_or_import("/* comment")

    def test_multi_line_comment_continuation(self, mapper):
        assert mapper._is_comment_or_import("* continuation")

    def test_package_statement(self, mapper):
        assert mapper._is_comment_or_import("package com.example;")

    def test_import_statement(self, mapper):
        assert mapper._is_comment_or_import("import java.util.List;")

    def test_empty_line(self, mapper):
        assert mapper._is_comment_or_import("")
        assert mapper._is_comment_or_import(None)

    def test_normal_code(self, mapper):
        assert not mapper._is_comment_or_import("int x = 1;")


class TestValidateVulnerabilityLocation:
    def test_valid_location(self, mapper):
        is_valid, reason = mapper.validate_vulnerability_location(
            25, "Runtime.getRuntime().exec(input);", "command injection"
        )
        assert is_valid

    def test_invalid_empty_line(self, mapper):
        is_valid, reason = mapper.validate_vulnerability_location(
            10, "", "command injection"
        )
        assert not is_valid

    def test_annotation_type_mismatch(self, mapper):
        is_valid, reason = mapper.validate_vulnerability_location(
            15, "int x = 1;", "annotation"
        )
        assert not is_valid

    def test_no_vulnerability_type(self, mapper):
        is_valid, reason = mapper.validate_vulnerability_location(
            15, "int x = 1;", ""
        )
        assert is_valid
        assert reason == "VALID"


class TestLineNumberValidatorInit:
    def test_init_default_tolerance(self, validator):
        assert validator.tolerance == 5

    def test_init_custom_tolerance(self, mapper):
        v = LineNumberValidator(mapper, tolerance=10)
        assert v.tolerance == 10


class TestLineNumberValidatorSnapshot:
    def test_record_snapshot(self, validator):
        validator.record_file_snapshot("test.py", "print('hello')")
        assert validator.get_file_content("test.py") == "print('hello')"


class TestLineNumberValidatorVerifyAndCorrect:
    def test_verify_exact_match(self, validator, sample_python_code):
        validator.record_file_snapshot("test.py", sample_python_code)
        result = validator.verify_and_correct(
            "test.py:4",
            code_snippet="result = eval(data)"
        )
        assert result['line_match_status'] == 'EXACT'
        assert result['is_valid']

    def test_verify_adjusted_match(self, validator, sample_python_code):
        validator.record_file_snapshot("test.py", sample_python_code)
        result = validator.verify_and_correct(
            "test.py:10",
            code_snippet="result = eval(data)"
        )
        assert result['line_match_status'] in ['EXACT', 'ADJUSTED', 'UNVERIFIED']
        assert result['is_valid'] or result.get('ai_hallucination_warning')

    def test_verify_no_snapshot(self, validator):
        result = validator.verify_and_correct(
            "test.py:10",
            code_snippet="some code"
        )
        assert result['line_match_status'] == 'NO_SNAPSHOT'

    def test_verify_invalid_location(self, validator):
        validator.record_file_snapshot("test.py", "some code")
        result = validator.verify_and_correct(
            "invalid_format",
            code_snippet="some code"
        )
        assert result['line_match_status'] == 'INVALID_LOCATION'

    def test_verify_no_snippet(self, validator, sample_python_code):
        validator.record_file_snapshot("test.py", sample_python_code)
        result = validator.verify_and_correct("test.py:10")
        assert result['line_match_status'] == 'UNVERIFIED'
        assert result['ai_hallucination_warning']

    def test_verify_not_found_status(self, validator, sample_python_code):
        validator.record_file_snapshot("test.py", sample_python_code)
        result = validator.verify_and_correct(
            "test.py:100",
            code_snippet="completely_unrelated_code_xyz"
        )
        assert result['is_valid']
        assert result['ai_hallucination_warning']

    def test_verify_custom_tolerance(self, validator, sample_python_code):
        validator.record_file_snapshot("test.py", sample_python_code)
        result = validator.verify_and_correct(
            "test.py:100",
            code_snippet="result = eval(data)",
            tolerance=1
        )
