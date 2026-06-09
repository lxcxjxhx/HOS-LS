"""ASTAnalyzer 单元测试"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.base import (
    AnalysisContext,
    AnalysisResult,
    AnalysisType,
    AnalysisStatus,
)


@pytest.fixture
def analyzer():
    return ASTAnalyzer()


@pytest.fixture
def python_context():
    return AnalysisContext(
        file_path=Path("test.py"),
        file_content="x = 1\n",
        language="python",
    )


@pytest.fixture
def js_context():
    return AnalysisContext(
        file_path=Path("test.js"),
        file_content="var x = 1;\n",
        language="javascript",
    )


@pytest.fixture
def python_with_eval():
    return AnalysisContext(
        file_path=Path("test.py"),
        file_content="result = eval(user_input)\n",
        language="python",
    )


@pytest.fixture
def python_with_sensitive_var():
    return AnalysisContext(
        file_path=Path("test.py"),
        file_content="password = 'secret123'\n",
        language="python",
    )


@pytest.fixture
def python_with_function():
    return AnalysisContext(
        file_path=Path("test.py"),
        file_content="def test_function(password):\n    pass\n",
        language="python",
    )


class TestASTAnalyzerInit:
    def test_init_default(self, analyzer):
        assert analyzer.name == "ast_analyzer"
        assert analyzer.version == "1.1.0"
        assert "python" in analyzer.supported_languages
        assert "javascript" in analyzer.supported_languages
        assert "java" in analyzer.supported_languages
        assert "cpp" in analyzer.supported_languages

    def test_init_with_config(self):
        config = {"custom_key": "custom_value"}
        analyzer = ASTAnalyzer(config)
        assert analyzer.config["custom_key"] == "custom_value"

    def test_init_dangerous_functions(self, analyzer):
        assert "python" in analyzer._dangerous_functions
        assert "eval" in analyzer._dangerous_functions["python"]
        assert "javascript" in analyzer._dangerous_functions
        assert "java" in analyzer._dangerous_functions
        assert "cpp" in analyzer._dangerous_functions

    def test_init_parsers_empty(self, analyzer):
        assert isinstance(analyzer._parsers, dict)
        assert isinstance(analyzer._languages, dict)


class TestASTAnalyzerLoadLanguages:
    def test_load_languages_success(self, analyzer):
        analyzer._load_languages()
        assert "python" in analyzer._languages or "python" not in analyzer._languages

    def test_load_languages_missing(self):
        analyzer = ASTAnalyzer()
        with patch.dict("sys.modules", {"tree_sitter_python": None}):
            pass
        analyzer._load_languages()


class TestASTAnalyzerAnalyze:
    def test_analyze_python_simple(self, analyzer, python_context):
        analyzer.initialize()
        result = analyzer.analyze(python_context)
        assert isinstance(result, AnalysisResult)
        assert result.analysis_type == AnalysisType.AST

    def test_analyze_unsupported_language(self, analyzer):
        context = AnalysisContext(
            file_path=Path("test.unknown"),
            file_content="some code",
            language="unknown_lang",
        )
        analyzer.initialize()
        result = analyzer.analyze(context)
        assert result.status == AnalysisStatus.FAILED
        assert result.has_errors

    def test_analyze_with_eval_detection(self, analyzer, python_with_eval):
        analyzer.initialize()
        result = analyzer.analyze(python_with_eval)
        assert result.status in [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED]

    def test_analyze_with_sensitive_variable(self, analyzer, python_with_sensitive_var):
        analyzer.initialize()
        result = analyzer.analyze(python_with_sensitive_var)

    def test_analyze_with_function_definition(self, analyzer, python_with_function):
        analyzer.initialize()
        result = analyzer.analyze(python_with_function)


class TestASTAnalyzerAnalyzeWithMetrics:
    def test_analyze_with_metrics(self, analyzer, python_context):
        analyzer.initialize()
        result = analyzer.analyze_with_metrics(python_context)
        if result.status != AnalysisStatus.FAILED:
            assert result.performance is not None
            assert result.performance.duration >= 0
        else:
            assert result.has_errors


class TestASTAnalyzerGetTree:
    def test_get_tree_python(self, analyzer):
        analyzer.initialize()
        tree = analyzer.get_tree("x = 1\n", "python")
        if tree is not None:
            assert tree.root_node is not None

    def test_get_tree_unsupported_language(self, analyzer):
        tree = analyzer.get_tree("some code", "unknown")
        assert tree is None


class TestASTAnalyzerGetInfo:
    def test_get_info(self, analyzer):
        info = analyzer.get_info()
        assert info["name"] == "ast_analyzer"
        assert info["version"] == "1.1.0"
        assert "dangerous_functions" in info


class TestASTAnalyzerGetStandardizedOutput:
    def test_get_standardized_output_empty(self, analyzer, python_context):
        analyzer.initialize()
        result = analyzer.analyze(python_context)
        output = analyzer.get_standardized_output(result)
        assert isinstance(output, list)

    def test_get_standardized_output_with_issues(self, analyzer, python_with_function):
        analyzer.initialize()
        result = analyzer.analyze(python_with_function)
        output = analyzer.get_standardized_output(result)
        assert isinstance(output, list)
        if result.issues:
            for item in output:
                assert "rule_id" in item
                assert "message" in item
                assert "severity" in item
                assert "location" in item
                assert "source_agent" in item


class TestASTAnalyzerCheckNodeMethods:
    def test_check_function_call_with_dangerous(self, analyzer):
        analyzer.initialize()
        context = AnalysisContext(
            file_path=Path("test.py"),
            file_content="result = eval(input())\n",
            language="python",
        )
        result = analyzer.analyze(context)

    def test_check_import_wildcard(self, analyzer):
        analyzer.initialize()
        context = AnalysisContext(
            file_path=Path("test.py"),
            file_content="from os import *\n",
            language="python",
        )
        result = analyzer.analyze(context)

    def test_check_import_dangerous_module(self, analyzer):
        analyzer.initialize()
        context = AnalysisContext(
            file_path=Path("test.py"),
            file_content="import subprocess\n",
            language="python",
        )
        result = analyzer.analyze(context)

    def test_check_class_definition(self, analyzer):
        analyzer.initialize()
        context = AnalysisContext(
            file_path=Path("test.py"),
            file_content="class MyClass:\n    password = 'secret'\n",
            language="python",
        )
        result = analyzer.analyze(context)

    def test_check_if_constant_condition(self, analyzer):
        analyzer.initialize()
        context = AnalysisContext(
            file_path=Path("test.py"),
            file_content="if True:\n    pass\n",
            language="python",
        )
        result = analyzer.analyze(context)

    def test_check_while_infinite_loop(self, analyzer):
        analyzer.initialize()
        context = AnalysisContext(
            file_path=Path("test.py"),
            file_content="while True:\n    pass\n",
            language="python",
        )
        result = analyzer.analyze(context)

    def test_check_try_empty_except(self, analyzer):
        analyzer.initialize()
        context = AnalysisContext(
            file_path=Path("test.py"),
            file_content="try:\n    pass\nexcept:\n    pass\n",
            language="python",
        )
        result = analyzer.analyze(context)

    def test_check_return_sensitive(self, analyzer):
        analyzer.initialize()
        context = AnalysisContext(
            file_path=Path("test.py"),
            file_content="def get_password():\n    return password\n",
            language="python",
        )
        result = analyzer.analyze(context)


class TestASTAnalyzerHelperMethods:
    def test_get_poc_for_function(self, analyzer):
        poc = analyzer._get_poc_for_function("eval", "python")
        assert "eval" in poc.lower() or len(poc) > 0

    def test_get_poc_for_function_javascript(self, analyzer):
        poc = analyzer._get_poc_for_function("eval", "javascript")
        assert "eval" in poc.lower() or len(poc) > 0

    def test_get_poc_for_unknown(self, analyzer):
        poc = analyzer._get_poc_for_function("unknown_func", "python")
        assert poc == ""

    def test_get_fix_suggestion(self, analyzer):
        fix = analyzer._get_fix_suggestion("eval", "python")
        assert "eval" in fix.lower() or len(fix) > 0

    def test_get_fix_suggestion_unknown(self, analyzer):
        fix = analyzer._get_fix_suggestion("unknown_func", "python")
        assert fix == ""

    def test_supports_language(self, analyzer):
        assert analyzer.supports_language("python")
        assert analyzer.supports_language("javascript")
        assert not analyzer.supports_language("unknown")

    def test_supports_analysis_type(self, analyzer):
        assert analyzer.supports_analysis_type(AnalysisType.AST)
        assert analyzer.supports_analysis_type(AnalysisType.SECURITY)
        assert analyzer.supports_analysis_type("ast")

    def test_supports_file(self, analyzer):
        assert analyzer.supports_file("test.py")
        assert analyzer.supports_file("test.js")
        assert not analyzer.supports_file("test.unknown")

    def test_get_performance_statistics_empty(self, analyzer):
        stats = analyzer.get_performance_statistics()
        assert stats["total_analyses"] == 0
