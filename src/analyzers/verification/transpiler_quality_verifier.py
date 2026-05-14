from dataclasses import dataclass, field
from typing import Any, List, Tuple, Optional, Set, Dict
import ast
import random
import inspect

from .universal_parser import SupportedLanguage


@dataclass
class TestCase:
    input_data: Any
    expected_output: Any
    description: str
    language: SupportedLanguage = SupportedLanguage.PYTHON


@dataclass
class VerificationResult:
    test_case: TestCase
    original_output: Any
    transpiled_output: Any
    is_equivalent: bool
    error_message: str = ""
    execution_time_original: float = 0.0
    execution_time_transpiled: float = 0.0
    source_language: SupportedLanguage = SupportedLanguage.PYTHON
    target_language: SupportedLanguage = SupportedLanguage.PYTHON


@dataclass
class QualityReport:
    total_test_cases: int
    passed: int
    failed: int
    equivalence_rate: float
    failed_cases: List[VerificationResult] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    language_stats: Dict[SupportedLanguage, Dict[str, Any]] = field(default_factory=dict)


class ASTTranspilerEngine:
    def transpile(self, source_code: str) -> str:
        raise NotImplementedError


class TranspilerQualityVerifier:
    def __init__(self, ast_transpiler: ASTTranspilerEngine, executor: 'PythonTestExecutor'):
        self.ast_transpiler = ast_transpiler
        self.executor = executor
        self._supported_languages: Set[SupportedLanguage] = {
            SupportedLanguage.PYTHON,
            SupportedLanguage.JAVA,
            SupportedLanguage.CPP,
            SupportedLanguage.GO,
            SupportedLanguage.RUST,
        }

    def generate_test_cases(self, source_code: str, count: int = 5, language: SupportedLanguage = SupportedLanguage.PYTHON) -> List[TestCase]:
        return self._generate_for_language(language, source_code, count)

    def _generate_for_language(self, language: SupportedLanguage, source_code: str, count: int) -> List[TestCase]:
        if language == SupportedLanguage.PYTHON:
            return self._generate_python_test_cases(source_code, count)
        elif language == SupportedLanguage.JAVA:
            return self._generate_java_test_cases(source_code, count)
        elif language == SupportedLanguage.CPP:
            return self._generate_cpp_test_cases(source_code, count)
        elif language == SupportedLanguage.GO:
            return self._generate_go_test_cases(source_code, count)
        elif language == SupportedLanguage.RUST:
            return self._generate_rust_test_cases(source_code, count)
        else:
            return self._generate_python_test_cases(source_code, count)

    def _generate_python_test_cases(self, source_code: str, count: int) -> List[TestCase]:
        test_cases = []
        inputs = self._identify_inputs(source_code)

        for inp in inputs:
            inp_type = self._get_input_type(inp)
            generated = self._generate_test_values_for_type(inp_type, count)
            for value in generated:
                test_cases.append(TestCase(
                    input_data=value,
                    expected_output=None,
                    description=f"{inp_type} test: {value}",
                    language=SupportedLanguage.PYTHON
                ))

        return test_cases[:count]

    def _generate_java_test_cases(self, source_code: str, count: int) -> List[TestCase]:
        test_cases = []
        inputs = self._identify_inputs(source_code)

        java_specific_values = [
            None,
            0, 1, -1, 42,
            0.0, 1.5,
            True, False,
            "",
            "hello",
            [],
            [1, 2, 3],
            {},
            {"key": "value"},
            java_object("SampleClass", {"field1": "value1", "field2": 42}),
            java_collection("ArrayList", [1, 2, 3]),
            java_collection("HashMap", {"a": 1, "b": 2}),
        ]

        for inp in inputs:
            inp_type = self._get_input_type(inp)
            generated = self._generate_test_values_for_type(inp_type, count)
            for value in generated:
                test_cases.append(TestCase(
                    input_data=value,
                    expected_output=None,
                    description=f"Java {inp_type} test: {value}",
                    language=SupportedLanguage.JAVA
                ))

        for value in java_specific_values[:count]:
            test_cases.append(TestCase(
                input_data=value,
                expected_output=None,
                description=f"Java-specific test: {type(value).__name__ if value is not None else 'null'}",
                language=SupportedLanguage.JAVA
            ))

        return test_cases[:count]

    def _generate_cpp_test_cases(self, source_code: str, count: int) -> List[TestCase]:
        test_cases = []
        inputs = self._identify_inputs(source_code)

        cpp_specific_values = [
            None,
            0, 1, -1, 42,
            0.0, 1.5,
            True, False,
            "",
            "hello",
            [],
            [1, 2, 3],
            {},
            {"key": "value"},
            cpp_pointer(42),
            cpp_reference(42),
            cpp_smart_pointer("unique_ptr", 42),
            cpp_vector([1, 2, 3]),
            cpp_map({"a": 1, "b": 2}),
        ]

        for inp in inputs:
            inp_type = self._get_input_type(inp)
            generated = self._generate_test_values_for_type(inp_type, count)
            for value in generated:
                test_cases.append(TestCase(
                    input_data=value,
                    expected_output=None,
                    description=f"C++ {inp_type} test: {value}",
                    language=SupportedLanguage.CPP
                ))

        for value in cpp_specific_values[:count]:
            test_cases.append(TestCase(
                input_data=value,
                expected_output=None,
                description=f"C++-specific test: {type(value).__name__ if value is not None else 'null'}",
                language=SupportedLanguage.CPP
            ))

        return test_cases[:count]

    def _generate_go_test_cases(self, source_code: str, count: int) -> List[TestCase]:
        test_cases = []
        inputs = self._identify_inputs(source_code)

        go_specific_values = [
            None,
            0, 1, -1, 42,
            0.0, 1.5,
            True, False,
            "",
            "hello",
            [],
            [1, 2, 3],
            {},
            {"key": "value"},
            go_slice([1, 2, 3]),
            go_map({"a": 1, "b": 2}),
            go_nil_slice(),
            go_nil_map(),
        ]

        for inp in inputs:
            inp_type = self._get_input_type(inp)
            generated = self._generate_test_values_for_type(inp_type, count)
            for value in generated:
                test_cases.append(TestCase(
                    input_data=value,
                    expected_output=None,
                    description=f"Go {inp_type} test: {value}",
                    language=SupportedLanguage.GO
                ))

        for value in go_specific_values[:count]:
            test_cases.append(TestCase(
                input_data=value,
                expected_output=None,
                description=f"Go-specific test: {type(value).__name__ if value is not None else 'nil'}",
                language=SupportedLanguage.GO
            ))

        return test_cases[:count]

    def _generate_rust_test_cases(self, source_code: str, count: int) -> List[TestCase]:
        test_cases = []
        inputs = self._identify_inputs(source_code)

        rust_specific_values = [
            None,
            0, 1, -1, 42,
            0.0, 1.5,
            True, False,
            "",
            "hello",
            [],
            [1, 2, 3],
            {},
            {"key": "value"},
            rust_option_some(42),
            rust_option_none(),
            rust_result_ok(42),
            rust_result_err("error"),
            rust_vec([1, 2, 3]),
            rust_hashmap({"a": 1, "b": 2}),
        ]

        for inp in inputs:
            inp_type = self._get_input_type(inp)
            generated = self._generate_test_values_for_type(inp_type, count)
            for value in generated:
                test_cases.append(TestCase(
                    input_data=value,
                    expected_output=None,
                    description=f"Rust {inp_type} test: {value}",
                    language=SupportedLanguage.RUST
                ))

        for value in rust_specific_values[:count]:
            test_cases.append(TestCase(
                input_data=value,
                expected_output=None,
                description=f"Rust-specific test: {type(value).__name__ if value is not None else 'None'}",
                language=SupportedLanguage.RUST
            ))

        return test_cases[:count]

    def _identify_inputs(self, source_code: str) -> List[Any]:
        try:
            tree = ast.parse(source_code)
            inputs = []

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id.lower()
                            if any(keyword in var_name for keyword in ['num', 'count', 'amount', 'price', 'age', 'score', 'rate']):
                                inputs.append(0)
                            elif any(keyword in var_name for keyword in ['name', 'text', 'str', 'msg', 'message', 'input']):
                                inputs.append("")
                            elif any(keyword in var_name for keyword in ['list', 'arr', 'items', 'data']):
                                inputs.append([])
                            elif any(keyword in var_name for keyword in ['dict', 'obj', 'config']):
                                inputs.append({})
                            else:
                                inputs.append(None)

                elif isinstance(node, ast.FunctionDef):
                    for arg in node.args.args:
                        arg_name = arg.arg.lower()
                        if any(keyword in arg_name for keyword in ['num', 'count', 'amount', 'price', 'age', 'score', 'rate']):
                            inputs.append(0)
                        elif any(keyword in arg_name for keyword in ['name', 'text', 'str', 'msg', 'message', 'input']):
                            inputs.append("")
                        elif any(keyword in arg_name for keyword in ['list', 'arr', 'items', 'data']):
                            inputs.append([])
                        elif any(keyword in arg_name for keyword in ['dict', 'obj', 'config']):
                            inputs.append({})
                        else:
                            inputs.append(None)

            if not inputs:
                inputs = [0, "", [], {}, None]

            return inputs

        except SyntaxError:
            return [0, "", [], {}, None]

    def _get_input_type(self, value: Any) -> str:
        if value is None:
            return "null"
        elif isinstance(value, bool):
            return "bool"
        elif isinstance(value, int) or isinstance(value, float):
            return "numeric"
        elif isinstance(value, str):
            return "string"
        elif isinstance(value, list) or isinstance(value, tuple):
            return "collection"
        elif isinstance(value, dict):
            return "object"
        elif isinstance(value, object):
            return "object"
        return "unknown"

    def _generate_test_values_for_type(self, type_name: str, count: int) -> List[Any]:
        if type_name == "numeric":
            return [
                0,
                1,
                -1,
                42,
                -42,
                0.0,
                1.5,
                -1.5,
                1e10,
                -1e10,
                1e-10,
                -1e-10,
                float('inf'),
                float('-inf'),
            ]
        elif type_name == "string":
            return [
                "",
                "hello",
                "world",
                "test@example.com",
                "<script>alert('xss')</script>",
                "'; DROP TABLE users; --",
                "abc123",
                "中文测试",
                "   ",
                "\n\t",
                "a" * 1000,
                "🌟 emoji test",
            ]
        elif type_name == "collection":
            return [
                [],
                [1],
                [1, 2, 3],
                list(range(100)),
                [None],
                [""],
                ["a", "b", "c"],
            ]
        elif type_name == "object":
            return [
                {},
                {"key": "value"},
                {"a": 1, "b": 2},
                {"nested": {"inner": "value"}},
                None,
            ]
        elif type_name == "bool":
            return [True, False]
        elif type_name == "null":
            return [None]
        else:
            return [None, 0, "", [], {}]

    def verify(self, source_code: str, transpiled_code: str, test_cases: List[TestCase]) -> List[VerificationResult]:
        results = []

        for test_case in test_cases:
            result = self._verify_single_test(source_code, transpiled_code, test_case)
            results.append(result)

        return results

    def _verify_single_test(self, source_code: str, transpiled_code: str, test_case: TestCase) -> VerificationResult:
        wrapper_original = self._create_execution_wrapper(source_code, test_case.input_data)
        wrapper_transpiled = self._create_execution_wrapper(transpiled_code, test_case.input_data)

        result_original = self.executor.execute(wrapper_original, timeout=30)
        result_transpiled = self.executor.execute(wrapper_transpiled, timeout=30)

        original_output = None
        transpiled_output = None
        error_message = ""
        is_equivalent = False

        if result_original["success"] and result_transpiled["success"]:
            try:
                original_output = eval(result_original["output"].strip()) if result_original["output"].strip() else None
                transpiled_output = eval(result_transpiled["output"].strip()) if result_transpiled["output"].strip() else None
                is_equivalent = self.are_equivalent(original_output, transpiled_output)
            except Exception as e:
                error_message = f"Output parsing error: {str(e)}"
        elif not result_original["success"]:
            error_message = f"Original code error: {result_original['error']}"
        elif not result_transpiled["success"]:
            error_message = f"Transpiled code error: {result_transpiled['error']}"

        return VerificationResult(
            test_case=test_case,
            original_output=original_output,
            transpiled_output=transpiled_output,
            is_equivalent=is_equivalent,
            error_message=error_message,
            execution_time_original=result_original.get("execution_time", 0.0),
            execution_time_transpiled=result_transpiled.get("execution_time", 0.0)
        )

    def _create_execution_wrapper(self, code: str, input_data: Any) -> str:
        input_repr = repr(input_data)
        return f"""
{code}

result = main({input_repr}) if 'main' in dir() else None
print(repr(result))
"""

    def are_equivalent(self, output1: Any, output2: Any, tolerance: float = 1e-9) -> bool:
        is_eq, _ = self.deep_compare(output1, output2)
        return is_eq

    def deep_compare(self, obj1: Any, obj2: Any, path: str = "") -> Tuple[bool, str]:
        if type(obj1) != type(obj2):
            if isinstance(obj1, (int, float)) and isinstance(obj2, (int, float)):
                if abs(float(obj1) - float(obj2)) <= tolerance:
                    return True, ""
                return False, f"Numeric difference at {path or 'root'}: {obj1} vs {obj2}"
            return False, f"Type mismatch at {path or 'root'}: {type(obj1).__name__} vs {type(obj2).__name__}"

        if obj1 is None and obj2 is None:
            return True, ""

        if isinstance(obj1, bool):
            return obj1 == obj2, "" if obj1 == obj2 else f"Bool mismatch at {path or 'root'}"

        if isinstance(obj1, (int, float)):
            if abs(obj1 - obj2) <= tolerance:
                return True, ""
            return False, f"Numeric difference at {path or 'root'}: {obj1} vs {obj2}"

        if isinstance(obj1, str):
            return obj1 == obj2, "" if obj1 == obj2 else f"String mismatch at {path or 'root'}"

        if isinstance(obj1, (list, tuple)):
            if len(obj1) != len(obj2):
                return False, f"Length mismatch at {path or 'root'}: {len(obj1)} vs {len(obj2)}"
            for i, (item1, item2) in enumerate(zip(obj1, obj2)):
                child_path = f"{path}[{i}]" if path else f"[{i}]"
                is_eq, msg = self.deep_compare(item1, item2, child_path)
                if not is_eq:
                    return False, msg
            return True, ""

        if isinstance(obj1, dict):
            if set(obj1.keys()) != set(obj2.keys()):
                return False, f"Key mismatch at {path or 'root'}: {set(obj1.keys())} vs {set(obj2.keys())}"
            for key in obj1:
                child_path = f"{path}.{key}" if path else key
                is_eq, msg = self.deep_compare(obj1[key], obj2[key], child_path)
                if not is_eq:
                    return False, msg
            return True, ""

        if isinstance(obj1, set):
            return obj1 == obj2, "" if obj1 == obj2 else f"Set mismatch at {path or 'root'}"

        if isinstance(obj1, object):
            attrs1 = self._get_comparable_attrs(obj1)
            attrs2 = self._get_comparable_attrs(obj2)
            if attrs1.keys() != attrs2.keys():
                return False, f"Object attribute mismatch at {path or 'root'}"
            for key in attrs1:
                is_eq, msg = self.deep_compare(attrs1[key], attrs2[key], f"{path}.{key}" if path else key)
                if not is_eq:
                    return False, msg
            return True, ""

        return obj1 == obj2, "" if obj1 == obj2 else f"Value mismatch at {path or 'root'}"

    def _get_comparable_attrs(self, obj: Any) -> dict:
        comparable = {}
        for attr_name in dir(obj):
            if not attr_name.startswith('_'):
                try:
                    value = getattr(obj, attr_name)
                    if not callable(value):
                        comparable[attr_name] = value
                except:
                    pass
        return comparable

    def generate_report(self, results: List[VerificationResult]) -> QualityReport:
        total = len(results)
        passed = sum(1 for r in results if r.is_equivalent)
        failed = total - passed
        equivalence_rate = (passed / total * 100) if total > 0 else 0.0

        failed_cases = [r for r in results if not r.is_equivalent]
        suggestions = self._generate_suggestions(failed_cases)

        language_stats = self._compute_language_stats(results)

        return QualityReport(
            total_test_cases=total,
            passed=passed,
            failed=failed,
            equivalence_rate=equivalence_rate,
            failed_cases=failed_cases,
            suggestions=suggestions,
            language_stats=language_stats
        )

    def _compute_language_stats(self, results: List[VerificationResult]) -> Dict[SupportedLanguage, Dict[str, Any]]:
        stats: Dict[SupportedLanguage, Dict[str, Any]] = {}

        for result in results:
            lang = result.source_language
            if lang not in stats:
                stats[lang] = {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "equivalence_rate": 0.0,
                }

            stats[lang]["total"] += 1
            if result.is_equivalent:
                stats[lang]["passed"] += 1
            else:
                stats[lang]["failed"] += 1

        for lang, stat in stats.items():
            if stat["total"] > 0:
                stat["equivalence_rate"] = (stat["passed"] / stat["total"] * 100)

        return stats

    def _generate_suggestions(self, failed_cases: List[VerificationResult]) -> List[str]:
        suggestions = []

        for result in failed_cases:
            suggestion = self.analyze_failure(result)
            if suggestion and suggestion not in suggestions:
                suggestions.append(suggestion)

        if not suggestions:
            suggestions.append("所有测试用例均通过，代码转换质量良好。")

        return suggestions

    def analyze_failure(self, result: VerificationResult) -> str:
        if not result.test_case:
            return "无法分析：测试用例信息缺失"

        input_type = self._get_input_type(result.test_case.input_data)
        issue_categories = []

        if "Type coercion" in result.error_message or (result.original_output is not None and result.transpiled_output is not None and type(result.original_output) != type(result.transpiled_output)):
            issue_categories.append("类型转换差异：转换过程中可能丢失了类型信息")

        if isinstance(result.test_case.input_data, (int, float)):
            if result.original_output is None and result.transpiled_output is not None:
                issue_categories.append("数值处理差异：原始代码返回None但转换代码返回了值")
            elif result.original_output is not None and result.transpiled_output is None:
                issue_categories.append("数值处理差异：转换代码未能正确处理数值输入")

        if isinstance(result.test_case.input_data, str):
            if result.original_output is None and result.transpiled_output is not None:
                issue_categories.append("字符串处理差异：字符串处理逻辑可能存在差异")

        if result.test_case.input_data is None:
            if not result.is_equivalent:
                issue_categories.append("空值处理差异：null/undefined处理逻辑可能不一致")

        if isinstance(result.test_case.input_data, (list, dict)):
            if not result.is_equivalent:
                issue_categories.append("集合类型差异：列表或字典的处理逻辑可能存在差异")

        if "method" in result.error_message.lower() or "attribute" in result.error_message.lower():
            issue_categories.append("方法调用差异：可能存在方法调用顺序或方式不一致")

        if "exception" in result.error_message.lower() or "error" in result.error_message.lower():
            if "original" in result.error_message.lower():
                issue_categories.append("原始代码执行异常：需要检查原始代码的正确性")
            elif "transpiled" in result.error_message.lower():
                issue_categories.append("转换代码执行异常：转换过程中可能引入了错误")

        if result.execution_time_original > 0 and result.execution_time_transpiled > 0:
            time_ratio = result.execution_time_transpiled / result.execution_time_original
            if time_ratio > 2.0:
                issue_categories.append(f"性能差异：转换代码执行时间是原始代码的 {time_ratio:.2f} 倍")

        if not issue_categories:
            issue_categories.append("未知差异：需要进一步调查具体的输出差异")

        return " | ".join(issue_categories) if issue_categories else "未发现问题"

    def verify_for_language(self, source_code: str, transpiled_code: str, language: SupportedLanguage, test_cases: List[TestCase]) -> List[VerificationResult]:
        results = []

        for test_case in test_cases:
            result = self._verify_single_test(source_code, transpiled_code, test_case)
            result.source_language = language
            result.target_language = SupportedLanguage.PYTHON
            results.append(result)

        return results

    def are_equivalent(self, output1: Any, output2: Any, tolerance: float = 1e-9, language: Optional[SupportedLanguage] = None) -> bool:
        if language == SupportedLanguage.JAVA:
            return self._are_equivalent_java(output1, output2, tolerance)
        elif language == SupportedLanguage.CPP:
            return self._are_equivalent_cpp(output1, output2, tolerance)
        elif language == SupportedLanguage.GO:
            return self._are_equivalent_go(output1, output2, tolerance)
        elif language == SupportedLanguage.RUST:
            return self._are_equivalent_rust(output1, output2, tolerance)
        else:
            is_eq, _ = self.deep_compare(output1, output2)
            return is_eq

    def _are_equivalent_java(self, output1: Any, output2: Any, tolerance: float) -> bool:
        if output1 is None and output2 is None:
            return True
        if output1 is None or output2 is None:
            return False

        if isinstance(output1, list) and isinstance(output2, list):
            if len(output1) != len(output2):
                return False
            for item1, item2 in zip(output1, output2):
                if not self._are_equivalent_java(item1, item2, tolerance):
                    return False
            return True

        if isinstance(output1, dict) and isinstance(output2, dict):
            if set(output1.keys()) != set(output2.keys()):
                return False
            for key in output1:
                if not self._are_equivalent_java(output1[key], output2[key], tolerance):
                    return False
            return True

        if isinstance(output1, (int, float)) and isinstance(output2, (int, float)):
            return abs(float(output1) - float(output2)) <= tolerance

        if isinstance(output1, str) and isinstance(output2, str):
            return output1 == output2

        if isinstance(output1, bool) and isinstance(output2, bool):
            return output1 == output2

        is_eq, _ = self.deep_compare(output1, output2)
        return is_eq

    def _are_equivalent_cpp(self, output1: Any, output2: Any, tolerance: float) -> bool:
        if output1 is None and output2 is None:
            return True
        if output1 is None or output2 is None:
            return False

        if isinstance(output1, dict) and isinstance(output2, dict):
            if set(output1.keys()) != set(output2.keys()):
                return False
            for key in output1:
                if not self._are_equivalent_cpp(output1[key], output2[key], tolerance):
                    return False
            return True

        if isinstance(output1, (int, float)) and isinstance(output2, (int, float)):
            return abs(float(output1) - float(output2)) <= tolerance

        if isinstance(output1, str) and isinstance(output2, str):
            return output1 == output2

        if isinstance(output1, bool) and isinstance(output2, bool):
            return output1 == output2

        if hasattr(output1, '_cpp_pointer_value__') and hasattr(output2, '_cpp_pointer_value__'):
            return output1._cpp_pointer_value__ == output2._cpp_pointer_value__

        if hasattr(output1, '_cpp_reference_value__') and hasattr(output2, '_cpp_reference_value__'):
            return output1._cpp_reference_value__ == output2._cpp_reference_value__

        is_eq, _ = self.deep_compare(output1, output2)
        return is_eq

    def _are_equivalent_go(self, output1: Any, output2: Any, tolerance: float) -> bool:
        if output1 is None and output2 is None:
            return True

        if isinstance(output1, list) and isinstance(output2, list):
            if len(output1) != len(output2):
                return False
            for item1, item2 in zip(output1, output2):
                if not self._are_equivalent_go(item1, item2, tolerance):
                    return False
            return True

        if isinstance(output1, dict) and isinstance(output2, dict):
            if set(output1.keys()) != set(output2.keys()):
                return False
            for key in output1:
                if not self._are_equivalent_go(output1[key], output2[key], tolerance):
                    return False
            return True

        if isinstance(output1, (int, float)) and isinstance(output2, (int, float)):
            return abs(float(output1) - float(output2)) <= tolerance

        if isinstance(output1, str) and isinstance(output2, str):
            return output1 == output2

        if isinstance(output1, bool) and isinstance(output2, bool):
            return output1 == output2

        is_eq, _ = self.deep_compare(output1, output2)
        return is_eq

    def _are_equivalent_rust(self, output1: Any, output2: Any, tolerance: float) -> bool:
        if output1 is None and output2 is None:
            return True

        if hasattr(output1, '_rust_option_is_some__') and hasattr(output2, '_rust_option_is_some__'):
            if output1._rust_option_is_some__ != output2._rust_option_is_some__:
                return False
            if output1._rust_option_is_some__:
                return self._are_equivalent_rust(output1._rust_option_value__, output2._rust_option_value__, tolerance)
            return True

        if hasattr(output1, '_rust_result_is_ok__') and hasattr(output2, '_rust_result_is_ok__'):
            if output1._rust_result_is_ok__ != output2._rust_result_is_ok__:
                return False
            if output1._rust_result_is_ok__:
                return self._are_equivalent_rust(output1._rust_result_value__, output2._rust_result_value__, tolerance)
            return True

        if isinstance(output1, list) and isinstance(output2, list):
            if len(output1) != len(output2):
                return False
            for item1, item2 in zip(output1, output2):
                if not self._are_equivalent_rust(item1, item2, tolerance):
                    return False
            return True

        if isinstance(output1, dict) and isinstance(output2, dict):
            if set(output1.keys()) != set(output2.keys()):
                return False
            for key in output1:
                if not self._are_equivalent_rust(output1[key], output2[key], tolerance):
                    return False
            return True

        if isinstance(output1, (int, float)) and isinstance(output2, (int, float)):
            return abs(float(output1) - float(output2)) <= tolerance

        if isinstance(output1, str) and isinstance(output2, str):
            return output1 == output2

        if isinstance(output1, bool) and isinstance(output2, bool):
            return output1 == output2

        is_eq, _ = self.deep_compare(output1, output2)
        return is_eq


def java_object(class_name: str, fields: Dict[str, Any]) -> Any:
    class Obj:
        def __init__(self, name, flds):
            self._class_name = name
            for k, v in flds.items():
                setattr(self, k, v)
        def __repr__(self):
            return f"{self._class_name}({', '.join(f'{k}={v!r}' for k, v in self.__dict__.items() if not k.startswith('_'))})"
    return Obj(class_name, fields)


def java_collection(collection_type: str, items: List[Any]) -> Any:
    class Collection:
        def __init__(self, ctype, items):
            self._collection_type = ctype
            self._items = list(items)
        def __iter__(self):
            return iter(self._items)
        def __len__(self):
            return len(self._items)
        def __repr__(self):
            return f"{self._collection_type}({self._items})"
    return Collection(collection_type, items)


def cpp_pointer(value: Any) -> Any:
    class Pointer:
        def __init__(self, val):
            self._cpp_pointer_value__ = val
        def __repr__(self):
            return f"ptr({self._cpp_pointer_value__})"
    return Pointer(value)


def cpp_reference(value: Any) -> Any:
    class Reference:
        def __init__(self, val):
            self._cpp_reference_value__ = val
        def __repr__(self):
            return f"ref({self._cpp_reference_value__})"
    return Reference(value)


def cpp_smart_pointer(pointer_type: str, value: Any) -> Any:
    class SmartPointer:
        def __init__(self, ptype, val):
            self._pointer_type = ptype
            self._cpp_pointer_value__ = val
        def __repr__(self):
            return f"{self._pointer_type}({self._cpp_pointer_value__})"
    return SmartPointer(pointer_type, value)


def cpp_vector(items: List[Any]) -> Any:
    class Vector:
        def __init__(self, items):
            self._items = list(items)
        def __iter__(self):
            return iter(self._items)
        def __len__(self):
            return len(self._items)
        def __repr__(self):
            return f"Vector({self._items})"
    return Vector(items)


def cpp_map(mapping: Dict[str, Any]) -> Any:
    class Map:
        def __init__(self, m):
            self._map = dict(m)
        def __getitem__(self, key):
            return self._map[key]
        def keys(self):
            return self._map.keys()
        def values(self):
            return self._map.values()
        def items(self):
            return self._map.items()
        def __len__(self):
            return len(self._map)
        def __repr__(self):
            return f"Map({self._map})"
    return Map(mapping)


def go_slice(items: List[Any]) -> Any:
    class Slice:
        def __init__(self, items):
            self._items = list(items)
            self._is_nil = False
        def __iter__(self):
            return iter(self._items)
        def __len__(self):
            return len(self._items)
        def __repr__(self):
            return f"Slice({self._items})"
    return Slice(items)


def go_map(mapping: Dict[str, Any]) -> Any:
    class GoMap:
        def __init__(self, m):
            self._map = dict(m)
            self._is_nil = False
        def __getitem__(self, key):
            return self._map[key]
        def keys(self):
            return self._map.keys()
        def values(self):
            return self._map.values()
        def items(self):
            return self._map.items()
        def __len__(self):
            return len(self._map)
        def __repr__(self):
            return f"Map({self._map})"
    return GoMap(mapping)


def go_nil_slice() -> Any:
    class NilSlice:
        def __init__(self):
            self._is_nil = True
            self._items = []
        def __iter__(self):
            return iter(self._items)
        def __len__(self):
            return 0
        def __repr__(self):
            return "nil"
    return NilSlice()


def go_nil_map() -> Any:
    class NilMap:
        def __init__(self):
            self._is_nil = True
            self._map = {}
        def __getitem__(self, key):
            raise KeyError(key)
        def keys(self):
            return self._map.keys()
        def __len__(self):
            return 0
        def __repr__(self):
            return "nil"
    return NilMap()


def rust_option_some(value: Any) -> Any:
    class Option:
        def __init__(self, val, is_some):
            self._rust_option_is_some__ = is_some
            self._rust_option_value__ = val
        def __repr__(self):
            if self._rust_option_is_some__:
                return f"Some({self._rust_option_value__})"
            return "None"
    return Option(value, True)


def rust_option_none() -> Any:
    class Option:
        def __init__(self):
            self._rust_option_is_some__ = False
            self._rust_option_value__ = None
        def __repr__(self):
            return "None"
    return Option()


def rust_result_ok(value: Any) -> Any:
    class Result:
        def __init__(self, val, is_ok):
            self._rust_result_is_ok__ = is_ok
            self._rust_result_value__ = val
            self._rust_result_err__ = None if is_ok else val
        def __repr__(self):
            if self._rust_result_is_ok__:
                return f"Ok({self._rust_result_value__})"
            return f"Err({self._rust_result_err__})"
    return Result(value, True)


def rust_result_err(error: Any) -> Any:
    class Result:
        def __init__(self, err, is_ok):
            self._rust_result_is_ok__ = is_ok
            self._rust_result_value__ = None
            self._rust_result_err__ = err
        def __repr__(self):
            if self._rust_result_is_ok__:
                return f"Ok({self._rust_result_value__})"
            return f"Err({self._rust_result_err__})"
    return Result(error, False)


def rust_vec(items: List[Any]) -> Any:
    class Vec:
        def __init__(self, items):
            self._items = list(items)
        def __iter__(self):
            return iter(self._items)
        def __len__(self):
            return len(self._items)
        def __repr__(self):
            return f"Vec({self._items})"
    return Vec(items)


def rust_hashmap(mapping: Dict[str, Any]) -> Any:
    class HashMap:
        def __init__(self, m):
            self._map = dict(m)
        def __getitem__(self, key):
            return self._map[key]
        def keys(self):
            return self._map.keys()
        def values(self):
            return self._map.values()
        def items(self):
            return self._map.items()
        def __len__(self):
            return len(self._map)
        def __repr__(self):
            return f"HashMap({self._map})"
    return HashMap(mapping)
