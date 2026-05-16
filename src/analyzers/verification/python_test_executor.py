import io
import sys
import time
import traceback
import threading
from typing import Dict, Any, Optional, List, Callable
from types import ModuleType

from .virtual_runtime import VirtualRuntimeEnvironment, setup_java_runtime, teardown_java_runtime
from .transpiler_quality_verifier import TranspilerQualityVerifier, TestCase, VerificationResult, QualityReport


class PythonTestExecutor:
    def __init__(self, use_virtual_runtime: bool = False):
        self._original_stdout: Optional[io.TextIOBase] = None
        self._original_stderr: Optional[io.TextIOBase] = None
        self._mock_modules: Dict[str, ModuleType] = {}
        self._execution_thread: Optional[threading.Thread] = None
        self._execution_result: Optional[Dict[str, Any]] = None
        self._use_virtual_runtime = use_virtual_runtime
        self._virtual_runtime: Optional[VirtualRuntimeEnvironment] = None

    def execute(self, python_code: str, timeout: int = 30) -> Dict[str, Any]:
        if self._use_virtual_runtime:
            self._setup_virtual_runtime()

        self._setup_environment()
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        start_time = time.time()
        success = False
        output = ""
        error = ""

        try:
            compiled_code = compile(python_code, "<string>", "exec")

            self._original_stdout = sys.stdout
            self._original_stderr = sys.stderr
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture

            self._execution_result = {"success": False, "output": "", "error": ""}

            def run_code():
                try:
                    exec(compiled_code, {"__builtins__": __builtins__})
                    self._execution_result["success"] = True
                except Exception as e:
                    tb = traceback.format_exc()
                    self._execution_result["error"] = tb

            self._execution_thread = threading.Thread(target=run_code)
            self._execution_thread.start()
            self._execution_thread.join(timeout=timeout)

            if self._execution_thread.is_alive():
                self._execution_result["error"] = f"Execution timeout after {timeout} seconds"
                self._execution_thread = None
            elif self._execution_result["error"]:
                pass
            else:
                self._execution_result["success"] = True

            success = self._execution_result["success"]
            if not success and not self._execution_result["error"]:
                self._execution_result["error"] = stderr_capture.getvalue() or "Unknown error occurred"

        except SyntaxError as e:
            error = f"Syntax Error: {e}"
        except Exception as e:
            error = f"Error: {str(e)}\n{traceback.format_exc()}"
        finally:
            sys.stdout = self._original_stdout
            sys.stderr = self._original_stderr

            output = stdout_capture.getvalue()
            if not success and not error:
                error = stderr_capture.getvalue()

            self._teardown_environment()

            if self._use_virtual_runtime:
                self._teardown_virtual_runtime()

        execution_time = time.time() - start_time

        return {
            "success": success,
            "output": output,
            "error": error,
            "execution_time": execution_time
        }

    def execute_file(self, file_path: str, timeout: int = 30) -> Dict[str, Any]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                python_code = f.read()
            return self.execute(python_code, timeout)
        except FileNotFoundError:
            return {
                "success": False,
                "output": "",
                "error": f"File not found: {file_path}",
                "execution_time": 0
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": f"Error reading file: {str(e)}",
                "execution_time": 0
            }

    def validate_syntax(self, code: str) -> Dict[str, Any]:
        try:
            compile(code, "<string>", "exec")
            return {
                "valid": True,
                "error": None
            }
        except SyntaxError as e:
            return {
                "valid": False,
                "error": f"Syntax Error at line {e.lineno}: {e.msg}"
            }
        except Exception as e:
            return {
                "valid": False,
                "error": f"Error: {str(e)}"
            }

    def _setup_environment(self):
        self._mock_modules = {}

        mock_requests = self._create_mock_requests()
        self._mock_modules["requests"] = mock_requests

        mock_json = self._create_mock_json()
        self._mock_modules["json"] = mock_json

        mock_re = self._create_mock_re()
        self._mock_modules["re"] = mock_re

        for module_name, module in self._mock_modules.items():
            sys.modules[module_name] = module

    def _teardown_environment(self):
        for module_name in self._mock_modules:
            if module_name in sys.modules:
                del sys.modules[module_name]
        self._mock_modules.clear()
        self._execution_thread = None
        self._execution_result = None

    def _setup_virtual_runtime(self) -> None:
        if self._virtual_runtime is None:
            self._virtual_runtime = setup_java_runtime()

    def _teardown_virtual_runtime(self) -> None:
        if self._virtual_runtime is not None:
            teardown_java_runtime()
            self._virtual_runtime = None

    def execute_with_mocks(
        self,
        python_code: str,
        timeout: int = 30,
        custom_mocks: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        original_use_vruntime = self._use_virtual_runtime
        self._use_virtual_runtime = True
        self._setup_virtual_runtime()

        if custom_mocks:
            for module_name, mock_module in custom_mocks.items():
                sys.modules[module_name] = mock_module

        result = self.execute(python_code, timeout)

        if custom_mocks:
            for module_name in custom_mocks:
                if module_name in sys.modules:
                    del sys.modules[module_name]

        self._teardown_virtual_runtime()
        self._use_virtual_runtime = original_use_vruntime

        return result

    def verify_equivalence(
        self,
        original_code: str,
        transpiled_code: str,
        test_cases: Optional[List[TestCase]] = None
    ) -> QualityReport:
        results: List[VerificationResult] = []
        passed = 0
        failed = 0

        if test_cases is None:
            test_cases = []

        for test_case in test_cases:
            original_result = self.execute(original_code, timeout=30)
            transpiled_result = self.execute(transpiled_code, timeout=30)

            original_output = original_result.get("output", "")
            transpiled_output = transpiled_result.get("output", "")

            is_equivalent = (
                original_result["success"] == transpiled_result["success"] and
                original_output == transpiled_output
            )

            if is_equivalent:
                passed += 1
            else:
                failed += 1

            verification_result = VerificationResult(
                test_case=test_case,
                original_output=original_output,
                transpiled_output=transpiled_output,
                is_equivalent=is_equivalent,
                error_message=(
                    f"Original error: {original_result.get('error', '')}; "
                    f"Transpiled error: {transpiled_result.get('error', '')}"
                ) if not is_equivalent else "",
                execution_time_original=original_result.get("execution_time", 0.0),
                execution_time_transpiled=transpiled_result.get("execution_time", 0.0)
            )
            results.append(verification_result)

        total = len(test_cases) if test_cases else 0
        equivalence_rate = passed / total if total > 0 else 0.0

        return QualityReport(
            total_test_cases=total,
            passed=passed,
            failed=failed,
            equivalence_rate=equivalence_rate,
            failed_cases=[r for r in results if not r.is_equivalent],
            suggestions=[]
        )

    def _create_mock_requests(self) -> ModuleType:
        mock = ModuleType("requests")

        class MockResponse:
            def __init__(self, text="", status_code=200, json_data=None):
                self.text = text
                self.status_code = status_code
                self._json_data = json_data

            def json(self):
                return self._json_data or {}

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise Exception(f"HTTP Error {self.status_code}")

        class MockRequestsModule:
            def get(self, url, **kwargs):
                return MockResponse(text=f"Mock GET response from {url}")

            def post(self, url, **kwargs):
                return MockResponse(text=f"Mock POST response from {url}")

            def put(self, url, **kwargs):
                return MockResponse(text=f"Mock PUT response from {url}")

            def delete(self, url, **kwargs):
                return MockResponse(text=f"Mock DELETE response from {url}")

            def patch(self, url, **kwargs):
                return MockResponse(text=f"Mock PATCH response from {url}")

            def head(self, url, **kwargs):
                return MockResponse(text="")

        mock_requests_instance = MockRequestsModule()
        mock_requests.__dict__.update(vars(mock_requests_instance))

        return mock

    def _create_mock_json(self) -> ModuleType:
        mock = ModuleType("json")

        mock_json_instance = ModuleType("json")

        def mock_loads(s, **kwargs):
            import json
            return json.loads(s, **kwargs)

        def mock_dumps(obj, **kwargs):
            import json
            return json.dumps(obj, **kwargs)

        def mock_load(fp, **kwargs):
            import json
            return json.load(fp, **kwargs)

        def mock_dump(obj, fp, **kwargs):
            import json
            json.dump(obj, fp, **kwargs)

        mock_json_instance.loads = mock_loads
        mock_json_instance.dumps = mock_dumps
        mock_json_instance.load = mock_load
        mock_json_instance.dump = mock_dump

        mock.__dict__.update(vars(mock_json_instance))

        return mock

    def _create_mock_re(self) -> ModuleType:
        import re
        mock = ModuleType("re")

        mock.__dict__.update(vars(re))

        return mock
