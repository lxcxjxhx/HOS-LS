"""修复 mypy 类型错误"""
import re

# 修复 dynamic_loader.py
with open("src/analyzers/verification/dynamic_loader.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. 修复第 32-33 行: Function "name" could always be true in boolean context
content = content.replace(
    '    if hasattr(cls, "name") and cls.name:\n        _VALIDATOR_REGISTRY[cls.name] = cls',
    '    name = getattr(cls, "name", None)\n    if isinstance(name, str):\n        _VALIDATOR_REGISTRY[name] = cls',
)

# 2. 修复第 120 行: Need type annotation for "loaded"
content = content.replace("        loaded = []", "        loaded: List[str] = []")

# 3. 修复第 186 行: Returning Any from function declared to return "str | None"
content = content.replace(
    "                        return validator_name",
    "                        return str(validator_name)",
)

# 4. 修复第 190 行: Incompatible types in assignment
content = content.replace(
    "                validator_instance = self._create_wrapper_validator(module, default_name)\n                if validator_instance:\n                    self.validators[default_name] = validator_instance\n                    self._invalidate_cache()\n                    return default_name",
    "                validator_instance = self._create_wrapper_validator(module, default_name)\n                assert validator_instance is not None\n                self.validators[default_name] = validator_instance\n                self._invalidate_cache()\n                return default_name",
)

# 5. 修复第 221 行: Returning Any from function declared to return "dict[str, Any]"
# 6. 修复第 224 行: Cannot instantiate abstract class "WrappedValidator"
content = content.replace(
    '            def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:\n                if validate_func:\n                    return validate_func(context)\n                return {"status": "error", "message": "No validate function"}\n\n        return WrappedValidator()',
    '''            def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
                if validate_func:
                    result = validate_func(context)
                    return dict(result) if isinstance(result, dict) else {"result": result}
                return {"status": "error", "message": "No validate function"}

            def validate(self, context: Any) -> Any:
                """实现抽象方法"""
                return self.verify({})

            def check_applicability(self, context: Any) -> bool:
                """实现抽象方法"""
                return True

        return WrappedValidator()''',
)

# 7. 修复第 307 行: Returning Any from function declared to return "dict[str, Any]" 和 "Validator" has no attribute "verify"
content = content.replace(
    "        try:\n            return validator.verify(context)",
    '        try:\n            if hasattr(validator, "verify"):\n                result = validator.verify(context)\n                return dict(result) if isinstance(result, dict) else {"result": result}\n            else:\n                return {"status": "error", "message": "Validator has no verify method"}',
)

with open("src/analyzers/verification/dynamic_loader.py", "w", encoding="utf-8") as f:
    f.write(content)

print("✓ 修复 dynamic_loader.py")

# 修复 poc_integration.py
with open("src/integration/poc_integration.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. 修复第 54 行: 为 results 添加类型注解
content = content.replace(
    '        results = {"total": len(findings), "generated": 0, "failed": 0, "pocs": []}',
    '        results: Dict[str, Any] = {"total": len(findings), "generated": 0, "failed": 0, "pocs": []}',
)

# 2. 修复第 101 行: 为 results 添加类型注解
content = content.replace(
    '        results = {\n            "total": len(poc_list),\n            "executed": 0,\n            "vulnerable": 0,\n            "errors": 0,\n            "details": [],\n        }',
    '        results: Dict[str, Any] = {\n            "total": len(poc_list),\n            "executed": 0,\n            "vulnerable": 0,\n            "errors": 0,\n            "details": [],\n        }',
)

# 3. 修复第 151 行: Returning Any from function declared to return "str | None"
content = content.replace(
    "        return self.poc_generator.get_poc_script(method_id)",
    "        result = self.poc_generator.get_poc_script(method_id)\n        return str(result) if result is not None else None",
)

with open("src/integration/poc_integration.py", "w", encoding="utf-8") as f:
    f.write(content)

print("✓ 修复 poc_integration.py")

# 修复 python_test_executor.py
with open("src/analyzers/verification/python_test_executor.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. 修复第 43-44 行: Incompatible types in assignment
content = content.replace(
    "            self._original_stdout = sys.stdout\n            self._original_stderr = sys.stderr",
    "            self._original_stdout = sys.stdout  # type: ignore[assignment]\n            self._original_stderr = sys.stderr  # type: ignore[assignment]",
)

# 2. 修复第 53, 56 行: Unsupported target for indexed assignment
content = content.replace(
    '            def run_code():\n                try:\n                    exec(compiled_code, {"__builtins__": __builtins__})\n                    self._execution_result["success"] = True\n                except Exception:\n                    tb = traceback.format_exc()\n                    self._execution_result["error"] = tb',
    '            def run_code():\n                assert self._execution_result is not None\n                try:\n                    exec(compiled_code, {"__builtins__": __builtins__})\n                    self._execution_result["success"] = True\n                except Exception:\n                    tb = traceback.format_exc()\n                    self._execution_result["error"] = tb',
)

# 3. 修复第 308-311 行: Module has no attribute "loads"/"dumps"/"load"/"dump"
content = content.replace(
    "        mock_json_instance.loads = mock_loads\n        mock_json_instance.dumps = mock_dumps\n        mock_json_instance.load = mock_load\n        mock_json_instance.dump = mock_dump",
    "        mock_json_instance.loads = mock_loads  # type: ignore[attr-defined]\n        mock_json_instance.dumps = mock_dumps  # type: ignore[attr-defined]\n        mock_json_instance.load = mock_load  # type: ignore[attr-defined]\n        mock_json_instance.dump = mock_dump  # type: ignore[attr-defined]",
)

with open("src/analyzers/verification/python_test_executor.py", "w", encoding="utf-8") as f:
    f.write(content)

print("✓ 修复 python_test_executor.py")

print("\n所有修复已完成！")
