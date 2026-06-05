import re
from typing import Optional, Dict, List, Set

from .ast_transpiler_engine import JavaASTParser, PythonASTParser, ASTTranspilerEngine, IntermediateRepresentation


class JavaToPythonConverter:
    def __init__(self, project_context: Optional[Dict] = None, use_ast_engine: bool = False):
        self.project_context = project_context or {}
        self._imports: Set[str] = set()
        self._mocks: List[str] = []
        self.use_ast_engine = use_ast_engine
        self._ast_parser: Optional[JavaASTParser] = None

    def convert(self, java_code: str) -> str:
        if self.use_ast_engine:
            return self.transpile_ast(java_code)

        lines = java_code.split('\n')
        result_lines = []
        in_multiline_comment = False

        for line in lines:
            stripped = line.strip()

            if stripped.startswith('/*'):
                in_multiline_comment = True
                result_lines.append(f'# {line.strip()[2:]}')
                continue

            if in_multiline_comment:
                if '*/' in stripped:
                    in_multiline_comment = False
                    result_lines.append(f'# {line.strip()[:-2]}')
                else:
                    result_lines.append(f'# {line.strip()}')
                continue

            if stripped.startswith('//'):
                result_lines.append(f'# {stripped[2:]}')
                continue

            converted_line = self._convert_line(stripped)
            result_lines.append(converted_line)

        result = '\n'.join(result_lines)
        result = self._convert_strings(result)
        result = self._convert_collections(result)
        result = self._convert_methods(result)
        result = self._convert_mybatis(result)
        result = self._convert_jackson(result)
        result = self._convert_imports(result)
        result = self._add_mocks(result)

        return result

    def _convert_line(self, line: str) -> str:
        line = self._convert_class_declaration(line)
        line = self._convert_main_method(line)
        line = self._convert_void_return(line)
        line = self._convert_visibility_modifiers(line)
        return line

    def _convert_class_declaration(self, line: str) -> str:
        pattern = r'public\s+class\s+(\w+)'
        match = re.search(pattern, line)
        if match:
            class_name = match.group(1)
            line = re.sub(pattern, f'class {class_name}:', line)
        return line

    def _convert_main_method(self, line: str) -> str:
        pattern = r'public\s+static\s+void\s+main\s*\(\s*String\s*\[\s*\]\s*\w+\s*\)'
        if re.search(pattern, line):
            line = 'if __name__ == "__main__":'
        return line

    def _convert_void_return(self, line: str) -> str:
        if re.search(r'\bvoid\s+\w+\s*\(', line):
            line = re.sub(r'\bvoid\b', 'None', line)
        return line

    def _convert_visibility_modifiers(self, line: str) -> str:
        line = re.sub(r'\bpublic\s+', '', line)
        line = re.sub(r'\bprivate\s+', '', line)
        line = re.sub(r'\bprotected\s+', '', line)
        return line

    def _convert_strings(self, code: str) -> str:
        code = self._convert_string_format(code)
        code = self._convert_string_concatenation(code)
        code = self._convert_string_builder(code)
        return code

    def _convert_string_format(self, code: str) -> str:
        pattern = r'String\.format\s*\(\s*"([^"]*)"(?:\s*,\s*([^)]+))?\s*\)'

        def replace_format(match):
            format_str = match.group(1)
            args = match.group(2)

            if args:
                args_list = [a.strip() for a in args.split(',')]
                placeholders = re.findall(r'%[sdfo]', format_str)

                if len(placeholders) == len(args_list):
                    fstring_parts = []
                    last_end = 0

                    for i, placeholder in enumerate(placeholders):
                        idx = format_str.find(placeholder, last_end)
                        literal_part = format_str[last_end:idx]
                        if literal_part:
                            fstring_parts.append(f'"{literal_part}"')
                        fstring_parts.append(f'{{{args_list[i]}}}')
                        last_end = idx + len(placeholder)

                    remaining = format_str[last_end:]
                    if remaining:
                        fstring_parts.append(f'"{remaining}"')

                    return 'f"' + ''.join(fstring_parts).replace('"{', '{').replace('}"', '}') + '"'

            return f'"{format_str}"'

        code = re.sub(pattern, replace_format, code)

        pattern2 = r'"([^"]*)"\.format\s*\(\s*([^)]+)\s*\)'

        def replace_format2(match):
            format_str = match.group(1)
            args = match.group(2)
            args_list = [a.strip() for a in args.split(',')]
            placeholders = re.findall(r'\{\d+\}', format_str)

            if placeholders:
                for i, arg in enumerate(args_list):
                    format_str = format_str.replace(f'{{{i}}}', f'{{{arg}}}')

            return f'f"{format_str}"'

        code = re.sub(pattern2, replace_format2, code)
        return code

    def _convert_string_concatenation(self, code: str) -> str:
        lines = code.split('\n')
        result = []

        for line in lines:
            if '+' in line and '"' in line:
                parts = re.split(r'(\+|"[^"]*")', line)
                if len(parts) > 3:
                    has_string = any('"' in p for p in parts)
                    has_plus = '+' in parts

                    if has_string and has_plus:
                        fstring_match = re.search(r'^(\s*)"""\s*\+\s*(.+)$', line)
                        if fstring_match:
                            indent = fstring_match.group(1)
                            rest = fstring_match.group(2)
                            line = f'{indent}f""" {rest}'
                            line = re.sub(r'\s*\+\s*"""\s*$', ' """', line)

            result.append(line)

        return '\n'.join(result)

    def _convert_string_builder(self, code: str) -> str:
        pattern = r'StringBuilder\s+(\w+)\s*=\s*new\s+StringBuilder\s*\(\s*\)'
        code = re.sub(pattern, r'__sb_\1 = []', code)

        pattern = r'(\w+)\.append\s*\(\s*([^)]+)\s*\)\s*;?'
        code = re.sub(pattern, r'__sb_\1.append(\2)', code)

        pattern = r'(\w+)\.toString\s*\(\s*\)'
        code = re.sub(pattern, r'"".join(__sb_\1)', code)

        return code

    def _convert_collections(self, code: str) -> str:
        code = self._convert_list_declaration(code)
        code = self._convert_map_declaration(code)
        code = self._convert_set_declaration(code)
        code = self._convert_arrays_as_list(code)
        return code

    def _convert_list_declaration(self, code: str) -> str:
        pattern = r'List<(\w+)>\s+(\w+)\s*='
        code = re.sub(pattern, r'\2: list[\1] =', code)

        pattern = r'ArrayList<(\w+)>\s+(\w+)\s*='
        code = re.sub(pattern, r'\2: list[\1] =', code)

        pattern = r'List<(\w+)>\s+(\w+)'
        code = re.sub(pattern, r'list[\1]', code)

        return code

    def _convert_map_declaration(self, code: str) -> str:
        pattern = r'Map<([^,]+),\s*([^>]+)>\s+(\w+)\s*='
        code = re.sub(pattern, r'\3: dict[\1, \2] =', code)

        pattern = r'HashMap<([^,]+),\s*([^>]+)>\s+(\w+)\s*='
        code = re.sub(pattern, r'\3: dict[\1, \2] =', code)

        pattern = r'Map<([^,]+),\s*([^>]+)>'
        code = re.sub(pattern, r'dict[\1, \2]', code)

        return code

    def _convert_set_declaration(self, code: str) -> str:
        pattern = r'Set<(\w+)>\s+(\w+)\s*='
        code = re.sub(pattern, r'\2: set[\1] =', code)

        pattern = r'HashSet<(\w+)>\s+(\w+)\s*='
        code = re.sub(pattern, r'\2: set[\1] =', code)

        pattern = r'Set<(\w+)>'
        code = re.sub(pattern, r'set[\1]', code)

        return code

    def _convert_arrays_as_list(self, code: str) -> str:
        pattern = r'Arrays\.asList\s*\(\s*([^)]+)\s*\)'
        code = re.sub(pattern, r'[\1]', code)
        return code

    def _convert_methods(self, code: str) -> str:
        code = self._convert_method_signatures(code)
        code = self._convert_static_method(code)
        return code

    def _convert_method_signatures(self, code: str) -> str:
        pattern = r'(public|private|protected)?\s*(static)?\s*(\w+)\s+(\w+)\s*\(([^)]*)\)'

        def replace_method(match):
            visibility = match.group(1) or ''
            is_static = match.group(2) is not None
            return_type = match.group(3)
            method_name = match.group(4)
            params = match.group(5)

            py_method_name = self._to_snake_case(method_name)

            if return_type == 'void':
                return_type = 'None'

            param_list = []
            if params.strip():
                param_parts = params.split(',')
                for param in param_parts:
                    param = param.strip()
                    if param:
                        parts = param.split()
                        if len(parts) >= 2:
                            param_type, param_name = parts[-2], parts[-1]
                            param_list.append(f'{param_name}')
                        else:
                            param_list.append(param)

            param_str = ', '.join(param_list)

            if is_static:
                return f'def {py_method_name}({param_str}) -> {return_type}:'
            else:
                return f'def {py_method_name}(self, {param_str}) -> {return_type}:'

        code = re.sub(pattern, replace_method, code)
        return code

    def _convert_static_method(self, code: str) -> str:
        pattern = r'public\s+static\s+(\w+)\s+(\w+)\s*\(([^)]*)\)'
        code = re.sub(pattern, r'def \2(\3) -> \1:', code)
        return code

    def _to_snake_case(self, name: str) -> str:
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

    def _convert_mybatis(self, code: str) -> str:
        pattern = r'\$\{([^}]+)\}'
        code = re.sub(pattern, r'{{\1}}', code)

        pattern = r'#\{([^}]+)\}'
        code = re.sub(pattern, r'{{\1}}', code)

        return code

    def _convert_jackson(self, code: str) -> str:
        pattern = r'ObjectMapper\s+(\w+)\s*=\s*new\s+ObjectMapper\s*\(\s*\)'
        code = re.sub(pattern, r'\1 = MockObjectMapper()', code)

        pattern = r'(\w+)\.readValue\s*\(\s*([^,]+)\s*,\s*(\w+)\s*\)\s*;?'
        code = re.sub(pattern, r'\1 = json.loads(\2)', code)

        pattern = r'(\w+)\.writeValueAsString\s*\(\s*([^)]+)\s*\)\s*;?'
        code = re.sub(pattern, r'\1 = json.dumps(\2)', code)

        pattern = r'ObjectMapper\s+(\w+)\s*=\s*new\s+ObjectMapper\s*\(\s*\)'
        if re.search(pattern, code) and 'import com.fasterxml.jackson' in code:
            self._mocks.append('class MockObjectMapper:\n    def read_value(self, data, cls):\n        import json\n        return json.loads(data)\n\n    def write_value_as_string(self, obj):\n        import json\n        return json.dumps(obj)\n')

        return code

    def _convert_imports(self, code: str) -> str:
        lines = code.split('\n')
        result = []

        for line in lines:
            if re.match(r'^import\s+java\.util\.', line):
                result.append(f'# {line}  # mocked')
                self._imports.add('java.util')
            elif re.match(r'^import\s+org\.springframework\.', line):
                result.append(f'# {line}  # mocked')
                self._imports.add('org.springframework')
            elif re.match(r'^import\s+com\.fasterxml\.jackson\.', line):
                result.append(f'# {line}  # mocked')
                self._imports.add('com.fasterxml.jackson')
            elif re.match(r'^import\s+', line):
                result.append(f'# {line}  # removed for testing')
            else:
                result.append(line)

        return '\n'.join(result)

    def _add_mocks(self, code: str) -> str:
        if not self._mocks:
            return code

        mock_code = '\n\n# Mock classes for framework dependencies\n'
        for mock in self._mocks:
            mock_code += mock + '\n'

        if 'if __name__' in code:
            parts = code.split('if __name__')
            code = parts[0] + mock_code + '\nif __name__' + 'if __name__'.join(parts[1:])
        else:
            code += mock_code

        return code


    def transpile_ast(self, java_code: str) -> str:
        if self._ast_parser is None:
            self._ast_parser = JavaASTParser()

        ir = self._ast_parser.parse_to_ir(java_code)

        python_ast = self._ast_parser.ir_to_ast(ir, target_lang="python")

        import ast
        return ast.unparse(python_ast)

    def verify_translation(self, java_code: str, python_code: str) -> Dict:
        try:
            from .transpiler_quality_verifier import TranspilerQualityVerifier
            from .python_test_executor import PythonTestExecutor
        except ImportError:
            return {
                "success": False,
                "error": "TranspilerQualityVerifier or PythonTestExecutor not available",
                "equivalence_rate": 0.0
            }

        try:
            executor = PythonTestExecutor()
            verifier = TranspilerQualityVerifier(self._ast_parser or JavaASTParser(), executor)

            test_cases = verifier.generate_test_cases(java_code, count=5)
            results = verifier.verify(java_code, python_code, test_cases)
            report = verifier.generate_report(results)

            return {
                "success": True,
                "total_test_cases": report.total_test_cases,
                "passed": report.passed,
                "failed": report.failed,
                "equivalence_rate": report.equivalence_rate,
                "failed_cases": [
                    {
                        "test_case": str(r.test_case.input_data),
                        "original_output": str(r.original_output),
                        "transpiled_output": str(r.transpiled_output),
                        "error_message": r.error_message
                    }
                    for r in report.failed_cases
                ],
                "suggestions": report.suggestions
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "equivalence_rate": 0.0
            }


def convert_java_to_python(java_code: str, project_context: Optional[Dict] = None) -> str:
    converter = JavaToPythonConverter(project_context)
    return converter.convert(java_code)
