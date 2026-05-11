import sys
import ast
import subprocess
import tempfile
import os
import runpy

project_root = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, project_root)

module_name = "ast_transpiler_engine"
module_path = os.path.join(project_root, "src", "analyzers", "verification", "ast_transpiler_engine.py")

mod_info = runpy.run_path(module_path, run_name=module_name)
GoASTParser = mod_info["GoASTParser"]


def test_go_to_python_transpilation():
    go_code = '''
package main

import "fmt"

type HelloWorld struct {
    name string
}

func NewHelloWorld(n string) *HelloWorld {
    return &HelloWorld{name: n}
}

func (h *HelloWorld) GetName() string {
    return h.name
}

func main() {
    hello := NewHelloWorld("World")
    fmt.Println(hello.GetName())
}
'''

    print("=" * 60)
    print("Go to Python Transpilation Test Results")
    print("=" * 60)

    print("\n[1] Original Go Code:")
    print("-" * 40)
    print(go_code)

    parser = GoASTParser()

    is_valid_syntax = False
    is_executable = False
    execution_output = ""
    error_message = ""
    python_code = ""

    try:
        python_code = parser.transpile(go_code, source_lang="go", target_lang="python")
    except Exception as e:
        error_message = f"Transpilation Error: {type(e).__name__}: {e}"
        print(f"\n[ERROR] Transpilation failed: {error_message}")
        print("\n" + "=" * 60)
        print("Test Summary")
        print("=" * 60)
        print(f"Transpilation:   FAILED")
        print(f"Syntax Valid:    N/A")
        print(f"Executable:      N/A")
        print(f"Error Message:   {error_message}")
        print("=" * 60)
        print("\nFINAL RESULT: TRANSPILATION FAILED")
        return {
            "transpilation_success": False,
            "syntax_valid": False,
            "executable": False,
            "execution_output": "",
            "error_message": error_message,
            "generated_code": ""
        }

    print("\n[2] Generated Python code:")
    print("-" * 40)
    print(python_code)
    print("-" * 40)

    try:
        ast.parse(python_code)
        is_valid_syntax = True
        print("\n[3] Syntax Validation: PASSED")
    except SyntaxError as e:
        error_message = f"Syntax Error: {e}"
        print(f"\n[3] Syntax Validation: FAILED")
        print(f"    Error: {error_message}")

    if is_valid_syntax:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(python_code)
            temp_file = f.name

        try:
            result = subprocess.run(
                [sys.executable, temp_file],
                capture_output=True,
                text=True,
                timeout=10
            )
            execution_output = result.stdout
            if result.stderr:
                execution_output += "\nSTDERR:\n" + result.stderr
            is_executable = result.returncode == 0
            if is_executable:
                print("[4] Execution: SUCCESS")
            else:
                print("[4] Execution: FAILED")
                print(f"    Return code: {result.returncode}")
            if execution_output:
                print(f"\n[5] Execution Output:")
                print(f"    {execution_output.strip()}")
        except subprocess.TimeoutExpired:
            error_message = "Execution timed out"
            print(f"[4] Execution: TIMEOUT")
        except Exception as e:
            error_message = f"Execution Error: {e}"
            print(f"[4] Execution: ERROR")
            print(f"    Error: {error_message}")
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    else:
        print("[4] Execution: SKIPPED (invalid syntax)")

    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"Transpilation:   SUCCESS")
    print(f"Syntax Valid:    {'YES' if is_valid_syntax else 'NO'}")
    print(f"Executable:      {'YES' if is_executable else 'NO'}")
    print(f"Execution Output: {execution_output.strip() if execution_output else 'N/A'}")

    if error_message:
        print(f"Error Message:   {error_message}")

    expected_output = "World"
    behavior_match = expected_output in execution_output if execution_output else False
    print(f"Output Matches:  {'YES' if behavior_match else 'NO (expected: World)'}")
    print("=" * 60)

    all_passed = is_valid_syntax and is_executable
    if all_passed:
        print("\nFINAL RESULT: ALL TESTS PASSED")
    else:
        print("\nFINAL RESULT: SOME TESTS FAILED")

    return {
        "transpilation_success": True,
        "syntax_valid": is_valid_syntax,
        "executable": is_executable,
        "execution_output": execution_output,
        "error_message": error_message,
        "generated_code": python_code
    }


if __name__ == "__main__":
    result = test_go_to_python_transpilation()
    transpile_ok = result["transpilation_success"]
    syntax_ok = result["syntax_valid"]
    exec_ok = result["executable"]
    sys.exit(0 if transpile_ok and syntax_ok and exec_ok else 1)
