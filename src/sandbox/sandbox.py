import os
import sys
import tempfile
import subprocess
import shutil
import time
from pathlib import Path
from typing import Dict, Optional


class CodeSandbox:
    def __init__(self, timeout: int = 30, temp_dir: Optional[str] = None):
        self.timeout = timeout
        self._temp_dir = temp_dir
        self._current_temp_path = None

    def is_available(self) -> bool:
        try:
            python_executable = self._get_python_executable()
            result = subprocess.run(
                [python_executable, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def execute_poc(self, poc_code: str, language: str = "python", timeout: int = 30) -> Dict:
        result = {
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "timed_out": False
        }

        if language.lower() != "python":
            result["stderr"] = f"Unsupported language: {language}"
            return result

        temp_path = None
        try:
            temp_path = self._create_temp_environment()
            script_path = self._write_script(temp_path, poc_code)

            python_executable = self._get_python_executable()
            env = self._build_execution_env(temp_path)

            process = subprocess.run(
                [python_executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=str(temp_path)
            )

            result["success"] = process.returncode == 0
            result["stdout"] = process.stdout
            result["stderr"] = process.stderr
            result["exit_code"] = process.returncode
            result["timed_out"] = False

        except subprocess.TimeoutExpired as e:
            result["success"] = False
            result["stdout"] = e.stdout if e.stdout else ""
            result["stderr"] = f"Execution timed out after {timeout} seconds"
            result["exit_code"] = -1
            result["timed_out"] = True
            if e.stderr and isinstance(e.stderr, str):
                result["stderr"] = result["stderr"] + "\n" + e.stderr

        except FileNotFoundError:
            result["stderr"] = "Python interpreter not found"
            result["success"] = False

        except PermissionError as e:
            result["stderr"] = f"Permission denied: {str(e)}"
            result["success"] = False

        except Exception as e:
            result["stderr"] = f"Unexpected error: {str(e)}"
            result["success"] = False

        finally:
            if temp_path:
                self._cleanup_environment(temp_path)

        return result

    def _create_temp_environment(self) -> Path:
        if self._temp_dir:
            base_dir = self._temp_dir
        else:
            base_dir = tempfile.gettempdir()

        dir_name = f"hos_sandbox_{int(time.time() * 1000)}"
        temp_path = Path(base_dir) / dir_name
        temp_path.mkdir(parents=True, exist_ok=True)
        self._current_temp_path = temp_path
        return temp_path

    def _write_script(self, temp_path: Path, code: str) -> Path:
        script_path = temp_path / "poc_script.py"
        script_path.write_text(code, encoding="utf-8")
        return script_path

    def _get_python_executable(self) -> str:
        return sys.executable

    def _build_execution_env(self, temp_path: Path) -> Dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(temp_path)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    def _cleanup_environment(self, temp_path: Path) -> None:
        try:
            if temp_path.exists():
                shutil.rmtree(str(temp_path), ignore_errors=True)
        except Exception:
            pass
