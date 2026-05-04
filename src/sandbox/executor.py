"""沙盒执行器模块

在隔离环境中安全执行代码，限制资源使用和网络访问。
"""

import contextlib
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class ExecutionStatus(Enum):
    """执行状态"""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"


class ExecutionLanguage(Enum):
    """执行语言"""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    BASH = "bash"
    POWERSHELL = "powershell"
    JAVA = "java"
    TYPESCRIPT = "typescript"
    C = "c"
    GO = "go"
    RUST = "rust"


@dataclass
class LanguageConfig:
    """语言运行时配置"""

    extension: str
    compile_cmd: str
    run_cmd: str
    interpreter_cmd: str
    needs_compilation: bool


LANGUAGE_CONFIGS: Dict[ExecutionLanguage, LanguageConfig] = {
    ExecutionLanguage.PYTHON: LanguageConfig(
        extension=".py",
        compile_cmd="",
        run_cmd="python {filename}",
        interpreter_cmd="python",
        needs_compilation=False,
    ),
    ExecutionLanguage.JAVASCRIPT: LanguageConfig(
        extension=".js",
        compile_cmd="",
        run_cmd="node {filename}",
        interpreter_cmd="node",
        needs_compilation=False,
    ),
    ExecutionLanguage.BASH: LanguageConfig(
        extension=".sh",
        compile_cmd="",
        run_cmd="bash {filename}",
        interpreter_cmd="bash",
        needs_compilation=False,
    ),
    ExecutionLanguage.POWERSHELL: LanguageConfig(
        extension=".ps1",
        compile_cmd="",
        run_cmd="powershell.exe -ExecutionPolicy Bypass -File {filename}",
        interpreter_cmd="powershell.exe",
        needs_compilation=False,
    ),
    ExecutionLanguage.JAVA: LanguageConfig(
        extension=".java",
        compile_cmd="javac {filename}",
        run_cmd="java {classname}",
        interpreter_cmd="java",
        needs_compilation=True,
    ),
    ExecutionLanguage.TYPESCRIPT: LanguageConfig(
        extension=".ts",
        compile_cmd="tsc {filename}",
        run_cmd="node {outputfile}",
        interpreter_cmd="tsc",
        needs_compilation=True,
    ),
    ExecutionLanguage.C: LanguageConfig(
        extension=".c",
        compile_cmd="gcc -o {outputname} {filename}",
        run_cmd="./{outputname}",
        interpreter_cmd="gcc",
        needs_compilation=True,
    ),
    ExecutionLanguage.GO: LanguageConfig(
        extension=".go",
        compile_cmd="go build -o {outputname} {filename}",
        run_cmd="./{outputname}",
        interpreter_cmd="go",
        needs_compilation=True,
    ),
    ExecutionLanguage.RUST: LanguageConfig(
        extension=".rs",
        compile_cmd="rustc -o {outputname} {filename}",
        run_cmd="./{outputname}",
        interpreter_cmd="rustc",
        needs_compilation=True,
    ),
}


@dataclass
class SandboxEnvironment:
    """沙盒环境"""

    temp_dir: Path
    env_vars: Dict[str, str]
    resource_limits: Dict[str, Any]
    network_access: bool
    file_system_access: bool
    start_time: datetime = field(default_factory=datetime.now)


@dataclass
class ExecutionResult:
    """执行结果"""

    status: ExecutionStatus
    output: str
    error: str
    exit_code: Optional[int] = None
    execution_time: float = 0.0
    memory_used: Optional[int] = None
    cpu_used: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "memory_used": self.memory_used,
            "cpu_used": self.cpu_used,
            "metadata": self.metadata,
        }


@dataclass
class SandboxConfig:
    """沙盒配置"""

    timeout: int = 30
    memory_limit: int = 512 * 1024 * 1024  # 512MB
    cpu_limit: float = 1.0  # 1 CPU
    network_access: bool = False
    file_system_access: bool = True
    temp_dir_prefix: str = "sandbox_"
    env_vars: Dict[str, str] = field(default_factory=dict)


class SandboxExecutor:
    """沙盒执行器

    在隔离环境中执行代码。
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        """初始化沙盒执行器

        Args:
            config: 沙盒配置
        """
        self.config = config or SandboxConfig()
        self._processes: Dict[int, subprocess.Popen] = {}

    def execute(
        self,
        code: str,
        language: Union[ExecutionLanguage, str],
        timeout: Optional[int] = None,
        memory_limit: Optional[int] = None,
        network_access: Optional[bool] = None,
    ) -> ExecutionResult:
        """在沙盒中执行代码

        Args:
            code: 代码
            language: 语言
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        if isinstance(language, str):
            try:
                language = ExecutionLanguage(language.lower())
            except ValueError:
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    output="",
                    error=f"Unsupported language: {language}",
                )

        env = self.config.env_vars.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["NODE_ENV"] = "production"

        sandbox_env = self.setup_sandbox()

        if language == ExecutionLanguage.PYTHON:
            result = self._execute_python(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                memory_limit=memory_limit or self.config.memory_limit,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        elif language == ExecutionLanguage.JAVASCRIPT:
            result = self._execute_javascript(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        elif language == ExecutionLanguage.BASH:
            result = self._execute_bash(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        elif language == ExecutionLanguage.POWERSHELL:
            result = self._execute_powershell(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        elif language == ExecutionLanguage.JAVA:
            result = self._execute_java(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                memory_limit=memory_limit or self.config.memory_limit,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        elif language == ExecutionLanguage.TYPESCRIPT:
            result = self._execute_typescript(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                memory_limit=memory_limit or self.config.memory_limit,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        elif language == ExecutionLanguage.C:
            result = self._execute_c(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                memory_limit=memory_limit or self.config.memory_limit,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        elif language == ExecutionLanguage.GO:
            result = self._execute_go(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                memory_limit=memory_limit or self.config.memory_limit,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        elif language == ExecutionLanguage.RUST:
            result = self._execute_rust(
                code=code,
                sandbox_env=sandbox_env,
                timeout=timeout or self.config.timeout,
                memory_limit=memory_limit or self.config.memory_limit,
                network_access=network_access if network_access is not None else self.config.network_access,
            )
        else:
            result = ExecutionResult(
                status=ExecutionStatus.ERROR,
                output="",
                error=f"Unsupported language: {language}",
            )

        self.cleanup_sandbox()
        return result

    def setup_sandbox(self) -> SandboxEnvironment:
        """设置沙盒环境

        Returns:
            沙盒环境
        """
        temp_dir = Path(tempfile.mkdtemp(prefix=self.config.temp_dir_prefix))

        env_vars = {
            "TMPDIR": str(temp_dir),
            "TEMP": str(temp_dir),
            "TMP": str(temp_dir),
        }
        env_vars.update(self.config.env_vars)

        resource_limits = {
            "memory": self.config.memory_limit,
            "cpu": self.config.cpu_limit,
        }

        return SandboxEnvironment(
            temp_dir=temp_dir,
            env_vars=env_vars,
            resource_limits=resource_limits,
            network_access=self.config.network_access,
            file_system_access=self.config.file_system_access,
        )

    def cleanup_sandbox(self) -> None:
        """清理沙盒环境"""
        for pid, process in list(self._processes.items()):
            try:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            except Exception:
                pass
            finally:
                del self._processes[pid]

    def _execute_python(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        memory_limit: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 Python 代码

        Args:
            code: Python 代码
            sandbox_env: 沙盒环境
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        code_file = sandbox_env.temp_dir / "script.py"
        code_file.write_text(code, encoding="utf-8")

        cmd = [sys.executable, str(code_file)]

        if not network_access:
            cmd = ["python", "-c", "import os; os.environ['NO_PROXY'] = '*'; exec(open('script.py').read())"]

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None

        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(sandbox_env.temp_dir),
                env=sandbox_env.env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )

            self._processes[process.pid] = process

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                output = stdout or ""
                error = stderr or ""
                exit_code = process.returncode
                status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
                status = ExecutionStatus.TIMEOUT
                error = f"Execution timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        memory_used = None
        cpu_used = None

        if PSUTIL_AVAILABLE:
            try:
                process = psutil.Process(os.getpid())
                memory_used = process.memory_info().rss
                cpu_used = process.cpu_percent()
            except Exception:
                pass

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            memory_used=memory_used,
            cpu_used=cpu_used,
            metadata={"language": "python"},
        )

    def _execute_javascript(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 JavaScript 代码

        Args:
            code: JavaScript 代码
            sandbox_env: 沙盒环境
            timeout: 超时时间
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        code_file = sandbox_env.temp_dir / "script.js"
        code_file.write_text(code, encoding="utf-8")

        node_cmd = "node"
        if sys.platform == "win32":
            node_cmd = "node.exe"

        cmd = [node_cmd, str(code_file)]

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None

        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(sandbox_env.temp_dir),
                env=sandbox_env.env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )

            self._processes[process.pid] = process

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                output = stdout or ""
                error = stderr or ""
                exit_code = process.returncode
                status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
                status = ExecutionStatus.TIMEOUT
                error = f"Execution timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            metadata={"language": "javascript"},
        )

    def _execute_bash(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 Bash 命令

        Args:
            code: Bash 命令
            sandbox_env: 沙盒环境
            timeout: 超时时间
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        script_file = sandbox_env.temp_dir / "script.sh"
        script_file.write_text(code, encoding="utf-8")
        script_file.chmod(0o755)

        cmd = ["bash", str(script_file)]

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None

        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(sandbox_env.temp_dir),
                env=sandbox_env.env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )

            self._processes[process.pid] = process

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                output = stdout or ""
                error = stderr or ""
                exit_code = process.returncode
                status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
                status = ExecutionStatus.TIMEOUT
                error = f"Execution timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            metadata={"language": "bash"},
        )

    def _execute_powershell(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 PowerShell 命令

        Args:
            code: PowerShell 命令
            sandbox_env: 沙盒环境
            timeout: 超时时间
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        script_file = sandbox_env.temp_dir / "script.ps1"
        script_file.write_text(code, encoding="utf-8")

        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(script_file)]

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None

        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(sandbox_env.temp_dir),
                env=sandbox_env.env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )

            self._processes[process.pid] = process

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                output = stdout or ""
                error = stderr or ""
                exit_code = process.returncode
                status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
                status = ExecutionStatus.TIMEOUT
                error = f"Execution timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            metadata={"language": "powershell"},
        )

    def _execute_java(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        memory_limit: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 Java 代码

        Args:
            code: Java 代码
            sandbox_env: 沙盒环境
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        java_file = sandbox_env.temp_dir / "Main.java"
        java_file.write_text(code, encoding="utf-8")

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None
        status = ExecutionStatus.SUCCESS

        try:
            compile_cmd = ["javac", str(java_file)]
            compile_process = subprocess.Popen(
                compile_cmd,
                cwd=str(sandbox_env.temp_dir),
                env=sandbox_env.env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )

            try:
                compile_stdout, compile_stderr = compile_process.communicate(timeout=timeout)
                compile_exit_code = compile_process.returncode

                if compile_exit_code != 0:
                    error = compile_stderr or ""
                    status = ExecutionStatus.FAILED
                    exit_code = compile_exit_code
                else:
                    class_file = sandbox_env.temp_dir / "Main.class"
                    if class_file.exists():
                        run_cmd = ["java", "-cp", str(sandbox_env.temp_dir), "Main"]
                        process = subprocess.Popen(
                            run_cmd,
                            cwd=str(sandbox_env.temp_dir),
                            env=sandbox_env.env_vars,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            shell=False,
                        )

                        self._processes[process.pid] = process

                        try:
                            stdout, stderr = process.communicate(timeout=timeout)
                            output = stdout or ""
                            error = stderr or ""
                            exit_code = process.returncode
                            status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            process.wait(timeout=5)
                            status = ExecutionStatus.TIMEOUT
                            error = f"Execution timed out after {timeout} seconds"
                    else:
                        status = ExecutionStatus.ERROR
                        error = "Compilation succeeded but class file not found"
            except subprocess.TimeoutExpired:
                compile_process.terminate()
                compile_process.wait(timeout=5)
                status = ExecutionStatus.TIMEOUT
                error = f"Compilation timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        memory_used = None
        cpu_used = None

        if PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process()
                children = proc.children(recursive=True)
                total_memory = proc.memory_info().rss
                total_cpu = proc.cpu_percent()
                for child in children:
                    try:
                        total_memory += child.memory_info().rss
                        total_cpu += child.cpu_percent()
                    except Exception:
                        pass
                memory_used = total_memory
                cpu_used = total_cpu
            except Exception:
                pass

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            memory_used=memory_used,
            cpu_used=cpu_used,
            metadata={"language": "java", "needs_compilation": True},
        )

    def _execute_typescript(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        memory_limit: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 TypeScript 代码

        Args:
            code: TypeScript 代码
            sandbox_env: 沙盒环境
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        ts_file = sandbox_env.temp_dir / "script.ts"
        ts_file.write_text(code, encoding="utf-8")

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None
        status = ExecutionStatus.SUCCESS

        try:
            tsnode_cmd = "ts-node"
            if sys.platform == "win32":
                tsnode_cmd = "ts-node.cmd"

            try:
                process = subprocess.Popen(
                    [tsnode_cmd, str(ts_file)],
                    cwd=str(sandbox_env.temp_dir),
                    env=sandbox_env.env_vars,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                )

                self._processes[process.pid] = process

                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                    output = stdout or ""
                    error = stderr or ""
                    exit_code = process.returncode
                    status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
                    status = ExecutionStatus.TIMEOUT
                    error = f"Execution timed out after {timeout} seconds"

            except FileNotFoundError:
                js_file = sandbox_env.temp_dir / "script.js"
                tsc_cmd = ["npx", "tsc", str(ts_file), "--outDir", str(sandbox_env.temp_dir), "--module", "commonjs", "--target", "ES2017"]

                compile_process = subprocess.Popen(
                    tsc_cmd,
                    cwd=str(sandbox_env.temp_dir),
                    env=sandbox_env.env_vars,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                )

                try:
                    compile_stdout, compile_stderr = compile_process.communicate(timeout=timeout)
                    compile_exit_code = compile_process.returncode

                    if compile_exit_code != 0:
                        error = compile_stderr or ""
                        status = ExecutionStatus.FAILED
                        exit_code = compile_exit_code
                    else:
                        node_cmd = "node"
                        if sys.platform == "win32":
                            node_cmd = "node.exe"

                        process = subprocess.Popen(
                            [node_cmd, str(js_file)],
                            cwd=str(sandbox_env.temp_dir),
                            env=sandbox_env.env_vars,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            shell=False,
                        )

                        self._processes[process.pid] = process

                        try:
                            stdout, stderr = process.communicate(timeout=timeout)
                            output = stdout or ""
                            error = stderr or ""
                            exit_code = process.returncode
                            status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            process.wait(timeout=5)
                            status = ExecutionStatus.TIMEOUT
                            error = f"Execution timed out after {timeout} seconds"
                except subprocess.TimeoutExpired:
                    compile_process.terminate()
                    compile_process.wait(timeout=5)
                    status = ExecutionStatus.TIMEOUT
                    error = f"Compilation timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        memory_used = None
        cpu_used = None

        if PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process()
                children = proc.children(recursive=True)
                total_memory = proc.memory_info().rss
                total_cpu = proc.cpu_percent()
                for child in children:
                    try:
                        total_memory += child.memory_info().rss
                        total_cpu += child.cpu_percent()
                    except Exception:
                        pass
                memory_used = total_memory
                cpu_used = total_cpu
            except Exception:
                pass

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            memory_used=memory_used,
            cpu_used=cpu_used,
            metadata={"language": "typescript"},
        )

    def _execute_c(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        memory_limit: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 C 代码

        Args:
            code: C 代码
            sandbox_env: 沙盒环境
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        c_file = sandbox_env.temp_dir / "main.c"
        c_file.write_text(code, encoding="utf-8")

        output_name = "main"
        if sys.platform == "win32":
            output_name = "main.exe"

        output_file = sandbox_env.temp_dir / output_name

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None
        status = ExecutionStatus.SUCCESS

        try:
            compile_cmd = ["gcc", "-o", str(output_file), str(c_file)]
            compile_process = subprocess.Popen(
                compile_cmd,
                cwd=str(sandbox_env.temp_dir),
                env=sandbox_env.env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )

            try:
                compile_stdout, compile_stderr = compile_process.communicate(timeout=timeout)
                compile_exit_code = compile_process.returncode

                if compile_exit_code != 0:
                    error = compile_stderr or ""
                    status = ExecutionStatus.FAILED
                    exit_code = compile_exit_code
                else:
                    if output_file.exists():
                        run_cmd = [str(output_file)]
                        process = subprocess.Popen(
                            run_cmd,
                            cwd=str(sandbox_env.temp_dir),
                            env=sandbox_env.env_vars,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            shell=False,
                        )

                        self._processes[process.pid] = process

                        try:
                            stdout, stderr = process.communicate(timeout=timeout)
                            output = stdout or ""
                            error = stderr or ""
                            exit_code = process.returncode
                            status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            process.wait(timeout=5)
                            status = ExecutionStatus.TIMEOUT
                            error = f"Execution timed out after {timeout} seconds"
                    else:
                        status = ExecutionStatus.ERROR
                        error = "Compilation succeeded but executable not found"
            except subprocess.TimeoutExpired:
                compile_process.terminate()
                compile_process.wait(timeout=5)
                status = ExecutionStatus.TIMEOUT
                error = f"Compilation timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        memory_used = None
        cpu_used = None

        if PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process()
                children = proc.children(recursive=True)
                total_memory = proc.memory_info().rss
                total_cpu = proc.cpu_percent()
                for child in children:
                    try:
                        total_memory += child.memory_info().rss
                        total_cpu += child.cpu_percent()
                    except Exception:
                        pass
                memory_used = total_memory
                cpu_used = total_cpu
            except Exception:
                pass

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            memory_used=memory_used,
            cpu_used=cpu_used,
            metadata={"language": "c", "needs_compilation": True},
        )

    def _execute_go(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        memory_limit: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 Go 代码

        Args:
            code: Go 代码
            sandbox_env: 沙盒环境
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        go_file = sandbox_env.temp_dir / "main.go"
        go_file.write_text(code, encoding="utf-8")

        output_name = "main"
        if sys.platform == "win32":
            output_name = "main.exe"

        output_file = sandbox_env.temp_dir / output_name

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None
        status = ExecutionStatus.SUCCESS

        try:
            use_go_run = True

            if use_go_run:
                run_cmd = ["go", "run", str(go_file)]
                process = subprocess.Popen(
                    run_cmd,
                    cwd=str(sandbox_env.temp_dir),
                    env=sandbox_env.env_vars,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                )

                self._processes[process.pid] = process

                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                    output = stdout or ""
                    error = stderr or ""
                    exit_code = process.returncode
                    status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
                    status = ExecutionStatus.TIMEOUT
                    error = f"Execution timed out after {timeout} seconds"
            else:
                compile_cmd = ["go", "build", "-o", str(output_file), str(go_file)]
                compile_process = subprocess.Popen(
                    compile_cmd,
                    cwd=str(sandbox_env.temp_dir),
                    env=sandbox_env.env_vars,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                )

                try:
                    compile_stdout, compile_stderr = compile_process.communicate(timeout=timeout)
                    compile_exit_code = compile_process.returncode

                    if compile_exit_code != 0:
                        error = compile_stderr or ""
                        status = ExecutionStatus.FAILED
                        exit_code = compile_exit_code
                    else:
                        if output_file.exists():
                            run_cmd = [str(output_file)]
                            process = subprocess.Popen(
                                run_cmd,
                                cwd=str(sandbox_env.temp_dir),
                                env=sandbox_env.env_vars,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                shell=False,
                            )

                            self._processes[process.pid] = process

                            try:
                                stdout, stderr = process.communicate(timeout=timeout)
                                output = stdout or ""
                                error = stderr or ""
                                exit_code = process.returncode
                                status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                            except subprocess.TimeoutExpired:
                                process.terminate()
                                process.wait(timeout=5)
                                status = ExecutionStatus.TIMEOUT
                                error = f"Execution timed out after {timeout} seconds"
                        else:
                            status = ExecutionStatus.ERROR
                            error = "Build succeeded but executable not found"
                except subprocess.TimeoutExpired:
                    compile_process.terminate()
                    compile_process.wait(timeout=5)
                    status = ExecutionStatus.TIMEOUT
                    error = f"Build timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        memory_used = None
        cpu_used = None

        if PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process()
                children = proc.children(recursive=True)
                total_memory = proc.memory_info().rss
                total_cpu = proc.cpu_percent()
                for child in children:
                    try:
                        total_memory += child.memory_info().rss
                        total_cpu += child.cpu_percent()
                    except Exception:
                        pass
                memory_used = total_memory
                cpu_used = total_cpu
            except Exception:
                pass

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            memory_used=memory_used,
            cpu_used=cpu_used,
            metadata={"language": "go", "needs_compilation": True},
        )

    def _execute_rust(
        self,
        code: str,
        sandbox_env: SandboxEnvironment,
        timeout: int,
        memory_limit: int,
        network_access: bool,
    ) -> ExecutionResult:
        """执行 Rust 代码

        Args:
            code: Rust 代码
            sandbox_env: 沙盒环境
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问

        Returns:
            执行结果
        """
        rs_file = sandbox_env.temp_dir / "main.rs"
        rs_file.write_text(code, encoding="utf-8")

        project_dir = sandbox_env.temp_dir / "rust_project"
        project_dir.mkdir(exist_ok=True)

        cargo_toml = project_dir / "Cargo.toml"
        cargo_toml.write_text(
            "[package]\nname = \"sandbox\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"../main.rs\"\n\n[[bin]]\nname = \"sandbox\"\npath = \"../main.rs\"\n",
            encoding="utf-8",
        )

        output_name = "sandbox"
        if sys.platform == "win32":
            output_name = "sandbox.exe"

        output_file = project_dir / "target" / "release" / output_name

        start_time = time.time()
        output = ""
        error = ""
        exit_code = None
        status = ExecutionStatus.SUCCESS

        try:
            compile_cmd = ["cargo", "build", "--release", "--manifest-path", str(cargo_toml)]
            compile_process = subprocess.Popen(
                compile_cmd,
                cwd=str(project_dir),
                env=sandbox_env.env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )

            try:
                compile_stdout, compile_stderr = compile_process.communicate(timeout=timeout)
                compile_exit_code = compile_process.returncode

                if compile_exit_code != 0:
                    error = compile_stderr or ""
                    if not error:
                        error = compile_stdout or ""
                    status = ExecutionStatus.FAILED
                    exit_code = compile_exit_code
                else:
                    if output_file.exists():
                        run_cmd = [str(output_file)]
                        process = subprocess.Popen(
                            run_cmd,
                            cwd=str(project_dir),
                            env=sandbox_env.env_vars,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            shell=False,
                        )

                        self._processes[process.pid] = process

                        try:
                            stdout, stderr = process.communicate(timeout=timeout)
                            output = stdout or ""
                            error = stderr or ""
                            exit_code = process.returncode
                            status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            process.wait(timeout=5)
                            status = ExecutionStatus.TIMEOUT
                            error = f"Execution timed out after {timeout} seconds"
                    else:
                        status = ExecutionStatus.ERROR
                        error = "Compilation succeeded but binary not found"
            except subprocess.TimeoutExpired:
                compile_process.terminate()
                compile_process.wait(timeout=5)
                status = ExecutionStatus.TIMEOUT
                error = f"Compilation timed out after {timeout} seconds"

        except Exception as e:
            status = ExecutionStatus.ERROR
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        memory_used = None
        cpu_used = None

        if PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process()
                children = proc.children(recursive=True)
                total_memory = proc.memory_info().rss
                total_cpu = proc.cpu_percent()
                for child in children:
                    try:
                        total_memory += child.memory_info().rss
                        total_cpu += child.cpu_percent()
                    except Exception:
                        pass
                memory_used = total_memory
                cpu_used = total_cpu
            except Exception:
                pass

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            exit_code=exit_code,
            execution_time=execution_time,
            memory_used=memory_used,
            cpu_used=cpu_used,
            metadata={"language": "rust", "needs_compilation": True},
        )

    def execute_function(
        self,
        func: callable,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """执行函数

        Args:
            func: 函数
            args: 位置参数
            kwargs: 关键字参数
            timeout: 超时时间

        Returns:
            执行结果
        """
        start_time = time.time()
        output = ""
        error = ""

        try:
            result = func(*args, **(kwargs or {}))
            output = str(result)
            status = ExecutionStatus.SUCCESS
        except Exception as e:
            status = ExecutionStatus.FAILED
            error = str(e)
        finally:
            execution_time = time.time() - start_time

        return ExecutionResult(
            status=status,
            output=output,
            error=error,
            execution_time=execution_time,
            metadata={"type": "function"},
        )

    def shutdown(self) -> None:
        """关闭执行器"""
        self.cleanup_sandbox()
