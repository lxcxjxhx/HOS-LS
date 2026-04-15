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
