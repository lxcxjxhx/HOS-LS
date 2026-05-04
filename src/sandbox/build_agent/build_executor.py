"""
BuildExecutor Agent - 构建执行器

执行项目构建。
"""

import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass


@dataclass
class BuildResult:
    """构建结果"""
    success: bool
    message: str
    duration: float
    output: str
    artifacts: List[str]


class BuildExecutor:
    """构建执行器

    执行各种类型项目的构建命令。
    """

    def __init__(self, project_root: str, timeout: int = 300):
        """初始化构建执行器

        Args:
            project_root: 项目根目录
            timeout: 超时时间（秒）
        """
        self.project_root = Path(project_root)
        self.timeout = timeout
        self.build_result: Optional[BuildResult] = None

    def build(self, build_command: List[str]) -> BuildResult:
        """执行构建

        Args:
            build_command: 构建命令

        Returns:
            BuildResult对象
        """
        print(f"[BuildExecutor] Starting build: {' '.join(build_command)}")
        print(f"[BuildExecutor] Working directory: {self.project_root}")

        start_time = time.time()

        try:
            process = subprocess.Popen(
                build_command,
                cwd=self.project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            output_lines = []
            for line in iter(process.stdout.readline, ""):
                if line:
                    output_lines.append(line.rstrip())
                    if len(output_lines) <= 100:
                        print(f"[BuildExecutor] {line.rstrip()}")

            process.wait(timeout=self.timeout)
            duration = time.time() - start_time

            if process.returncode == 0:
                artifacts = self._find_artifacts()
                result = BuildResult(
                    success=True,
                    message="Build successful",
                    duration=duration,
                    output="\n".join(output_lines),
                    artifacts=artifacts,
                )
                print(f"[BuildExecutor] Build completed in {duration:.2f}s")
                print(f"[BuildExecutor] Artifacts: {artifacts}")
            else:
                result = BuildResult(
                    success=False,
                    message=f"Build failed with exit code {process.returncode}",
                    duration=duration,
                    output="\n".join(output_lines),
                    artifacts=[],
                )
                print(f"[BuildExecutor] Build failed: {result.message}")

        except subprocess.TimeoutExpired:
            process.kill()
            duration = time.time() - start_time
            result = BuildResult(
                success=False,
                message=f"Build timeout after {self.timeout}s",
                duration=duration,
                output="",
                artifacts=[],
            )
            print(f"[BuildExecutor] Build timeout")

        except Exception as e:
            duration = time.time() - start_time
            result = BuildResult(
                success=False,
                message=f"Build error: {str(e)}",
                duration=duration,
                output="",
                artifacts=[],
            )
            print(f"[BuildExecutor] Build error: {e}")

        self.build_result = result
        return result

    def _find_artifacts(self) -> List[str]:
        """查找构建产物"""
        artifacts = []

        target_dir = self.project_root / "target"
        if target_dir.exists():
            for jar in target_dir.glob("*.jar"):
                if not jar.name.endswith("-sources.jar") and not jar.name.endswith("-javadoc.jar"):
                    artifacts.append(str(jar))

        build_dir = self.project_root / "build"
        if build_dir.exists():
            libs_dir = build_dir / "libs"
            if libs_dir.exists():
                for jar in libs_dir.glob("*.jar"):
                    if not jar.name.endswith("-sources.jar"):
                        artifacts.append(str(jar))

        return artifacts

    def mvn_build(self) -> BuildResult:
        """Maven构建"""
        return self.build(["mvn", "clean", "package", "-DskipTests"])

    def gradle_build(self) -> BuildResult:
        """Gradle构建"""
        return self.build(["gradle", "build", "-x", "test"])

    def npm_build(self) -> BuildResult:
        """npm构建"""
        return self.build(["npm", "install"])

    def pip_build(self) -> BuildResult:
        """pip构建"""
        requirements_file = self.project_root / "requirements.txt"
        if requirements_file.exists():
            return self.build(["pip", "install", "-r", "requirements.txt"])
        return BuildResult(
            success=False,
            message="No requirements.txt found",
            duration=0,
            output="",
            artifacts=[],
        )

    def is_build_successful(self) -> bool:
        """检查构建是否成功"""
        return self.build_result is not None and self.build_result.success

    def get_artifacts(self) -> List[str]:
        """获取构建产物"""
        if self.build_result:
            return self.build_result.artifacts
        return []
