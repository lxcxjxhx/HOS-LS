import os
import shutil
import subprocess
import tempfile
import threading
import atexit
import logging
import time
import random
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List, Any
from enum import Enum

from .java_to_python_converter import JavaToPythonConverter
from .python_test_executor import PythonTestExecutor

logger = logging.getLogger(__name__)


class ProjectType(Enum):
    MAVEN = "maven"
    GRADLE = "gradle"
    UNKNOWN = "unknown"


@dataclass
class SandboxInfo:
    sandbox_id: str
    sandbox_path: str
    project_path: str
    project_type: ProjectType
    created_at: datetime
    services: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SandboxEnvironmentManager:
    def __init__(self, sandbox_root: Optional[str] = None):
        self._sandbox_root = sandbox_root or tempfile.gettempdir()
        self._sandboxes: Dict[str, SandboxInfo] = {}
        self._services: Dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()
        atexit.register(self.cleanup_all)

    def _generate_sandbox_id(self) -> str:
        timestamp = int(time.time() * 1000)
        random_part = random.randint(1000, 9999)
        return f"sandbox_{timestamp}_{random_part}"

    def _detect_project_type(self, project_path: str) -> ProjectType:
        pom_xml = os.path.join(project_path, "pom.xml")
        build_gradle = os.path.join(project_path, "build.gradle")
        settings_gradle = os.path.join(project_path, "settings.gradle")

        if os.path.exists(pom_xml):
            return ProjectType.MAVEN
        elif os.path.exists(build_gradle) or os.path.exists(settings_gradle):
            return ProjectType.GRADLE
        return ProjectType.UNKNOWN

    def _is_spring_boot_project(self, project_path: str) -> bool:
        pom_xml = os.path.join(project_path, "pom.xml")
        build_gradle = os.path.join(project_path, "build.gradle")

        if os.path.exists(pom_xml):
            try:
                with open(pom_xml, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'spring-boot-starter' in content or 'spring-boot-maven-plugin' in content:
                        return True
            except Exception as e:
                logger.warning(f"Failed to read pom.xml: {e}")

        if os.path.exists(build_gradle):
            try:
                with open(build_gradle, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'spring-boot' in content:
                        return True
            except Exception as e:
                logger.warning(f"Failed to read build.gradle: {e}")

        return False

    def copy_project_to_sandbox(self, project_path: str, sandbox_root: Optional[str] = None) -> str:
        if not os.path.exists(project_path):
            raise FileNotFoundError(f"Project path does not exist: {project_path}")

        sandbox_id = self._generate_sandbox_id()
        target_root = sandbox_root or self._sandbox_root
        sandbox_path = os.path.join(target_root, sandbox_id)

        try:
            shutil.copytree(project_path, sandbox_path)
            logger.info(f"Copied project from {project_path} to {sandbox_path}")

            project_type = self._detect_project_type(project_path)
            is_spring_boot = self._is_spring_boot_project(project_path)

            with self._lock:
                self._sandboxes[sandbox_id] = SandboxInfo(
                    sandbox_id=sandbox_id,
                    sandbox_path=sandbox_path,
                    project_path=project_path,
                    project_type=project_type,
                    created_at=datetime.now(),
                    metadata={
                        "is_spring_boot": is_spring_boot,
                        "original_project_name": os.path.basename(project_path)
                    }
                )

            return sandbox_path

        except Exception as e:
            if os.path.exists(sandbox_path):
                shutil.rmtree(sandbox_path, ignore_errors=True)
            raise RuntimeError(f"Failed to copy project to sandbox: {e}") from e

    def start_isolated_service(self, sandbox_path: str, port: int, service_name: Optional[str] = None) -> str:
        if not os.path.exists(sandbox_path):
            raise ValueError(f"Sandbox path does not exist: {sandbox_path}")

        service_id = f"service_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
        service_name = service_name or f"isolated_service_{port}"

        project_type = None
        with self._lock:
            for sandbox_info in self._sandboxes.values():
                if sandbox_info.sandbox_path == sandbox_path:
                    project_type = sandbox_info.project_type
                    break

        if project_type == ProjectType.MAVEN:
            jar_file = self._find_jar_file(sandbox_path)
            if jar_file:
                cmd = ["java", "-jar", jar_file, f"--server.port={port}"]
            else:
                mvn_cmd = self._build_maven_command(sandbox_path, port)
                cmd = mvn_cmd
        elif project_type == ProjectType.GRADLE:
            gradle_cmd = self._build_gradle_command(sandbox_path, port)
            cmd = gradle_cmd
        else:
            raise ValueError(f"Unsupported project type or no build file found in {sandbox_path}")

        try:
            process = subprocess.Popen(
                cmd,
                cwd=sandbox_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            with self._lock:
                self._services[service_id] = process

                for sandbox_info in self._sandboxes.values():
                    if sandbox_info.sandbox_path == sandbox_path:
                        sandbox_info.services.append(service_id)
                        break

            logger.info(f"Started isolated service {service_id} on port {port} with command: {' '.join(cmd)}")
            return service_id

        except Exception as e:
            raise RuntimeError(f"Failed to start isolated service: {e}") from e

    def _find_jar_file(self, sandbox_path: str) -> Optional[str]:
        for root, dirs, files in os.walk(sandbox_path):
            for file in files:
                if file.endswith(".jar") and "spring-boot" in file or file.endswith("-boot.jar"):
                    return os.path.join(root, file)

        target_dir = os.path.join(sandbox_path, "target")
        if os.path.exists(target_dir):
            for file in os.listdir(target_dir):
                if file.endswith(".jar"):
                    return os.path.join(target_dir, file)

        return None

    def _build_maven_command(self, sandbox_path: str, port: int) -> List[str]:
        if self._is_spring_boot_project(sandbox_path):
            return ["mvn", "spring-boot:run", f"-Dspring-boot.run.arguments=--server.port={port}"]
        return ["mvn", "spring-boot:run", f"-Dserver.port={port}"]

    def _build_gradle_command(self, sandbox_path: str, port: int) -> List[str]:
        if self._is_spring_boot_project(sandbox_path):
            return ["gradle", "bootRun", f"--args=--server.port={port}"]
        return ["gradle", "bootRun", f"-Pport={port}"]

    def stop_isolated_service(self, service_id: str) -> bool:
        with self._lock:
            if service_id not in self._services:
                logger.warning(f"Service {service_id} not found")
                return False

            process = self._services[service_id]

        try:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

            with self._lock:
                del self._services[service_id]

                for sandbox_info in self._sandboxes.values():
                    if service_id in sandbox_info.services:
                        sandbox_info.services.remove(service_id)

            logger.info(f"Stopped isolated service {service_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to stop service {service_id}: {e}")
            return False

    def cleanup_sandbox(self, sandbox_id: str) -> bool:
        with self._lock:
            if sandbox_id not in self._sandboxes:
                logger.warning(f"Sandbox {sandbox_id} not found")
                return False

            sandbox_info = self._sandboxes[sandbox_id]
            sandbox_path = sandbox_info.sandbox_path

        services_to_stop = list(sandbox_info.services)
        for service_id in services_to_stop:
            self.stop_isolated_service(service_id)

        try:
            if os.path.exists(sandbox_path):
                shutil.rmtree(sandbox_path)
                logger.info(f"Cleaned up sandbox {sandbox_id} at {sandbox_path}")

            with self._lock:
                del self._sandboxes[sandbox_id]

            return True

        except Exception as e:
            logger.error(f"Failed to cleanup sandbox {sandbox_id}: {e}")
            return False

    def cleanup_all(self) -> None:
        sandbox_ids = list(self._sandboxes.keys())

        for sandbox_id in sandbox_ids:
            try:
                self.cleanup_sandbox(sandbox_id)
            except Exception as e:
                logger.error(f"Error cleaning up sandbox {sandbox_id}: {e}")

        with self._lock:
            self._services.clear()

        logger.info("Cleaned up all sandboxes")

    def get_sandbox_info(self, sandbox_id: str) -> Optional[SandboxInfo]:
        with self._lock:
            return self._sandboxes.get(sandbox_id)

    def list_sandboxes(self) -> List[SandboxInfo]:
        with self._lock:
            return list(self._sandboxes.values())

    def get_service_status(self, service_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if service_id not in self._services:
                return None

            process = self._services[service_id]
            return {
                "service_id": service_id,
                "running": process.poll() is None,
                "return_code": process.returncode if process.poll() is not None else None
            }

    def run_python_test(self, java_code: str, timeout: int = 30) -> dict:
        """
        Run Python test from Java code.

        Args:
            java_code: Java code to convert and execute
            timeout: Execution timeout in seconds

        Returns:
            dict with keys: success, converted_code, output, error, execution_time
        """
        result = {
            "success": False,
            "converted_code": None,
            "output": None,
            "error": None,
            "execution_time": 0.0
        }

        try:
            converter = JavaToPythonConverter()
            converted_code = converter.convert(java_code)
            result["converted_code"] = converted_code
        except Exception as e:
            logger.error(f"Java to Python conversion failed: {e}")
            result["error"] = f"Conversion failed: {str(e)}"
            return result

        try:
            executor = PythonTestExecutor()
            exec_result = executor.execute(converted_code, timeout=timeout)
            result["output"] = exec_result.get("output")
            result["error"] = exec_result.get("error")
            result["execution_time"] = exec_result.get("execution_time", 0.0)
            result["success"] = exec_result.get("success", False)
        except Exception as e:
            logger.error(f"Python test execution failed: {e}")
            result["error"] = f"Execution failed: {str(e)}"

        return result

    def convert_java_to_python(self, java_code: str) -> str:
        """
        Shortcut to convert Java code to Python.

        Args:
            java_code: Java code to convert

        Returns:
            Converted Python code string
        """
        try:
            converter = JavaToPythonConverter()
            return converter.convert(java_code)
        except Exception as e:
            logger.error(f"Java to Python conversion failed: {e}")
            raise RuntimeError(f"Conversion failed: {str(e)}") from e

    def execute_python_test(self, python_code: str, timeout: int = 30) -> dict:
        """
        Shortcut to execute Python test code.

        Args:
            python_code: Python code to execute
            timeout: Execution timeout in seconds

        Returns:
            dict with execution results
        """
        try:
            executor = PythonTestExecutor()
            return executor.execute(python_code, timeout=timeout)
        except Exception as e:
            logger.error(f"Python test execution failed: {e}")
            raise RuntimeError(f"Execution failed: {str(e)}") from e

    def __del__(self):
        try:
            self.cleanup_all()
        except Exception:
            pass
