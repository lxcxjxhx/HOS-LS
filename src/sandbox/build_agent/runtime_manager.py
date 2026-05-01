"""
RuntimeManager Agent - 运行时管理器

启动、监控和关闭服务。
"""

import subprocess
import time
import socket
import os
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class ServiceStatus(Enum):
    """服务状态"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class RuntimeInfo:
    """运行时信息"""
    status: ServiceStatus
    port: int
    pid: Optional[int]
    base_url: str
    startup_duration: float
    error_message: Optional[str] = None


class RuntimeManager:
    """运行时管理器

    管理服务的生命周期：启动、监控、关闭。
    """

    def __init__(
        self,
        project_root: str,
        run_command: List[str],
        port: int = 8080,
        startup_timeout: int = 60,
        health_check_interval: int = 2,
    ):
        """初始化运行时管理器

        Args:
            project_root: 项目根目录
            run_command: 运行命令
            port: 端口
            startup_timeout: 启动超时（秒）
            health_check_interval: 健康检查间隔（秒）
        """
        self.project_root = Path(project_root)
        self.run_command = run_command
        self.port = port
        self.startup_timeout = startup_timeout
        self.health_check_interval = health_check_interval
        self.process: Optional[subprocess.Popen] = None
        self.runtime_info: Optional[RuntimeInfo] = None

    def start(self) -> RuntimeInfo:
        """启动服务

        Returns:
            RuntimeInfo对象
        """
        print(f"[RuntimeManager] Starting service: {' '.join(self.run_command)}")
        print(f"[RuntimeManager] Port: {self.port}")

        if self._is_port_in_use(self.port):
            print(f"[RuntimeManager] Port {self.port} is in use, trying to find available port")
            self.port = self._find_available_port(8000, 9000)
            print(f"[RuntimeManager] Using port: {self.port}")

        start_time = time.time()

        try:
            env = self._get_env()
            self.process = subprocess.Popen(
                self.run_command,
                cwd=self.project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )

            self.runtime_info = RuntimeInfo(
                status=ServiceStatus.STARTING,
                port=self.port,
                pid=self.process.pid,
                base_url=f"http://localhost:{self.port}",
                startup_duration=0,
            )

            if self._wait_for_ready():
                self.runtime_info.status = ServiceStatus.RUNNING
                self.runtime_info.startup_duration = time.time() - start_time
                print(f"[RuntimeManager] Service started successfully in {self.runtime_info.startup_duration:.2f}s")
            else:
                self.runtime_info.status = ServiceStatus.ERROR
                self.runtime_info.error_message = "Service failed to become ready"
                print(f"[RuntimeManager] Service failed to become ready")

        except Exception as e:
            self.runtime_info = RuntimeInfo(
                status=ServiceStatus.ERROR,
                port=self.port,
                pid=None,
                base_url=f"http://localhost:{self.port}",
                startup_duration=time.time() - start_time,
                error_message=str(e),
            )
            print(f"[RuntimeManager] Service start error: {e}")

        return self.runtime_info

    def _get_env(self) -> Dict[str, str]:
        """获取环境变量"""
        env = dict(os.environ)
        if "PORT" not in env:
            env["PORT"] = str(self.port)
        if "SERVER_PORT" not in env:
            env["SERVER_PORT"] = str(self.port)
        return env

    def _is_port_in_use(self, port: int) -> bool:
        """检查端口是否被占用"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(("localhost", port)) == 0

    def _find_available_port(self, start: int, end: int) -> int:
        """查找可用端口"""
        for port in range(start, end + 1):
            if not self._is_port_in_use(port):
                return port
        return start

    def _wait_for_ready(self) -> bool:
        """等待服务就绪"""
        print(f"[RuntimeManager] Waiting for service to be ready...")

        end_time = time.time() + self.startup_timeout
        last_error = None

        while time.time() < end_time:
            if self.process and self.process.poll() is not None:
                print(f"[RuntimeManager] Process died unexpectedly")
                return False

            try:
                response = requests.get(
                    f"http://localhost:{self.port}/actuator/health",
                    timeout=2,
                )
                if response.status_code == 200:
                    print(f"[RuntimeManager] Service is ready")
                    return True
            except requests.exceptions.RequestException:
                pass

            try:
                response = requests.get(
                    f"http://localhost:{self.port}/health",
                    timeout=2,
                )
                if response.status_code == 200:
                    print(f"[RuntimeManager] Service is ready")
                    return True
            except requests.exceptions.RequestException:
                pass

            try:
                response = requests.get(
                    f"http://localhost:{self.port}/",
                    timeout=2,
                )
                print(f"[RuntimeManager] Service responded with status {response.status_code}")
                return True
            except requests.exceptions.RequestException as e:
                last_error = e

            time.sleep(self.health_check_interval)

        print(f"[RuntimeManager] Service did not become ready in time")
        return False

    def stop(self) -> bool:
        """停止服务"""
        print(f"[RuntimeManager] Stopping service...")

        if self.runtime_info:
            self.runtime_info.status = ServiceStatus.STOPPING

        success = True

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
                print(f"[RuntimeManager] Service terminated gracefully")
            except subprocess.TimeoutExpired:
                self.process.kill()
                print(f"[RuntimeManager] Service killed")
            except Exception as e:
                print(f"[RuntimeManager] Error stopping service: {e}")
                success = False

        if self._is_port_in_use(self.port):
            print(f"[RuntimeManager] Port still in use, force killing...")
            self._kill_process_on_port(self.port)

        if self.runtime_info:
            self.runtime_info.status = ServiceStatus.STOPPED

        return success

    def _kill_process_on_port(self, port: int):
        """强制关闭端口上的进程"""
        try:
            result = subprocess.run(
                ["powershell", "-Command", f"(Get-NetTCPConnection -LocalPort {port}).OwningProcess | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"],
                capture_output=True,
                text=True,
            )
        except Exception:
            pass

    def get_status(self) -> ServiceStatus:
        """获取服务状态"""
        if self.runtime_info:
            return self.runtime_info.status

        if self.process and self.process.poll() is None:
            return ServiceStatus.RUNNING

        return ServiceStatus.STOPPED

    def get_base_url(self) -> str:
        """获取服务URL"""
        if self.runtime_info:
            return self.runtime_info.base_url
        return f"http://localhost:{self.port}"

    def is_running(self) -> bool:
        """检查服务是否运行"""
        return self.get_status() == ServiceStatus.RUNNING

    def get_pid(self) -> Optional[int]:
        """获取进程ID"""
        if self.runtime_info:
            return self.runtime_info.pid
        if self.process:
            return self.process.pid
        return None
