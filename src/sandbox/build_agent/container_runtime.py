"""
ContainerRuntime - 容器化运行时管理器

在Docker容器中启动和管理服务。
"""

import docker
import time
import socket
import logging
import uuid
from typing import Optional, List, Dict
from dataclasses import dataclass
from enum import Enum

from .image_manager import ImageManager


logger = logging.getLogger(__name__)


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
    container_id: str
    base_url: str
    startup_duration: float
    logs: str
    error_message: Optional[str] = None


class ContainerRuntime:
    """容器化运行时管理器"""

    def __init__(
        self,
        project_root: str,
        project_type: str,
        run_command: List[str],
        port: int = 8080,
        image_manager: Optional[ImageManager] = None,
        startup_timeout: int = 60,
        health_check_interval: int = 2,
        memory_limit: str = "1g",
        cpu_limit: float = 1.0,
        network_name: str = "hos-ls-network",
    ):
        self.project_root = project_root
        self.project_type = project_type
        self.run_command = run_command
        self.port = port
        self.image_manager = image_manager or ImageManager()
        self.startup_timeout = startup_timeout
        self.health_check_interval = health_check_interval
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network_name = network_name

        self.container: Optional[docker.models.containers.Container] = None
        self.runtime_info: Optional[RuntimeInfo] = None
        self._container_name: Optional[str] = None
        self._mapped_port: Optional[int] = None

    def _generate_container_name(self) -> str:
        """生成唯一的容器名称"""
        unique_id = uuid.uuid4().hex[:8]
        return f"hos-ls-runtime-{unique_id}"

    def start(self) -> RuntimeInfo:
        """启动服务容器"""
        start_time = time.time()

        logger.info(f"[ContainerRuntime] Starting service for {self.project_type}")
        logger.info(f"[ContainerRuntime] Run command: {' '.join(self.run_command)}")

        image = self.image_manager.ensure_image(self.project_type)
        if not image:
            return RuntimeInfo(
                status=ServiceStatus.ERROR,
                port=self.port,
                container_id="",
                base_url="",
                startup_duration=0,
                logs="",
                error_message=f"Failed to get image for {self.project_type}"
            )

        logger.info(f"[ContainerRuntime] Using image: {image}")

        self._container_name = self._generate_container_name()
        actual_port = self._find_available_port()

        try:
            self.container = self._create_service_container(image, actual_port)
            logger.info(f"[ContainerRuntime] Created container: {self.container.id[:12]}")

            actual_port = self._get_mapped_port()
            self._mapped_port = actual_port

            if self._wait_for_ready(actual_port):
                self.runtime_info = RuntimeInfo(
                    status=ServiceStatus.RUNNING,
                    port=actual_port,
                    container_id=self.container.id,
                    base_url=f"http://localhost:{actual_port}",
                    startup_duration=time.time() - start_time,
                    logs=""
                )
                logger.info(f"[ContainerRuntime] Service started successfully at {self.runtime_info.base_url}")
            else:
                self.runtime_info = RuntimeInfo(
                    status=ServiceStatus.ERROR,
                    port=actual_port,
                    container_id=self.container.id,
                    base_url=f"http://localhost:{actual_port}",
                    startup_duration=time.time() - start_time,
                    logs=self.get_logs(),
                    error_message="Service failed to become ready"
                )
                logger.warning(f"[ContainerRuntime] Service failed to become ready")

        except Exception as e:
            logger.error(f"[ContainerRuntime] Service start error: {e}")
            self.runtime_info = RuntimeInfo(
                status=ServiceStatus.ERROR,
                port=actual_port,
                container_id="",
                base_url=f"http://localhost:{actual_port}",
                startup_duration=time.time() - start_time,
                logs="",
                error_message=str(e)
            )

        return self.runtime_info

    def _create_service_container(self, image: str, port: int) -> docker.models.containers.Container:
        """创建服务容器"""
        try:
            network = self.image_manager.client.networks.get(self.network_name)
            logger.info(f"[ContainerRuntime] Using existing network: {self.network_name}")
        except docker.errors.NotFound:
            logger.info(f"[ContainerRuntime] Creating network: {self.network_name}")
            network = self.image_manager.client.networks.create(self.network_name, driver="bridge")

        container = self.image_manager.client.containers.run(
            image,
            command=" ".join(self.run_command),
            detach=True,
            mem_limit=self.memory_limit,
            cpu_period=100000,
            cpu_quota=int(self.cpu_limit * 100000),
            ports={f"{port}/tcp": ("127.0.0.1", port)},
            environment={
                "SERVER_PORT": str(port),
                "PORT": str(port),
                "SPRING_PROFILES_ACTIVE": "dev"
            },
            networks=[self.network_name],
            remove=False,
            name=self._container_name
        )

        return container

    def _get_mapped_port(self) -> int:
        """获取容器映射的实际端口"""
        if not self.container:
            return self.port

        try:
            container.reload()
            ports = container.ports
            if not ports:
                logger.warning("[ContainerRuntime] No ports mapped yet")
                return self.port
            for container_port, host_bindings in ports.items():
                if host_bindings and len(host_bindings) > 0:
                    try:
                        mapped_port = host_bindings[0].get("HostPort")
                        if mapped_port:
                            logger.info(f"[ContainerRuntime] Mapped port: {mapped_port}")
                            return int(mapped_port)
                    except (ValueError, TypeError, IndexError) as e:
                        logger.warning(f"[ContainerRuntime] Failed to parse mapped port: {e}")
                        continue
        except docker.errors.NotFound:
            logger.warning("[ContainerRuntime] Container not found during port mapping")
        except docker.errors.APIError as e:
            logger.warning(f"[ContainerRuntime] Docker API error during port mapping: {e}")
        except Exception as e:
            logger.warning(f"[ContainerRuntime] Failed to get mapped port: {e}")

        return self.port

    def _wait_for_ready(self, port: int) -> bool:
        """等待服务就绪"""
        end_time = time.time() + self.startup_timeout
        last_error = None

        logger.info(f"[ContainerRuntime] Waiting for service to be ready on port {port}...")

        while time.time() < end_time:
            if not self.container or self.container.status != "running":
                logger.warning(f"[ContainerRuntime] Container is not running")
                return False

            try:
                import requests
                response = requests.get(f"http://localhost:{port}/actuator/health", timeout=2)
                if response.status_code == 200:
                    logger.info(f"[ContainerRuntime] Service is ready (actuator)")
                    return True
            except:
                pass

            try:
                response = requests.get(f"http://localhost:{port}/health", timeout=2)
                if response.status_code == 200:
                    logger.info(f"[ContainerRuntime] Service is ready (health)")
                    return True
            except Exception as e:
                last_error = e

            try:
                response = requests.get(f"http://localhost:{port}/", timeout=2)
                if response.status_code in [200, 404, 403]:
                    logger.info(f"[ContainerRuntime] Service is ready (root)")
                    return True
            except Exception as e:
                last_error = e

            time.sleep(self.health_check_interval)

        logger.warning(f"[ContainerRuntime] Service did not become ready in time. Last error: {last_error}")
        return False

    def stop(self) -> bool:
        """停止服务容器"""
        logger.info("[ContainerRuntime] Stopping service...")

        if self.runtime_info:
            self.runtime_info.status = ServiceStatus.STOPPING

        success = True

        if self.container:
            container_id = self.container.id
            try:
                self.container.stop(timeout=10)
                logger.info("[ContainerRuntime] Service stopped gracefully")
            except docker.errors.NotFound:
                logger.warning("[ContainerRuntime] Container already removed")
            except docker.errors.APIError as e:
                if "already killing" in str(e).lower() or "already stopped" in str(e).lower():
                    logger.info("[ContainerRuntime] Container already in stopping state")
                else:
                    logger.warning(f"[ContainerRuntime] Docker API error during stop: {e}")
                    try:
                        self.container.kill()
                        logger.info("[ContainerRuntime] Service killed")
                    except docker.errors.NotFound:
                        logger.warning("[ContainerRuntime] Container not found during kill")
                    except docker.errors.APIError as kill_error:
                        logger.error(f"[ContainerRuntime] Error killing service: {kill_error}")
                        success = False
            except Exception as e:
                logger.warning(f"[ContainerRuntime] Unexpected error during stop: {e}")
                try:
                    self.container.kill()
                    logger.info("[ContainerRuntime] Service killed")
                except docker.errors.NotFound:
                    logger.warning("[ContainerRuntime] Container not found during kill")
                except docker.errors.APIError as kill_error:
                    logger.error(f"[ContainerRuntime] Error killing service: {kill_error}")
                    success = False
            finally:
                try:
                    if self.container:
                        self.container.remove(force=True)
                        logger.info(f"[ContainerRuntime] Removed container: {container_id[:12]}")
                except docker.errors.NotFound:
                    logger.info(f"[ContainerRuntime] Container already removed")
                except docker.errors.APIError as remove_error:
                    if "no such container" in str(remove_error).lower():
                        logger.info(f"[ContainerRuntime] Container already removed")
                    else:
                        logger.warning(f"[ContainerRuntime] Error removing container: {remove_error}")
                except Exception as remove_error:
                    logger.warning(f"[ContainerRuntime] Unexpected error removing container: {remove_error}")
                finally:
                    self.container = None

        if self.runtime_info:
            self.runtime_info.status = ServiceStatus.STOPPED

        return success

    def get_logs(self, tail: int = 100) -> str:
        """获取容器日志"""
        if self.container:
            try:
                return self.container.logs(stdout=True, stderr=True, tail=tail).decode("utf-8", errors="ignore")
            except Exception:
                return ""
        return ""

    def _find_available_port(self, start: int = 8000, end: int = 9000) -> int:
        """查找可用端口"""
        for port in range(start, end + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("localhost", port)) != 0:
                    logger.info(f"[ContainerRuntime] Found available port: {port}")
                    return port
        logger.warning(f"[ContainerRuntime] No available port found in range {start}-{end}, using {start}")
        return start

    def is_running(self) -> bool:
        """检查服务是否运行"""
        if not self.container:
            return False
        try:
            self.container.reload()
            return self.container.status == "running"
        except docker.errors.NotFound:
            logger.warning("[ContainerRuntime] Container not found during status check")
            return False
        except docker.errors.APIError as e:
            logger.warning(f"[ContainerRuntime] Docker API error during status check: {e}")
            return False
        except Exception as e:
            logger.warning(f"[ContainerRuntime] Unexpected error during status check: {e}")
            return False

    def get_status(self) -> ServiceStatus:
        """获取服务状态"""
        if self.runtime_info:
            return self.runtime_info.status
        if not self.container:
            return ServiceStatus.STOPPED
        try:
            self.container.reload()
            if self.container.status == "running":
                return ServiceStatus.RUNNING
            elif self.container.status == "exited":
                return ServiceStatus.STOPPED
            elif self.container.status in ["created", "restarting", "paused", "removing"]:
                return ServiceStatus.STOPPING
            else:
                return ServiceStatus.ERROR
        except docker.errors.NotFound:
            logger.warning("[ContainerRuntime] Container not found during status get")
            return ServiceStatus.STOPPED
        except docker.errors.APIError as e:
            logger.warning(f"[ContainerRuntime] Docker API error during status get: {e}")
            return ServiceStatus.ERROR
        except Exception as e:
            logger.warning(f"[ContainerRuntime] Unexpected error during status get: {e}")
            return ServiceStatus.ERROR

    def restart(self) -> RuntimeInfo:
        """重启服务"""
        logger.info("[ContainerRuntime] Restarting service...")
        self.stop()
        time.sleep(2)
        return self.start()

    def get_container_info(self) -> Optional[dict]:
        """获取容器信息"""
        if self.container:
            try:
                container_info = self.image_manager.client.containers.get(self.container.id)
                return {
                    "id": container_info.id,
                    "name": container_info.name,
                    "status": container_info.status,
                    "ports": container_info.ports,
                    "created": container_info.attrs.get("Created", ""),
                }
            except Exception as e:
                logger.error(f"[ContainerRuntime] Failed to get container info: {e}")
                return None
        return None
