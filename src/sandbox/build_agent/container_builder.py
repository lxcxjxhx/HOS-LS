"""
ContainerBuilder - 容器化构建执行器

在Docker容器中执行项目构建。
"""

import docker
import time
import logging
import uuid
import platform
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

from .image_manager import ImageManager
from .volume_manager import VolumeManager


logger = logging.getLogger(__name__)


class BuildStatus(Enum):
    """构建状态"""
    PENDING = "pending"
    BUILDING = "building"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class BuildResult:
    """构建结果"""
    status: BuildStatus
    message: str
    duration: float
    artifacts: List[str]
    logs: str


class ContainerBuilder:
    """容器化构建执行器"""

    def __init__(
        self,
        project_root: str,
        project_type: str,
        image_manager: Optional[ImageManager] = None,
        volume_manager: Optional[VolumeManager] = None,
        timeout: int = 600,
        memory_limit: str = "2g",
        cpu_limit: float = 2.0,
    ):
        self.project_root = project_root
        self.project_type = project_type
        self.image_manager = image_manager or ImageManager()
        self.volume_manager = volume_manager or VolumeManager()
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit

        self.container: Optional[docker.models.containers.Container] = None
        self.build_result: Optional[BuildResult] = None
        self.project_id: Optional[str] = None
        self._container_name: Optional[str] = None
        self._is_windows = platform.system().lower() == "windows"

    def _generate_container_name(self) -> str:
        """生成唯一的容器名称"""
        unique_id = uuid.uuid4().hex[:8]
        return f"hos-ls-build-{unique_id}"

    def build(self, build_command: List[str], version: Optional[str] = None) -> BuildResult:
        """在容器中执行构建"""
        start_time = time.time()
        self.project_id = f"build-{uuid.uuid4().hex[:12]}"
        self._container_name = self._generate_container_name()

        logger.info(f"[ContainerBuilder] Starting build for {self.project_type}")
        logger.info(f"[ContainerBuilder] Build command: {' '.join(build_command)}")

        image = self.image_manager.ensure_image(self.project_type, version)
        if not image:
            return BuildResult(
                status=BuildStatus.FAILED,
                message=f"Failed to get image for {self.project_type}",
                duration=0,
                artifacts=[],
                logs=""
            )

        logger.info(f"[ContainerBuilder] Using image: {image}")

        try:
            volume_mount = self.volume_manager.create_project_volume(
                project_id=self.project_id,
                project_path=self.project_root
            )

            self.container = self._create_container(image, volume_mount, build_command)
            self.container.start()

            logs = self._wait_for_completion()

            artifacts = self._find_artifacts(volume_mount.source)

            if self.build_result and self.build_result.status == BuildStatus.FAILED:
                return self.build_result

            self.build_result = BuildResult(
                status=BuildStatus.SUCCESS,
                message="Build completed successfully",
                duration=time.time() - start_time,
                artifacts=artifacts,
                logs=logs
            )

            logger.info(f"[ContainerBuilder] Build successful, {len(artifacts)} artifacts found")

        except Exception as e:
            logger.error(f"[ContainerBuilder] Build error: {e}")
            self.build_result = BuildResult(
                status=BuildStatus.FAILED,
                message=f"Build failed: {str(e)}",
                duration=time.time() - start_time,
                artifacts=[],
                logs=""
            )

        finally:
            self._cleanup_container()

        return self.build_result

    def _create_container(
        self,
        image: str,
        volume_mount,
        command: List[str]
    ) -> docker.models.containers.Container:
        """创建容器"""
        if self._is_windows:
            volumes = [f"{volume_mount.source}:{volume_mount.target}:rw"]
        else:
            volumes = [f"{volume_mount.source}:{volume_mount.target}:rw:z"]

        container = self.image_manager.client.containers.run(
            image,
            command=" ".join(command),
            detach=True,
            mem_limit=self.memory_limit,
            cpu_period=100000,
            cpu_quota=int(self.cpu_limit * 100000),
            volumes=volumes,
            working_dir=volume_mount.target,
            network_disabled=False,
            remove=False,
        )
        logger.info(f"[ContainerBuilder] Created container: {container.id[:12]}")
        return container

    def _wait_for_completion(self) -> str:
        """等待容器完成并返回日志"""
        timeout_seconds = self.timeout
        interval = 2

        start = time.time()
        while time.time() - start < timeout_seconds:
            if not self.container or self.container.status != "running":
                break
            time.sleep(interval)

        if not self.container:
            return ""

        try:
            result = self.container.wait(timeout=5)
            logs = self.container.logs(stdout=True, stderr=True).decode("utf-8", errors="ignore")

            if result["StatusCode"] != 0:
                logger.warning(f"[ContainerBuilder] Build exited with code {result['StatusCode']}")
                self.build_result = BuildResult(
                    status=BuildStatus.FAILED,
                    message=f"Build command exited with code {result['StatusCode']}",
                    duration=time.time() - start,
                    artifacts=[],
                    logs=logs
                )

            return logs

        except Exception as e:
            logger.error(f"[ContainerBuilder] Error waiting for container: {e}")
            return ""

    def _find_artifacts(self, base_path: str) -> List[str]:
        """查找构建产物"""
        artifacts = []
        search_paths = ["target", "build", "dist", "out", "bin"]

        logger.info(f"[ContainerBuilder] Searching for artifacts in: {base_path}")

        for search_path in search_paths:
            full_path = Path(base_path) / search_path
            if full_path.exists():
                logger.info(f"[ContainerBuilder] Found directory: {search_path}")

                if search_path == "target":
                    for jar in full_path.glob("*.jar"):
                        if not jar.name.endswith("-sources.jar") and not jar.name.endswith("-javadoc.jar"):
                            artifacts.append(str(jar))
                            logger.info(f"[ContainerBuilder] Found JAR: {jar.name}")

                elif search_path in ["build", "dist", "out", "bin"]:
                    for jar in full_path.rglob("*.jar"):
                        if not jar.name.endswith("-sources.jar") and not jar.name.endswith("-javadoc.jar"):
                            artifacts.append(str(jar))
                            logger.info(f"[ContainerBuilder] Found JAR: {jar.name}")

                    for war in full_path.rglob("*.war"):
                        artifacts.append(str(war))
                        logger.info(f"[ContainerBuilder] Found WAR: {war.name}")

        logger.info(f"[ContainerBuilder] Total artifacts found: {len(artifacts)}")
        return artifacts

    def _cleanup_container(self):
        """清理容器"""
        if self.container:
            try:
                if self.container.status == "running":
                    self.container.stop(timeout=5)
                self.container.remove(force=True)
                logger.info(f"[ContainerBuilder] Removed container: {self.container.id[:12]}")
            except Exception as e:
                logger.warning(f"[ContainerBuilder] Failed to remove container: {e}")
            self.container = None

    def cancel(self):
        """取消构建"""
        logger.info("[ContainerBuilder] Cancelling build...")
        if self.container:
            try:
                self.container.stop(timeout=5)
            except Exception:
                try:
                    self.container.kill()
                except Exception:
                    pass
            finally:
                self._cleanup_container()
                if self.build_result:
                    self.build_result.status = BuildStatus.CANCELLED

        if self.project_id:
            self.volume_manager.cleanup_project(self.project_id)

    def get_build_logs(self, tail: int = 500) -> str:
        """获取构建日志"""
        if self.container:
            try:
                return self.container.logs(stdout=True, stderr=True, tail=tail).decode("utf-8", errors="ignore")
            except Exception:
                return ""
        return ""

    def is_building(self) -> bool:
        """检查是否正在构建"""
        return self.container is not None and self.container.status == "running"
