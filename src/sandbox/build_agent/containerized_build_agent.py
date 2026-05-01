"""
ContainerizedBuildAgent - 容器化构建Agent编排器

协调所有组件执行完整的容器化构建、运行、测试流程。
"""

import time
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

from .project_analyzer import ProjectAnalyzer, ProjectInfo, ProjectType
from .container_builder import ContainerBuilder, BuildResult, BuildStatus
from .container_runtime import ContainerRuntime, RuntimeInfo, ServiceStatus
from .image_manager import ImageManager
from .volume_manager import VolumeManager
from .network_manager import NetworkManager


logger = logging.getLogger(__name__)


class OrchestratorStatus(Enum):
    """编排器状态"""
    IDLE = "idle"
    ANALYZING = "analyzing"
    BUILDING = "building"
    RUNNING = "running"
    TESTING = "testing"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class OrchestratorResult:
    """编排结果"""
    status: OrchestratorStatus
    project_info: Optional[ProjectInfo]
    build_result: Optional[BuildResult]
    runtime_info: Optional[RuntimeInfo]
    error_message: Optional[str]
    duration: float


class ContainerizedBuildAgent:
    """容器化构建Agent编排器

    协调ImageManager、ContainerBuilder、ContainerRuntime执行
    完整的容器化构建-运行-测试流程。
    """

    def __init__(
        self,
        project_root: str,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.project_root = project_root
        self.config = config or {}

        self.image_manager = ImageManager(
            auto_pull=self.config.get("auto_pull_images", True)
        )
        self.volume_manager = VolumeManager()
        self.network_manager = NetworkManager(
            network_name=self.config.get("network_name", "hos-ls-network")
        )

        self.analyzer: Optional[ProjectAnalyzer] = None
        self.builder: Optional[ContainerBuilder] = None
        self.runtime: Optional[ContainerRuntime] = None

        self.status = OrchestratorStatus.IDLE
        self.result: Optional[OrchestratorResult] = None

    def is_docker_available(self) -> bool:
        """检查Docker是否可用"""
        return self.image_manager.is_available()

    def run_full_pipeline(
        self,
        skip_build: bool = False,
        skip_runtime: bool = False,
    ) -> OrchestratorResult:
        """执行完整流程

        Args:
            skip_build: 跳过构建阶段
            skip_runtime: 跳过运行时阶段

        Returns:
            OrchestratorResult对象
        """
        start_time = time.time()
        error_message = None

        project_info = None
        build_result = None
        runtime_info = None

        try:
            print("\n" + "=" * 60)
            print("ContainerizedBuildAgent - Starting Full Pipeline")
            print("=" * 60 + "\n")

            if not self.is_docker_available():
                error_message = "Docker is not available. Please ensure Docker is installed and running."
                self.status = OrchestratorStatus.ERROR
                return OrchestratorResult(
                    status=self.status,
                    project_info=None,
                    build_result=None,
                    runtime_info=None,
                    error_message=error_message,
                    duration=time.time() - start_time,
                )

            self.status = OrchestratorStatus.ANALYZING
            print("[1/4] Phase 1: Project Analysis")
            project_info = self._analyze_project()

            if not project_info or project_info.project_type == ProjectType.UNKNOWN:
                error_message = f"Unsupported project type: {project_info.project_type if project_info else 'UNKNOWN'}"
                self.status = OrchestratorStatus.ERROR
                return OrchestratorResult(
                    status=self.status,
                    project_info=project_info,
                    build_result=None,
                    runtime_info=None,
                    error_message=error_message,
                    duration=time.time() - start_time,
                )

            print(f"[1/4] Project type: {project_info.project_type.value}")
            print(f"[1/4] Build command: {' '.join(project_info.build_command)}")
            print(f"[1/4] Run command: {' '.join(project_info.run_command)}")

            if not skip_build:
                self.status = OrchestratorStatus.BUILDING
                print("\n[2/4] Phase 2: Building Project (Containerized)")
                build_result = self._build_project(project_info)

                if not build_result or build_result.status != BuildStatus.SUCCESS:
                    error_message = f"Build failed: {build_result.message if build_result else 'Unknown error'}"
                    self.status = OrchestratorStatus.ERROR
                    return OrchestratorResult(
                        status=self.status,
                        project_info=project_info,
                        build_result=build_result,
                        runtime_info=None,
                        error_message=error_message,
                        duration=time.time() - start_time,
                    )

                print(f"[2/4] Build successful: {len(build_result.artifacts)} artifacts")
            else:
                print("\n[2/4] Phase 2: Build skipped")

            if not skip_runtime:
                self.status = OrchestratorStatus.RUNNING
                print("\n[3/4] Phase 3: Starting Service (Containerized)")
                runtime_info = self._start_runtime(project_info)

                if not runtime_info or runtime_info.status != ServiceStatus.RUNNING:
                    error_message = f"Runtime start failed: {runtime_info.error_message if runtime_info else 'Unknown error'}"
                    self.status = OrchestratorStatus.ERROR
                    return OrchestratorResult(
                        status=self.status,
                        project_info=project_info,
                        build_result=build_result,
                        runtime_info=runtime_info,
                        error_message=error_message,
                        duration=time.time() - start_time,
                    )

                print(f"[3/4] Service running at {runtime_info.base_url}")
            else:
                print("\n[3/4] Phase 3: Runtime skipped")

            self.status = OrchestratorStatus.COMPLETED

        except Exception as e:
            error_message = f"Pipeline error: {str(e)}"
            self.status = OrchestratorStatus.ERROR
            logger.error(f"[ERROR] {error_message}")

        finally:
            self._cleanup()

        duration = time.time() - start_time
        self.result = OrchestratorResult(
            status=self.status,
            project_info=project_info,
            build_result=build_result,
            runtime_info=runtime_info,
            error_message=error_message,
            duration=duration,
        )

        print("\n" + "=" * 60)
        print("Pipeline Summary")
        print("=" * 60)
        print(f"Status: {self.status.value}")
        print(f"Duration: {duration:.2f}s")
        if project_info:
            print(f"Project Type: {project_info.project_type.value}")
        if build_result:
            print(f"Build: {'SUCCESS' if build_result.success else 'FAILED'}")
        if runtime_info:
            print(f"Runtime: {runtime_info.status.value} at {runtime_info.base_url}")
        print("=" * 60 + "\n")

        return self.result

    def _analyze_project(self) -> ProjectInfo:
        """分析项目"""
        self.analyzer = ProjectAnalyzer(self.project_root)
        return self.analyzer.analyze()

    def _build_project(self, project_info: ProjectInfo) -> BuildResult:
        """构建项目"""
        self.builder = ContainerBuilder(
            project_root=self.project_root,
            project_type=project_info.project_type.value,
            image_manager=self.image_manager,
            volume_manager=self.volume_manager,
            timeout=self.config.get("build_timeout", 600),
            memory_limit=self.config.get("build_memory_limit", "2g"),
            cpu_limit=self.config.get("build_cpu_limit", 2.0),
        )
        return self.builder.build(
            build_command=project_info.build_command,
            version=getattr(project_info, 'version', None)
        )

    def _start_runtime(self, project_info: ProjectInfo) -> RuntimeInfo:
        """启动运行时"""
        self.runtime = ContainerRuntime(
            project_root=self.project_root,
            project_type=project_info.project_type.value,
            run_command=project_info.run_command,
            port=project_info.port or 8080,
            image_manager=self.image_manager,
            startup_timeout=self.config.get("startup_timeout", 60),
            memory_limit=self.config.get("runtime_memory_limit", "1g"),
            cpu_limit=self.config.get("runtime_cpu_limit", 1.0),
            network_name=self.config.get("network_name", "hos-ls-network"),
        )
        return self.runtime.start()

    def _cleanup(self):
        """清理资源"""
        if self.runtime:
            print("\n[Cleanup] Stopping runtime container...")
            self.runtime.stop()

        if self.builder:
            print("[Cleanup] Cleaning up build container...")
            self.builder.cancel()

        print("[Cleanup] Cleaning up volumes...")
        self.volume_manager.cleanup_all()

    def get_status(self) -> OrchestratorStatus:
        """获取状态"""
        return self.status

    def is_running(self) -> bool:
        """检查是否在运行"""
        return self.status in [
            OrchestratorStatus.ANALYZING,
            OrchestratorStatus.BUILDING,
            OrchestratorStatus.RUNNING,
            OrchestratorStatus.TESTING,
        ]

    def stop(self):
        """停止流程"""
        self._cleanup()
        self.status = OrchestratorStatus.ERROR

    def get_build_result(self) -> Optional[BuildResult]:
        """获取构建结果"""
        return self.builder.build_result if self.builder else None

    def get_runtime_info(self) -> Optional[RuntimeInfo]:
        """获取运行时信息"""
        return self.runtime.runtime_info if self.runtime else None

    def get_project_info(self) -> Optional[ProjectInfo]:
        """获取项目信息"""
        return self.analyzer.project_info if self.analyzer else None
