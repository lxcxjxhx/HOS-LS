"""
沙盒项目构建Agent模块

提供自动化项目编译、运行和动态测试能力。
支持本地构建和容器化构建两种模式。
"""

from src.sandbox.build_agent.project_analyzer import ProjectAnalyzer, ProjectInfo, ProjectType
from src.sandbox.build_agent.build_executor import BuildExecutor, BuildResult
from src.sandbox.build_agent.runtime_manager import RuntimeManager, RuntimeInfo, ServiceStatus
from src.sandbox.build_agent.dynamic_tester import DynamicTester, DynamicTestReport, VulnerabilityTest
from src.sandbox.build_agent.agent_orchestrator import AgentOrchestrator, OrchestratorResult, OrchestratorStatus

from src.sandbox.build_agent.image_manager import ImageManager, RuntimeImage, RUNTIME_IMAGES
from src.sandbox.build_agent.volume_manager import VolumeManager, VolumeMount
from src.sandbox.build_agent.network_manager import NetworkManager
from src.sandbox.build_agent.container_builder import ContainerBuilder, BuildStatus
from src.sandbox.build_agent.container_runtime import ContainerRuntime
from src.sandbox.build_agent.containerized_build_agent import ContainerizedBuildAgent

__all__ = [
    "ProjectAnalyzer",
    "ProjectInfo",
    "ProjectType",
    "BuildExecutor",
    "BuildResult",
    "RuntimeManager",
    "RuntimeInfo",
    "ServiceStatus",
    "DynamicTester",
    "DynamicTestReport",
    "VulnerabilityTest",
    "AgentOrchestrator",
    "OrchestratorResult",
    "OrchestratorStatus",
    "ImageManager",
    "RuntimeImage",
    "RUNTIME_IMAGES",
    "VolumeManager",
    "VolumeMount",
    "NetworkManager",
    "ContainerBuilder",
    "BuildStatus",
    "ContainerRuntime",
    "ContainerizedBuildAgent",
]
