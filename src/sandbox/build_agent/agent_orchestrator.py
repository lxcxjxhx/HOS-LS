"""
AgentOrchestrator - Agent编排器

协调所有Agent执行完整的构建、运行、测试流程。
"""

import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from src.sandbox.build_agent.project_analyzer import ProjectAnalyzer, ProjectInfo, ProjectType
from src.sandbox.build_agent.build_executor import BuildExecutor, BuildResult
from src.sandbox.build_agent.runtime_manager import RuntimeManager, RuntimeInfo, ServiceStatus
from src.sandbox.build_agent.dynamic_tester import DynamicTester, DynamicTestReport, VulnerabilityTest


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
    test_report: Optional[DynamicTestReport]
    vulnerabilities: List[VulnerabilityTest]
    error_message: Optional[str]
    duration: float


class AgentOrchestrator:
    """Agent编排器

    协调ProjectAnalyzer、BuildExecutor、RuntimeManager、DynamicTester
    执行完整的构建-运行-测试流程。
    """

    def __init__(self, project_root: str, config: Optional[Dict] = None):
        """初始化编排器

        Args:
            project_root: 项目根目录
            config: 配置字典
        """
        self.project_root = project_root
        self.config = config or {}

        self.analyzer: Optional[ProjectAnalyzer] = None
        self.builder: Optional[BuildExecutor] = None
        self.runtime: Optional[RuntimeManager] = None
        self.tester: Optional[DynamicTester] = None

        self.status = OrchestratorStatus.IDLE
        self.result: Optional[OrchestratorResult] = None

    def run_full_pipeline(self) -> OrchestratorResult:
        """执行完整流程

        Returns:
            OrchestratorResult对象
        """
        start_time = time.time()
        error_message = None

        project_info = None
        build_result = None
        runtime_info = None
        test_report = None
        vulnerabilities = []

        try:
            print("\n" + "=" * 60)
            print("Agent Orchestrator - Starting Full Pipeline")
            print("=" * 60 + "\n")

            self.status = OrchestratorStatus.ANALYZING
            print("[1/4] Phase 1: Project Analysis")
            self.analyzer = ProjectAnalyzer(self.project_root)
            project_info = self.analyzer.analyze()

            if not self.analyzer.is_supported():
                error_message = f"Unsupported project type: {project_info.project_type.value}"
                self.status = OrchestratorStatus.ERROR
                return OrchestratorResult(
                    status=self.status,
                    project_info=project_info,
                    build_result=None,
                    runtime_info=None,
                    test_report=None,
                    vulnerabilities=[],
                    error_message=error_message,
                    duration=time.time() - start_time,
                )

            print(f"[1/4] Project type: {project_info.project_type.value}")
            print(f"[1/4] Build command: {' '.join(project_info.build_command)}")
            print(f"[1/4] Run command: {' '.join(project_info.run_command)}")

            self.status = OrchestratorStatus.BUILDING
            print("\n[2/4] Phase 2: Building Project")
            timeout = self.config.get("build_timeout", 300)
            self.builder = BuildExecutor(self.project_root, timeout=timeout)
            build_result = self.builder.build(project_info.build_command)

            if not build_result.success:
                error_message = f"Build failed: {build_result.message}"
                self.status = OrchestratorStatus.ERROR
                return OrchestratorResult(
                    status=self.status,
                    project_info=project_info,
                    build_result=build_result,
                    runtime_info=None,
                    test_report=None,
                    vulnerabilities=[],
                    error_message=error_message,
                    duration=time.time() - start_time,
                )

            print(f"[2/4] Build successful: {len(build_result.artifacts)} artifacts")

            self.status = OrchestratorStatus.RUNNING
            print("\n[3/4] Phase 3: Starting Service")
            startup_timeout = self.config.get("startup_timeout", 60)
            health_check_interval = self.config.get("health_check_interval", 2)
            self.runtime = RuntimeManager(
                self.project_root,
                project_info.run_command,
                port=project_info.port or 8080,
                startup_timeout=startup_timeout,
                health_check_interval=health_check_interval,
            )
            runtime_info = self.runtime.start()

            if runtime_info.status != ServiceStatus.RUNNING:
                error_message = f"Service failed to start: {runtime_info.error_message}"
                self.status = OrchestratorStatus.ERROR
                return OrchestratorResult(
                    status=self.status,
                    project_info=project_info,
                    build_result=build_result,
                    runtime_info=runtime_info,
                    test_report=None,
                    vulnerabilities=[],
                    error_message=error_message,
                    duration=time.time() - start_time,
                )

            print(f"[3/4] Service running at {runtime_info.base_url}")

            self.status = OrchestratorStatus.TESTING
            print("\n[4/4] Phase 4: Dynamic Testing")
            try:
                from src.sandbox.cve_database import CVEDatabase
                cve_db = CVEDatabase()
                cve_db.load(verbose=False)
                print(f"[4/4] CVE database loaded: {len(cve_db.cve_index)} CVEs")
            except Exception as e:
                print(f"[4/4] CVE database load failed: {e}, continuing without CVE data")
                cve_db = None

            self.tester = DynamicTester(runtime_info.base_url, cve_db=cve_db)
            endpoints = self.tester.discover_endpoints()
            print(f"[4/4] Discovered {len(endpoints)} endpoints")

            test_report = self.tester.run_full_test(endpoints)
            vulnerabilities = test_report.vulnerabilities

            self.status = OrchestratorStatus.COMPLETED

        except Exception as e:
            error_message = f"Pipeline error: {str(e)}"
            self.status = OrchestratorStatus.ERROR
            print(f"[ERROR] {error_message}")

        finally:
            if self.runtime and self.runtime.is_running():
                print("\n[Cleanup] Stopping service...")
                self.runtime.stop()

            if self.tester:
                self.tester.close()

        duration = time.time() - start_time
        self.result = OrchestratorResult(
            status=self.status,
            project_info=project_info,
            build_result=build_result,
            runtime_info=runtime_info,
            test_report=test_report,
            vulnerabilities=vulnerabilities,
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
        if test_report:
            print(f"Tests: {test_report.total_tests} total, {test_report.vulnerabilities_found} vulnerabilities")
        print("=" * 60 + "\n")

        return self.result

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

    def get_vulnerabilities(self) -> List[VulnerabilityTest]:
        """获取发现的漏洞"""
        if self.result:
            return self.result.vulnerabilities
        return []

    def stop(self):
        """停止流程"""
        if self.runtime and self.runtime.is_running():
            self.runtime.stop()
        if self.tester:
            self.tester.close()
        self.status = OrchestratorStatus.ERROR
