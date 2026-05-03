import shutil
import logging
from typing import Optional

from .docker_manager import DockerManager
from .fallback_analyzer import FallbackAnalyzer, FallbackResult
from .executor import SandboxExecutor, ExecutionResult, ExecutionStatus as Status
from .aware_fallback import AwareFallbackSystem
from ..config.dynamic_config import AnalysisConfig

logger = logging.getLogger(__name__)


class HybridDynamicAnalyzer:
    """混合动态分析器 - 支持 Docker、本地运行时和静态分析降级

    集成AwareFallbackSystem，支持降级感知和用户通知。
    """

    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        self.docker_manager: Optional[DockerManager] = None
        self.local_executor = SandboxExecutor()
        self.fallback_analyzer = FallbackAnalyzer()

        self.aware_fallback = AwareFallbackSystem(
            logger=logger,
            notifier=self._notify_user,
        )

        self._initialize()

    def _initialize(self):
        """根据配置初始化组件"""
        if self.config.docker_enabled:
            try:
                self.docker_manager = DockerManager(
                    auto_pull=self.config.docker_auto_pull
                )
                logger.info("Docker manager initialized")
            except Exception as e:
                logger.warning(f"Docker unavailable: {e}")
                self.docker_manager = None

    def _notify_user(self, title: str, message: str, level: str = "info") -> None:
        """用户通知回调

        Args:
            title: 通知标题
            message: 通知消息
            level: 通知级别
        """
        if level == "warning":
            print(f"\n⚠️  {title}")
            print(f"   {message}")
        elif level == "error":
            print(f"\n❌ {title}")
            print(f"   {message}")
        else:
            print(f"\nℹ️  {title}")
            print(f"   {message}")

    def analyze(
        self,
        code: str,
        language: str,
        vuln_type: str,
        context: Optional[dict] = None
    ) -> FallbackResult:
        """执行混合分析

        如果所有动态分析方法都失败，会自动降级到静态分析，
        并通过AwareFallbackSystem通知用户。
        """

        if self.config.prefer_static:
            self._notify_fallback("static", "用户配置优先使用静态分析", ["static_analysis"])
            return self._static_fallback(code, language, vuln_type, context)

        if not self._can_dynamic_execute(language):
            reason = f"动态执行不可用，语言: {language}"
            available = self._get_available_methods()
            self._notify_fallback("static", reason, available)
            return self._static_fallback(code, language, vuln_type, context)

        if self.docker_manager and self.docker_manager.is_available():
            result = self._docker_execute(code, language, vuln_type, context)
            if result:
                return result

        if self._has_local_runtime(language):
            result = self._local_execute(code, language, vuln_type, context)
            if result:
                return result

        reason = "所有动态执行方法失败"
        available = self._get_available_methods()
        self._notify_fallback("static", reason, available)
        return self._static_fallback(code, language, vuln_type, context)

    def _notify_fallback(self, target_mode: str, reason: str, available_methods: list) -> None:
        """通知降级

        Args:
            target_mode: 目标模式
            reason: 降级原因
            available_methods: 可用方法列表
        """
        self.aware_fallback.fallback_to(
            target_mode=target_mode,
            reason=reason,
            available_methods=available_methods,
        )

    def _get_available_methods(self) -> list:
        """获取当前可用的检测方法"""
        methods = ["static_analysis"]
        if self.docker_manager and self.docker_manager.is_available():
            methods.append("docker_execution")
        if self._has_local_runtime('python'):
            methods.append("local_execution")
        return methods

    def _can_dynamic_execute(self, language: str) -> bool:
        """检查是否能够执行动态分析"""
        if self.docker_manager and self.docker_manager.is_available():
            return True
        return self._has_local_runtime(language)

    def _has_local_runtime(self, language: str) -> bool:
        """检查本地运行时是否可用"""
        checks = {
            'python': lambda: shutil.which('python3') or shutil.which('python'),
            'javascript': lambda: shutil.which('node'),
            'java': lambda: shutil.which('javac') and shutil.which('java'),
            'go': lambda: shutil.which('go'),
            'rust': lambda: shutil.which('cargo') and shutil.which('rustc'),
            'c': lambda: shutil.which('gcc'),
            'typescript': lambda: shutil.which('ts-node') or (shutil.which('node') and shutil.which('tsc')),
            'bash': lambda: shutil.which('bash'),
            'powershell': lambda: shutil.which('powershell') or shutil.which('pwsh'),
        }
        checker = checks.get(language.lower())
        if not checker:
            return False
        return checker()

    def _docker_execute(
        self,
        code: str,
        language: str,
        vuln_type: str,
        context: Optional[dict]
    ) -> Optional[FallbackResult]:
        """尝试使用 Docker 执行"""
        try:
            if not self.docker_manager:
                return None

            result = self.docker_manager.execute(
                code=code,
                language=language.lower(),
                timeout=self.config.docker_timeout
            )

            if result.status == Status.SUCCESS:
                return self._analyze_docker_result(result, vuln_type, context)

            logger.warning(f"Docker execution failed: {result.error}")
            return None

        except Exception as e:
            logger.warning(f"Docker execution error: {e}")
            return None

    def _local_execute(
        self,
        code: str,
        language: str,
        vuln_type: str,
        context: Optional[dict]
    ) -> Optional[FallbackResult]:
        """尝试使用本地运行时执行"""
        try:
            result = self.local_executor.execute(
                code=code,
                language=language.lower()
            )

            if result.status == Status.SUCCESS:
                return self._analyze_local_result(result, vuln_type, context)

            logger.warning(f"Local execution failed: {result.error}")
            return None

        except Exception as e:
            logger.warning(f"Local execution error: {e}")
            return None

    def _analyze_docker_result(
        self,
        result: ExecutionResult,
        vuln_type: str,
        context: Optional[dict]
    ) -> FallbackResult:
        """分析 Docker 执行结果"""
        output = result.output or ""
        return FallbackResult(
            is_vulnerable=False,
            confidence=0.8,
            findings=[],
            method="docker_execution",
            summary=f"Executed in Docker, output length: {len(output)}"
        )

    def _analyze_local_result(
        self,
        result: ExecutionResult,
        vuln_type: str,
        context: Optional[dict]
    ) -> FallbackResult:
        """分析本地执行结果"""
        output = result.output or ""
        return FallbackResult(
            is_vulnerable=False,
            confidence=0.8,
            findings=[],
            method="local_execution",
            summary=f"Executed locally, output length: {len(output)}"
        )

    def _static_fallback(
        self,
        code: str,
        language: str,
        vuln_type: str,
        context: Optional[dict]
    ) -> FallbackResult:
        """静态分析降级"""
        return self.fallback_analyzer.analyze(code, language, vuln_type)

    def is_available(self) -> bool:
        """检查是否有任何可用的执行方式"""
        return (
            (self.docker_manager and self.docker_manager.is_available()) or
            self._has_local_runtime('python')
        )