"""AI 自适应工具调度器

整合目标分析、策略规划、结果分析和自适应执行，实现智能扫描。
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from src.tools.ai_decision_engine import (
    AIDecisionEngine,
    TargetProfile,
    ScanStrategy,
    AnalysisReport,
    LLMProvider,
)
from src.tools.target_analyzer import TargetAnalyzer
from src.tools.strategy_planner import StrategyPlanner
from src.tools.result_analyzer import ResultAnalyzer, AnalysisReport as ReportType
from src.tools.adaptive_executor import AdaptiveExecutor, ExecutionResult, ProgressCallback
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScanReport:
    """扫描报告"""

    target_url: str
    target_profile: TargetProfile
    scan_strategy: ScanStrategy
    execution_results: List[ExecutionResult]
    analysis_report: AnalysisReport
    total_time: float
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_profile": self.target_profile.to_dict(),
            "scan_strategy": self.scan_strategy.to_dict(),
            "execution_results": [r.to_dict() for r in self.execution_results],
            "analysis_report": self.analysis_report.to_dict(),
            "total_time": self.total_time,
            "timestamp": self.timestamp,
        }


class AIToolOrchestrator:
    """AI 自适应工具调度器

    整合目标分析、策略规划和自适应执行，实现智能扫描。
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        llm_provider: Optional[LLMProvider] = None,
        api_key: Optional[str] = None,
    ):
        """初始化 AI 工具调度器

        Args:
            config: 配置字典
            llm_provider: LLM提供商
            api_key: API密钥
        """
        self.config = config or {}

        self.ai_decision_engine = AIDecisionEngine(
            llm_provider=llm_provider or LLMProvider.DEEPSEEK,
            api_key=api_key,
        )

        self.target_analyzer = TargetAnalyzer(
            timeout=self.config.get("fingerprint_timeout", 30)
        )

        self.strategy_planner = StrategyPlanner()

        self.result_analyzer = ResultAnalyzer(
            confidence_threshold=self.config.get("confidence_threshold", 0.7),
            ai_verification_enabled=self.config.get("verify_with_ai", True),
        )

        self.adaptive_executor = AdaptiveExecutor(
            max_retries=self.config.get("max_retries", 3),
            timeout_per_tool=self.config.get("timeout_per_tool", 300),
            fallback_enabled=self.config.get("fallback_on_failure", True),
        )

        self._tool_executors: Dict[str, Callable] = {}

        self._register_default_executors()

    def _register_default_executors(self) -> None:
        """注册默认工具执行器"""
        from src.tools.orchestrator import ToolOrchestrator

        orchestrator = ToolOrchestrator()

        self._tool_executors["semgrep"] = self._wrap_orchestrator(orchestrator._run_semgrep)
        self._tool_executors["trivy"] = self._wrap_orchestrator(orchestrator._run_trivy)
        self._tool_executors["gitleaks"] = self._wrap_orchestrator(orchestrator._run_gitleaks)
        self._tool_executors["code_vuln_scanner"] = self._wrap_orchestrator(orchestrator._run_code_vuln_scanner)
        self._tool_executors["zap"] = self._wrap_orchestrator(orchestrator._run_zap)
        self._tool_executors["http_security"] = self._wrap_orchestrator(orchestrator._run_http_security)
        self._tool_executors["api_security"] = self._wrap_orchestrator(orchestrator._run_api_security)
        self._tool_executors["fuzzing"] = self._wrap_orchestrator(orchestrator._run_fuzzing)

    def _wrap_orchestrator(self, method: Callable) -> Callable:
        """包装 orchestrator 方法

        Args:
            method: orchestrator 方法

        Returns:
            包装后的方法
        """
        def wrapped(tool: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
            try:
                result = method(params.get("target", ""))
                return result if isinstance(result, list) else []
            except Exception as e:
                logger.error(f"Tool {tool} execution error: {e}")
                return []

        return wrapped

    def register_executor(self, tool_name: str, executor: Callable) -> None:
        """注册工具执行器

        Args:
            tool_name: 工具名称
            executor: 执行函数
        """
        self._tool_executors[tool_name] = executor

    async def adaptive_scan(
        self,
        target: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> ScanReport:
        """自适应扫描

        AI 自动分析目标并选择最优工具组合。

        Args:
            target: 目标 URL
            progress_callback: 进度回调

        Returns:
            扫描报告
        """
        start_time = time.time()

        print(f"\n{'='*60}")
        print(f"AI 自适应扫描: {target}")
        print(f"{'='*60}\n")

        target_profile = await self._analyze_target(target)
        print(f"[*] 目标分析完成: {target_profile.type}")
        print(f"    技术栈: {', '.join(target_profile.fingerprint.get('technologies', [])[:3])}")

        strategy = self._plan_strategy(target_profile)
        print(f"[*] 策略规划完成")
        print(f"    选择工具: {', '.join(strategy.selected_tools)}")

        execution_results = await self._execute_strategy(strategy, progress_callback)

        all_results = []
        for result in execution_results:
            all_results.extend(result.results)

        analysis = self._analyze_results(all_results, target, target_profile)

        total_time = time.time() - start_time

        print(f"\n{'='*60}")
        print(f"扫描完成: {target}")
        print(f"总耗时: {total_time:.2f} 秒")
        print(f"发现漏洞: {len(all_results)} 个")
        print(f"高置信度: {len(analysis.high_confidence_findings)} 个")
        print(f"{'='*60}\n")

        return ScanReport(
            target_url=target,
            target_profile=target_profile,
            scan_strategy=strategy,
            execution_results=execution_results,
            analysis_report=analysis,
            total_time=total_time,
        )

    async def _analyze_target(self, target: str) -> TargetProfile:
        """分析目标

        Args:
            target: 目标 URL

        Returns:
            目标画像
        """
        local_analyzer = TargetAnalyzer(timeout=30)
        profile = local_analyzer.analyze(target)
        local_analyzer.close()

        if self.ai_decision_engine.is_available():
            try:
                ai_profile = await self.ai_decision_engine.analyze_target(
                    target_url=target,
                    headers=profile.fingerprint.get("headers"),
                    fingerprint=profile.fingerprint,
                )

                if ai_profile.confidence > profile.confidence:
                    return ai_profile

            except Exception as e:
                logger.warning(f"AI target analysis failed, using local: {e}")

        return profile

    def _plan_strategy(self, target: TargetProfile) -> ScanStrategy:
        """规划策略

        Args:
            target: 目标画像

        Returns:
            扫描策略
        """
        timeout = self.config.get("timeout", 300)
        parallel = self.config.get("parallel_execution", True)

        strategy = self.strategy_planner.plan(
            target=target,
            timeout=timeout,
            parallel=parallel,
            prefer_fast=self.config.get("prefer_fast", False),
        )

        if self.ai_decision_engine.is_available():
            try:
                ai_strategy = asyncio.run(
                    self.ai_decision_engine.plan_strategy(
                        target=target,
                        available_tools=strategy.selected_tools,
                        timeout=timeout,
                        parallel=parallel,
                    )
                )

                if ai_strategy.confidence > strategy.confidence:
                    return ai_strategy

            except Exception as e:
                logger.warning(f"AI strategy planning failed, using local: {e}")

        return strategy

    async def _execute_strategy(
        self,
        strategy: ScanStrategy,
        progress_callback: Optional[ProgressCallback],
    ) -> List[ExecutionResult]:
        """执行策略

        Args:
            strategy: 扫描策略
            progress_callback: 进度回调

        Returns:
            执行结果列表
        """
        return await self.adaptive_executor.execute(
            strategy=strategy,
            tool_executors=self._tool_executors,
            progress_callback=progress_callback,
        )

    def _analyze_results(
        self,
        results: List[Dict[str, Any]],
        target: str,
        target_profile: TargetProfile,
    ) -> AnalysisReport:
        """分析结果

        Args:
            results: 扫描结果
            target: 目标 URL
            target_profile: 目标画像

        Returns:
            分析报告
        """
        analysis = self.result_analyzer.analyze(results, target)

        if self.ai_decision_engine.is_available() and self.config.get("verify_with_ai", True):
            try:
                ai_analysis = asyncio.run(
                    self.ai_decision_engine.analyze_results(
                        results=results,
                        target_url=target,
                        target_type=target_profile.type,
                        fingerprint=target_profile.fingerprint,
                    )
                )

                if ai_analysis.confidence > analysis.confidence:
                    return ai_analysis

            except Exception as e:
                logger.warning(f"AI result analysis failed, using local: {e}")

        return analysis

    def get_available_tools(self) -> List[str]:
        """获取可用工具列表

        Returns:
            可用工具名称列表
        """
        return list(self._tool_executors.keys())

    def get_statistics(self) -> Dict[str, Any]:
        """获取执行统计

        Returns:
            统计信息
        """
        return {
            "ai_decision_engine": self.ai_decision_engine.get_tool_info(),
            "adaptive_executor": self.adaptive_executor.get_statistics(),
            "available_tools": self.get_available_tools(),
        }


def create_ai_tool_orchestrator(
    config: Optional[Dict[str, Any]] = None,
) -> AIToolOrchestrator:
    """创建 AI 工具调度器的便捷函数

    Args:
        config: 配置字典

    Returns:
        AIToolOrchestrator 实例
    """
    return AIToolOrchestrator(config=config)
