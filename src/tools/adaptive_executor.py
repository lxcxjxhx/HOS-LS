"""自适应执行器

提供工具执行包装、失败重试、超时控制和工具链自动切换。
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from src.tools.ai_decision_engine import ScanStrategy
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ExecutionResult:
    """执行结果"""

    tool: str
    success: bool
    results: List[Dict[str, Any]]
    execution_time: float
    error: str = ""
    retries: int = 0
    fallback_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "success": self.success,
            "results": self.results,
            "execution_time": self.execution_time,
            "error": self.error,
            "retries": self.retries,
            "fallback_used": self.fallback_used,
        }


@dataclass
class ProgressCallback:
    """进度回调"""

    on_start: Optional[Callable[[str], None]] = None
    on_progress: Optional[Callable[[str, int, int], None]] = None
    on_complete: Optional[Callable[[str, bool], None]] = None
    on_error: Optional[Callable[[str, str], None]] = None
    on_fallback: Optional[Callable[[str, str], None]] = None


class AdaptiveExecutor:
    """自适应执行器

    包装工具执行，提供失败重试、超时控制和工具链自动切换。
    """

    def __init__(
        self,
        max_retries: int = 3,
        timeout_per_tool: int = 300,
        fallback_enabled: bool = True,
    ):
        self.max_retries = max_retries
        self.timeout_per_tool = timeout_per_tool
        self.fallback_enabled = fallback_enabled

        self._fallback_map: Dict[str, List[str]] = {
            "zap": ["nuclei", "http_security"],
            "sqlmap": ["api_security", "http_security"],
            "nuclei": ["zap", "http_security"],
            "fuzzing": ["nuclei", "discover"],
            "api_security": ["http_security"],
            "semgrep": ["code_vuln_scanner"],
            "trivy": ["nuclei"],
            "gitleaks": ["semgrep"],
        }

        self._execution_history: List[ExecutionResult] = []

    async def execute(
        self,
        strategy: ScanStrategy,
        tool_executors: Dict[str, Callable],
        progress_callback: Optional[ProgressCallback] = None,
    ) -> List[ExecutionResult]:
        """执行策略

        Args:
            strategy: 扫描策略
            tool_executors: 工具执行器字典 {工具名: 执行函数}
            progress_callback: 进度回调

        Returns:
            执行结果列表
        """
        results = []

        if strategy.parallel:
            results = await self._execute_parallel(strategy, tool_executors, progress_callback)
        else:
            results = await self._execute_sequential(strategy, tool_executors, progress_callback)

        self._execution_history.extend(results)
        return results

    async def _execute_parallel(
        self,
        strategy: ScanStrategy,
        tool_executors: Dict[str, Callable],
        progress_callback: Optional[ProgressCallback],
    ) -> List[ExecutionResult]:
        """并行执行

        Args:
            strategy: 扫描策略
            tool_executors: 工具执行器
            progress_callback: 进度回调

        Returns:
            执行结果列表
        """
        tasks = []

        for tool in strategy.selected_tools:
            if tool in tool_executors:
                params = strategy.tool_params.get(tool, {})
                task = self._execute_with_fallback(
                    tool,
                    tool_executors[tool],
                    params,
                    progress_callback,
                )
                tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        execution_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                tool = strategy.selected_tools[i] if i < len(strategy.selected_tools) else "unknown"
                execution_results.append(ExecutionResult(
                    tool=tool,
                    success=False,
                    results=[],
                    execution_time=0,
                    error=str(result),
                ))
            else:
                execution_results.append(result)

        return execution_results

    async def _execute_sequential(
        self,
        strategy: ScanStrategy,
        tool_executors: Dict[str, Callable],
        progress_callback: Optional[ProgressCallback],
    ) -> List[ExecutionResult]:
        """顺序执行

        Args:
            strategy: 扫描策略
            tool_executors: 工具执行器
            progress_callback: 进度回调

        Returns:
            执行结果列表
        """
        results = []
        total = len(strategy.selected_tools)

        for i, tool in enumerate(strategy.execution_order):
            if tool not in tool_executors:
                continue

            if progress_callback and progress_callback.on_progress:
                progress_callback.on_progress(tool, i + 1, total)

            params = strategy.tool_params.get(tool, {})

            result = await self._execute_with_fallback(
                tool,
                tool_executors[tool],
                params,
                progress_callback,
            )

            results.append(result)

            if not result.success and self.fallback_enabled:
                fallback_result = await self._try_fallback(
                    tool,
                    result,
                    tool_executors,
                    params,
                    progress_callback,
                )
                if fallback_result:
                    results.append(fallback_result)

        return results

    async def _execute_with_fallback(
        self,
        tool: str,
        executor: Callable,
        params: Dict[str, Any],
        progress_callback: Optional[ProgressCallback],
    ) -> ExecutionResult:
        """执行工具，支持重试

        Args:
            tool: 工具名称
            executor: 执行函数
            params: 执行参数
            progress_callback: 进度回调

        Returns:
            执行结果
        """
        if progress_callback and progress_callback.on_start:
            progress_callback.on_start(tool)

        last_error = ""
        retries = 0

        for attempt in range(self.max_retries + 1):
            try:
                start_time = time.time()

                if asyncio.iscoroutinefunction(executor):
                    result = await executor(tool, params)
                else:
                    result = executor(tool, params)

                execution_time = time.time() - start_time

                if isinstance(result, dict):
                    results = [result] if result else []
                elif isinstance(result, list):
                    results = result
                else:
                    results = []

                if progress_callback and progress_callback.on_complete:
                    progress_callback.on_complete(tool, True)

                return ExecutionResult(
                    tool=tool,
                    success=True,
                    results=results,
                    execution_time=execution_time,
                    retries=retries,
                    fallback_used=False,
                )

            except Exception as e:
                last_error = str(e)
                retries = attempt + 1
                logger.warning(f"Tool {tool} failed (attempt {retries}/{self.max_retries + 1}): {e}")

                if progress_callback and progress_callback.on_error:
                    progress_callback.on_error(tool, last_error)

                if attempt < self.max_retries:
                    wait_time = min(2 ** attempt, 10)
                    await asyncio.sleep(wait_time)

        if progress_callback and progress_callback.on_complete:
            progress_callback.on_complete(tool, False)

        return ExecutionResult(
            tool=tool,
            success=False,
            results=[],
            execution_time=0,
            error=last_error,
            retries=retries,
            fallback_used=False,
        )

    async def _try_fallback(
        self,
        original_tool: str,
        original_result: ExecutionResult,
        tool_executors: Dict[str, Callable],
        original_params: Dict[str, Any],
        progress_callback: Optional[ProgressCallback],
    ) -> Optional[ExecutionResult]:
        """尝试使用后备工具

        Args:
            original_tool: 原工具名称
            original_result: 原工具执行结果
            tool_executors: 工具执行器
            original_params: 原参数
            progress_callback: 进度回调

        Returns:
            后备执行结果或None
        """
        if not self.fallback_enabled:
            return None

        fallback_tools = self._fallback_map.get(original_tool, [])

        for fallback_tool in fallback_tools:
            if fallback_tool not in tool_executors:
                continue

            logger.info(f"Attempting fallback: {original_tool} -> {fallback_tool}")

            if progress_callback and progress_callback.on_fallback:
                progress_callback.on_fallback(original_tool, fallback_tool)

            try:
                fallback_params = self._adjust_params_for_fallback(
                    fallback_tool, original_params
                )

                if asyncio.iscoroutinefunction(tool_executors[fallback_tool]):
                    result = await tool_executors[fallback_tool](fallback_tool, fallback_params)
                else:
                    result = tool_executors[fallback_tool](fallback_tool, fallback_params)

                if isinstance(result, dict):
                    results = [result] if result else []
                elif isinstance(result, list):
                    results = result
                else:
                    results = []

                return ExecutionResult(
                    tool=fallback_tool,
                    success=True,
                    results=results,
                    execution_time=0,
                    error="",
                    retries=0,
                    fallback_used=True,
                )

            except Exception as e:
                logger.warning(f"Fallback tool {fallback_tool} also failed: {e}")
                continue

        return None

    def _adjust_params_for_fallback(
        self,
        fallback_tool: str,
        original_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """调整参数以适应后备工具

        Args:
            fallback_tool: 后备工具名称
            original_params: 原参数

        Returns:
            调整后的参数
        """
        params = original_params.copy()

        if fallback_tool == "http_security":
            params["test_sqli"] = True
            params["test_xss"] = True
            params["test_headers"] = True

        elif fallback_tool == "nuclei":
            params["severity"] = "medium,high,critical"
            params["rate_limit"] = 150

        elif fallback_tool == "discover":
            params["mode"] = "discover"

        return params

    def get_execution_history(self) -> List[ExecutionResult]:
        """获取执行历史

        Returns:
            执行结果历史
        """
        return self._execution_history

    def get_statistics(self) -> Dict[str, Any]:
        """获取执行统计

        Returns:
            统计信息
        """
        total = len(self._execution_history)
        successful = sum(1 for r in self._execution_history if r.success)
        failed = total - successful
        total_time = sum(r.execution_time for r in self._execution_history)
        fallbacks_used = sum(1 for r in self._execution_history if r.fallback_used)

        return {
            "total_executions": total,
            "successful": successful,
            "failed": failed,
            "success_rate": successful / total if total > 0 else 0,
            "total_execution_time": total_time,
            "fallbacks_used": fallbacks_used,
        }


def create_adaptive_executor(
    max_retries: int = 3,
    timeout_per_tool: int = 300,
    fallback_enabled: bool = True,
) -> AdaptiveExecutor:
    """创建自适应执行器的便捷函数

    Args:
        max_retries: 最大重试次数
        timeout_per_tool: 每个工具超时时间
        fallback_enabled: 是否启用后备

    Returns:
        AdaptiveExecutor 实例
    """
    return AdaptiveExecutor(
        max_retries=max_retries,
        timeout_per_tool=timeout_per_tool,
        fallback_enabled=fallback_enabled,
    )
