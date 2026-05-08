"""扫描流水线并行优化器

优化扫描流水线的并行处理，提高扫描效率。
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, TypeVar
from functools import wraps
import logging

from src.utils.logger import get_logger

logger = get_logger(__name__)

T = TypeVar('T')


@dataclass
class PipelineStage:
    """流水线阶段"""
    name: str
    process_func: Callable
    estimated_time: float = 0.0
    actual_time: float = 0.0
    dependencies: List[str] = field(default_factory=list)


class ParallelScanOptimizer:
    """扫描流水线并行优化器

    优化扫描流水线的并行处理：
    - 自动识别可并行的阶段
    - 动态调整并发数
    - 瓶颈阶段检测
    - 资源使用优化
    """

    def __init__(self, max_workers: int = 4, enable_profiling: bool = False):
        """初始化并行优化器

        Args:
            max_workers: 最大工作线程数
            enable_profiling: 是否启用性能分析
        """
        self.max_workers = max_workers
        self.enable_profiling = enable_profiling
        self.stages: Dict[str, PipelineStage] = {}
        self.stage_times: Dict[str, List[float]] = {}
        self._executor: Optional[ThreadPoolExecutor] = None

    def add_stage(self, name: str, process_func: Callable, dependencies: List[str] = None) -> None:
        """添加流水线阶段

        Args:
            name: 阶段名称
            process_func: 处理函数
            dependencies: 依赖阶段列表
        """
        self.stages[name] = PipelineStage(
            name=name,
            process_func=process_func,
            dependencies=dependencies or [],
        )
        self.stage_times[name] = []

    def analyze_dependencies(self) -> Dict[str, List[str]]:
        """分析阶段依赖关系

        Returns:
            可并行的阶段组
        """
        parallel_groups = []
        completed = set()
        remaining = set(self.stages.keys())

        while remaining:
            current_group = []
            for stage_name in list(remaining):
                stage = self.stages[stage_name]
                deps_met = all(dep in completed for dep in stage.dependencies)

                if deps_met:
                    current_group.append(stage_name)

            if not current_group:
                break

            parallel_groups.append(current_group)
            for stage_name in current_group:
                completed.add(stage_name)
                remaining.remove(stage_name)

        return parallel_groups

    async def execute_stage(self, stage_name: str, data: Any, *args, **kwargs) -> Any:
        """执行单个阶段

        Args:
            stage_name: 阶段名称
            data: 输入数据
            *args: 位置参数
            **kwargs: 关键字参数

        Returns:
            执行结果
        """
        if stage_name not in self.stages:
            raise ValueError(f"Unknown stage: {stage_name}")

        stage = self.stages[stage_name]
        start_time = time.time()

        try:
            if asyncio.iscoroutinefunction(stage.process_func):
                result = await stage.process_func(data, *args, **kwargs)
            else:
                result = stage.process_func(data, *args, **kwargs)

            elapsed = time.time() - start_time
            stage.actual_time = elapsed
            self.stage_times[stage_name].append(elapsed)

            if self.enable_profiling:
                logger.info(f"[Profile] Stage {stage_name} completed in {elapsed:.2f}s")

            return result
        except Exception as e:
            logger.error(f"Stage {stage_name} failed: {e}")
            raise

    async def execute_pipeline(self, initial_data: Any) -> Dict[str, Any]:
        """执行完整流水线

        Args:
            initial_data: 初始输入数据

        Returns:
            各阶段结果字典
        """
        parallel_groups = self.analyze_dependencies()
        results = {}
        current_data = initial_data

        for group_idx, group in enumerate(parallel_groups):
            logger.debug(f"Executing parallel group {group_idx + 1}/{len(parallel_groups)}: {group}")

            if len(group) == 1:
                stage_name = group[0]
                current_data = await self.execute_stage(stage_name, current_data)
                results[stage_name] = current_data
            else:
                tasks = [
                    self.execute_stage(stage_name, current_data)
                    for stage_name in group
                ]
                group_results = await asyncio.gather(*tasks, return_exceptions=True)

                for stage_name, result in zip(group, group_results):
                    if isinstance(result, Exception):
                        logger.error(f"Stage {stage_name} failed: {result}")
                        results[stage_name] = None
                    else:
                        results[stage_name] = result

        return results

    def get_bottleneck_stages(self, threshold_percent: float = 0.3) -> List[str]:
        """获取瓶颈阶段

        Args:
            threshold_percent: 时间占比阈值

        Returns:
            瓶颈阶段名称列表
        """
        total_time = sum(sum(times) for times in self.stage_times.values())

        if total_time == 0:
            return []

        bottlenecks = []
        for stage_name, times in self.stage_times.items():
            if not times:
                continue

            avg_time = sum(times) / len(times)
            time_percent = avg_time / total_time

            if time_percent > threshold_percent:
                bottlenecks.append(stage_name)

        return bottlenecks

    def get_optimization_suggestions(self) -> List[str]:
        """获取优化建议

        Returns:
            优化建议列表
        """
        suggestions = []

        bottlenecks = self.get_bottleneck_stages()
        if bottlenecks:
            suggestions.append(f"瓶颈阶段: {', '.join(bottlenecks)}")

        for stage_name, times in self.stage_times.items():
            if len(times) > 1:
                variance = self._calculate_variance(times)
                if variance > 0.5:
                    suggestions.append(
                        f"{stage_name} 执行时间波动较大，可能需要稳定输入或添加缓存"
                    )

        return suggestions

    def _calculate_variance(self, values: List[float]) -> float:
        """计算方差"""
        if not values:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance

    async def close(self) -> None:
        """关闭执行器"""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None


def parallel_map(func: Callable[[T], Any], items: List[T], max_workers: int = 4) -> List[Any]:
    """并行映射

    Args:
        func: 处理函数
        items: 待处理项目列表
        max_workers: 最大工作线程数

    Returns:
        处理结果列表
    """
    if not items:
        return []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(func, items))

    return results


async def parallel_map_async(
    func: Callable[[T], Any],
    items: List[T],
    max_workers: int = 4,
) -> List[Any]:
    """异步并行映射

    Args:
        func: 异步处理函数
        items: 待处理项目列表
        max_workers: 最大并发数

    Returns:
        处理结果列表
    """
    if not items:
        return []

    semaphore = asyncio.Semaphore(max_workers)

    async def bounded_func(item):
        async with semaphore:
            return await func(item)

    tasks = [bounded_func(item) for item in items]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    return [r if not isinstance(r, Exception) else None for r in results]
