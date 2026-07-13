"""性能监控模块

提供性能监控和分析功能，用于跟踪 AI 分析的性能指标。
"""

import time
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PerformanceMetric:
    """性能指标"""
    name: str
    value: float
    unit: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class PerformanceRecord:
    """性能记录"""
    operation: str
    duration: float
    metrics: List[PerformanceMetric] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class PerformanceMonitor:
    """性能监控器"""

    def __init__(self):
        """初始化性能监控器"""
        self.records: List[PerformanceRecord] = []
        self._current_operations: Dict[str, float] = {}

    def start(self, operation: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """开始监控操作

        Args:
            operation: 操作名称
            metadata: 操作元数据
        """
        self._current_operations[operation] = time.time()
        if metadata:
            # 可以在这里存储元数据，以便在结束时使用
            pass

    def stop(self, operation: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[PerformanceRecord]:
        """停止监控操作

        Args:
            operation: 操作名称
            metadata: 操作元数据

        Returns:
            性能记录
        """
        if operation not in self._current_operations:
            logger.warning(f"Operation {operation} not started")
            return None

        start_time = self._current_operations.pop(operation)
        duration = time.time() - start_time

        record = PerformanceRecord(
            operation=operation,
            duration=duration,
            metadata=metadata or {},
        )

        self.records.append(record)
        return record

    def add_metric(self, operation: str, name: str, value: float, unit: str) -> None:
        """添加性能指标

        Args:
            operation: 操作名称
            name: 指标名称
            value: 指标值
            unit: 指标单位
        """
        metric = PerformanceMetric(name=name, value=value, unit=unit)
        
        # 查找最近的操作记录
        for record in reversed(self.records):
            if record.operation == operation:
                record.metrics.append(metric)
                break

    def get_statistics(self, operation: Optional[str] = None) -> Dict[str, Any]:
        """获取性能统计信息

        Args:
            operation: 操作名称，为 None 时获取所有操作的统计信息

        Returns:
            性能统计信息
        """
        if operation:
            relevant_records = [r for r in self.records if r.operation == operation]
        else:
            relevant_records = self.records

        if not relevant_records:
            return {}

        durations = [r.duration for r in relevant_records]
        stats = {
            "count": len(durations),
            "mean": statistics.mean(durations),
            "median": statistics.median(durations),
            "min": min(durations),
            "max": max(durations),
            "stddev": statistics.stdev(durations) if len(durations) > 1 else 0,
        }

        # 按操作类型分组统计
        if not operation:
            by_operation = {}
            for record in relevant_records:
                if record.operation not in by_operation:
                    by_operation[record.operation] = []
                by_operation[record.operation].append(record.duration)

            operation_stats = {}
            for op, ops_durations in by_operation.items():
                operation_stats[op] = {
                    "count": len(ops_durations),
                    "mean": statistics.mean(ops_durations),
                    "median": statistics.median(ops_durations),
                    "min": min(ops_durations),
                    "max": max(ops_durations),
                    "stddev": statistics.stdev(ops_durations) if len(ops_durations) > 1 else 0,
                }
            stats["by_operation"] = operation_stats

        return stats

    def clear(self) -> None:
        """清除所有性能记录"""
        self.records.clear()
        self._current_operations.clear()

    def export(self) -> List[Dict[str, Any]]:
        """导出性能记录

        Returns:
            性能记录列表
        """
        return [
            {
                "operation": record.operation,
                "duration": record.duration,
                "metrics": [
                    {
                        "name": metric.name,
                        "value": metric.value,
                        "unit": metric.unit,
                        "timestamp": metric.timestamp,
                    }
                    for metric in record.metrics
                ],
                "metadata": record.metadata,
                "timestamp": record.timestamp,
            }
            for record in self.records
        ]


# 全局性能监控器实例
_performance_monitor: Optional[PerformanceMonitor] = None


def get_performance_monitor() -> PerformanceMonitor:
    """获取性能监控器实例

    Returns:
        性能监控器实例
    """
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


def measure_performance(operation: str, metadata: Optional[Dict[str, Any]] = None):
    """性能测量装饰器

    Args:
        operation: 操作名称
        metadata: 操作元数据

    Returns:
        装饰器
    """
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            monitor = get_performance_monitor()
            monitor.start(operation, metadata)
            try:
                result = await func(*args, **kwargs)
                monitor.stop(operation, metadata)
                return result
            except Exception as e:
                monitor.stop(operation, {**(metadata or {}), "error": str(e)})
                raise

        def sync_wrapper(*args, **kwargs):
            monitor = get_performance_monitor()
            monitor.start(operation, metadata)
            try:
                result = func(*args, **kwargs)
                monitor.stop(operation, metadata)
                return result
            except Exception as e:
                monitor.stop(operation, {**(metadata or {}), "error": str(e)})
                raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


# 导入 asyncio 以支持异步装饰器
import asyncio
