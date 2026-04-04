"""性能监控测试"""

import pytest
import time
from src.utils.performance_monitor import (
    PerformanceMonitor,
    get_performance_monitor,
    measure_performance
)


class TestPerformanceMonitor:
    def test_get_instance(self):
        """测试获取单例"""
        monitor1 = get_performance_monitor()
        monitor2 = get_performance_monitor()
        assert monitor1 is monitor2

    def test_start_stop(self):
        """测试开始和停止监控"""
        monitor = get_performance_monitor()
        monitor.clear()
        
        monitor.start("test_operation")
        time.sleep(0.1)
        record = monitor.stop("test_operation")
        
        assert record is not None
        assert record.operation == "test_operation"
        assert record.duration >= 0.1

    def test_add_metric(self):
        """测试添加性能指标"""
        monitor = get_performance_monitor()
        monitor.clear()
        
        monitor.start("test_operation")
        time.sleep(0.1)
        monitor.stop("test_operation")
        
        monitor.add_metric("test_operation", "test_metric", 100, "ms")
        
        records = monitor.export()
        assert len(records) == 1
        assert len(records[0]["metrics"]) == 1
        assert records[0]["metrics"][0]["name"] == "test_metric"
        assert records[0]["metrics"][0]["value"] == 100
        assert records[0]["metrics"][0]["unit"] == "ms"

    def test_get_statistics(self):
        """测试获取性能统计信息"""
        monitor = get_performance_monitor()
        monitor.clear()
        
        # 运行多次操作
        for i in range(3):
            monitor.start("test_operation")
            time.sleep(0.05)
            monitor.stop("test_operation")
        
        stats = monitor.get_statistics("test_operation")
        assert stats["count"] == 3
        assert stats["mean"] >= 0.05

    def test_clear(self):
        """测试清除记录"""
        monitor = get_performance_monitor()
        monitor.clear()
        
        monitor.start("test_operation")
        time.sleep(0.1)
        monitor.stop("test_operation")
        
        assert len(monitor.export()) == 1
        
        monitor.clear()
        assert len(monitor.export()) == 0


class TestPerformanceDecorator:
    def test_sync_decorator(self):
        """测试同步函数装饰器"""
        monitor = get_performance_monitor()
        monitor.clear()
        
        @measure_performance("test_sync")
        def test_function():
            time.sleep(0.1)
            return "test"
        
        result = test_function()
        assert result == "test"
        
        records = monitor.export()
        assert len(records) == 1
        assert records[0]["operation"] == "test_sync"
        assert records[0]["duration"] >= 0.1

    async def test_async_decorator(self):
        """测试异步函数装饰器"""
        monitor = get_performance_monitor()
        monitor.clear()
        
        @measure_performance("test_async")
        async def test_function():
            await asyncio.sleep(0.1)
            return "test"
        
        result = await test_function()
        assert result == "test"
        
        records = monitor.export()
        assert len(records) == 1
        assert records[0]["operation"] == "test_async"
        assert records[0]["duration"] >= 0.1


# 导入 asyncio 以支持异步测试
import asyncio
