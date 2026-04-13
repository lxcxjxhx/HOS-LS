"""时间工具函数

提供时间相关的工具函数，包括执行时间计算、时间格式化等。
"""

from datetime import datetime
from typing import Optional, Callable, Any


def calculate_execution_time(func: Callable, *args, **kwargs) -> tuple[Any, float]:
    """计算函数执行时间

    Args:
        func: 要执行的函数
        *args: 函数参数
        **kwargs: 函数关键字参数

    Returns:
        tuple[Any, float]: (函数返回值, 执行时间秒数)
    """
    start_time = datetime.now()
    result = func(*args, **kwargs)
    end_time = datetime.now()
    execution_time = (end_time - start_time).total_seconds()
    return result, execution_time


def format_execution_time(seconds: float) -> str:
    """格式化执行时间

    Args:
        seconds: 执行时间秒数

    Returns:
        str: 格式化后的时间字符串
    """
    if seconds < 1:
        return f"{seconds * 1000:.2f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.2f}s"


class Timer:
    """计时器类

    用于测量代码块的执行时间。
    """
    
    def __init__(self):
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
    
    def start(self) -> None:
        """开始计时"""
        self.start_time = datetime.now()
        self.end_time = None
    
    def stop(self) -> float:
        """停止计时并返回执行时间

        Returns:
            float: 执行时间秒数
        """
        if self.start_time is None:
            return 0.0
        self.end_time = datetime.now()
        return (self.end_time - self.start_time).total_seconds()
    
    def elapsed(self) -> float:
        """返回从开始到现在的经过时间

        Returns:
            float: 经过时间秒数
        """
        if self.start_time is None:
            return 0.0
        current_time = datetime.now()
        return (current_time - self.start_time).total_seconds()
    
    def __enter__(self) -> 'Timer':
        """上下文管理器入口"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """上下文管理器出口"""
        self.stop()