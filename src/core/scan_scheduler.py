"""扫描调度器模块

提供并发、重试、限流的扫描调度功能。
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable, Awaitable
from enum import Enum
from functools import wraps


class ScanStatus(Enum):
    """扫描任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class ScanTask:
    """扫描任务"""

    task_id: str = ""
    task_type: str = ""  # "function", "class", "file"
    target: str = ""
    status: ScanStatus = ScanStatus.PENDING
    priority: int = 0
    retry_count: int = 0
    max_retries: int = 3
    result: Optional[Any] = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """获取任务执行时长"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0


def async_retry(max_retries: int = 3, retry_delay: float = 1.0, backoff_factor: float = 2.0):
    """异步重试装饰器"""
    def decorator(func: Callable[..., Awaitable[Any]]):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        delay = retry_delay * (backoff_factor ** attempt)
                        await asyncio.sleep(delay)
            raise last_exception
        return wrapper
    return decorator


class RateLimiter:
    """速率限制器"""

    def __init__(self, max_requests: int = 10, time_window: float = 60.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """获取令牌"""
        async with self._lock:
            now = time.time()
            # 移除过期的请求记录
            self.requests = [t for t in self.requests if now - t < self.time_window]
            
            while len(self.requests) >= self.max_requests:
                # 等待到最早的请求过期
                wait_time = self.requests[0] + self.time_window - now
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                now = time.time()
                self.requests = [t for t in self.requests if now - t < self.time_window]
            
            self.requests.append(time.time())


class ScanScheduler:
    """扫描调度器"""

    def __init__(
        self,
        max_concurrent: int = 5,
        max_retries: int = 3,
        rate_limit: int = 10,
        rate_limit_window: float = 60.0,
        retry_delay: float = 1.0,
    ):
        """初始化扫描调度器"""
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.rate_limiter = RateLimiter(rate_limit, rate_limit_window)
        self.tasks: Dict[str, ScanTask] = {}
        self._task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._running = False
        self._worker_tasks: List[asyncio.Task] = []
        self._results: List[Any] = []
        self._errors: List[str] = []

    async def add_task(
        self,
        task_id: str,
        task_type: str,
        target: str,
        priority: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """添加扫描任务"""
        task = ScanTask(
            task_id=task_id,
            task_type=task_type,
            target=target,
            priority=priority,
            max_retries=self.max_retries,
            metadata=metadata or {},
        )
        self.tasks[task_id] = task
        # 使用负优先级实现降序排列（优先级高的先执行）
        await self._task_queue.put((-priority, task_id))
        return task_id

    async def _worker(self, scan_func: Callable[[ScanTask], Awaitable[Any]]):
        """工作协程"""
        while self._running:
            try:
                priority, task_id = await asyncio.wait_for(
                    self._task_queue.get(),
                    timeout=0.1
                )
                task = self.tasks[task_id]
                
                if task.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
                    self._task_queue.task_done()
                    continue

                task.status = ScanStatus.RUNNING
                task.start_time = time.time()

                try:
                    # 速率限制
                    await self.rate_limiter.acquire()
                    
                    # 执行扫描
                    result = await self._execute_with_retry(task, scan_func)
                    
                    task.result = result
                    task.status = ScanStatus.COMPLETED
                    self._results.append(result)
                    
                except Exception as e:
                    task.error = str(e)
                    task.status = ScanStatus.FAILED
                    self._errors.append(f"Task {task_id} failed: {e}")

                task.end_time = time.time()
                self._task_queue.task_done()

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"[ERROR] Worker error: {e}")

    @async_retry(max_retries=3, retry_delay=1.0)
    async def _execute_with_retry(
        self,
        task: ScanTask,
        scan_func: Callable[[ScanTask], Awaitable[Any]],
    ) -> Any:
        """带重试的执行"""
        task.retry_count += 1
        if task.retry_count > 1:
            task.status = ScanStatus.RETRYING
        return await scan_func(task)

    async def start(
        self,
        scan_func: Callable[[ScanTask], Awaitable[Any]],
    ):
        """启动调度器"""
        self._running = True
        self._worker_tasks = [
            asyncio.create_task(self._worker(scan_func))
            for _ in range(self.max_concurrent)
        ]

    async def wait(self):
        """等待所有任务完成"""
        await self._task_queue.join()
        self._running = False
        for worker in self._worker_tasks:
            worker.cancel()
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)

    async def run(
        self,
        scan_func: Callable[[ScanTask], Awaitable[Any]],
    ) -> List[Any]:
        """运行调度器（启动 + 等待）"""
        await self.start(scan_func)
        await self.wait()
        return self._results

    def get_task_status(self, task_id: str) -> Optional[ScanStatus]:
        """获取任务状态"""
        task = self.tasks.get(task_id)
        return task.status if task else None

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.tasks)
        completed = sum(1 for t in self.tasks.values() if t.status == ScanStatus.COMPLETED)
        failed = sum(1 for t in self.tasks.values() if t.status == ScanStatus.FAILED)
        pending = sum(1 for t in self.tasks.values() if t.status == ScanStatus.PENDING)
        
        total_duration = sum(t.duration for t in self.tasks.values() if t.duration > 0)
        avg_duration = total_duration / completed if completed > 0 else 0

        return {
            "total_tasks": total,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "total_duration": total_duration,
            "avg_duration": avg_duration,
            "errors": self._errors,
        }


class MultiPhaseScanner:
    """多阶段扫描器"""

    def __init__(self, scheduler: ScanScheduler):
        self.scheduler = scheduler

    async def scan_phase1(
        self,
        code: str,
        file_path: str,
    ) -> List[Dict[str, Any]]:
        """第一阶段：轻量定位（低 token）"""
        # 这里是简化实现，实际应该调用 LLM
        # 查找可疑点
        suspicious = []
        
        # 简单的模式匹配作为示例
        patterns = [
            ("sql_injection", ["sql", "execute", "cursor"]),
            ("xss", ["innerHTML", "document.write"]),
            ("command_injection", ["subprocess", "os.system", "exec"]),
            ("hardcoded_credentials", ["password", "api_key", "secret"]),
        ]

        for vuln_type, keywords in patterns:
            for keyword in keywords:
                if keyword.lower() in code.lower():
                    lines = code.split('\n')
                    for i, line in enumerate(lines):
                        if keyword.lower() in line.lower():
                            suspicious.append({
                                "line": i + 1,
                                "type": vuln_type,
                                "snippet": line.strip()
                            })
                            break
        
        return suspicious

    async def scan_phase2(
        self,
        code: str,
        file_path: str,
        suspicious_points: List[Dict[str, Any]],
        context_lines: int = 50,
    ) -> List[Any]:
        """第二阶段：精扫（只分析局部代码 ±context_lines 行）"""
        results = []
        lines = code.split('\n')
        
        for point in suspicious_points:
            line_num = point["line"] - 1
            start_line = max(0, line_num - context_lines)
            end_line = min(len(lines), line_num + context_lines + 1)
            local_code = '\n'.join(lines[start_line:end_line])
            
            # 这里应该调用 LLM 进行精细分析
            # 简化实现，实际应调用 AI 分析器
            result = {
                "file_path": file_path,
                "start_line": start_line + 1,
                "end_line": end_line,
                "suspicious_type": point["type"],
                "code": local_code,
            }
            results.append(result)
        
        return results

    async def multi_phase_scan(
        self,
        code: str,
        file_path: str,
    ) -> List[Any]:
        """执行多阶段扫描"""
        # 第一阶段：轻量定位
        suspicious = await self.scan_phase1(code, file_path)
        
        if not suspicious:
            return []
        
        # 第二阶段：精扫
        results = await self.scan_phase2(code, file_path, suspicious)
        
        return results
