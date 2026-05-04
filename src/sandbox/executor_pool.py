"""沙盒执行器池模块

管理多个沙盒执行器，支持并发执行任务。
"""

import concurrent.futures
import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union

from .executor import SandboxExecutor, ExecutionResult, ExecutionLanguage, SandboxConfig


@dataclass
class PoolConfig:
    """执行器池配置"""

    pool_size: int = 4
    max_queue_size: int = 100
    keep_alive: bool = True
    monitor_interval: int = 60


@dataclass
class TaskInfo:
    """任务信息"""

    task_id: str
    task: Callable
    priority: int = 0
    submitted_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[ExecutionResult] = None


class SandboxExecutorPool:
    """沙盒执行器池

    管理多个沙盒执行器，支持并发执行。
    """

    def __init__(self, config: Optional[PoolConfig] = None, sandbox_config: Optional[SandboxConfig] = None):
        """初始化沙盒执行器池

        Args:
            config: 执行器池配置
            sandbox_config: 沙盒配置
        """
        self.config = config or PoolConfig()
        self.sandbox_config = sandbox_config or SandboxConfig()

        self._executors = [SandboxExecutor(self.sandbox_config) for _ in range(self.config.pool_size)]
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.config.pool_size)
        self._tasks: Dict[str, TaskInfo] = {}
        self._task_counter = 0
        self._lock = threading.RLock()
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = True
        self._compiled_cache: Dict[str, Optional[ExecutionResult]] = {}

        if self.config.keep_alive:
            self._start_monitor()

    def execute(
        self,
        task: Union[Callable, str],
        language: Optional[Union[ExecutionLanguage, str]] = None,
        timeout: int = 30,
        memory_limit: int = 512 * 1024 * 1024,
        network_access: bool = False,
        use_cache: bool = True,
    ) -> ExecutionResult:
        """执行任务

        Args:
            task: 任务函数或代码字符串
            language: 语言（如果 task 是代码字符串）
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问
            use_cache: 是否使用编译缓存

        Returns:
            执行结果
        """
        if isinstance(task, str):
            if not language:
                return ExecutionResult(
                    status="error",
                    output="",
                    error="Language must be specified for code strings",
                )

            language_upper = str(language).upper()
            compiled_cache_key = None
            needs_compilation = language_upper in ("JAVA", "C", "GO", "RUST", "TYPESCRIPT")

            if needs_compilation and use_cache:
                code_hash = hashlib.sha256(task.encode()).hexdigest()
                compiled_cache_key = f"{language_upper}_{code_hash}"
                if compiled_cache_key in self._compiled_cache:
                    cached_result = self._compiled_cache[compiled_cache_key]
                    if cached_result:
                        return cached_result

            def code_task():
                executor = self._get_available_executor()
                return executor.execute(
                    code=task,
                    language=language,
                    timeout=timeout,
                    memory_limit=memory_limit,
                    network_access=network_access,
                )

            task_func = code_task
        else:
            task_func = task
            compiled_cache_key = None

        future = self._pool.submit(task_func)

        try:
            result = future.result(timeout=timeout + 5)
            if compiled_cache_key and result.status == "success":
                self._compiled_cache[compiled_cache_key] = result
            return result
        except concurrent.futures.TimeoutError:
            return ExecutionResult(
                status="timeout",
                output="",
                error=f"Task timed out after {timeout} seconds",
            )
        except Exception as e:
            return ExecutionResult(
                status="error",
                output="",
                error=str(e),
            )

    def execute_batch(
        self,
        tasks: List[Union[Callable, str]],
        language: Optional[Union[ExecutionLanguage, str]] = None,
        timeout: int = 30,
        memory_limit: int = 512 * 1024 * 1024,
        network_access: bool = False,
        use_cache: bool = True,
    ) -> List[ExecutionResult]:
        """批量执行任务

        Args:
            tasks: 任务列表
            language: 语言（如果 tasks 包含代码字符串）
            timeout: 超时时间
            memory_limit: 内存限制
            network_access: 是否允许网络访问
            use_cache: 是否使用编译缓存

        Returns:
            执行结果列表
        """
        futures = []
        task_cache_keys = []

        language_upper = str(language).upper() if language else None
        needs_compilation = language_upper in ("JAVA", "C", "GO", "RUST", "TYPESCRIPT") if language_upper else False

        for task in tasks:
            if isinstance(task, str):
                compiled_cache_key = None

                if needs_compilation and use_cache:
                    code_hash = hashlib.sha256(task.encode()).hexdigest()
                    compiled_cache_key = f"{language_upper}_{code_hash}"
                    task_cache_keys.append(compiled_cache_key)

                    if compiled_cache_key in self._compiled_cache:
                        cached_result = self._compiled_cache[compiled_cache_key]
                        if cached_result:
                            futures.append(None)
                            continue

                def code_task(t=task):
                    executor = self._get_available_executor()
                    return executor.execute(
                        code=t,
                        language=language,
                        timeout=timeout,
                        memory_limit=memory_limit,
                        network_access=network_access,
                    )

                task_func = code_task
            else:
                task_func = task
                task_cache_keys.append(None)

            future = self._pool.submit(task_func)
            futures.append(future)

        results = []
        cache_idx = 0
        for i, future in enumerate(concurrent.futures.as_completed(futures, timeout=timeout + 5)):
            if futures[i] is None:
                cache_key = task_cache_keys[i]
                cached_result = self._compiled_cache.get(cache_key) if cache_key else None
                results.append(cached_result if cached_result else ExecutionResult(
                    status="error",
                    output="",
                    error="Cache miss",
                ))
                continue

            try:
                result = future.result()
                if task_cache_keys[i] and result.status == "success":
                    self._compiled_cache[task_cache_keys[i]] = result
                results.append(result)
            except concurrent.futures.TimeoutError:
                results.append(
                    ExecutionResult(
                        status="timeout",
                        output="",
                        error=f"Task timed out after {timeout} seconds",
                    )
                )
            except Exception as e:
                results.append(
                    ExecutionResult(
                        status="error",
                        output="",
                        error=str(e),
                    )
                )

        return results

    def submit_task(
        self,
        task: Callable,
        priority: int = 0,
    ) -> str:
        """提交任务到队列

        Args:
            task: 任务函数
            priority: 优先级

        Returns:
            任务ID
        """
        with self._lock:
            task_id = f"task_{self._task_counter}"
            self._task_counter += 1

            task_info = TaskInfo(
                task_id=task_id,
                task=task,
                priority=priority,
            )
            self._tasks[task_id] = task_info

            future = self._pool.submit(self._execute_task, task_info)

            def callback(fut):
                try:
                    result = fut.result()
                    with self._lock:
                        if task_id in self._tasks:
                            self._tasks[task_id].result = result
                            self._tasks[task_id].completed_at = time.time()
                except Exception:
                    pass

            future.add_done_callback(callback)

            return task_id

    def get_task_status(self, task_id: str) -> Optional[TaskInfo]:
        """获取任务状态

        Args:
            task_id: 任务ID

        Returns:
            任务信息
        """
        with self._lock:
            return self._tasks.get(task_id)

    def get_task_result(self, task_id: str) -> Optional[ExecutionResult]:
        """获取任务结果

        Args:
            task_id: 任务ID

        Returns:
            执行结果
        """
        with self._lock:
            task_info = self._tasks.get(task_id)
            return task_info.result if task_info else None

    def cancel_task(self, task_id: str) -> bool:
        """取消任务

        Args:
            task_id: 任务ID

        Returns:
            是否成功取消
        """
        with self._lock:
            if task_id in self._tasks:
                del self._tasks[task_id]
                return True
            return False

    def get_queue_size(self) -> int:
        """获取队列大小

        Returns:
            队列大小
        """
        with self._lock:
            return len(self._tasks)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息
        """
        with self._lock:
            pending = 0
            running = 0
            completed = 0

            for task_info in self._tasks.values():
                if task_info.result is None:
                    if task_info.started_at:
                        running += 1
                    else:
                        pending += 1
                else:
                    completed += 1

            return {
                "pool_size": self.config.pool_size,
                "queue_size": len(self._tasks),
                "pending_tasks": pending,
                "running_tasks": running,
                "completed_tasks": completed,
                "active_workers": self._pool._work_queue.qsize(),
            }

    def shutdown(self, wait: bool = True) -> None:
        """关闭执行器池

        Args:
            wait: 是否等待所有任务完成
        """
        self._running = False

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

        self._pool.shutdown(wait=wait)

        for executor in self._executors:
            executor.shutdown()

    def _get_available_executor(self) -> SandboxExecutor:
        """获取可用的执行器

        Returns:
            沙盒执行器
        """
        # 简单的轮询策略
        executor_index = self._task_counter % len(self._executors)
        return self._executors[executor_index]

    def _execute_task(self, task_info: TaskInfo) -> ExecutionResult:
        """执行任务

        Args:
            task_info: 任务信息

        Returns:
            执行结果
        """
        with self._lock:
            task_info.started_at = time.time()

        try:
            result = task_info.task()
            if not isinstance(result, ExecutionResult):
                result = ExecutionResult(
                    status="success",
                    output=str(result),
                    error="",
                )
            return result
        except Exception as e:
            return ExecutionResult(
                status="error",
                output="",
                error=str(e),
            )

    def _start_monitor(self) -> None:
        """启动监控线程"""
        def monitor():
            while self._running:
                time.sleep(self.config.monitor_interval)
                self._cleanup_completed_tasks()

        self._monitor_thread = threading.Thread(target=monitor, daemon=True)
        self._monitor_thread.start()

    def _cleanup_completed_tasks(self) -> None:
        """清理已完成的任务"""
        with self._lock:
            completed_tasks = [
                task_id
                for task_id, task_info in self._tasks.items()
                if task_info.completed_at
            ]

            for task_id in completed_tasks:
                del self._tasks[task_id]

    def __enter__(self):
        """进入上下文管理器"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文管理器"""
        self.shutdown()
