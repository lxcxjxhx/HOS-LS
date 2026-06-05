import asyncio
from typing import List, Dict, Any, Callable
import concurrent.futures
from .environment import get_optimized_config

class ConcurrencyManager:
    """并发执行管理器
    
    管理AI分析的并发执行，提高性能
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化并发管理器
        
        Args:
            config: 配置参数
        """
        # 使用环境检测模块优化配置
        self.config = get_optimized_config(config)
        self.max_workers = self.config.get('max_workers')
        self.timeout = self.config.get('timeout')  # 5分钟超时
        self.batch_size = self.config.get('batch_size')
    
    async def execute_concurrently(self, tasks: List[Callable], *args, **kwargs) -> List[Any]:
        """并发执行多个任务
        
        Args:
            tasks: 任务列表
            *args: 传递给任务的参数
            **kwargs: 传递给任务的关键字参数
            
        Returns:
            任务执行结果列表
        """
        results = []
        
        if not tasks:
            return results
        
        # 根据任务数量动态调整并发数
        actual_workers = min(self.max_workers, len(tasks))
        
        # 任务分组，避免过多任务同时执行
        task_groups = []
        for i in range(0, len(tasks), actual_workers):
            task_groups.append(tasks[i:i+actual_workers])
        
        # 分组执行任务
        for group_idx, task_group in enumerate(task_groups):
            print(f"[PURE-AI] 执行任务组 {group_idx + 1}/{len(task_groups)}")
            
            # 使用asyncio.gather执行异步任务
            if all(asyncio.iscoroutinefunction(task) for task in task_group):
                group_results = await asyncio.gather(*(task(*args, **kwargs) for task in task_group), return_exceptions=True)
            else:
                # 使用ThreadPoolExecutor执行同步任务
                with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers) as executor:
                    future_to_task = {executor.submit(task, *args, **kwargs): task for task in task_group}
                    group_results = []
                    for future in concurrent.futures.as_completed(future_to_task, timeout=self.timeout):
                        try:
                            result = future.result()
                            group_results.append(result)
                        except Exception as e:
                            group_results.append(e)
            
            results.extend(group_results)
        
        return results
    
    async def execute_in_batches(self, items: List[Any], process_func: Callable, batch_size: int = None, 
                               *args, **kwargs) -> List[Any]:
        """批量执行任务
        
        Args:
            items: 待处理的项目列表
            process_func: 处理函数
            batch_size: 批次大小，默认使用配置中的值
            *args: 传递给处理函数的参数
            **kwargs: 传递给处理函数的关键字参数
            
        Returns:
            处理结果列表
        """
        results = []
        
        if not items:
            return results
        
        # 使用配置中的批次大小或传入的值
        actual_batch_size = batch_size or self.batch_size
        
        # 动态调整批次大小，根据项目数量和系统资源
        if len(items) < actual_batch_size:
            actual_batch_size = len(items)
        elif len(items) > 100:
            # 大量项目时，适当增加批次大小以减少批处理开销
            actual_batch_size = min(actual_batch_size * 2, 32)  # 最大批次大小为32
        
        # 分批处理
        total_batches = (len(items) + actual_batch_size - 1) // actual_batch_size
        print(f"[PURE-AI] 开始处理 {len(items)} 个项目，分 {total_batches} 批次")
        
        for i in range(0, len(items), actual_batch_size):
            batch = items[i:i+actual_batch_size]
            batch_num = i // actual_batch_size + 1
            print(f"[PURE-AI] 处理批次 {batch_num}/{total_batches} ({len(batch)} 个项目)")
            
            # 为每个项目创建一个任务
            batch_tasks = []
            for item in batch:
                if asyncio.iscoroutinefunction(process_func):
                    batch_tasks.append(process_func(item, *args, **kwargs))
                else:
                    # 包装同步函数为异步，避免闭包问题
                    async def wrapper(item):
                        return process_func(item, *args, **kwargs)
                    batch_tasks.append(wrapper(item))
            
            # 并发执行批次任务
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            results.extend(batch_results)
        
        return results
    
    def limit_concurrency(self, max_concurrency: int):
        """限制并发数
        
        Args:
            max_concurrency: 最大并发数
        """
        self.max_workers = max_concurrency
    
    def set_timeout(self, timeout: int):
        """设置超时时间
        
        Args:
            timeout: 超时时间（秒）
        """
        self.timeout = timeout
    
    def set_batch_size(self, batch_size: int):
        """设置批次大小
        
        Args:
            batch_size: 批次大小
        """
        self.batch_size = batch_size
