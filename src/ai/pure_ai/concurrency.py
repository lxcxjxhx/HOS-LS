import asyncio
from typing import List, Dict, Any, Callable
import concurrent.futures

class ConcurrencyManager:
    """并发执行管理器
    
    管理AI分析的并发执行，提高性能
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化并发管理器
        
        Args:
            config: 配置参数
        """
        self.config = config or {}
        self.max_workers = self.config.get('max_workers', 4)
        self.timeout = self.config.get('timeout', 300)  # 5分钟超时
    
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
        
        # 使用asyncio.gather执行异步任务
        if all(asyncio.iscoroutinefunction(task) for task in tasks):
            results = await asyncio.gather(*(task(*args, **kwargs) for task in tasks), return_exceptions=True)
        else:
            # 使用ThreadPoolExecutor执行同步任务
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_task = {executor.submit(task, *args, **kwargs): task for task in tasks}
                for future in concurrent.futures.as_completed(future_to_task, timeout=self.timeout):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        results.append(e)
        
        return results
    
    async def execute_in_batches(self, items: List[Any], batch_size: int, 
                               process_func: Callable, *args, **kwargs) -> List[Any]:
        """批量执行任务
        
        Args:
            items: 待处理的项目列表
            batch_size: 批次大小
            process_func: 处理函数
            *args: 传递给处理函数的参数
            **kwargs: 传递给处理函数的关键字参数
            
        Returns:
            处理结果列表
        """
        results = []
        
        # 分批处理
        for i in range(0, len(items), batch_size):
            batch = items[i:i+batch_size]
            print(f"[PURE-AI] 处理批次 {i//batch_size + 1}/{(len(items) + batch_size - 1)//batch_size}")
            
            # 为每个项目创建一个任务
            batch_tasks = []
            for item in batch:
                if asyncio.iscoroutinefunction(process_func):
                    batch_tasks.append(process_func(item, *args, **kwargs))
                else:
                    # 包装同步函数为异步
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
