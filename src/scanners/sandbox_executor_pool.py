import concurrent.futures
import logging
from typing import List, Dict, Any, Optional, Callable

class SandboxExecutorPool:
    _instance = None
    _max_workers = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SandboxExecutorPool, cls).__new__(cls)
        return cls._instance

    def initialize(self, max_workers: Optional[int] = None):
        """初始化执行池
        
        Args:
            max_workers: 最大工作线程数，默认使用系统CPU核心数
        """
        self._max_workers = max_workers

    def execute_parallel(self, files: List[str], task_func: Callable[[str], Dict[str, Any]]) -> List[Dict[str, Any]]:
        """并行执行沙盒分析任务
        
        Args:
            files: 要分析的文件列表
            task_func: 分析函数，接收文件路径返回分析结果
            
        Returns:
            分析结果列表
        """
        results = []
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_file = {executor.submit(task_func, file): file for file in files}
            
            for future in concurrent.futures.as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logging.error(f"分析文件 {file} 时出错: {str(e)}")
                    results.append({
                        "file": file,
                        "error": str(e),
                        "success": False
                    })
        
        return results

    def execute_sequential(self, files: List[str], task_func: Callable[[str], Dict[str, Any]]) -> List[Dict[str, Any]]:
        """顺序执行沙盒分析任务
        
        Args:
            files: 要分析的文件列表
            task_func: 分析函数，接收文件路径返回分析结果
            
        Returns:
            分析结果列表
        """
        results = []
        
        for file in files:
            try:
                result = task_func(file)
                results.append(result)
            except Exception as e:
                logging.error(f"分析文件 {file} 时出错: {str(e)}")
                results.append({
                    "file": file,
                    "error": str(e),
                    "success": False
                })
        
        return results

    def execute(self, files: List[str], task_func: Callable[[str], Dict[str, Any]], parallel: bool = True) -> List[Dict[str, Any]]:
        """执行沙盒分析任务
        
        Args:
            files: 要分析的文件列表
            task_func: 分析函数，接收文件路径返回分析结果
            parallel: 是否并行执行
            
        Returns:
            分析结果列表
        """
        if parallel and len(files) > 1:
            return self.execute_parallel(files, task_func)
        else:
            return self.execute_sequential(files, task_func)

    def get_max_workers(self) -> int:
        """获取最大工作线程数
        
        Returns:
            最大工作线程数
        """
        return self._max_workers or concurrent.futures.ProcessPoolExecutor()._max_workers

sandbox_executor_pool = SandboxExecutorPool()
