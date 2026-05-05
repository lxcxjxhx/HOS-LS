"""关联文件预加载器模块

在扫描过程中预加载关联文件，减少等待时间。
"""

import threading
from concurrent.futures import ThreadPoolExecutor, Future
from pathlib import Path
from typing import Dict, List, Optional, Set
import logging

logger = logging.getLogger(__name__)


class FileLoadingStatus:
    PENDING = "pending"
    LOADING = "loading"
    LOADED = "loaded"
    FAILED = "failed"


class RelatedFilePreloader:
    """关联文件预加载器

    在后台预加载相关文件，减少扫描等待时间。
    """

    def __init__(self, dependency_graph=None, max_workers: int = 4):
        self.dependency_graph = dependency_graph
        self.max_workers = max_workers
        self._content_cache: Dict[str, str] = {}
        self._loading_status: Dict[str, str] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._pending_futures: Dict[str, Future] = {}

    def preload_related_files(self, file_path: str, depth: int = 2) -> None:
        """预加载指定文件的关联文件

        Args:
            file_path: 文件路径
            depth: 查找深度
        """
        if not self.dependency_graph:
            return

        related_files = self.dependency_graph.get_related_files(file_path, depth=depth)

        for related_file in related_files:
            self._submit_load_task(related_file)

    def _submit_load_task(self, file_path: str) -> None:
        """提交文件加载任务

        Args:
            file_path: 文件路径
        """
        with self._lock:
            if file_path in self._content_cache:
                return
            if file_path in self._pending_futures:
                return
            if self._loading_status.get(file_path) == FileLoadingStatus.LOADING:
                return

            self._loading_status[file_path] = FileLoadingStatus.PENDING

        future = self._executor.submit(self._load_file_content, file_path)
        with self._lock:
            self._pending_futures[file_path] = future

        future.add_done_callback(
            lambda f, fp=file_path: self._handle_load_complete(fp, f)
        )

    def _load_file_content(self, file_path: str) -> Optional[str]:
        """加载文件内容

        Args:
            file_path: 文件路径

        Returns:
            文件内容或 None
        """
        with self._lock:
            self._loading_status[file_path] = FileLoadingStatus.LOADING

        try:
            path = Path(file_path)
            if not path.exists():
                with self._lock:
                    self._loading_status[file_path] = FileLoadingStatus.FAILED
                return None

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            with self._lock:
                self._content_cache[file_path] = content
                self._loading_status[file_path] = FileLoadingStatus.LOADED

            logger.debug(f"Loaded file content: {file_path}")
            return content

        except Exception as e:
            with self._lock:
                self._loading_status[file_path] = FileLoadingStatus.FAILED
            logger.warning(f"Failed to load file {file_path}: {e}")
            return None

    def _handle_load_complete(self, file_path: str, future: Future) -> None:
        """处理加载完成回调

        Args:
            file_path: 文件路径
            future: Future 对象
        """
        with self._lock:
            if file_path in self._pending_futures:
                del self._pending_futures[file_path]

    def get_file_content(self, file_path: str) -> Optional[str]:
        """获取文件内容（从缓存或磁盘）

        Args:
            file_path: 文件路径

        Returns:
            文件内容或 None
        """
        with self._lock:
            if file_path in self._content_cache:
                return self._content_cache[file_path]

        content = self._load_file_content(file_path)
        return content

    def is_loaded(self, file_path: str) -> bool:
        """检查文件是否已加载

        Args:
            file_path: 文件路径

        Returns:
            是否已加载
        """
        with self._lock:
            return self._loading_status.get(file_path) == FileLoadingStatus.LOADED

    def get_loading_status(self) -> Dict[str, str]:
        """获取加载状态

        Returns:
            文件路径到状态的字典
        """
        with self._lock:
            return dict(self._loading_status)

    def wait_for_file(self, file_path: str, timeout: float = 5.0) -> Optional[str]:
        """等待文件加载完成

        Args:
            file_path: 文件路径
            timeout: 超时时间（秒）

        Returns:
            文件内容或 None
        """
        with self._lock:
            if file_path in self._content_cache:
                return self._content_cache[file_path]

            if file_path in self._pending_futures:
                future = self._pending_futures[file_path]

        try:
            return future.result(timeout=timeout)
        except Exception:
            return self.get_file_content(file_path)

    def preload_files(self, file_paths: List[str]) -> None:
        """预加载多个文件

        Args:
            file_paths: 文件路径列表
        """
        for file_path in file_paths:
            self._submit_load_task(file_path)

    def get_cache_size(self) -> int:
        """获取缓存大小

        Returns:
            缓存的文件数量
        """
        with self._lock:
            return len(self._content_cache)

    def clear_cache(self) -> None:
        """清空缓存"""
        with self._lock:
            self._content_cache.clear()
            self._loading_status.clear()
            self._pending_futures.clear()

    def shutdown(self, wait: bool = True) -> None:
        """关闭预加载器

        Args:
            wait: 是否等待所有任务完成
        """
        self._executor.shutdown(wait=wait)

    def get_stats(self) -> Dict[str, int]:
        """获取统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            status_counts = {}
            for status in [FileLoadingStatus.PENDING, FileLoadingStatus.LOADING,
                          FileLoadingStatus.LOADED, FileLoadingStatus.FAILED]:
                status_counts[status] = sum(
                    1 for s in self._loading_status.values() if s == status
                )

            return {
                'cache_size': len(self._content_cache),
                'pending_count': status_counts.get(FileLoadingStatus.PENDING, 0),
                'loading_count': status_counts.get(FileLoadingStatus.LOADING, 0),
                'loaded_count': status_counts.get(FileLoadingStatus.LOADED, 0),
                'failed_count': status_counts.get(FileLoadingStatus.FAILED, 0),
                'pending_futures': len(self._pending_futures),
            }
