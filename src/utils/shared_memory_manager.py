import multiprocessing
from multiprocessing import shared_memory, Manager
from typing import Dict, Any, List, Optional
import json

class SharedMemoryManager:
    _instance = None
    _shared_memory = None
    _manager = None
    _shared_dict = None
    _shared_list = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SharedMemoryManager, cls).__new__(cls)
        return cls._instance

    def initialize(self):
        """初始化共享内存管理器"""
        # 初始化 Manager 用于共享数据结构
        self._manager = Manager()
        self._shared_dict = self._manager.dict()
        self._shared_list = self._manager.list()

    def get_shared_dict(self) -> Dict[str, Any]:
        """获取共享字典"""
        if not self._shared_dict:
            self.initialize()
        return self._shared_dict

    def get_shared_list(self) -> List[Any]:
        """获取共享列表"""
        if not self._shared_list:
            self.initialize()
        return self._shared_list

    def set_value(self, key: str, value: Any):
        """设置共享值"""
        shared_dict = self.get_shared_dict()
        shared_dict[key] = value

    def get_value(self, key: str, default: Any = None) -> Any:
        """获取共享值"""
        shared_dict = self.get_shared_dict()
        return shared_dict.get(key, default)

    def append_to_list(self, item: Any):
        """向共享列表添加项"""
        shared_list = self.get_shared_list()
        shared_list.append(item)

    def get_list(self) -> List[Any]:
        """获取共享列表的副本"""
        shared_list = self.get_shared_list()
        return list(shared_list)

    def clear(self):
        """清空共享数据"""
        if self._shared_dict:
            self._shared_dict.clear()
        if self._shared_list:
            while self._shared_list:
                self._shared_list.pop()

    def shutdown(self):
        """关闭共享内存管理器"""
        if self._manager:
            self._manager.shutdown()
        self._shared_dict = None
        self._shared_list = None
        self._manager = None

class RedisLikeQueue:
    """Redis 风格的轻量队列，基于共享内存"""
    
    def __init__(self, name: str):
        self.name = name
        self.shared_memory_manager = SharedMemoryManager()
        self.queue_key = f"queue:{name}"
        self._ensure_queue_exists()

    def _ensure_queue_exists(self):
        """确保队列存在"""
        shared_dict = self.shared_memory_manager.get_shared_dict()
        if self.queue_key not in shared_dict:
            shared_dict[self.queue_key] = self.shared_memory_manager._manager.list()

    def push(self, item: Any):
        """推送项到队列"""
        shared_dict = self.shared_memory_manager.get_shared_dict()
        queue = shared_dict[self.queue_key]
        queue.append(item)

    def pop(self) -> Optional[Any]:
        """从队列弹出项"""
        shared_dict = self.shared_memory_manager.get_shared_dict()
        queue = shared_dict[self.queue_key]
        if queue:
            return queue.pop(0)
        return None

    def size(self) -> int:
        """获取队列大小"""
        shared_dict = self.shared_memory_manager.get_shared_dict()
        queue = shared_dict[self.queue_key]
        return len(queue)

    def clear(self):
        """清空队列"""
        shared_dict = self.shared_memory_manager.get_shared_dict()
        queue = shared_dict[self.queue_key]
        while queue:
            queue.pop()

shared_memory_manager = SharedMemoryManager()
