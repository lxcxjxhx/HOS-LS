"""Memory Manager 统一管理入口

提供单例模式的Memory管理，协调User/Project/Execution三层记忆，
提供内存缓存和高级查询接口。
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    UserMemory,
    UserPreferences,
    BehaviorStats,
    UserHabits,
    ProjectMemory,
    RiskProfile,
    ScanHistory,
    ExecutionLog,
    Intent,
)
from .storage import MemoryStorage
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MemoryManager:
    """Memory管理器（单例）

    协调三层记忆的读写操作，提供内存缓存以避免频繁IO。
    """

    _instance: Optional["MemoryManager"] = None
    _initialized: bool = False

    def __new__(cls) -> "MemoryManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, base_path: Optional[Path] = None):
        """初始化Memory管理器

        Args:
            base_path: 基础存储路径
        """
        if self._initialized:
            return

        self._storage = MemoryStorage(base_path)
        self._user_memory_cache: Optional[UserMemory] = None
        self._project_memory_cache: Dict[str, ProjectMemory] = {}
        self._cache_ttl: int = 300  # 缓存有效期（秒）
        self._last_cache_time: Dict[str, datetime] = {}

        # 尝试加载用户记忆到缓存
        self._load_user_to_cache()

        self._initialized = True
        logger.info("MemoryManager初始化完成")

    def _load_user_to_cache(self):
        """加载用户记忆到缓存"""
        try:
            self._user_memory_cache = self._storage.load_user_memory()
            if self._user_memory_cache is None:
                self._user_memory_cache = UserMemory()
                self._storage.save_user_memory(self._user_memory_cache)
                logger.debug("创建新的用户记忆")
            else:
                logger.debug(f"加载用户记忆成功: {self._user_memory_cache.user_id[:8]}...")
        except Exception as e:
            logger.error(f"加载用户记忆失败: {e}")
            self._user_memory_cache = UserMemory()

    def _is_cache_valid(self, cache_key: str) -> bool:
        """检查缓存是否有效"""
        last_time = self._last_cache_time.get(cache_key)
        if not last_time:
            return False
        return (datetime.now() - last_time).total_seconds() < self._cache_ttl

    def get_user_preferences(self) -> UserPreferences:
        """获取用户偏好

        Returns:
            用户偏好对象
        """
        if self._user_memory_cache:
            return self._user_memory_cache.preferences
        return UserPreferences()

    def get_user_memory(self) -> UserMemory:
        """获取完整用户记忆

        Returns:
            用户记忆对象
        """
        if self._user_memory_cache is None:
            self._load_user_to_cache()
        return self._user_memory_cache or UserMemory()

    def update_user_preference(self, key: str, value: Any) -> None:
        """更新用户偏好

        Args:
            key: 偏好键名
            value: 偏好值
        """
        if not self._user_memory_cache:
            self._user_memory_cache = UserMemory()

        if hasattr(self._user_memory_cache.preferences, key):
            setattr(self._user_memory_cache.preferences, key, value)
            self._user_memory_cache.updated_at = datetime.now()
            self._persist_user_memory()
            logger.debug(f"用户偏好已更新: {key}={value}")
        else:
            logger.warning(f"未知的用户偏好键: {key}")

    def update_user_habit(self, key: str, value: Any) -> None:
        """更新用户习惯

        Args:
            key: 习惯键名
            value: 习惯值
        """
        if not self._user_memory_cache:
            self._user_memory_cache = UserMemory()

        if hasattr(self._user_memory_cache.habits, key):
            setattr(self._user_memory_cache.habits, key, value)
            self._user_memory_cache.updated_at = datetime.now()
            self._persist_user_memory()
            logger.debug(f"用户习惯已更新: {key}={value}")
        else:
            logger.warning(f"未知的用户习惯键: {key}")

    def record_usage(self) -> None:
        """记录一次使用"""
        if self._user_memory_cache:
            self._user_memory_cache.update_usage()
            self._persist_user_memory()

    def get_project_context(self, project_path: str) -> Optional[ProjectMemory]:
        """获取项目上下文

        Args:
            project_path: 项目路径

        Returns:
            项目记忆对象
        """
        from .models import ProjectMemory
        project_hash = ProjectMemory.generate_hash(project_path)

        # 检查缓存
        if self._is_cache_valid(project_hash) and project_hash in self._project_memory_cache:
            return self._project_memory_cache[project_hash]

        # 从存储加载
        project_memory = self._storage.load_project_memory(project_hash)

        if project_memory:
            self._project_memory_cache[project_hash] = project_memory
            self._last_cache_time[project_hash] = datetime.now()
        else:
            # 创建新的项目记忆
            project_memory = ProjectMemory(project_path=project_path, project_hash=project_hash)
            self._storage.save_project_memory(project_memory)
            self._project_memory_cache[project_hash] = project_memory
            self._last_cache_time[project_hash] = datetime.now()
            logger.debug(f"创建新项目记忆: {project_hash}")

        return project_memory

    def update_project_risk(self, project_path: str, risk_info: Dict[str, Any]) -> None:
        """更新项目风险画像

        Args:
            project_path: 项目路径
            risk_info: 风险信息字典
        """
        from .models import ProjectMemory
        project_memory = self.get_project_context(project_path)
        if not project_memory:
            return

        for key, value in risk_info.items():
            if hasattr(project_memory.risk_profile, key):
                setattr(project_memory.risk_profile, key, value)

        project_memory.risk_profile.last_assessed = datetime.now()
        project_memory.updated_at = datetime.now()

        self._storage.save_project_memory(project_memory)

        # 更新缓存
        project_hash = project_memory.project_hash
        self._project_memory_cache[project_hash] = project_memory
        self._last_cache_time[project_hash] = datetime.now()

        logger.debug(f"项目风险已更新: {project_path}")

    def update_project_tech_stack(self, project_path: str, tech_stack: List[str]) -> None:
        """更新项目技术栈

        Args:
            project_path: 项目路径
            tech_stack: 技术栈列表
        """
        project_memory = self.get_project_context(project_path)
        if not project_memory:
            return

        project_memory.update_tech_stack(tech_stack)
        self._storage.save_project_memory(project_memory)

        # 更新缓存
        project_hash = project_memory.project_hash
        self._project_memory_cache[project_hash] = project_memory
        self._last_cache_time[project_hash] = datetime.now()

        logger.debug(f"项目技术栈已更新: {project_path} -> {tech_stack}")

    def record_scan_history(
        self,
        project_path: str,
        duration: float,
        findings: int,
        depth: str = "medium",
    ) -> None:
        """记录扫描历史

        Args:
            project_path: 项目路径
            duration: 扫描耗时（秒）
            findings: 发现数
            depth: 扫描深度
        """
        project_memory = self.get_project_context(project_path)
        if not project_memory:
            return

        project_memory.scan_history.record_scan(duration, findings, depth)
        project_memory.updated_at = datetime.now()
        self._storage.save_project_memory(project_memory)

        # 更新缓存
        project_hash = project_memory.project_hash
        self._project_memory_cache[project_hash] = project_memory
        self._last_cache_time[project_hash] = datetime.now()

    def record_execution(self, log: ExecutionLog) -> None:
        """记录执行日志

        Args:
            log: 执行日志对象
        """
        self._storage.append_execution_log(log)

        # 更新用户使用统计
        if self._user_memory_cache:
            self._user_memory_cache.behavior_stats.total_scans += 1
            if log.success:
                total_success = self._user_memory_cache.behavior_stats.total_scans
                total_with_current = (
                    self._user_memory_cache.behavior_stats.success_rate * (total_success - 1) + 1.0
                    if total_success > 1
                    else 1.0
                )
                self._user_memory_cache.behavior_stats.success_rate = total_with_current / total_success
            else:
                total_scans = self._user_memory_cache.behavior_stats.total_scans
                total_with_current = (
                    self._user_memory_cache.behavior_stats.success_rate * (total_scans - 1)
                    if total_scans > 1
                    else 0.0
                )
                self._user_memory_cache.behavior_stats.success_rate = total_with_current / total_scans

            self._persist_user_memory()

    def get_recent_executions(self, n: int = 10) -> List[ExecutionLog]:
        """获取最近的执行记录

        Args:
            n: 返回数量

        Returns:
            执行日志列表
        """
        return self._storage.get_execution_logs(limit=n)

    def get_project_executions(self, project_path: str, limit: int = 50) -> List[ExecutionLog]:
        """获取项目的执行历史

        Args:
            project_path: 项目路径
            limit: 返回数量限制

        Returns:
            执行日志列表
        """
        from .models import ProjectMemory
        project_hash = ProjectMemory.generate_hash(project_path)
        return self._storage.get_project_history(project_hash, limit)

    def search_similar_projects(self, tech_stack: List[str], limit: int = 5) -> List[ProjectMemory]:
        """搜索相似项目

        Args:
            tech_stack: 技术栈列表
            limit: 返回数量限制

        Returns:
            相似项目列表
        """
        return self._storage.search_projects_by_tech(tech_stack, limit)

    def get_all_projects(self) -> List[ProjectMemory]:
        """获取所有项目记忆

        Returns:
            项目记忆列表
        """
        return self._storage.load_all_project_memories()

    def clear_cache(self) -> None:
        """清除所有缓存"""
        self._user_memory_cache = None
        self._project_memory_cache.clear()
        self._last_cache_time.clear()
        logger.debug("Memory缓存已清除")

    def reset_all(self) -> None:
        """重置所有数据（危险操作）"""
        self._storage.clear_all_data()
        self.clear_cache()
        self._load_user_to_cache()
        logger.warning("所有Memory数据已重置")

    def get_storage_stats(self) -> Dict[str, Any]:
        """获取存储统计信息

        Returns:
            统计信息字典
        """
        return self._storage.get_storage_stats()

    def create_backup(self) -> str:
        """创建备份

        Returns:
            备份路径
        """
        return self._storage.create_backup()

    def _persist_user_memory(self) -> None:
        """持久化用户记忆"""
        if self._user_memory_cache:
            try:
                self._storage.save_user_memory(self._user_memory_cache)
            except Exception as e:
                logger.error(f"持久化用户记忆失败: {e}")


# 全局实例
_memory_manager: Optional[MemoryManager] = None


def get_memory_manager(base_path: Optional[Path] = None) -> MemoryManager:
    """获取全局MemoryManager实例

    Args:
        base_path: 可选的基础路径

    Returns:
        MemoryManager单例实例
    """
    global _memory_manager
    if _memory_manager is None:
        _memory_manager = MemoryManager(base_path)
    return _memory_manager
