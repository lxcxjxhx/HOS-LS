"""Memory 存储管理器

提供基于JSON的本地存储功能，支持用户记忆、项目记忆和执行日志的持久化。
未来可扩展支持SQLite后端。
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from threading import Lock

from .models import UserMemory, ProjectMemory, ExecutionLog
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MemoryStorage:
    """Memory存储管理器

    提供线程安全的文件读写操作，支持自动备份。
    """

    def __init__(self, base_path: Optional[Path] = None):
        """初始化存储管理器

        Args:
            base_path: 基础路径，默认为 ~/.hos-ls/memory/
        """
        if base_path is None:
            base_path = Path.home() / ".hos-ls" / "memory"

        self.base_path = base_path
        self.user_file = base_path / "user.json"
        self.projects_dir = base_path / "projects"
        self.history_file = base_path / "history" / "logs.json"
        self.backup_dir = base_path / "backups"

        self._lock = Lock()

        self._ensure_directories()

    def _ensure_directories(self):
        """确保所有必要目录存在"""
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def save_user_memory(self, memory: UserMemory) -> None:
        """保存用户记忆

        Args:
            memory: 用户记忆对象
        """
        with self._lock:
            try:
                data = memory.to_dict()
                self._write_json(self.user_file, data)
                logger.debug(f"用户记忆已保存: {memory.user_id[:8]}...")
            except Exception as e:
                logger.error(f"保存用户记忆失败: {e}")
                raise

    def load_user_memory(self) -> Optional[UserMemory]:
        """加载用户记忆

        Returns:
            用户记忆对象，如果不存在则返回None
        """
        with self._lock:
            try:
                if not self.user_file.exists():
                    return None

                data = self._read_json(self.user_file)
                if data is None:
                    return None

                return UserMemory.from_dict(data)
            except Exception as e:
                logger.error(f"加载用户记忆失败: {e}")
                return None

    def save_project_memory(self, memory: ProjectMemory) -> None:
        """保存项目记忆

        Args:
            memory: 项目记忆对象
        """
        with self._lock:
            try:
                project_file = self.projects_dir / f"{memory.project_hash}.json"
                data = memory.to_dict()
                self._write_json(project_file, data)
                logger.debug(f"项目记忆已保存: {memory.project_hash} ({memory.project_path})")
            except Exception as e:
                logger.error(f"保存项目记忆失败: {e}")
                raise

    def load_project_memory(self, project_hash: str) -> Optional[ProjectMemory]:
        """加载项目记忆

        Args:
            project_hash: 项目hash

        Returns:
            项目记忆对象，如果不存在则返回None
        """
        with self._lock:
            try:
                project_file = self.projects_dir / f"{project_hash}.json"
                if not project_file.exists():
                    return None

                data = self._read_json(project_file)
                if data is None:
                    return None

                return ProjectMemory.from_dict(data)
            except Exception as e:
                logger.error(f"加载项目记忆失败: {e}")
                return None

    def load_all_project_memories(self) -> List[ProjectMemory]:
        """加载所有项目记忆

        Returns:
            项目记忆列表
        """
        memories = []
        with self._lock:
            try:
                for project_file in self.projects_dir.glob("*.json"):
                    try:
                        data = self._read_json(project_file)
                        if data:
                            memories.append(ProjectMemory.from_dict(data))
                    except Exception as e:
                        logger.warning(f"加载项目记忆失败 {project_file}: {e}")
            except Exception as e:
                logger.error(f"加载项目记忆列表失败: {e}")
        return memories

    def append_execution_log(self, log: ExecutionLog) -> None:
        """追加执行日志

        Args:
            log: 执行日志对象
        """
        with self._lock:
            try:
                logs = self._load_all_logs()
                logs.append(log.to_dict())

                # 保留最近1000条日志（防止文件过大）
                if len(logs) > 1000:
                    logs = logs[-1000:]

                self._write_json(self.history_file, logs)
                logger.debug(f"执行日志已追加: {log.log_id}")
            except Exception as e:
                logger.error(f"追加执行日志失败: {e}")
                raise

    def get_execution_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        target_path: Optional[str] = None,
    ) -> List[ExecutionLog]:
        """获取执行日志

        Args:
            limit: 返回数量限制
            offset: 偏移量
            target_path: 可选的目标路径过滤

        Returns:
            执行日志列表
        """
        with self._lock:
            try:
                all_logs = self._load_all_logs()

                # 过滤
                if target_path:
                    all_logs = [log for log in all_logs if log.get("target_path") == target_path]

                # 分页
                logs_data = all_logs[offset : offset + limit]

                return [ExecutionLog.from_dict(log_data) for log_data in logs_data]
            except Exception as e:
                logger.error(f"获取执行日志失败: {e}")
                return []

    def get_project_history(self, project_hash: str, limit: int = 50) -> List[ExecutionLog]:
        """获取项目的执行历史

        Args:
            project_hash: 项目hash
            limit: 返回数量限制

        Returns:
            该项目的执行日志列表
        """
        # 通过target_path匹配（需要反向查找）
        project_memory = self.load_project_memory(project_hash)
        if not project_memory:
            return []

        return self.get_execution_logs(limit=limit, target_path=project_memory.project_path)

    def search_projects_by_tech(self, tech_stack: List[str], limit: int = 5) -> List[ProjectMemory]:
        """根据技术栈搜索相似项目

        Args:
            tech_stack: 技术栈列表
            limit: 返回数量限制

        Returns:
            相似项目列表
        """
        all_projects = self.load_all_project_memories()
        tech_set = set(t.lower() for t in tech_stack)

        scored_projects = []
        for project in all_projects:
            project_tech_set = set(t.lower() for t in project.tech_stack)
            overlap = len(tech_set & project_tech_set)
            if overlap > 0:
                scored_projects.append((overlap, project))

        # 按重叠度排序
        scored_projects.sort(key=lambda x: x[0], reverse=True)

        return [project for _, project in scored_projects[:limit]]

    def create_backup(self) -> str:
        """创建备份

        Returns:
            备份文件路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{timestamp}"
        backup_path = self.backup_dir / backup_name

        try:
            shutil.copytree(self.base_path, backup_path, ignore=lambda _, files: ["backups"])
            logger.info(f"备份已创建: {backup_path}")
            return str(backup_path)
        except Exception as e:
            logger.error(f"创建备份失败: {e}")
            raise

    def restore_backup(self, backup_path: str) -> bool:
        """从备份恢复

        Args:
            backup_path: 备份路径

        Returns:
            是否成功
        """
        try:
            backup = Path(backup_path)
            if not backup.exists():
                logger.error(f"备份不存在: {backup_path}")
                return False

            # 先创建当前状态的备份
            self.create_backup()

            # 恢复
            shutil.rmtree(self.base_path)
            shutil.copytree(backup, self.base_path, ignore=lambda _, files: ["backups"])
            self._ensure_directories()

            logger.info(f"已从备份恢复: {backup_path}")
            return True
        except Exception as e:
            logger.error(f"恢复备份失败: {e}")
            return False

    def list_backups(self) -> List[Dict[str, Any]]:
        """列出所有备份

        Returns:
            备份信息列表
        """
        backups = []
        if not self.backup_dir.exists():
            return backups

        for backup_dir in sorted(self.backup_dir.glob("backup_*"), reverse=True):
            stat = backup_dir.stat()
            backups.append({
                "path": str(backup_dir),
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
            })

        return backups

    def clear_all_data(self) -> None:
        """清除所有数据（危险操作）"""
        with self._lock:
            try:
                # 创建最终备份
                self.create_backup()

                # 删除数据文件
                if self.user_file.exists():
                    self.user_file.unlink()

                for project_file in self.projects_dir.glob("*.json"):
                    project_file.unlink()

                if self.history_file.exists():
                    self.history_file.unlink()

                logger.warning("所有Memory数据已清除")
            except Exception as e:
                logger.error(f"清除数据失败: {e}")
                raise

    def get_storage_stats(self) -> Dict[str, Any]:
        """获取存储统计信息

        Returns:
            统计信息字典
        """
        stats = {
            "user_memory_exists": self.user_file.exists(),
            "project_count": len(list(self.projects_dir.glob("*.json"))),
            "history_size_kb": round(self.history_file.stat().st_size / 1024) if self.history_file.exists() else 0,
            "total_size_mb": 0,
        }

        total_size = 0
        for path in [self.user_file, self.history_file]:
            if path.exists():
                total_size += path.stat().st_size

        for project_file in self.projects_dir.glob("*.json"):
            total_size += project_file.stat().st_size

        stats["total_size_mb"] = round(total_size / (1024 * 1024), 2)

        return stats

    def _write_json(self, file_path: Path, data: Any) -> None:
        """写入JSON文件

        Args:
            file_path: 文件路径
            data: 数据
        """
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _read_json(self, file_path: Path) -> Optional[Any]:
        """读取JSON文件

        Args:
            file_path: 文件路径

        Returns:
            数据，读取失败返回None
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析错误 {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return None

    def _load_all_logs(self) -> List[Dict]:
        """加载所有执行日志

        Returns:
            日志字典列表
        """
        if not self.history_file.exists():
            return []

        data = self._read_json(self.history_file)
        if data is None:
            return []

        if isinstance(data, list):
            return data

        logger.warning(f"历史日志格式异常: {self.history_file}")
        return []
