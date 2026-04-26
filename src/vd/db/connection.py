"""VD数据库连接管理"""
import sqlite3
import threading
from pathlib import Path
from typing import Optional


class VDConnection:
    """VD漏洞数据库连接管理器"""

    _instance: Optional['VDConnection'] = None
    _lock = threading.Lock()

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = self._get_default_db_path()

        self.db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None
        self._local = threading.local()

    @classmethod
    def get_instance(cls, db_path: str = None) -> 'VDConnection':
        """获取单例实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(db_path)
        return cls._instance

    @classmethod
    def _get_default_db_path(cls) -> str:
        """获取默认数据库路径"""
        from .. import get_project_root
        project_root = get_project_root()
        db_dir = project_root / "data" / "vd"
        db_dir.mkdir(parents=True, exist_ok=True)
        return str(db_dir / "vuln_detection.db")

    def get_connection(self) -> sqlite3.Connection:
        """获取线程本地连接"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    def get_cursor(self):
        """获取游标"""
        return self.get_connection().cursor()

    def commit(self):
        """提交事务"""
        self.get_connection().commit()

    def close(self):
        """关闭连接"""
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.get_connection().rollback()
        else:
            self.commit()
