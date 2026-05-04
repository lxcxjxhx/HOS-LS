import os
import sqlite3
from contextlib import contextmanager
from typing import Optional, Any, Dict
from dataclasses import dataclass
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class SQLiteConfig:
    """SQLite数据库配置"""
    database: str = "nvd_vulnerability.db"
    timeout: float = 30.0

class SQLiteConnection:
    """SQLite数据库连接管理器"""

    _instance: Optional['SQLiteConnection'] = None
    _connection: Optional[sqlite3.Connection] = None
    _cached_db_path: Optional[Path] = None

    def __init__(self, config: Optional[SQLiteConfig] = None):
        self.config = config or self._load_config()
        self._connection = None

    @classmethod
    def _load_config(cls) -> SQLiteConfig:
        """从环境变量加载配置或使用默认"""
        db_path = os.getenv('NVD_SQLITE_PATH', 'nvd_vulnerability.db')
        return SQLiteConfig(
            database=db_path,
            timeout=float(os.getenv('NVD_SQLITE_TIMEOUT', '30.0'))
        )

    @classmethod
    def _find_database_path(cls, db_path: str) -> Optional[Path]:
        """尝试多种方式查找数据库路径（增强稳定性）"""
        path = Path(db_path)

        if path.is_absolute() and path.exists() and path.is_file():
            logger.info(f"[DB] 使用绝对路径: {path}")
            return path.resolve()

        if path.exists() and path.is_file():
            return path.resolve()

        env_path = os.getenv('NVD_SQLITE_PATH')
        if env_path:
            env_db_path = Path(env_path)
            if env_db_path.exists() and env_db_path.is_file():
                logger.info(f"[DB] 使用环境变量路径: {env_db_path}")
                return env_db_path.resolve()

        project_root = cls._find_project_root()
        logger.debug(f"[DB] 项目根目录: {project_root}")

        search_locations = [
            project_root / 'All Vulnerabilities' / 'sql_data' / path.name,
            project_root / 'sql_data' / path.name,
            project_root / path.name,
            path,
        ]

        found_path = None
        for search_path in search_locations:
            search_path = search_path.resolve()
            logger.debug(f"[DB] 检查路径: {search_path}")

            if search_path.exists() and search_path.is_file():
                try:
                    test_conn = sqlite3.connect(str(search_path), timeout=1.0)
                    test_conn.execute("SELECT 1")
                    test_conn.close()
                    logger.info(f"[DB] 找到有效数据库: {search_path}")
                    found_path = search_path
                    break
                except Exception as e:
                    logger.debug(f"[DB] 数据库文件存在但无法打开: {search_path}, 错误: {e}")
                    if search_path.suffix != '.db':
                        db_attempt = search_path.with_suffix('.db')
                        if db_attempt.exists() and db_attempt.is_file():
                            try:
                                test_conn = sqlite3.connect(str(db_attempt), timeout=1.0)
                                test_conn.execute("SELECT 1")
                                test_conn.close()
                                logger.info(f"[DB] 找到有效数据库(自动添加后缀): {db_attempt}")
                                found_path = db_attempt
                                break
                            except Exception:
                                pass

        cls._cached_db_path = found_path
        return found_path

    @classmethod
    def _find_project_root(cls) -> Path:
        """查找项目根目录（增强稳定性）"""
        possible_roots = [
            Path.cwd(),
            Path(__file__).parent.parent.parent.parent,
            Path(__file__).parent.parent.parent,
            Path(os.getcwd()),
            Path.home() / 'projects' / 'HOS-LS' if (Path.home() / 'projects' / 'HOS-LS').exists() else None,
        ]

        for root in possible_roots:
            if root and root.exists() and root.is_dir():
                candidate = root / 'All Vulnerabilities'
                if candidate.exists() and candidate.is_dir():
                    return root
                if (root / 'src').exists():
                    return root

        return Path.cwd()

    @classmethod
    def get_instance(cls) -> 'SQLiteConnection':
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def connect(self) -> None:
        """初始化数据库连接"""
        if self._connection is None:
            db_path = Path(self.config.database)

            if not db_path.is_absolute():
                found_path = self._find_database_path(str(db_path))
                if found_path:
                    db_path = found_path
                else:
                    default_path = Path(__file__).parent.parent.parent.parent / 'All Vulnerabilities' / 'sql_data' / self.config.database
                    if default_path.exists():
                        db_path = default_path
                    else:
                        logger.warning(f"NVD数据库未找到: {self.config.database}")
                        logger.warning(f"请确保数据库文件存在于以下位置之一:")
                        logger.warning(f"  - {default_path}")
                        logger.warning(f"  - ./All Vulnerabilities/sql_data/{self.config.database}")
                        logger.warning(f"  - ./sql_data/{self.config.database}")
                        return

            if not db_path.exists():
                logger.warning(f"NVD数据库文件不存在: {db_path}")
                return

            self._connection = sqlite3.connect(str(db_path), timeout=self.config.timeout)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA cache_size=-64000")
            self._connection.execute("PRAGMA temp_store=MEMORY")
            logger.info(f"NVD数据库连接成功: {db_path}")

    def disconnect(self) -> None:
        """关闭数据库连接"""
        if self._connection:
            self._connection.close()
            self._connection = None

    @property
    def connection(self) -> sqlite3.Connection:
        """获取连接属性"""
        if self._connection is None:
            self.connect()
        return self._connection

    @contextmanager
    def get_connection(self):
        """获取数据库连接的上下文管理器"""
        if self._connection is None:
            self.connect()

        try:
            yield self._connection
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    @contextmanager
    def get_cursor(self, cursor_factory=None):
        """获取数据库游标的上下文管理器"""
        with self.get_connection() as conn:
            if cursor_factory:
                cursor = conn.cursor(cursor_factory=cursor_factory)
            else:
                cursor = conn.cursor()
            try:
                yield cursor
            finally:
                cursor.close()

    def execute(self, query: str, params: tuple = None) -> None:
        """执行SQL查询"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())

    def fetch_one(self, query: str, params: tuple = None) -> Optional[Any]:
        """获取单条记录"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())
            row = cursor.fetchone()
            return tuple(row) if row else None

    def fetch_all(self, query: str, params: tuple = None) -> list:
        """获取所有记录"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())
            return [tuple(row) for row in cursor.fetchall()]

    def execute_batch(self, query: str, params_list: list) -> None:
        """批量执行SQL"""
        with self.get_cursor() as cursor:
            cursor.executemany(query, params_list)

    def table_exists(self, table_name: str) -> bool:
        """检查表是否存在"""
        query = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
        result = self.fetch_one(query, (table_name,))
        return result is not None

    def get_table_columns(self, table_name: str) -> list:
        """获取表的所有列名"""
        query = f"PRAGMA table_info({table_name})"
        results = self.fetch_all(query)
        return [r[1] for r in results] if results else []

    def get_vulnerability_stats(self) -> Dict[str, int]:
        """获取漏洞数据库统计信息"""
        stats = {}
        tables = ['cve', 'cvss', 'cpe', 'cwe', 'cve_cwe', 'kev', 'exploit', 'poc']

        with self.get_cursor() as cursor:
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    stats[table] = count
                except Exception as e:
                    stats[table] = 0
                    logger.debug(f"获取表 {table} 统计失败: {e}")

        return stats

    def is_connected(self) -> bool:
        """检查数据库是否已连接"""
        return self._connection is not None

    def __enter__(self):
        """上下文管理器入口"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        if exc_type is None:
            self._connection.commit()
        else:
            if self._connection:
                self._connection.rollback()
        return False
