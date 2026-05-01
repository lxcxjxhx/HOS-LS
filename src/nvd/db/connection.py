import os
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
from typing import Optional, Any
from dataclasses import dataclass

@dataclass
class NVDConfig:
    """NVD数据库配置"""
    host: str = "localhost"
    port: int = 5432
    database: str = "nvd_vulnerability"
    user: str = "postgres"
    password: str = ""
    min_connections: int = 1
    max_connections: int = 10

class NVDConnection:
    """NVD漏洞数据库连接管理器"""

    _instance: Optional['NVDConnection'] = None
    _pool: Optional[pool.ThreadedConnectionPool] = None

    def __init__(self, config: Optional[NVDConfig] = None):
        self.config = config or self._load_config_from_env()

    @classmethod
    def _load_config_from_env(cls) -> NVDConfig:
        """从环境变量加载配置"""
        return NVDConfig(
            host=os.getenv('NVD_DB_HOST', 'localhost'),
            port=int(os.getenv('NVD_DB_PORT', '5432')),
            database=os.getenv('NVD_DB_NAME', 'nvd_vulnerability'),
            user=os.getenv('NVD_DB_USER', 'postgres'),
            password=os.getenv('NVD_DB_PASSWORD', ''),
            min_connections=int(os.getenv('NVD_DB_MIN_CONN', '1')),
            max_connections=int(os.getenv('NVD_DB_MAX_CONN', '10'))
        )

    @classmethod
    def get_instance(cls) -> 'NVDConnection':
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def connect(self) -> None:
        """初始化连接池"""
        if self._pool is None:
            self._pool = pool.ThreadedConnectionPool(
                self.config.min_connections,
                self.config.max_connections,
                host=self.config.host,
                port=self.config.port,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password
            )

    def disconnect(self) -> None:
        """关闭连接池"""
        if self._pool:
            self._pool.closeall()
            self._pool = None

    @contextmanager
    def get_connection(self):
        """获取数据库连接的上下文管理器"""
        if self._pool is None:
            self.connect()

        conn = self._pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    @contextmanager
    def get_cursor(self, cursor_factory=None):
        """获取数据库游标的上下文管理器"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cursor
            finally:
                cursor.close()

    def execute(self, query: str, params: tuple = None) -> None:
        """执行SQL查询"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)

    def fetch_one(self, query: str, params: tuple = None) -> Optional[Any]:
        """获取单条记录"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchone()

    def fetch_all(self, query: str, params: tuple = None) -> list:
        """获取所有记录"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()

    def execute_batch(self, query: str, params_list: list) -> None:
        """批量执行SQL"""
        with self.get_cursor() as cursor:
            cursor.executemany(query, params_list)

    def table_exists(self, table_name: str) -> bool:
        """检查表是否存在"""
        query = """
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = %s
            )
        """
        result = self.fetch_one(query, (table_name,))
        return result[0] if result else False

    def get_table_columns(self, table_name: str) -> list:
        """获取表的所有列名"""
        query = """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = %s
            ORDER BY ordinal_position
        """
        results = self.fetch_all(query, (table_name,))
        return [r[0] for r in results] if results else []

    def __enter__(self):
        """上下文管理器入口"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.disconnect()
        return False
