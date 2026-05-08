"""数据库连接模块

提供 SQLite 数据库连接管理功能，支持 WAL 模式和连接池。
"""

import asyncio
from pathlib import Path
from typing import Optional

import aiosqlite

from src.core.config import Config, get_config


class DatabaseManager:
    """数据库管理器

    管理 SQLite 数据库连接和事务。
    """

    _instance: Optional["DatabaseManager"] = None
    _initialized: bool = False

    def __new__(cls) -> "DatabaseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self._config: Optional[Config] = None
            self._connection: Optional[aiosqlite.Connection] = None
            self._initialized = True

    async def initialize(self, config: Optional[Config] = None) -> None:
        """初始化数据库

        Args:
            config: 配置对象
        """
        self._config = config or get_config()

        # 解析数据库 URL
        db_url = self._config.database.url
        if db_url.startswith("sqlite:///"):
            db_path = db_url[10:]
        else:
            db_path = db_url

        # 创建数据库目录
        db_path = Path(db_path).expanduser().resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # 连接数据库
        self._connection = await aiosqlite.connect(str(db_path))

        # 启用 WAL 模式
        if self._config.database.wal_mode:
            await self._connection.execute("PRAGMA journal_mode=WAL")

        # 创建表
        await self._create_tables()

    async def _create_tables(self) -> None:
        """创建数据库表"""
        if self._connection is None:
            raise RuntimeError("数据库未初始化")

        # 扫描表
        await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                duration REAL,
                total_findings INTEGER DEFAULT 0,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 发现表
        await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                file_path TEXT,
                line INTEGER,
                column INTEGER,
                confidence REAL,
                message TEXT,
                code_snippet TEXT,
                fix_suggestion TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        """)

        # 创建索引
        await self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id)
        """)
        await self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity)
        """)
        await self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings (rule_id)
        """)

        await self._connection.commit()

    async def close(self) -> None:
        """关闭数据库连接"""
        if self._connection:
            await self._connection.close()
            self._connection = None

    async def execute(self, sql: str, parameters: Optional[tuple] = None) -> aiosqlite.Cursor:
        """执行 SQL 语句

        Args:
            sql: SQL 语句
            parameters: 参数

        Returns:
            游标对象
        """
        if self._connection is None:
            raise RuntimeError("数据库未初始化")

        if parameters:
            return await self._connection.execute(sql, parameters)
        return await self._connection.execute(sql)

    async def executemany(self, sql: str, parameters: list) -> aiosqlite.Cursor:
        """执行多条 SQL 语句

        Args:
            sql: SQL 语句
            parameters: 参数列表

        Returns:
            游标对象
        """
        if self._connection is None:
            raise RuntimeError("数据库未初始化")

        return await self._connection.executemany(sql, parameters)

    async def fetchone(self, sql: str, parameters: Optional[tuple] = None) -> Optional[tuple]:
        """获取一条记录

        Args:
            sql: SQL 语句
            parameters: 参数

        Returns:
            记录元组
        """
        cursor = await self.execute(sql, parameters)
        return await cursor.fetchone()

    async def fetchall(self, sql: str, parameters: Optional[tuple] = None) -> list:
        """获取所有记录

        Args:
            sql: SQL 语句
            parameters: 参数

        Returns:
            记录列表
        """
        cursor = await self.execute(sql, parameters)
        return await cursor.fetchall()

    async def commit(self) -> None:
        """提交事务"""
        if self._connection:
            await self._connection.commit()

    @property
    def connection(self) -> Optional[aiosqlite.Connection]:
        """获取数据库连接"""
        return self._connection


# 全局实例
_db_manager: Optional[DatabaseManager] = None


async def get_db_manager(config: Optional[Config] = None) -> DatabaseManager:
    """获取数据库管理器实例

    Args:
        config: 配置对象

    Returns:
        数据库管理器实例
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        await _db_manager.initialize(config)
    return _db_manager
