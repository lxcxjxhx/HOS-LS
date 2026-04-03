import asyncio
import sqlite3
import threading
import time
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool, QueuePool

class DatabaseLayer:
    _instance = None
    _lock = threading.Lock()
    _engine = None
    _async_engine = None
    _session_factory = None
    _async_session_factory = None
    _scoped_session = None
    _write_lock = threading.Lock()  # 单写锁

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(DatabaseLayer, cls).__new__(cls)
        return cls._instance

    def initialize(self, db_path="provenance.db", enable_wal=True):
        self.db_path = db_path
        self._init_sync_engine(db_path, enable_wal)
        self._init_async_engine(db_path, enable_wal)
        self._init_session_factories()

    def _init_sync_engine(self, db_path, enable_wal):
        sync_url = f"sqlite:///{db_path}"
        # 使用QueuePool替代StaticPool以更好地处理并发
        self._engine = create_engine(
            sync_url,
            connect_args={
                "check_same_thread": False,
                "timeout": 30.0,  # 连接超时30秒
            },
            poolclass=QueuePool,
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=3600,
            echo=False
        )
        if enable_wal:
            with self._engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA synchronous=NORMAL"))
                conn.execute(text("PRAGMA busy_timeout=30000"))  # 30秒busy超时
                conn.execute(text("PRAGMA temp_store=MEMORY"))
                conn.execute(text("PRAGMA mmap_size=30000000000"))
                conn.commit()

    def _init_async_engine(self, db_path, enable_wal):
        async_url = f"sqlite+aiosqlite:///{db_path}"
        self._async_engine = create_async_engine(
            async_url,
            connect_args={
                "check_same_thread": False,
                "timeout": 30.0,
            },
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=3600,
            echo=False
        )
        if enable_wal:
            asyncio.run(self._enable_wal_async())

    async def _enable_wal_async(self):
        async with self._async_engine.connect() as conn:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA synchronous=NORMAL"))
            await conn.execute(text("PRAGMA busy_timeout=30000"))
            await conn.execute(text("PRAGMA temp_store=MEMORY"))
            await conn.commit()

    def _init_session_factories(self):
        self._session_factory = sessionmaker(bind=self._engine)
        self._async_session_factory = sessionmaker(
            bind=self._async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        self._scoped_session = scoped_session(self._session_factory)

    def get_session(self):
        return self._scoped_session()

    async def get_async_session(self):
        return self._async_session_factory()

    def execute_sync(self, query, params=None):
        """同步执行查询 - 使用写锁确保串行化"""
        with self._write_lock:
            max_retries = 3
            retry_delay = 0.1
            
            for attempt in range(max_retries):
                try:
                    with self.get_session() as session:
                        result = session.execute(query, params or {})
                        session.commit()
                        return result
                except Exception as e:
                    if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                        time.sleep(retry_delay * (attempt + 1))
                        continue
                    raise

    async def execute_async(self, query, params=None):
        """异步执行查询 - 使用写锁确保串行化"""
        with self._write_lock:
            max_retries = 3
            retry_delay = 0.1
            
            for attempt in range(max_retries):
                try:
                    async with await self.get_async_session() as session:
                        result = await session.execute(query, params or {})
                        await session.commit()
                        return result
                except Exception as e:
                    if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay * (attempt + 1))
                        continue
                    raise

    def execute_read_sync(self, query, params=None):
        """同步读操作 - 不需要写锁"""
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                with self.get_session() as session:
                    result = session.execute(query, params or {})
                    return result
            except Exception as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                raise

    async def execute_read_async(self, query, params=None):
        """异步读操作 - 不需要写锁"""
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                async with await self.get_async_session() as session:
                    result = await session.execute(query, params or {})
                    return result
            except Exception as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay * (attempt + 1))
                    continue
                raise

    def create_tables(self, Base):
        with self._write_lock:
            Base.metadata.create_all(bind=self._engine)

    async def create_tables_async(self, Base):
        with self._write_lock:
            async with self._async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

    def get_sqlite_connection(self):
        """获取原始sqlite3连接 - 用于兼容旧代码"""
        conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,
            check_same_thread=False
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def dispose(self):
        if self._engine:
            self._engine.dispose()
        if self._async_engine:
            asyncio.run(self._async_engine.dispose())
        if self._scoped_session:
            self._scoped_session.remove()

database_layer = DatabaseLayer()
