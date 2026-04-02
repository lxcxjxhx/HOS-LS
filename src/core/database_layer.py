import asyncio
import sqlite3
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool

class DatabaseLayer:
    _instance = None
    _engine = None
    _async_engine = None
    _session_factory = None
    _async_session_factory = None
    _scoped_session = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseLayer, cls).__new__(cls)
        return cls._instance

    def initialize(self, db_path="provenance.db", enable_wal=True):
        self._init_sync_engine(db_path, enable_wal)
        self._init_async_engine(db_path, enable_wal)
        self._init_session_factories()

    def _init_sync_engine(self, db_path, enable_wal):
        sync_url = f"sqlite:///{db_path}"
        self._engine = create_engine(
            sync_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )
        if enable_wal:
            with self._engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA synchronous=NORMAL"))
                conn.execute(text("PRAGMA busy_timeout=30000"))

    def _init_async_engine(self, db_path, enable_wal):
        async_url = f"sqlite+aiosqlite:///{db_path}"
        self._async_engine = create_async_engine(
            async_url,
            connect_args={"check_same_thread": False}
        )
        if enable_wal:
            asyncio.run(self._enable_wal_async())

    async def _enable_wal_async(self):
        async with self._async_engine.connect() as conn:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA synchronous=NORMAL"))
            await conn.execute(text("PRAGMA busy_timeout=30000"))
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
        with self.get_session() as session:
            result = session.execute(query, params or {})
            session.commit()
            return result

    async def execute_async(self, query, params=None):
        async with await self.get_async_session() as session:
            result = await session.execute(query, params or {})
            await session.commit()
            return result

    def create_tables(self, Base):
        Base.metadata.create_all(bind=self._engine)

    async def create_tables_async(self, Base):
        async with self._async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def dispose(self):
        if self._engine:
            self._engine.dispose()
        if self._async_engine:
            asyncio.run(self._async_engine.dispose())
        if self._scoped_session:
            self._scoped_session.remove()

database_layer = DatabaseLayer()
