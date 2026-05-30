"""SQLite连接管理模块

提供NVD SQLite数据库的连接管理功能
优化：确保连接正确关闭，临时文件及时清理
"""

import sqlite3
import os
import gc
from pathlib import Path
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class SQLiteConnection:
    """SQLite数据库连接管理器（单例模式）
    
    优化：
    - 使用上下文管理器确保连接正确关闭
    - 添加连接池管理
    - 确保SQLite临时文件及时清理
    """
    
    _instance: Optional['SQLiteConnection'] = None
    _lock = __import__('threading').Lock()
    
    def __init__(self, db_path: Optional[str] = None):
        """初始化SQLite连接
        
        Args:
            db_path: 数据库路径，如果不提供则使用默认路径
        """
        if db_path is None:
            db_path = self._find_database_path()
        
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._is_connected = False
        
        if db_path and os.path.exists(db_path):
            self._connect()
            if self._is_connected:
                logger.info(f"SQLite连接成功: {db_path}")
        else:
            logger.warning(f"SQLite数据库文件不存在: {db_path}")
    
    @staticmethod
    def _find_database_path() -> Optional[str]:
        """查找默认的NVD数据库路径（静态方法，可被外部调用）"""
        possible_paths = [
            Path(__file__).parent.parent.parent.parent / 'All Vulnerabilities' / 'sql_data' / 'nvd_vulnerability.db',
            Path('c:/1AAA_PROJECT/HOS/HOS-LS/HOS-LS/All Vulnerabilities/sql_data/nvd_vulnerability.db'),
            Path.cwd() / 'All Vulnerabilities' / 'sql_data' / 'nvd_vulnerability.db',
        ]
        
        for path in possible_paths:
            if path.exists() and path.is_file():
                # 使用 check_db 函数测试连接，确保连接被正确关闭
                if SQLiteConnection._check_db_accessible(str(path)):
                    logger.info(f"找到NVD数据库: {path}")
                    return str(path)
        
        return None
    
    @staticmethod
    def _check_db_accessible(db_path: str) -> bool:
        """检查数据库是否可访问（测试后立即关闭连接并清理临时文件）

        Args:
            db_path: 数据库路径

        Returns:
            是否可访问
        """
        test_conn = None
        try:
            test_conn = sqlite3.connect(db_path, timeout=1.0)
            test_conn.execute("SELECT 1")
            test_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            test_conn.close()
            test_conn = None
            return True
        except Exception:
            return False
        finally:
            if test_conn is not None:
                try:
                    test_conn.close()
                except Exception:
                    pass
            gc.collect()
    
    def _connect(self) -> bool:
        """连接到SQLite数据库
        
        优化：
        - 设置 WAL 模式提高并发性能
        - 设置适当的超时
        - 启用自动清理临时文件
        """
        if self._is_connected and self._conn is not None:
            return True
            
        try:
            self._conn = sqlite3.connect(
                self._db_path,
                timeout=30.0,
                isolation_level=None  # 自动提交模式
            )
            self._conn.row_factory = sqlite3.Row
            
            # 启用 WAL 模式提高性能
            self._conn.execute("PRAGMA journal_mode=WAL")
            # 设置自动清理
            self._conn.execute("PRAGMA wal_autocheckpoint=1000")
            # 优化临时文件清理
            self._conn.execute("PRAGMA synchronous=NORMAL")
            
            self._is_connected = True
            return True
        except Exception as e:
            logger.error(f"SQLite连接失败: {e}")
            self._is_connected = False
            self._conn = None
            return False
    
    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> 'SQLiteConnection':
        """获取单例实例（线程安全）
        
        Args:
            db_path: 数据库路径
            
        Returns:
            SQLiteConnection实例
        """
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance
    
    @classmethod
    def reset_instance(cls):
        """重置单例实例（用于测试）"""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None
    
    @classmethod
    def find_database_path(cls) -> Optional[str]:
        """公开方法：查找数据库路径（供外部调用）
        
        Returns:
            数据库路径或None
        """
        return cls._find_database_path()
    
    def get_cursor(self) -> sqlite3.Cursor:
        """获取游标
        
        Returns:
            sqlite3.Cursor实例
        """
        if not self._is_connected or self._conn is None:
            if not self._connect():
                raise RuntimeError("数据库未连接且连接失败")
        return self._conn.cursor()
    
    def table_exists(self, table_name: str) -> bool:
        """检查表是否存在
        
        Args:
            table_name: 表名
            
        Returns:
            表是否存在
        """
        try:
            cursor = self.get_cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            )
            result = cursor.fetchone() is not None
            cursor.close()
            return result
        except Exception as e:
            logger.error(f"检查表存在失败: {e}")
            return False
    
    def get_vulnerability_stats(self) -> dict:
        """获取漏洞数据库统计信息"""
        stats = {}
        tables = ['cve', 'cvss', 'cpe', 'cwe', 'cve_cwe', 'kev', 'exploit', 'poc']
        
        try:
            cursor = self.get_cursor()
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    stats[table] = count
                except Exception:
                    stats[table] = 0
            cursor.close()
        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
        
        return stats
    
    def close(self):
        """关闭数据库连接并清理临时文件"""
        if self._conn is not None:
            try:
                # 检查点确保WAL文件被合并
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.close()
            except Exception as e:
                logger.debug(f"关闭连接时出错（可忽略）: {e}")
            finally:
                self._conn = None
                self._is_connected = False
                # 强制垃圾回收，确保SQLite临时文件被清理
                gc.collect()
                logger.info("SQLite连接已关闭")
    
    def is_connected(self) -> bool:
        """检查连接状态"""
        if not self._is_connected or self._conn is None:
            return False
        try:
            self._conn.execute("SELECT 1")
            return True
        except Exception:
            self._is_connected = False
            return False
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出时关闭连接"""
        self.close()
        return False
    
    def __del__(self):
        """析构时关闭连接"""
        self.close()
