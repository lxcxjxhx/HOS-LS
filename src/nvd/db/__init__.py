"""
NVD数据库模块 (SQLite版本)

提供NVD漏洞数据的数据库连接和模式定义功能：
- SQLiteConnection: SQLite数据库连接管理
- SQLiteSche: SQLite数据库模式定义
"""

from .sqlite_connection import SQLiteConnection
from .sqlite_schema import SQLiteSche

__all__ = ['SQLiteConnection', 'SQLiteSche']
