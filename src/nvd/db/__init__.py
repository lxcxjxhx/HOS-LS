"""
NVD数据库模块

提供NVD漏洞数据的数据库连接和模式定义功能：
- NVDConnection: 数据库连接管理
- NVDSche: 数据库模式定义
"""

from .connection import NVDConnection
from .schema import NVDSche

__all__ = ['NVDConnection', 'NVDSche']
