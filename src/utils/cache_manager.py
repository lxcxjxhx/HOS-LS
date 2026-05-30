"""缓存管理器

统一管理所有临时/状态数据文件
"""

import json
import os
import shutil
from pathlib import Path
from typing import Any, Optional, Dict
from datetime import datetime, timedelta


class CacheManager:
    """缓存管理器

    统一管理所有临时/状态数据文件到 .cache/hos-ls/ 目录
    """

    CACHE_DIR = Path(__file__).parent.parent.parent / '.cache' / 'hos-ls'

    SUBDIRS = {
        'scan_state': 'scan-state',
        'token_usage': 'token-usage',
        'pure_ai': 'pure-ai',
        'temp': 'temp'
    }

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not CacheManager._initialized:
            self._ensure_directories()
            CacheManager._initialized = True

    def _ensure_directories(self) -> None:
        """确保缓存目录存在"""
        for name, subdir in self.SUBDIRS.items():
            dir_path = self.CACHE_DIR / subdir
            dir_path.mkdir(parents=True, exist_ok=True)

    def get_path(self, category: str, filename: str) -> Path:
        """获取缓存文件路径

        Args:
            category: 分类（如 'scan_state', 'token_usage'）
            filename: 文件名

        Returns:
            完整的文件路径
        """
        subdir = self.SUBDIRS.get(category, 'temp')
        return self.CACHE_DIR / subdir / filename

    def _get_old_path(self, filename: str) -> Optional[Path]:
        """获取旧路径

        Args:
            filename: 文件名

        Returns:
            旧路径，如果不存在返回 None
        """
        old_path = Path.cwd() / filename
        if old_path.exists():
            return old_path
        return None

    def read_json(self, category: str, filename: str, default: Any = None) -> Any:
        """读取 JSON 缓存文件

        Args:
            category: 分类
            filename: 文件名
            default: 默认返回值

        Returns:
            读取的数据，失败返回 default
        """
        new_path = self.get_path(category, filename)

        if new_path.exists():
            try:
                with open(new_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                from src.utils.logger import get_logger
                logger = get_logger(__name__)
                logger.warning(f"读取缓存文件失败 {new_path}: {e}")

        old_path = self._get_old_path(filename)
        if old_path and old_path.exists():
            try:
                with open(old_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                self.write_json(category, filename, data)
                old_path.unlink()

                from src.utils.logger import get_logger
                logger = get_logger(__name__)
                logger.info(f"已迁移旧文件到新路径: {old_path} -> {new_path}")

                return data
            except Exception as e:
                from src.utils.logger import get_logger
                logger = get_logger(__name__)
                logger.warning(f"读取旧文件失败 {old_path}: {e}")

        return default

    def write_json(self, category: str, filename: str, data: Any) -> bool:
        """写入 JSON 缓存文件

        Args:
            category: 分类
            filename: 文件名
            data: 要写入的数据

        Returns:
            是否写入成功
        """
        path = self.get_path(category, filename)

        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            from src.utils.logger import get_logger
            logger = get_logger(__name__)
            logger.error(f"写入缓存文件失败 {path}: {e}")
            return False

    def exists(self, category: str, filename: str) -> bool:
        """检查缓存文件是否存在

        Args:
            category: 分类
            filename: 文件名

        Returns:
            是否存在
        """
        new_path = self.get_path(category, filename)
        if new_path.exists():
            return True

        old_path = self._get_old_path(filename)
        return old_path is not None and old_path.exists()

    def delete(self, category: str, filename: str) -> bool:
        """删除缓存文件

        Args:
            category: 分类
            filename: 文件名

        Returns:
            是否删除成功
        """
        path = self.get_path(category, filename)
        deleted = False

        if path.exists():
            try:
                path.unlink()
                deleted = True
            except Exception:
                pass

        old_path = self._get_old_path(filename)
        if old_path and old_path.exists():
            try:
                old_path.unlink()
                deleted = True
            except Exception:
                pass

        return deleted

    def cleanup_old_files(self, category: str, max_age_days: int = 7) -> int:
        """清理过期文件

        Args:
            category: 分类
            max_age_days: 最大保留天数

        Returns:
            删除的文件数量
        """
        subdir = self.SUBDIRS.get(category, 'temp')
        dir_path = self.CACHE_DIR / subdir
        deleted_count = 0

        if not dir_path.exists():
            return 0

        cutoff_time = datetime.now() - timedelta(days=max_age_days)

        for file_path in dir_path.glob('*.json'):
            try:
                mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if mtime < cutoff_time:
                    file_path.unlink()
                    deleted_count += 1
            except Exception:
                pass

        return deleted_count

    def cleanup_all(self, max_age_days: int = 7) -> Dict[str, int]:
        """清理所有类别的过期文件

        Args:
            max_age_days: 最大保留天数

        Returns:
            每类删除的文件数量
        """
        results = {}
        for category in self.SUBDIRS.keys():
            results[category] = self.cleanup_old_files(category, max_age_days)
        return results

    def get_cache_size(self) -> Dict[str, int]:
        """获取各类别缓存大小

        Returns:
            各类别的文件大小（字节）
        """
        sizes = {}
        for category, subdir in self.SUBDIRS.items():
            dir_path = self.CACHE_DIR / subdir
            total_size = 0

            if dir_path.exists():
                for file_path in dir_path.rglob('*'):
                    if file_path.is_file():
                        total_size += file_path.stat().st_size

            sizes[category] = total_size

        return sizes

    def list_files(self, category: str) -> list:
        """列出指定类别的所有文件

        Args:
            category: 分类

        Returns:
            文件路径列表
        """
        subdir = self.SUBDIRS.get(category, 'temp')
        dir_path = self.CACHE_DIR / subdir

        if not dir_path.exists():
            return []

        return [str(f) for f in dir_path.glob('*') if f.is_file()]


_global_cache_manager: Optional[CacheManager] = None


def get_cache_manager() -> CacheManager:
    """获取全局缓存管理器实例

    Returns:
        CacheManager 实例
    """
    global _global_cache_manager
    if _global_cache_manager is None:
        _global_cache_manager = CacheManager()
    return _global_cache_manager


def read_cache_json(category: str, filename: str, default: Any = None) -> Any:
    """快捷函数：读取缓存 JSON

    Args:
        category: 分类
        filename: 文件名
        default: 默认返回值

    Returns:
        读取的数据
    """
    return get_cache_manager().read_json(category, filename, default)


def write_cache_json(category: str, filename: str, data: Any) -> bool:
    """快捷函数：写入缓存 JSON

    Args:
        category: 分类
        filename: 文件名
        data: 数据

    Returns:
        是否成功
    """
    return get_cache_manager().write_json(category, filename, data)