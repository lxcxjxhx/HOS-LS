"""增量扫描缓存管理器

支持增量扫描，跳过未变更的文件，提高扫描效率。
"""

import hashlib
import json
import pickle
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import logging

logger = logging.getLogger(__name__)


@dataclass
class FileCacheEntry:
    """文件缓存条目"""
    file_path: str
    content_hash: str
    last_modified: float
    analysis_result: Optional[str] = None
    analysis_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class IncrementalScanCache:
    """增量扫描缓存管理器

    管理文件分析结果的缓存，支持基于内容哈希的变更检测。
    """

    CACHE_VERSION = "1.0"
    CACHE_FILE = ".hos_scan_cache.pkl"

    def __init__(self, project_root: str):
        """初始化增量扫描缓存

        Args:
            project_root: 项目根目录
        """
        self.project_root = Path(project_root)
        self.cache_file = self.project_root / self.CACHE_FILE
        self.entries: Dict[str, FileCacheEntry] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        """加载缓存文件"""
        if not self.cache_file.exists():
            return

        try:
            with open(self.cache_file, 'rb') as f:
                data = pickle.load(f)

            if data.get('version') != self.CACHE_VERSION:
                logger.info("缓存版本不匹配，将重新创建缓存")
                return

            for file_path, entry_data in data.get('entries', {}).items():
                self.entries[file_path] = FileCacheEntry(**entry_data)

            logger.info(f"已加载 {len(self.entries)} 个缓存条目")
        except Exception as e:
            logger.warning(f"加载缓存失败: {e}")

    def _save_cache(self) -> None:
        """保存缓存文件"""
        try:
            data = {
                'version': self.CACHE_VERSION,
                'entries': {
                    fp: {
                        'file_path': entry.file_path,
                        'content_hash': entry.content_hash,
                        'last_modified': entry.last_modified,
                        'analysis_result': entry.analysis_result,
                        'analysis_time': entry.analysis_time,
                        'metadata': entry.metadata,
                    }
                    for fp, entry in self.entries.items()
                },
                'saved_at': datetime.now().isoformat(),
            }

            with open(self.cache_file, 'wb') as f:
                pickle.dump(data, f)

            logger.debug(f"已保存 {len(self.entries)} 个缓存条目")
        except Exception as e:
            logger.warning(f"保存缓存失败: {e}")

    def compute_file_hash(self, file_path: str) -> str:
        """计算文件内容哈希

        Args:
            file_path: 文件路径

        Returns:
            文件内容哈希
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return ""

            with open(path, 'rb') as f:
                content = f.read()
                return hashlib.sha256(content).hexdigest()
        except Exception as e:
            logger.debug(f"计算文件哈希失败 {file_path}: {e}")
            return ""

    def get_changed_files(
        self,
        file_paths: List[str],
        force_full: bool = False,
    ) -> List[str]:
        """获取变更的文件列表

        Args:
            file_paths: 要检查的文件列表
            force_full: 是否强制全量扫描

        Returns:
            变更的文件列表
        """
        if force_full:
            logger.info("强制全量扫描模式")
            return file_paths

        changed_files = []

        for file_path in file_paths:
            if not self._is_cached(file_path):
                changed_files.append(file_path)
                continue

            current_hash = self.compute_file_hash(file_path)
            cached_entry = self.entries.get(file_path)

            if not cached_entry or current_hash != cached_entry.content_hash:
                changed_files.append(file_path)

        if changed_files:
            logger.info(f"发现 {len(changed_files)} 个变更文件 (共 {len(file_paths)} 个)")
        else:
            logger.info("所有文件未变更，可使用缓存结果")

        return changed_files

    def _is_cached(self, file_path: str) -> bool:
        """检查文件是否在缓存中

        Args:
            file_path: 文件路径

        Returns:
            是否在缓存中
        """
        return file_path in self.entries

    def get_cached_result(self, file_path: str) -> Optional[str]:
        """获取缓存的分析结果

        Args:
            file_path: 文件路径

        Returns:
            缓存的分析结果
        """
        if file_path not in self.entries:
            return None

        entry = self.entries[file_path]
        current_hash = self.compute_file_hash(file_path)

        if current_hash != entry.content_hash:
            return None

        return entry.analysis_result

    def save_result(
        self,
        file_path: str,
        content_hash: str,
        analysis_result: str,
        analysis_time: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """保存分析结果到缓存

        Args:
            file_path: 文件路径
            content_hash: 文件内容哈希
            analysis_result: 分析结果
            analysis_time: 分析耗时
            metadata: 元数据
        """
        path = Path(file_path)

        entry = FileCacheEntry(
            file_path=file_path,
            content_hash=content_hash,
            last_modified=path.stat().st_mtime if path.exists() else 0.0,
            analysis_result=analysis_result,
            analysis_time=analysis_time,
            metadata=metadata or {},
        )

        self.entries[file_path] = entry

    def invalidate(self, file_path: Optional[str] = None) -> None:
        """使缓存失效

        Args:
            file_path: 要失效的文件路径，None 表示清除所有缓存
        """
        if file_path is None:
            self.entries.clear()
            logger.info("已清除所有缓存")
        elif file_path in self.entries:
            del self.entries[file_path]
            logger.debug(f"已清除缓存: {file_path}")

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息

        Returns:
            缓存统计信息
        """
        total_entries = len(self.entries)
        total_time = sum(e.analysis_time for e in self.entries.values())

        return {
            'total_entries': total_entries,
            'total_analysis_time': total_time,
            'cache_file': str(self.cache_file),
            'version': self.CACHE_VERSION,
        }

    def close(self) -> None:
        """关闭并保存缓存"""
        self._save_cache()


def get_incremental_cache(project_root: str) -> IncrementalScanCache:
    """获取增量扫描缓存实例

    Args:
        project_root: 项目根目录

    Returns:
        增量扫描缓存实例
    """
    return IncrementalScanCache(project_root)
