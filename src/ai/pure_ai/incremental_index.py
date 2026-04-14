import hashlib
import os
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class FileIndexEntry:
    file_path: str
    file_hash: str
    mtime: float
    size: int
    indexed_at: float
    language: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileIndexEntry':
        return cls(**data)


class IncrementalIndexManager:
    """增量索引管理器

    用于高效扫描的增量索引管理，支持基于文件哈希和修改时间的智能变更检测
    """

    def __init__(self, project_path: str, config: Optional[Dict[str, Any]] = None):
        """初始化增量索引管理器

        Args:
            project_path: 项目根目录路径
            config: 配置参数
        """
        self.project_path = project_path
        self.config = config or {}
        self._index: Dict[str, FileIndexEntry] = {}

        self.index_dir = Path(self.config.get('index_dir', '.hos-ls/indexes'))
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self.index_dir / f"{self._get_project_hash()}.json"

        self._hash_cache_size = self.config.get('hash_cache_size', 65536)
        self._mtime_cache: Dict[str, float] = {}

    def _get_project_hash(self) -> str:
        """获取项目唯一标识哈希

        Returns:
            项目路径的哈希值
        """
        return hashlib.sha256(self.project_path.encode('utf-8')).hexdigest()[:16]

    def _compute_file_hash(self, file_path: str) -> Optional[str]:
        """计算文件SHA256哈希值

        Args:
            file_path: 文件路径

        Returns:
            文件哈希值，失败返回None
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(self._hash_cache_size), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def is_index_valid(self) -> bool:
        """检查索引是否有效

        Returns:
            索引是否存在且有效
        """
        if not self._index_path.exists():
            return False
        try:
            with open(self._index_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict) or 'entries' not in data:
                return False
            return True
        except Exception:
            return False

    def _load_index(self) -> bool:
        """从磁盘加载索引

        Returns:
            是否成功加载索引
        """
        if not self.is_index_valid():
            return False
        try:
            with open(self._index_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            entries = data.get('entries', {})
            self._index = {
                path: FileIndexEntry.from_dict(entry_data)
                for path, entry_data in entries.items()
            }
            return True
        except Exception:
            return False

    def _save_index(self) -> bool:
        """保存索引到磁盘

        Returns:
            是否成功保存索引
        """
        try:
            data = {
                'version': '1.0',
                'project_path': self.project_path,
                'created_at': time.time(),
                'updated_at': time.time(),
                'entries': {
                    path: entry.to_dict()
                    for path, entry in self._index.items()
                }
            }
            with open(self._index_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    def build_index(self, files: List[str]) -> int:
        """构建完整索引

        Args:
            files: 文件路径列表

        Returns:
            索引的文件数量
        """
        self._index.clear()
        current_time = time.time()
        indexed_count = 0

        for file_path in files:
            try:
                stat = os.stat(file_path)
                file_hash = self._compute_file_hash(file_path)
                if file_hash is None:
                    continue

                self._index[file_path] = FileIndexEntry(
                    file_path=file_path,
                    file_hash=file_hash,
                    mtime=stat.st_mtime,
                    size=stat.st_size,
                    indexed_at=current_time
                )
                indexed_count += 1
            except Exception:
                continue

        self._save_index()
        return indexed_count

    def detect_changes(self, current_files: List[str]) -> Dict[str, Set[str]]:
        """检测文件变更

        性能要求: 1000个文件 < 100ms

        Args:
            current_files: 当前文件列表

        Returns:
            变更信息字典，包含changed(变更)、added(新增)、removed(移除)文件集合
        """
        start_time = time.time()

        current_files_set = set(current_files)
        indexed_files_set = set(self._index.keys())

        removed = indexed_files_set - current_files_set
        added = current_files_set - indexed_files_set

        changed: Set[str] = set()
        for file_path in current_files_set & indexed_files_set:
            try:
                stat = os.stat(file_path)
                indexed_entry = self._index[file_path]

                if stat.st_mtime > indexed_entry.mtime or stat.st_size != indexed_entry.size:
                    current_hash = self._compute_file_hash(file_path)
                    if current_hash and current_hash != indexed_entry.file_hash:
                        changed.add(file_path)
            except Exception:
                continue

        elapsed = time.time() - start_time
        if elapsed > 0.1 and len(current_files) >= 1000:
            print(f"[IncrementalIndex] 变更检测耗时: {elapsed*1000:.2f}ms (文件数: {len(current_files)})")

        return {
            "changed": changed,
            "added": added,
            "removed": removed
        }

    def get_unchanged_files(self, changed_files: Set[str], all_files: List[str]) -> List[str]:
        """获取未变更文件列表

        Args:
            changed_files: 变更文件集合
            all_files: 所有文件列表

        Returns:
            未变更文件列表，可跳过扫描
        """
        changed_set = set(changed_files)
        return [f for f in all_files if f not in changed_set]

    def update_index(self, file_path: str, file_hash: str, mtime: float, size: int) -> None:
        """更新索引条目

        Args:
            file_path: 文件路径
            file_hash: 文件哈希值
            mtime: 修改时间
            size: 文件大小
        """
        self._index[file_path] = FileIndexEntry(
            file_path=file_path,
            file_hash=file_hash,
            mtime=mtime,
            size=size,
            indexed_at=time.time()
        )

    def get_indexed_files(self) -> List[str]:
        """获取所有已索引文件

        Returns:
            已索引文件路径列表
        """
        return list(self._index.keys())

    def get_index_entry(self, file_path: str) -> Optional[FileIndexEntry]:
        """获取指定文件的索引条目

        Args:
            file_path: 文件路径

        Returns:
            索引条目，不存在返回None
        """
        return self._index.get(file_path)

    def remove_from_index(self, file_path: str) -> bool:
        """从索引中移除文件

        Args:
            file_path: 文件路径

        Returns:
            是否成功移除
        """
        if file_path in self._index:
            del self._index[file_path]
            return True
        return False

    def save_index(self) -> bool:
        """保存索引到磁盘

        Returns:
            是否成功保存
        """
        return self._save_index()

    def get_index_stats(self) -> Dict[str, Any]:
        """获取索引统计信息

        Returns:
            索引统计信息
        """
        total_size = sum(entry.size for entry in self._index.values())
        return {
            'indexed_files': len(self._index),
            'total_size': total_size,
            'index_path': str(self._index_path),
            'project_path': self.project_path
        }

    def clear_index(self) -> bool:
        """清除所有索引数据

        Returns:
            是否成功清除
        """
        try:
            self._index.clear()
            if self._index_path.exists():
                self._index_path.unlink()
            return True
        except Exception:
            return False
