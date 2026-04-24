"""扫描状态管理模块

管理扫描的截断和断点续传功能
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import time


@dataclass
class ScanState:
    """扫描状态类"""
    scan_id: str
    started_at: str
    last_updated: str
    total_files: int
    completed_files: List[str]
    findings: List[Dict[str, Any]]
    truncated: bool = False
    truncation_reason: Optional[str] = None
    max_duration: int = 0
    max_files: int = 0
    start_time: float = 0.0

    @classmethod
    def create(cls, total_files: int, max_duration: int = 0, max_files: int = 0) -> 'ScanState':
        """创建新的扫描状态"""
        now = datetime.now().isoformat()
        return cls(
            scan_id=str(uuid.uuid4()),
            started_at=now,
            last_updated=now,
            total_files=total_files,
            completed_files=[],
            findings=[],
            truncated=False,
            truncation_reason=None,
            max_duration=max_duration,
            max_files=max_files,
            start_time=time.time()
        )

    @classmethod
    def load(cls, path: str) -> Optional['ScanState']:
        """从文件加载扫描状态"""
        try:
            state_file = Path(path)
            if not state_file.exists():
                return None

            with open(state_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            return cls(
                scan_id=data['scan_id'],
                started_at=data['started_at'],
                last_updated=data['last_updated'],
                total_files=data['total_files'],
                completed_files=data.get('completed_files', []),
                findings=data.get('findings', []),
                truncated=data.get('truncated', False),
                truncation_reason=data.get('truncation_reason'),
                max_duration=data.get('max_duration', 0),
                max_files=data.get('max_files', 0),
                start_time=data.get('start_time', 0.0)
            )
        except Exception as e:
            print(f"[DEBUG] Failed to load scan state: {e}")
            return None

    def _to_dict(self) -> Dict[str, Any]:
        """将状态转换为可序列化的字典"""
        def make_serializable(obj):
            if isinstance(obj, Path):
                return str(obj)
            elif hasattr(obj, '__dict__'):
                return {k: make_serializable(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, dict):
                return {k: make_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [make_serializable(item) for item in obj]
            elif isinstance(obj, (int, float, str, bool, type(None))):
                return obj
            else:
                try:
                    json.dumps(obj)
                    return obj
                except (TypeError, ValueError):
                    return str(obj)

        return {
            'scan_id': self.scan_id,
            'started_at': self.started_at,
            'last_updated': self.last_updated,
            'total_files': self.total_files,
            'completed_files': [str(f) for f in self.completed_files],
            'findings': make_serializable(self.findings),
            'truncated': self.truncated,
            'truncation_reason': self.truncation_reason,
            'max_duration': self.max_duration,
            'max_files': self.max_files,
            'start_time': self.start_time,
        }

    def save(self, path: str) -> bool:
        """保存扫描状态到文件"""
        try:
            self.last_updated = datetime.now().isoformat()
            state_file = Path(path)
            state_file.parent.mkdir(parents=True, exist_ok=True)

            serializable_state = self._to_dict()
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_state, f, ensure_ascii=False, indent=2)

            return True
        except Exception as e:
            print(f"[DEBUG] Failed to save scan state: {e}")
            return False

    def add_completed_file(self, file_path: str, findings: List[Dict[str, Any]] = None):
        """添加已完成的文件"""
        file_path_str = str(file_path)
        if file_path_str not in self.completed_files:
            self.completed_files.append(file_path_str)

        if findings:
            self.findings.extend(findings)

    def should_truncate(self) -> tuple[bool, Optional[str]]:
        """检查是否应该截断

        Returns:
            (should_truncate, reason)
        """
        if self.max_duration > 0:
            elapsed = time.time() - self.start_time
            if elapsed >= self.max_duration:
                return True, f"max-duration ({self.max_duration}s)"

        if self.max_files > 0:
            if len(self.completed_files) >= self.max_files:
                return True, f"max-files ({self.max_files})"

        return False, None

    def get_pending_files(self, all_files: List[str]) -> List[str]:
        """获取待扫描文件列表"""
        return [f for f in all_files if f not in self.completed_files]

    def mark_truncated(self, reason: str):
        """标记为截断状态"""
        self.truncated = True
        self.truncation_reason = reason

    def get_progress(self) -> Dict[str, Any]:
        """获取进度信息"""
        return {
            'total': self.total_files,
            'completed': len(self.completed_files),
            'pending': self.total_files - len(self.completed_files),
            'percentage': (len(self.completed_files) / self.total_files * 100) if self.total_files > 0 else 0,
            'truncated': self.truncated,
            'truncation_reason': self.truncation_reason
        }
