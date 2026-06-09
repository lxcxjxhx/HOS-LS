import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict, field
import shutil


@dataclass
class ScanProgress:
    total_files: int = 0
    completed_files: int = 0
    completed_file_paths: List[str] = field(default_factory=list)
    failed_file_paths: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    file_path: str
    vulnerabilities: List[Dict[str, Any]]
    scan_time: str
    error: Optional[str] = None


@dataclass
class ScanSession:
    session_id: str
    target: str
    start_time: str
    last_update: str
    config: Dict[str, Any]
    progress: ScanProgress
    results: List[ScanResult] = field(default_factory=list)
    selected_files: List[str] = field(default_factory=list)
    status: str = "running"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'target': self.target,
            'start_time': self.start_time,
            'last_update': self.last_update,
            'config': self.config,
            'progress': asdict(self.progress),
            'results': [asdict(r) if isinstance(r, ScanResult) else r for r in self.results],
            'selected_files': self.selected_files,
            'status': self.status
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanSession':
        progress = ScanProgress(**data.get('progress', {}))
        results = [ScanResult(**r) if isinstance(r, dict) else r for r in data.get('results', [])]
        return cls(
            session_id=data['session_id'],
            target=data['target'],
            start_time=data['start_time'],
            last_update=data['last_update'],
            config=data.get('config', {}),
            progress=progress,
            results=results,
            selected_files=data.get('selected_files', []),
            status=data.get('status', 'running')
        )


class ScanCacheManager:
    def __init__(self, cache_dir: Optional[str] = None):
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path('.hos-ls-cache') / 'scan_cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, session_id: str) -> Path:
        return self.cache_dir / f"{session_id}.json"

    def create_session(self, target: str, config: Optional[Dict[str, Any]] = None) -> ScanSession:
        session_id = str(uuid.uuid4())[:8]
        now = datetime.now().isoformat()
        session = ScanSession(
            session_id=session_id,
            target=str(target),
            start_time=now,
            last_update=now,
            config=config or {},
            progress=ScanProgress()
        )
        self.save_session(session)
        return session

    def save_session(self, session: ScanSession) -> None:
        session.last_update = datetime.now().isoformat()
        cache_path = self._get_cache_path(session.session_id)
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(session.to_dict(), f, ensure_ascii=False, indent=2)

    def load_session(self, session_id: str) -> Optional[ScanSession]:
        cache_path = self._get_cache_path(session_id)
        if not cache_path.exists():
            return None
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return ScanSession.from_dict(data)
        except Exception:
            return None

    def load_latest_session(self, target: Optional[str] = None) -> Optional[ScanSession]:
        sessions = self.list_sessions(target)
        if not sessions:
            return None
        return sessions[0]

    def list_sessions(self, target: Optional[str] = None) -> List[ScanSession]:
        sessions = []
        for cache_file in self.cache_dir.glob('*.json'):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                session = ScanSession.from_dict(data)
                if target is None or session.target == str(target):
                    sessions.append(session)
            except Exception:
                continue
        sessions.sort(key=lambda s: s.last_update, reverse=True)
        return sessions

    def delete_session(self, session_id: str) -> bool:
        cache_path = self._get_cache_path(session_id)
        if cache_path.exists():
            cache_path.unlink()
            return True
        return False

    def add_result(self, session_id: str, file_path: str, vulnerabilities: List[Dict[str, Any]], error: Optional[str] = None) -> bool:
        session = self.load_session(session_id)
        if not session:
            return False
        result = ScanResult(
            file_path=str(file_path),
            vulnerabilities=vulnerabilities,
            scan_time=datetime.now().isoformat(),
            error=error
        )
        session.results.append(result)
        if file_path not in session.progress.completed_file_paths:
            session.progress.completed_file_paths.append(str(file_path))
            session.progress.completed_files = len(session.progress.completed_file_paths)
        self.save_session(session)
        return True

    def update_progress(self, session_id: str, total_files: int) -> bool:
        session = self.load_session(session_id)
        if not session:
            return False
        session.progress.total_files = total_files
        self.save_session(session)
        return True

    def mark_failed(self, session_id: str, file_path: str) -> bool:
        session = self.load_session(session_id)
        if not session:
            return False
        if file_path not in session.progress.failed_file_paths:
            session.progress.failed_file_paths.append(str(file_path))
        self.save_session(session)
        return True

    def get_pending_files(self, session_id: str, all_files: List[str]) -> List[str]:
        session = self.load_session(session_id)
        if not session:
            return all_files
        completed = set(session.progress.completed_file_paths)
        failed = set(session.progress.failed_file_paths)
        pending = [f for f in all_files if f not in completed and f not in failed]
        return pending

    def resume_session(self, session_id: str) -> Optional[ScanSession]:
        """恢复指定会话，返回会话及其进度信息"""
        session = self.load_session(session_id)
        if not session:
            return None
        # 更新状态为 running
        session.status = "running"
        self.save_session(session)
        return session

    def get_completed_files(self, session_id: str) -> List[str]:
        """获取会话中已完成的文件列表"""
        session = self.load_session(session_id)
        if not session:
            return []
        return list(session.progress.completed_file_paths)

    def add_selected_files(self, session_id: str, file_paths: List[str]) -> bool:
        """为会话添加选中的文件列表"""
        session = self.load_session(session_id)
        if not session:
            return False
        session.selected_files = list(file_paths)
        self.save_session(session)
        return True

    def find_latest_incomplete_session(self, target: str) -> Optional[ScanSession]:
        """查找目标最新未完成（可续传）的会话"""
        sessions = self.list_sessions(target)
        for session in sessions:
            # 已完成的会话不应该续传
            if session.status == "completed":
                continue
            # 有完成进度的会话才是可续传的
            if session.progress.completed_file_paths:
                return session
        return None

    def mark_session_completed(self, session_id: str) -> bool:
        """标记会话为已完成"""
        session = self.load_session(session_id)
        if not session:
            return False
        session.status = "completed"
        self.save_session(session)
        return True

    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话摘要信息"""
        session = self.load_session(session_id)
        if not session:
            return None
        return {
            'session_id': session.session_id,
            'target': session.target,
            'status': session.status,
            'total_files': session.progress.total_files,
            'completed_files': session.progress.completed_files,
            'failed_files': len(session.progress.failed_file_paths),
            'start_time': session.start_time,
            'last_update': session.last_update,
            'selected_files_count': len(session.selected_files),
            'findings_count': len(session.results)
        }

    def export_session(self, session_id: str, output_path: str) -> bool:
        session = self.load_session(session_id)
        if not session:
            return False
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(session.to_dict(), f, ensure_ascii=False, indent=2)
        return True

    def import_session(self, import_path: str) -> Optional[ScanSession]:
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            session = ScanSession.from_dict(data)
            new_session_id = str(uuid.uuid4())[:8]
            session.session_id = new_session_id
            session.last_update = datetime.now().isoformat()
            self.save_session(session)
            return session
        except Exception:
            return None


def get_scan_cache_manager() -> ScanCacheManager:
    return ScanCacheManager()
