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

    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'target': self.target,
            'start_time': self.start_time,
            'last_update': self.last_update,
            'config': self.config,
            'progress': asdict(self.progress),
            'results': [asdict(r) if isinstance(r, ScanResult) else r for r in self.results]
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
            results=results
        )


class ScanCacheManager:
    def __init__(self, cache_dir: Optional[str] = None):
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / '.hos-ls' / 'scan_cache'
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
