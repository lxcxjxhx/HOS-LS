import asyncio
import hashlib
import os
from pathlib import Path
from typing import Dict, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class FileState:
    path: str
    hash: str
    last_modified: float
    node_count: int


class GraphSyncEngine:

    def __init__(self, code_graph_engine, project_path: str):
        self.engine = code_graph_engine
        self.project_path = Path(str(project_path))
        self._file_states: Dict[str, FileState] = {}
        self._debounce_timer: Optional[asyncio.Task] = None
        self._debounce_delay: float = 1.0
        self._pending_changes: Dict[str, str] = {}
        self._on_sync_complete: Optional[Callable] = None
        self._running = False

    async def watch(self, callback: Callable = None):
        self._on_sync_complete = callback
        self._running = True
        await self._init_file_states()
        await self._poll_loop()

    async def _init_file_states(self):
        for ext in ("*.py", "*.js", "*.ts", "*.java", "*.go", "*.rs", "*.cpp", "*.c", "*.php"):
            for file_path in self.project_path.rglob(ext):
                file_path_str = str(file_path)
                if ".codegraph" in file_path_str:
                    continue
                try:
                    with open(file_path_str, "r", encoding="utf-8") as f:
                        content = f.read()
                    new_hash = hashlib.sha256(content.encode()).hexdigest()
                    stat = os.stat(file_path_str)
                    self._file_states[file_path_str] = FileState(
                        path=file_path_str,
                        hash=new_hash,
                        last_modified=stat.st_mtime,
                        node_count=0,
                    )
                except Exception:
                    pass

    async def _poll_loop(self):
        while self._running:
            await self._check_changes()
            await asyncio.sleep(0.5)

    async def _check_changes(self):
        current_files = set()
        for ext in ("*.py", "*.js", "*.ts", "*.java", "*.go", "*.rs", "*.cpp", "*.c", "*.php"):
            for file_path in self.project_path.rglob(ext):
                file_path_str = str(file_path)
                if ".codegraph" in file_path_str:
                    continue
                current_files.add(file_path_str)

                try:
                    with open(file_path_str, "r", encoding="utf-8") as f:
                        content = f.read()
                    new_hash = hashlib.sha256(content.encode()).hexdigest()
                    old_state = self._file_states.get(file_path_str)

                    if old_state is None:
                        await self._handle_change(file_path_str, "added")
                    elif old_state.hash != new_hash:
                        await self._handle_change(file_path_str, "modified")
                except Exception:
                    pass

        deleted = set(self._file_states.keys()) - current_files
        for deleted_path in deleted:
            await self._handle_change(deleted_path, "deleted")

    async def _handle_change(self, file_path: str, event_type: str):
        self._pending_changes[str(file_path)] = event_type

        if self._debounce_timer:
            self._debounce_timer.cancel()

        self._debounce_timer = asyncio.create_task(
            self._execute_sync()
        )

    async def _execute_sync(self):
        await asyncio.sleep(self._debounce_delay)

        changes = dict(self._pending_changes)
        self._pending_changes.clear()

        for file_path, event_type in changes.items():
            if event_type in ("modified", "added"):
                await self._sync_file(file_path)
            elif event_type == "deleted":
                try:
                    await self.engine.delete_file(file_path)
                except Exception:
                    pass
                self._file_states.pop(str(file_path), None)

        if self._on_sync_complete:
            self._on_sync_complete(len(changes))

    async def _sync_file(self, file_path: str):
        try:
            file_path_str = str(file_path)
            with open(file_path_str, "r", encoding="utf-8") as f:
                content = f.read()

            new_hash = hashlib.sha256(content.encode()).hexdigest()

            old_state = self._file_states.get(file_path_str)
            if old_state and old_state.hash == new_hash:
                return

            language = self._detect_language(file_path_str)
            try:
                await self.engine.delete_file(file_path_str)
            except Exception:
                pass

            result = await self.engine.index_file(file_path_str, content, language)

            stat = os.stat(file_path_str)
            self._file_states[file_path_str] = FileState(
                path=file_path_str,
                hash=new_hash,
                last_modified=stat.st_mtime,
                node_count=result.get("nodes", 0) if isinstance(result, dict) else 0,
            )
        except Exception:
            pass

    def _detect_language(self, file_path: str) -> str:
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".cpp": "cpp",
            ".c": "c",
            ".php": "php",
        }
        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext, "unknown")

    def stop(self):
        self._running = False
        if self._debounce_timer:
            self._debounce_timer.cancel()
            self._debounce_timer = None
