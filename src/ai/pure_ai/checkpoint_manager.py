import json
import time
import hashlib
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime


@dataclass
class CheckpointLevel:
    STEP = "step"
    FILE = "file"
    AGENT = "agent"


@dataclass
class CheckpointData:
    checkpoint_id: str
    level: str
    timestamp: float
    project_path: str
    current_step: str
    processed_files: List[str]
    current_file: Optional[str] = None
    agent_states: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckpointData":
        return cls(**data)


class CheckpointManager:
    MAX_SAVE_TIME_MS = 50
    MAX_FILE_SIZE_KB = 100
    DEFAULT_AUTO_SAVE_INTERVAL = 10

    def __init__(self, project_path: str, config: Optional[Dict[str, Any]] = None):
        self.project_path = Path(project_path).resolve()
        self.checkpoint_dir = self.project_path / ".hos-ls" / "checkpoints"
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or {}
        self.auto_save_interval = self.config.get(
            "auto_save_interval", self.DEFAULT_AUTO_SAVE_INTERVAL
        )
        self.max_checkpoints = self.config.get("max_checkpoints", 50)
        self._current_checkpoint: Optional[CheckpointData] = None
        self._files_since_last_save = 0

    def create_checkpoint(
        self,
        level: str,
        current_step: str,
        processed_files: List[str],
        current_file: Optional[str] = None,
        agent_states: Optional[Dict[str, Any]] = None,
    ) -> CheckpointData:
        checkpoint_id = self._generate_checkpoint_id()
        checkpoint = CheckpointData(
            checkpoint_id=checkpoint_id,
            level=level,
            timestamp=time.time(),
            project_path=str(self.project_path),
            current_step=current_step,
            processed_files=processed_files.copy(),
            current_file=current_file,
            agent_states=agent_states or {},
        )
        self._current_checkpoint = checkpoint
        return checkpoint

    def save_checkpoint(self, checkpoint: CheckpointData) -> bool:
        start_time = time.time()
        try:
            checkpoint_file = self.checkpoint_dir / f"{checkpoint.checkpoint_id}.json"
            temp_file = self.checkpoint_dir / f"{checkpoint.checkpoint_id}.tmp"

            data = checkpoint.to_dict()
            with open(temp_file, "w", encoding="utf-8", errors="replace") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            shutil.move(str(temp_file), str(checkpoint_file))

            elapsed_ms = (time.time() - start_time) * 1000
            file_size_kb = checkpoint_file.stat().st_size / 1024

            if elapsed_ms > self.MAX_SAVE_TIME_MS:
                pass
            if file_size_kb > self.MAX_FILE_SIZE_KB:
                pass

            self._files_since_last_save = 0
            return True
        except Exception:
            return False

    def load_checkpoint(self, checkpoint_id: str) -> Optional[CheckpointData]:
        try:
            checkpoint_file = self.checkpoint_dir / f"{checkpoint_id}.json"
            if not checkpoint_file.exists():
                return None

            with open(checkpoint_file, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            return CheckpointData.from_dict(data)
        except Exception:
            return None

    def list_checkpoints(self) -> List[CheckpointData]:
        checkpoints = []
        try:
            for checkpoint_file in self.checkpoint_dir.glob("*.json"):
                try:
                    with open(
                        checkpoint_file, "r", encoding="utf-8", errors="replace"
                    ) as f:
                        data = json.load(f)
                    checkpoints.append(CheckpointData.from_dict(data))
                except Exception:
                    continue
        except Exception:
            pass

        checkpoints.sort(key=lambda x: x.timestamp, reverse=True)
        return checkpoints

    def get_latest_checkpoint(self) -> Optional[CheckpointData]:
        checkpoints = self.list_checkpoints()
        return checkpoints[0] if checkpoints else None

    def get_latest_checkpoint_by_level(self, level: str) -> Optional[CheckpointData]:
        checkpoints = self.list_checkpoints()
        for checkpoint in checkpoints:
            if checkpoint.level == level:
                return checkpoint
        return None

    def should_auto_save(self) -> bool:
        self._files_since_last_save += 1
        return self._files_since_last_save >= self.auto_save_interval

    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        try:
            checkpoint_file = self.checkpoint_dir / f"{checkpoint_id}.json"
            if checkpoint_file.exists():
                checkpoint_file.unlink()
                return True
            return False
        except Exception:
            return False

    def cleanup_old_checkpoints(self, keep_count: Optional[int] = None) -> int:
        if keep_count is None:
            keep_count = self.max_checkpoints

        checkpoints = self.list_checkpoints()
        deleted_count = 0

        for checkpoint in checkpoints[keep_count:]:
            if self.delete_checkpoint(checkpoint.checkpoint_id):
                deleted_count += 1

        return deleted_count

    def _generate_checkpoint_id(self) -> str:
        timestamp = str(time.time())
        random_part = hashlib.md5(timestamp.encode()).hexdigest()[:8]
        return f"ckpt_{int(time.time())}_{random_part}"

    def get_checkpoint_stats(self) -> Dict[str, Any]:
        try:
            checkpoints = self.list_checkpoints()
            total_size = sum(
                (self.checkpoint_dir / f"{cp.checkpoint_id}.json").stat().st_size
                for cp in checkpoints
                if (self.checkpoint_dir / f"{cp.checkpoint_id}.json").exists()
            )

            level_counts: Dict[str, int] = {}
            for cp in checkpoints:
                level_counts[cp.level] = level_counts.get(cp.level, 0) + 1

            return {
                "total_checkpoints": len(checkpoints),
                "total_size_bytes": total_size,
                "total_size_kb": round(total_size / 1024, 2),
                "level_counts": level_counts,
                "checkpoint_dir": str(self.checkpoint_dir),
                "auto_save_interval": self.auto_save_interval,
            }
        except Exception:
            return {"error": "无法获取检查点统计信息"}

    def export_checkpoint(self, checkpoint_id: str, target_path: str) -> bool:
        try:
            checkpoint_file = self.checkpoint_dir / f"{checkpoint_id}.json"
            if not checkpoint_file.exists():
                return False

            target = Path(target_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(checkpoint_file), str(target))
            return True
        except Exception:
            return False

    def import_checkpoint(self, source_path: str) -> Optional[CheckpointData]:
        try:
            source = Path(source_path)
            if not source.exists():
                return None

            with open(source, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            checkpoint = CheckpointData.from_dict(data)
            self.save_checkpoint(checkpoint)
            return checkpoint
        except Exception:
            return None

    def clear_all_checkpoints(self) -> bool:
        try:
            for checkpoint_file in self.checkpoint_dir.glob("*.json"):
                try:
                    checkpoint_file.unlink()
                except Exception:
                    continue
            self._current_checkpoint = None
            self._files_since_last_save = 0
            return True
        except Exception:
            return False

    @property
    def current_checkpoint(self) -> Optional[CheckpointData]:
        return self._current_checkpoint

    def restore_from_checkpoint(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        checkpoint = self.load_checkpoint(checkpoint_id)
        if not checkpoint:
            return None

        self._current_checkpoint = checkpoint
        return {
            "current_step": checkpoint.current_step,
            "processed_files": checkpoint.processed_files,
            "current_file": checkpoint.current_file,
            "agent_states": checkpoint.agent_states,
        }
