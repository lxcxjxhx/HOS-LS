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
    truncation_events: List[Dict[str, Any]] = field(default_factory=list)
    partial_analysis_files: List[str] = field(default_factory=list)
    rescan_count: int = 0
    anomaly_events: List[Dict[str, Any]] = field(default_factory=list)

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

            # 首先检查指定路径
            if state_file.exists():
                with open(state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return cls._from_dict(data)

            # 回退检查：检查旧路径（当前工作目录下的同名文件）
            old_path = Path.cwd() / state_file.name
            if old_path.exists():
                with open(old_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return cls._from_dict(data)

            return None
        except Exception as e:
            print(f"[DEBUG] Failed to load scan state: {e}")
            return None

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> 'ScanState':
        """从字典数据创建 ScanState 实例"""
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
            start_time=data.get('start_time', 0.0),
            truncation_events=data.get('truncation_events', []),
            partial_analysis_files=data.get('partial_analysis_files', []),
            rescan_count=data.get('rescan_count', 0),
            anomaly_events=data.get('anomaly_events', [])
        )

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
            'truncation_events': self.truncation_events,
            'partial_analysis_files': self.partial_analysis_files,
            'rescan_count': self.rescan_count,
            'anomaly_events': self.anomaly_events,
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

    def record_truncation_event(self, file_path: str, schema: str, reason: str, attempt: int = 0) -> None:
        """记录截断事件

        Args:
            file_path: 文件路径
            schema: Schema 名称
            reason: 截断原因
            attempt: 尝试次数
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'file_path': str(file_path),
            'schema': schema,
            'reason': reason,
            'attempt': attempt,
        }
        self.truncation_events.append(event)

        if file_path not in self.partial_analysis_files:
            self.partial_analysis_files.append(str(file_path))

        self.rescan_count += 1

    def record_anomaly_event(self, anomaly_type: str, description: str, file_path: str = '', severity: str = 'medium', details: Dict[str, Any] = None) -> None:
        """记录异常事件

        Args:
            anomaly_type: 异常类型
            description: 异常描述
            file_path: 文件路径
            severity: 严重程度 (critical, high, medium, low, info)
            details: 详细信息
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': anomaly_type,
            'description': description,
            'file_path': str(file_path),
            'severity': severity,
            'details': details or {},
        }
        self.anomaly_events.append(event)

        if file_path and file_path not in self.partial_analysis_files:
            self.partial_analysis_files.append(str(file_path))

    def get_anomaly_summary(self) -> Dict[str, Any]:
        """获取异常摘要统计

        Returns:
            包含异常统计的字典
        """
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        type_counts: Dict[str, int] = {}

        for event in self.anomaly_events:
            severity = event.get('severity', 'medium')
            if severity in severity_counts:
                severity_counts[severity] += 1

            anomaly_type = event.get('type', 'unknown')
            type_counts[anomaly_type] = type_counts.get(anomaly_type, 0) + 1

        return {
            'total_anomalies': len(self.anomaly_events),
            'severity_counts': severity_counts,
            'type_counts': type_counts,
            'truncation_count': len(self.truncation_events),
            'partial_analysis_count': len(self.partial_analysis_files),
            'total_rescans': self.rescan_count,
        }

    def print_anomaly_summary(self) -> None:
        """在控制台打印异常摘要"""
        summary = self.get_anomaly_summary()

        if summary['total_anomalies'] == 0 and summary['truncation_count'] == 0:
            return

        print("\n" + "="*60)
        print("[!] 扫描异常摘要")
        print("="*60)

        if summary['truncation_count'] > 0:
            print(f"  截断事件: {summary['truncation_count']} 次")
            print(f"  重扫次数: {summary['total_rescans']} 次")
            print(f"  部分分析文件: {summary['partial_analysis_count']} 个")

        if summary['total_anomalies'] > 0:
            print(f"\n  异常总数: {summary['total_anomalies']}")
            print(f"  严重程度分布:")
            for severity, count in summary['severity_counts'].items():
                if count > 0:
                    print(f"    - {severity}: {count}")

            print(f"\n  异常类型分布:")
            for anomaly_type, count in summary['type_counts'].items():
                print(f"    - {anomaly_type}: {count}")

        if summary['partial_analysis_count'] > 0:
            print(f"\n  部分分析文件列表:")
            for file_path in self.partial_analysis_files[:10]:
                print(f"    - {file_path}")
            if len(self.partial_analysis_files) > 10:
                print(f"    ... 及其他 {len(self.partial_analysis_files) - 10} 个文件")

        print("="*60 + "\n")