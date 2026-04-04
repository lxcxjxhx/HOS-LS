"""数据库模型模块

定义数据库表结构的数据模型。
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Scan:
    """扫描记录"""

    id: Optional[int] = None
    target: str = ""
    status: str = "pending"
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: float = 0.0
    total_findings: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "total_findings": self.total_findings,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_db_tuple(self) -> tuple:
        """转换为数据库元组"""
        return (
            self.target,
            self.status,
            self.start_time.isoformat() if self.start_time else None,
            self.end_time.isoformat() if self.end_time else None,
            self.duration,
            self.total_findings,
            json.dumps(self.metadata) if self.metadata else None,
        )

    @classmethod
    def from_db_row(cls, row: tuple) -> "Scan":
        """从数据库行创建实例"""
        return cls(
            id=row[0],
            target=row[1],
            status=row[2],
            start_time=datetime.fromisoformat(row[3]) if row[3] else None,
            end_time=datetime.fromisoformat(row[4]) if row[4] else None,
            duration=row[5] or 0.0,
            total_findings=row[6] or 0,
            metadata=json.loads(row[7]) if row[7] else {},
            created_at=datetime.fromisoformat(row[8]) if row[8] else None,
        )


@dataclass
class Finding:
    """安全发现记录"""

    id: Optional[int] = None
    scan_id: int = 0
    rule_id: str = ""
    rule_name: str = ""
    description: str = ""
    severity: str = "medium"
    file_path: str = ""
    line: int = 0
    column: int = 0
    confidence: float = 1.0
    message: str = ""
    code_snippet: str = ""
    fix_suggestion: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "confidence": self.confidence,
            "message": self.message,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_db_tuple(self) -> tuple:
        """转换为数据库元组"""
        return (
            self.scan_id,
            self.rule_id,
            self.rule_name,
            self.description,
            self.severity,
            self.file_path,
            self.line,
            self.column,
            self.confidence,
            self.message,
            self.code_snippet,
            self.fix_suggestion,
            json.dumps(self.metadata) if self.metadata else None,
        )

    @classmethod
    def from_db_row(cls, row: tuple) -> "Finding":
        """从数据库行创建实例"""
        return cls(
            id=row[0],
            scan_id=row[1],
            rule_id=row[2],
            rule_name=row[3],
            description=row[4] or "",
            severity=row[5],
            file_path=row[6] or "",
            line=row[7] or 0,
            column=row[8] or 0,
            confidence=row[9] or 1.0,
            message=row[10] or "",
            code_snippet=row[11] or "",
            fix_suggestion=row[12] or "",
            metadata=json.loads(row[13]) if row[13] else {},
            created_at=datetime.fromisoformat(row[14]) if row[14] else None,
        )


@dataclass
class ScanResult:
    """扫描结果"""

    scan: Scan
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "scan": self.scan.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }


# 基类（用于类型提示）
Base = Scan
