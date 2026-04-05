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


@dataclass
class CVE:
    """CVE 漏洞数据模型（v3 优化版）"""

    cve_id: str = ""
    description: str = ""
    cwe: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_vector: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    exploit: bool = False
    exploit_refs: List[str] = field(default_factory=list)
    patch_refs: List[str] = field(default_factory=list)
    attack_vector: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    affected_products: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cwe": self.cwe,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v3_vector": self.cvss_v3_vector,
            "cvss_v2_score": self.cvss_v2_score,
            "cvss_v2_vector": self.cvss_v2_vector,
            "cpe": self.cpe,
            "exploit": self.exploit,
            "exploit_refs": self.exploit_refs,
            "patch_refs": self.patch_refs,
            "attack_vector": self.attack_vector,
            "tags": self.tags,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified_date": self.last_modified_date.isoformat() if self.last_modified_date else None,
            "affected_products": self.affected_products,
            "references": self.references,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVE":
        """从字典创建实例"""
        published_date = None
        if data.get("published_date"):
            try:
                published_date = datetime.fromisoformat(data["published_date"])
            except (ValueError, TypeError):
                pass

        last_modified_date = None
        if data.get("last_modified_date"):
            try:
                last_modified_date = datetime.fromisoformat(data["last_modified_date"])
            except (ValueError, TypeError):
                pass

        return cls(
            cve_id=data.get("cve_id", ""),
            description=data.get("description", ""),
            cwe=data.get("cwe"),
            cvss_v3_score=data.get("cvss_v3_score"),
            cvss_v3_vector=data.get("cvss_v3_vector"),
            cvss_v2_score=data.get("cvss_v2_score"),
            cvss_v2_vector=data.get("cvss_v2_vector"),
            cpe=data.get("cpe", []),
            exploit=data.get("exploit", False),
            exploit_refs=data.get("exploit_refs", []),
            patch_refs=data.get("patch_refs", []),
            attack_vector=data.get("attack_vector"),
            tags=data.get("tags", []),
            published_date=published_date,
            last_modified_date=last_modified_date,
            affected_products=data.get("affected_products", []),
            references=data.get("references", []),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "CVE":
        """从 JSON 字符串创建实例"""
        data = json.loads(json_str)
        return cls.from_dict(data)

    @property
    def severity(self) -> str:
        """根据 CVSS 分数获取严重级别"""
        if self.cvss_v3_score is not None:
            score = self.cvss_v3_score
        elif self.cvss_v2_score is not None:
            score = self.cvss_v2_score
        else:
            return "medium"

        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"


@dataclass
class CVECollection:
    """CVE 数据集合（用于批量操作）"""

    cves: List[CVE] = field(default_factory=list)
    last_sync_time: Optional[datetime] = None
    sync_source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "cves": [cve.to_dict() for cve in self.cves],
            "last_sync_time": self.last_sync_time.isoformat() if self.last_sync_time else None,
            "sync_source": self.sync_source,
        }

    def to_json(self) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVECollection":
        """从字典创建实例"""
        last_sync_time = None
        if data.get("last_sync_time"):
            try:
                last_sync_time = datetime.fromisoformat(data["last_sync_time"])
            except (ValueError, TypeError):
                pass

        cves = [CVE.from_dict(cve_data) for cve_data in data.get("cves", [])]
        return cls(
            cves=cves,
            last_sync_time=last_sync_time,
            sync_source=data.get("sync_source", ""),
        )

    def add_cve(self, cve: CVE) -> None:
        """添加 CVE"""
        self.cves.append(cve)

    def get_cve(self, cve_id: str) -> Optional[CVE]:
        """根据 ID 获取 CVE"""
        for cve in self.cves:
            if cve.cve_id == cve_id:
                return cve
        return None

    def filter_by_severity(self, severity: str) -> "CVECollection":
        """按严重级别过滤"""
        filtered_cves = [cve for cve in self.cves if cve.severity == severity]
        return CVECollection(cves=filtered_cves, last_sync_time=self.last_sync_time, sync_source=self.sync_source)

    def filter_by_exploit(self, has_exploit: bool = True) -> "CVECollection":
        """按是否有 exploit 过滤"""
        filtered_cves = [cve for cve in self.cves if cve.exploit == has_exploit]
        return CVECollection(cves=filtered_cves, last_sync_time=self.last_sync_time, sync_source=self.sync_source)


# 基类（用于类型提示）
Base = Scan
