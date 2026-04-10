"""Memory 数据模型定义

定义用户记忆、项目记忆和执行日志的核心数据结构。
"""

import hashlib
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ScanDepth(str, Enum):
    """扫描深度"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class OutputStyle(str, Enum):
    """输出风格"""

    CONCISE = "concise"
    DETAILED = "detailed"
    VERBOSE = "verbose"


class StrategyMode(str, Enum):
    """策略模式"""

    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    CONSERVATIVE = "conservative"
    FAST = "fast"
    DEEP = "deep"


class RiskLevel(str, Enum):
    """风险级别"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntentType(str, Enum):
    """意图类型"""

    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    FIX = "fix"
    INFO = "info"
    GIT = "git"
    PLAN = "plan"
    GENERAL = "general"


@dataclass
class UserPreferences:
    """用户偏好设置"""

    scan_depth: str = "medium"
    output_style: str = "concise"
    poc_enabled: bool = False
    preferred_mode: str = "balanced"
    auto_confirm: bool = False  # 是否自动确认策略
    language: str = "zh-CN"  # 界面语言

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserPreferences":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class BehaviorStats:
    """用户行为统计"""

    total_scans: int = 0
    total_usage_hours: float = 0.0
    avg_wait_time: float = 180.0  # 平均等待时间（秒）
    cancel_rate: float = 0.0  # 取消率
    success_rate: float = 1.0  # 成功率
    last_active_time: Optional[datetime] = None
    usage_count: int = 0  # 总使用次数（用于判断高级用户）

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.last_active_time:
            data["last_active_time"] = self.last_active_time.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BehaviorStats":
        if data.get("last_active_time"):
            data["last_active_time"] = datetime.fromisoformat(data["last_active_time"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class UserHabits:
    """用户习惯模式"""

    prefers_fast_first: bool = True  # 偏好快速优先
    avoids_aggressive: bool = False  # 避免激进策略
    likes_detail_report: bool = True  # 喜欢详细报告
    often_uses_poc: bool = False  # 经常使用POC
    works_in_production: bool = False  # 在生产环境工作
    typical_project_types: List[str] = field(default_factory=list)  # 典型项目类型 [web_api, microservice]
    active_hours: List[int] = field(default_factory=lambda: [9, 10, 11, 14, 15, 16])  # 活跃时段

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserHabits":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class UserMemory:
    """用户记忆"""

    user_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    preferences: UserPreferences = field(default_factory=UserPreferences)
    behavior_stats: BehaviorStats = field(default_factory=BehaviorStats)
    habits: UserHabits = field(default_factory=UserHabits)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "preferences": self.preferences.to_dict(),
            "behavior_stats": self.behavior_stats.to_dict(),
            "habits": self.habits.to_dict(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserMemory":
        return cls(
            user_id=data.get("user_id", str(uuid.uuid4())),
            preferences=UserPreferences.from_dict(data.get("preferences", {})),
            behavior_stats=BehaviorStats.from_dict(data.get("behavior_stats", {})),
            habits=UserHabits.from_dict(data.get("habits", {})),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
        )

    def is_advanced_user(self) -> bool:
        """判断是否为高级用户（使用次数>50）"""
        return self.behavior_stats.usage_count >= 50

    def update_usage(self):
        """更新使用统计"""
        self.behavior_stats.usage_count += 1
        self.behavior_stats.last_active_time = datetime.now()
        self.updated_at = datetime.now()


@dataclass
class RiskProfile:
    """项目风险画像"""

    overall: str = "medium"  # 整体风险级别
    auth_risk: str = "low"  # 认证风险
    injection_risk: str = "low"  # 注入风险
    xss_risk: str = "low"  # XSS风险
    data_exposure_risk: str = "low"  # 数据暴露风险
    dependency_risk: str = "low"  # 依赖风险
    finding_density: str = "low"  # 漏洞密度
    last_assessed: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.last_assessed:
            data["last_assessed"] = self.last_assessed.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RiskProfile":
        if data.get("last_assessed"):
            data["last_assessed"] = datetime.fromisoformat(data["last_assessed"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def get_max_risk(self) -> str:
        """获取最高风险级别"""
        risks = [
            self.auth_risk,
            self.injection_risk,
            self.xss_risk,
            self.data_exposure_risk,
            self.dependency_risk,
        ]
        risk_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_risk = max(risks, key=lambda x: risk_order.get(x, 0))
        return max_risk


@dataclass
class ScanHistory:
    """扫描历史"""

    last_scan_depth: str = "medium"
    last_scan_duration: float = 0.0  # 上次扫描耗时（秒）
    last_scan_findings: int = 0  # 上次扫描发现数
    total_scans: int = 0  # 总扫描次数
    last_scan_time: Optional[datetime] = None
    average_findings_per_scan: float = 0.0  # 平均每次扫描发现数

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.last_scan_time:
            data["last_scan_time"] = self.last_scan_time.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanHistory":
        if data.get("last_scan_time"):
            data["last_scan_time"] = datetime.fromisoformat(data["last_scan_time"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def record_scan(self, duration: float, findings: int, depth: str = "medium"):
        """记录一次扫描"""
        self.total_scans += 1
        self.last_scan_duration = duration
        self.last_scan_findings = findings
        self.last_scan_depth = depth
        self.last_scan_time = datetime.now()

        if self.total_scans > 0:
            self.average_findings_per_scan = (
                (self.average_findings_per_scan * (self.total_scans - 1) + findings) / self.total_scans
            )


@dataclass
class ProjectMemory:
    """项目记忆"""

    project_hash: str = ""
    project_path: str = ""
    tech_stack: List[str] = field(default_factory=list)
    risk_profile: RiskProfile = field(default_factory=RiskProfile)
    previous_findings: Dict[str, Any] = field(default_factory=dict)
    scan_history: ScanHistory = field(default_factory=ScanHistory)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    @staticmethod
    def generate_hash(project_path: str) -> str:
        """生成项目路径的hash"""
        return hashlib.sha256(project_path.encode()).hexdigest()[:16]

    def __post_init__(self):
        if not self.project_hash and self.project_path:
            self.project_hash = self.generate_hash(self.project_path)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_hash": self.project_hash,
            "project_path": self.project_path,
            "tech_stack": self.tech_stack,
            "risk_profile": self.risk_profile.to_dict(),
            "previous_findings": self.previous_findings,
            "scan_history": self.scan_history.to_dict(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProjectMemory":
        return cls(
            project_hash=data.get("project_hash", ""),
            project_path=data.get("project_path", ""),
            tech_stack=data.get("tech_stack", []),
            risk_profile=RiskProfile.from_dict(data.get("risk_profile", {})),
            previous_findings=data.get("previous_findings", {}),
            scan_history=ScanHistory.from_dict(data.get("scan_history", {})),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
        )

    def update_tech_stack(self, new_tech: List[str]):
        """更新技术栈（去重）"""
        existing = set(self.tech_stack)
        for tech in new_tech:
            if tech.lower() not in {t.lower() for t in existing}:
                self.tech_stack.append(tech)
        self.updated_at = datetime.now()

    def is_high_risk(self) -> bool:
        """判断是否为高风险项目"""
        return self.risk_profile.overall in ["high", "critical"]

    def is_first_scan(self) -> bool:
        """判断是否首次扫描"""
        return self.scan_history.total_scans == 0


@dataclass
class ExecutionLog:
    """执行日志"""

    log_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    plan_id: str = ""
    strategy_used: Dict[str, Any] = field(default_factory=dict)
    intent: str = ""
    target_path: str = ""
    duration: float = 0.0
    findings_count: int = 0
    success: bool = True
    user_feedback: Optional[int] = None  # 用户满意度评分 1-5
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id,
            "plan_id": self.plan_id,
            "strategy_used": self.strategy_used,
            "intent": self.intent,
            "target_path": self.target_path,
            "duration": self.duration,
            "findings_count": self.findings_count,
            "success": self.success,
            "user_feedback": self.user_feedback,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionLog":
        return cls(
            log_id=data.get("log_id", str(uuid.uuid4())[:8]),
            plan_id=data.get("plan_id", ""),
            strategy_used=data.get("strategy_used", {}),
            intent=data.get("intent", ""),
            target_path=data.get("target_path", ""),
            duration=data.get("duration", 0.0),
            findings_count=data.get("findings_count", 0),
            success=data.get("success", True),
            user_feedback=data.get("user_feedback"),
            error_message=data.get("error_message"),
            timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else datetime.now(),
        )


@dataclass
class Intent:
    """用户意图"""

    intent_type: IntentType = IntentType.GENERAL
    original_text: str = ""
    extracted_params: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent_type": self.intent_type.value,
            "original_text": self.original_text,
            "extracted_params": self.extracted_params,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Intent":
        intent_type = data.get("intent_type", "general")
        if isinstance(intent_type, str):
            intent_type = IntentType(intent_type)
        return cls(
            intent_type=intent_type,
            original_text=data.get("original_text", ""),
            extracted_params=data.get("extracted_params", {}),
            confidence=data.get("confidence", 1.0),
        )
