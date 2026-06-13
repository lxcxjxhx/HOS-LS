"""Pydantic response models for the Web API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Health ────────────────────────────────────────────────────────────

class HealthStatus(str, Enum):
    healthy = "healthy"
    degraded = "degraded"
    unhealthy = "unhealthy"


class HealthResponse(BaseModel):
    """健康检查响应"""
    status: HealthStatus = Field(default=HealthStatus.healthy)
    version: str
    build_time: Optional[str] = None
    components: Dict[str, str] = Field(default_factory=dict)


# ── Task Status ──────────────────────────────────────────────────────

class TaskStatusEnum(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class TaskStatus(BaseModel):
    """任务状态"""
    task_id: str
    type: str  # scan / pentest / etc.
    status: TaskStatusEnum
    progress: float = Field(default=0.0, ge=0.0, le=100.0)
    message: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    # 扫描专用字段
    findings_count: int = 0
    current_file: str = ""
    files_scanned: int = 0
    total_files: int = 0


# ── Findings ─────────────────────────────────────────────────────────

class SeverityEnum(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingResponse(BaseModel):
    """安全发现响应"""
    id: str
    rule_id: str
    severity: SeverityEnum
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_ids: List[str] = Field(default_factory=list)
    fix_suggestion: Optional[str] = None
    attack_chain: Optional[List[str]] = None
    created_at: Optional[datetime] = None


# ── Session ──────────────────────────────────────────────────────────

class SessionResponse(BaseModel):
    """会话响应"""
    session_id: str
    name: str
    type: str  # scan / pentest / chat
    status: TaskStatusEnum
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ── Star Map ─────────────────────────────────────────────────────────

class StarMapNode(BaseModel):
    """星图节点"""
    id: str
    label: str
    type: str  # file / function / vulnerability / etc.
    severity: Optional[SeverityEnum] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    x: Optional[float] = None
    y: Optional[float] = None


class StarMapEdge(BaseModel):
    """星图边"""
    id: str
    source: str
    target: str
    relation: str  # calls / imports / depends_on / etc.
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StarMapResponse(BaseModel):
    """星图响应"""
    nodes: List[StarMapNode] = Field(default_factory=list)
    edges: List[StarMapEdge] = Field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0


# ── Chat ─────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    """对话消息"""
    role: str  # user / assistant / system
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    """对话响应"""
    message: ChatMessage
    session_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class ChatSessionResponse(BaseModel):
    """对话会话摘要"""
    session_id: str
    name: str
    message_count: int = 0
    created_at: str = ""
