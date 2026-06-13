"""Pydantic request schemas for the Web API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Scan ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """扫描请求"""
    target_path: str = Field(..., description="目标路径或目录")
    scan_mode: str = Field(default="auto", description="扫描模式: auto, static, dynamic, hybrid")
    include_patterns: Optional[List[str]] = Field(
        default=None,
        description="包含的文件模式，如 ['*.py', '*.js']"
    )
    exclude_patterns: Optional[List[str]] = Field(
        default=None,
        description="排除的文件模式"
    )
    rules: Optional[List[str]] = Field(
        default=None,
        description="启用的规则列表"
    )
    max_workers: Optional[int] = Field(default=None, ge=1, le=16)
    ai_enabled: bool = Field(default=False, description="是否启用 AI 分析")
    nvd_enabled: bool = Field(default=True, description="是否启用 NVD 漏洞库")
    priority_strategy: str = Field(default="full-scan", description="优先级策略")
    options: Optional[Dict[str, Any]] = Field(
        default=None,
        description="其他扫描选项"
    )


# ── Pentest ──────────────────────────────────────────────────────────

class PentestRequest(BaseModel):
    """渗透测试请求"""
    target_url: str = Field(..., description="目标 URL")
    mode: str = Field(default="recon", description="模式: recon, scan, exploit, full")
    tools: Optional[List[str]] = Field(
        default=None,
        description="启用的工具列表，如 ['nmap', 'httpx', 'nuclei']"
    )
    max_depth: Optional[int] = Field(default=3, ge=1, le=10, description="最大探测深度")
    aggressive: bool = Field(default=False, description="是否使用激进模式")
    options: Optional[Dict[str, Any]] = Field(
        default=None,
        description="其他渗透测试选项"
    )


# ── Chat ─────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    """AI 对话请求"""
    message: str = Field(..., description="用户消息")
    session_id: Optional[str] = Field(default=None, description="会话 ID")
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="上下文信息，如当前扫描结果、选中的漏洞等"
    )
    ai_provider: Optional[str] = Field(default=None, description="指定 AI 提供商")
    ai_model: Optional[str] = Field(default=None, description="指定 AI 模型")


# ── Star Map ─────────────────────────────────────────────────────────

class StarMapRequest(BaseModel):
    """星图查询请求"""
    filters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="过滤条件，如 {'severity': ['high', 'critical']}"
    )
    depth: Optional[int] = Field(default=2, ge=1, le=10, description="关系深度")
    node_types: Optional[List[str]] = Field(
        default=None,
        description="节点类型过滤"
    )
    edge_types: Optional[List[str]] = Field(
        default=None,
        description="边类型过滤"
    )


# ── Session ──────────────────────────────────────────────────────────

class SessionCreateRequest(BaseModel):
    """创建会话请求"""
    name: str = Field(..., description="会话名称")
    type: str = Field(..., description="会话类型: scan, pentest, chat")
    metadata: Optional[Dict[str, Any]] = Field(default=None)


# ── Task ─────────────────────────────────────────────────────────────

class TaskCancelRequest(BaseModel):
    """取消任务请求"""
    task_id: str = Field(..., description="任务 ID")
    reason: Optional[str] = Field(default=None, description="取消原因")
