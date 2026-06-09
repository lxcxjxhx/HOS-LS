"""Scan API — integrates with existing scan engine (src.core.scanner, src.scanners.*)."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from src.core.config import Config
from src.core.engine import Finding, ScanResult, Severity
from src.core.scanner import create_scanner
from src.web.api.tasks import register_task
from src.web.models import FindingResponse, SeverityEnum, TaskStatus, TaskStatusEnum
from src.web.schemas import ScanRequest

router = APIRouter(prefix="/scan", tags=["scan"])

# In-memory task store for scan tasks (also registered in unified tasks registry)
_scan_tasks: dict[str, TaskStatus] = {}
# Cancel events keyed by task_id
_cancel_events: dict[str, threading.Event] = {}


def _ws_push(task_id: str, message: dict) -> None:
    """Thread-safe WebSocket push to scan/{task_id} channel."""
    try:
        from src.web.app import _get_ws_manager
        ws = _get_ws_manager()
        if ws:
            ws.push_to_channel_threadsafe(f"scan/{task_id}", message)
    except Exception:
        pass


def _build_config(request: ScanRequest) -> Config:
    """根据前端请求构建扫描配置"""
    config = Config()
    config.debug = False
    config.quiet = True
    config.verbose = False

    # 扫描模式映射
    scan_mode_map = {
        "auto": "auto",
        "static": "auto",
        "dynamic": "auto",
        "hybrid": "auto",
    }
    config.scan_mode = scan_mode_map.get(request.scan_mode, "auto")
    config.pure_ai = request.scan_mode == "static"

    # AI / NVD 选项
    config.ai.enabled = request.ai_enabled
    if hasattr(config.nvd, "enabled"):
        config.nvd.enabled = request.nvd_enabled

    # 包含 / 排除模式
    if request.include_patterns:
        config.scan.include_patterns = request.include_patterns
    if request.exclude_patterns:
        config.scan.exclude_patterns = request.exclude_patterns

    # 规则
    if request.rules:
        config.rules.enabled = request.rules

    # 并发数
    if request.max_workers:
        config.scan.max_workers = request.max_workers

    # 优先级策略
    if request.priority_strategy:
        config.scan.priority_strategy = request.priority_strategy

    return config


def _run_scan_task(task: TaskStatus, config: Config, target_path: str) -> None:
    """后台线程执行扫描"""
    task.status = TaskStatusEnum.running
    task.progress = 0.0
    task.message = f"Scanning: {target_path}"
    task.updated_at = datetime.utcnow()

    cancel_event = _cancel_events.get(task.task_id)

    # 启动监控线程定期推送进度
    _ws_push(task.task_id, {
        "type": "scan_progress",
        "task_id": task.task_id,
        "progress": 0,
        "message": "Starting scan...",
    })

    monitor_stop = threading.Event()
    monitor_thread = threading.Thread(
        target=_scan_monitor,
        args=(task, task.task_id, monitor_stop),
        daemon=True,
        name=f"scan-monitor-{task.task_id}",
    )
    monitor_thread.start()

    try:
        scanner = create_scanner(config)
        result: ScanResult = scanner.scan_sync(target_path)

        # 检查是否在扫描期间被取消
        if cancel_event and cancel_event.is_set():
            monitor_stop.set()
            monitor_thread.join(timeout=2)
            task.status = TaskStatusEnum.cancelled
            task.message = "Scan cancelled by user"
            task.progress = 0.0
            task.updated_at = datetime.utcnow()
            _ws_push(task.task_id, {
                "type": "scan_cancelled", "task_id": task.task_id,
            })
            return

        # 转换 findings 为响应格式
        findings_data: List[Dict[str, Any]] = []
        for i, finding in enumerate(result.findings):
            findings_data.append(_finding_to_dict(finding, i))

        total_files = result.metadata.get("total_files", 0)
        if total_files == 0 and hasattr(result, "metadata"):
            total_files = result.metadata.get("files_scanned", 0)

        task.status = TaskStatusEnum.completed
        task.progress = 100.0
        task.files_scanned = total_files
        task.findings_count = len(findings_data)
        task.message = f"Scan completed: {len(findings_data)} findings in {total_files} files"
        task.result = {
            "findings": findings_data,
            "files_scanned": total_files,
            "findings_count": len(findings_data),
            "scan_duration": result.duration,
            "target": result.target,
        }
        task.updated_at = datetime.utcnow()

        _ws_push(task.task_id, {
            "type": "scan_complete",
            "task_id": task.task_id,
            "findings_count": len(findings_data),
            "files_scanned": total_files,
        })

    except Exception as e:
        task.status = TaskStatusEnum.failed
        task.error = str(e)
        task.message = f"Scan failed: {str(e)}"
        task.progress = 0.0
        task.updated_at = datetime.utcnow()
        _ws_push(task.task_id, {
            "type": "scan_failed",
            "task_id": task.task_id,
            "error": str(e),
        })
    finally:
        monitor_stop.set()
        monitor_thread.join(timeout=2)
        _cancel_events.pop(task.task_id, None)


def _scan_monitor(task: TaskStatus, task_id: str, stop_event: threading.Event) -> None:
    """监控线程：定期推送扫描进度"""
    last_pushed_progress = -1
    while not stop_event.wait(1.0):  # 每秒检查一次
        if task.status != TaskStatusEnum.running:
            break
        # 只有进度变化时才推送
        if task.progress != last_pushed_progress:
            last_pushed_progress = task.progress
            msg: Dict[str, Any] = {
                "type": "scan_progress",
                "task_id": task_id,
                "progress": int(task.progress),
                "message": task.message or "",
            }
            if task.current_file:
                msg["current_file"] = task.current_file
            if task.files_scanned:
                msg["files_scanned"] = task.files_scanned
            if task.total_files:
                msg["total_files"] = task.total_files
            _ws_push(task_id, msg)


def _finding_to_dict(finding: Finding, index: int) -> Dict[str, Any]:
    """将引擎 Finding 转换为 API 响应 dict"""
    severity_map = {
        Severity.CRITICAL: SeverityEnum.critical,
        Severity.HIGH: SeverityEnum.high,
        Severity.MEDIUM: SeverityEnum.medium,
        Severity.LOW: SeverityEnum.low,
        Severity.INFO: SeverityEnum.info,
    }

    severity = finding.severity
    if isinstance(severity, Severity):
        severity_enum = severity_map.get(severity, SeverityEnum.info)
    else:
        severity_enum = SeverityEnum.info

    code_snippet = finding.code_snippet
    if not code_snippet and finding.code_context:
        lines = finding.code_context.context_before + [finding.code_context.vulnerable_line] + finding.code_context.context_after
        code_snippet = "\n".join(lines)

    return {
        "id": f"finding-{index:04d}",
        "rule_id": finding.rule_id,
        "severity": severity_enum,
        "confidence": finding.confidence,
        "title": finding.rule_name or finding.rule_id,
        "description": finding.description or finding.message,
        "file_path": finding.location.file if finding.location else "",
        "line_number": finding.location.line if finding.location else None,
        "code_snippet": code_snippet,
        "cwe_id": finding.metadata.get("cwe_id"),
        "cve_ids": finding.metadata.get("cve_ids", []),
        "fix_suggestion": finding.fix_suggestion,
        "attack_chain": finding.metadata.get("attack_chain"),
        "created_at": finding.timestamp if hasattr(finding, "timestamp") else None,
    }


@router.post("", response_model=TaskStatus)
async def start_scan(request: ScanRequest) -> TaskStatus:
    """启动安全扫描"""
    task_id = str(uuid.uuid4())
    config = _build_config(request)
    target_path = str(Path(request.target_path).resolve())

    cancel_event = threading.Event()
    _cancel_events[task_id] = cancel_event

    task = TaskStatus(
        task_id=task_id,
        type="scan",
        status=TaskStatusEnum.pending,
        message=f"Scan queued for target: {target_path}",
        total_files=0,
    )
    _scan_tasks[task_id] = task

    thread = threading.Thread(
        target=_run_scan_task,
        args=(task, config, target_path),
        daemon=True,
        name=f"scan-{task_id}",
    )
    register_task(task, thread=thread)
    thread.start()

    return task


@router.get("/{task_id}", response_model=TaskStatus)
async def get_scan_status(task_id: str) -> TaskStatus:
    """获取扫描任务状态"""
    task = _scan_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return task


@router.post("/{task_id}/cancel", response_model=TaskStatus)
async def cancel_scan(task_id: str) -> TaskStatus:
    """取消扫描任务"""
    task = _scan_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    cancel_event = _cancel_events.get(task_id)
    if cancel_event:
        cancel_event.set()

    task.status = TaskStatusEnum.cancelled
    task.message = "Scan cancelled by user"
    task.updated_at = datetime.utcnow()
    return task


@router.get("/{task_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(task_id: str) -> List[FindingResponse]:
    """获取扫描发现的安全问题"""
    task = _scan_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    if task.status == TaskStatusEnum.pending:
        return []

    if task.status == TaskStatusEnum.running:
        # 扫描进行中，返回目前已发现的
        if task.result and "findings" in task.result:
            findings = task.result["findings"]
            return [FindingResponse(**f) for f in findings]
        return []

    if task.status == TaskStatusEnum.failed:
        return []

    # completed / cancelled
    if task.result and "findings" in task.result:
        findings = task.result["findings"]
        return [FindingResponse(**f) for f in findings]

    return []


@router.get("/{task_id}/summary")
async def get_scan_summary(task_id: str) -> Dict[str, Any]:
    """获取扫描统计摘要"""
    task = _scan_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    if task.status not in (TaskStatusEnum.completed, TaskStatusEnum.failed):
        return {
            "task_id": task_id,
            "status": task.status.value,
            "message": task.message,
            "progress": task.progress,
        }

    result = task.result or {}
    findings = result.get("findings", [])

    severity_counts: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in findings:
        sev = f.get("severity", "info")
        if isinstance(sev, str):
            sev = sev.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    scan_duration = result.get("scan_duration", 0.0)

    return {
        "task_id": task_id,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "files_scanned": result.get("files_scanned", task.files_scanned),
        "scan_duration": scan_duration,
        "status": task.status.value,
    }
