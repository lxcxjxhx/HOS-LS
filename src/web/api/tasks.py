"""Tasks API — unified task management for all async operations."""

import threading
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from src.web.models import TaskStatus, TaskStatusEnum
from src.web.schemas import TaskCancelRequest

router = APIRouter(prefix="/tasks", tags=["tasks"])

# Unified task registry — populated by scan, pentest, etc.
_all_tasks: Dict[str, TaskStatus] = {}
_lock = threading.Lock()

# Track active thread IDs for orphan detection
_active_threads: Dict[str, threading.Thread] = {}


def register_task(task: TaskStatus, thread: threading.Thread | None = None) -> None:
    """Register a task (called by scan/pentest routers)."""
    with _lock:
        _all_tasks[task.task_id] = task
        if thread:
            _active_threads[task.task_id] = thread


def unregister_task(task_id: str) -> None:
    """Unregister a task from the active registry (keep in history if needed)."""
    with _lock:
        _all_tasks.pop(task_id, None)
        _active_threads.pop(task_id, None)


def get_task(task_id: str) -> TaskStatus | None:
    """Get a task by ID (thread-safe)."""
    with _lock:
        return _all_tasks.get(task_id)


def list_tasks(type: str | None = None, status: TaskStatusEnum | None = None, limit: int = 50) -> List[TaskStatus]:
    """List tasks with optional filters (thread-safe)."""
    with _lock:
        results = list(_all_tasks.values())

    if type:
        results = [t for t in results if t.type == type]
    if status:
        results = [t for t in results if t.status == status]

    return results[:limit]


def _count_orphan_tasks() -> List[str]:
    """Find tasks marked as 'running' whose thread has ended."""
    orphans = []
    with _lock:
        for task_id, thread in _active_threads.items():
            if not thread.is_alive():
                orphans.append(task_id)
    # Also check tasks marked running but not in active threads
    with _lock:
        for task_id, task in _all_tasks.items():
            if task.status == TaskStatusEnum.running and task_id not in _active_threads:
                if task_id not in orphans:
                    orphans.append(task_id)
    return orphans


# ── API Endpoints ────────────────────────────────────────────────────
# IMPORTANT: literal paths (health, cleanup, cancel) MUST be defined
# before {task_id} to avoid FastAPI matching "health" as a task_id.


@router.get("/health")
async def tasks_health() -> Dict[str, Any]:
    """任务系统健康检查"""
    with _lock:
        total = len(_all_tasks)
        running = sum(1 for t in _all_tasks.values() if t.status == TaskStatusEnum.running)
        completed = sum(1 for t in _all_tasks.values() if t.status == TaskStatusEnum.completed)
        failed = sum(1 for t in _all_tasks.values() if t.status == TaskStatusEnum.failed)
        cancelled = sum(1 for t in _all_tasks.values() if t.status == TaskStatusEnum.cancelled)
        pending = sum(1 for t in _all_tasks.values() if t.status == TaskStatusEnum.pending)

    orphans = _count_orphan_tasks()

    return {
        "total_tasks": total,
        "running": running,
        "completed": completed,
        "failed": failed,
        "cancelled": cancelled,
        "pending": pending,
        "orphan_tasks": len(orphans),
        "orphan_task_ids": orphans,
    }


@router.post("/cleanup")
async def tasks_cleanup() -> Dict[str, Any]:
    """清理孤儿任务（状态为 running 但线程已结束的任务）"""
    orphans = _count_orphan_tasks()
    cleaned = []
    for task_id in orphans:
        task = get_task(task_id)
        if task:
            old_status = task.status
            task.status = TaskStatusEnum.failed
            task.error = "Task orphaned: thread terminated unexpectedly"
            task.message = f"Task was {old_status.value} but thread ended"
            unregister_task(task_id)
            cleaned.append(task_id)

    return {
        "cleaned_count": len(cleaned),
        "cleaned_task_ids": cleaned,
    }


@router.get("", response_model=List[TaskStatus])
async def list_tasks_endpoint(
    type: str | None = None,
    status: TaskStatusEnum | None = None,
    limit: int = 50,
) -> List[TaskStatus]:
    """列出所有任务，支持按类型和状态过滤"""
    return list_tasks(type=type, status=status, limit=limit)


@router.post("/cancel", response_model=TaskStatus)
async def cancel_task(request: TaskCancelRequest) -> TaskStatus:
    """取消任务"""
    task = get_task(request.task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {request.task_id} not found")
    task.status = TaskStatusEnum.cancelled
    task.message = f"Task cancelled: {request.reason or 'no reason given'}"
    return task


@router.get("/{task_id}", response_model=TaskStatus)
async def get_task_endpoint(task_id: str) -> TaskStatus:
    """获取任务详情"""
    task = get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return task


@router.get("/{task_id}/status", response_model=TaskStatus)
async def get_task_status_endpoint(task_id: str) -> TaskStatus:
    """获取任务状态"""
    task = get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return task


@router.post("/{task_id}/cancel", response_model=TaskStatus)
async def cancel_task_endpoint(task_id: str) -> TaskStatus:
    """取消指定任务"""
    task = get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    if task.status not in (TaskStatusEnum.pending, TaskStatusEnum.running):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel task in '{task.status.value}' state. Only 'pending' or 'running' tasks can be cancelled."
        )

    # Try scan cancel first (has real cancel event)
    try:
        from src.web.api.scan import _cancel_events as _scan_cancel_events
        cancel_event = _scan_cancel_events.get(task_id)
        if cancel_event:
            cancel_event.set()
    except ImportError:
        pass

    # Try pentest cancel
    try:
        from src.web.api.pentest import _cancel_events as _pentest_cancel_events
        cancel_event = _pentest_cancel_events.get(task_id)
        if cancel_event:
            cancel_event.set()
    except ImportError:
        pass

    task.status = TaskStatusEnum.cancelled
    task.message = "Task cancelled by user"
    task.updated_at = datetime.utcnow()
    return task
