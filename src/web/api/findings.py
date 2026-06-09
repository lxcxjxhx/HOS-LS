"""Findings API — query and manage security findings."""
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from src.web.models import FindingResponse, SeverityEnum

router = APIRouter(prefix="/findings", tags=["findings"])


def _collect_all_findings() -> list[dict]:
    """Aggregate findings from all completed/running scan and pentest tasks."""
    all_findings: list[dict] = []
    try:
        from src.web.api.tasks import list_tasks
        from src.web.models import TaskStatusEnum
        completed_tasks = list_tasks(status=TaskStatusEnum.completed)
        running_tasks = list_tasks(status=TaskStatusEnum.running)
        for task in completed_tasks + running_tasks:
            if task.result and "findings" in task.result:
                task_findings = task.result["findings"]
                if isinstance(task_findings, list):
                    all_findings.extend(task_findings)
    except ImportError:
        pass
    return all_findings


@router.get("", response_model=List[FindingResponse])
async def list_findings(
    severity: Optional[List[SeverityEnum]] = Query(default=None),
    file_path: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> List[FindingResponse]:
    """列出安全发现 — 从真实扫描/渗透任务中聚合"""
    results_raw = _collect_all_findings()

    # Apply filters
    if severity:
        results_raw = [f for f in results_raw if f.get("severity") in [s.value for s in severity]]
    if file_path:
        results_raw = [f for f in results_raw if file_path.lower() in f.get("file_path", f.get("file", "")).lower()]
    if rule_id:
        results_raw = [f for f in results_raw if f.get("rule_id") == rule_id]

    # Convert to FindingResponse models
    findings = []
    for f in results_raw[:limit]:
        try:
            findings.append(FindingResponse(**f))
        except Exception:
            continue

    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str) -> FindingResponse:
    """获取单个安全发现详情"""
    all_findings = _collect_all_findings()
    for f in all_findings:
        if f.get("id") == finding_id:
            return FindingResponse(**f)
    raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
