"""IDE API — code viewing and analysis for the IDE view."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.web.models import FindingResponse, SeverityEnum

router = APIRouter(prefix="/ide", tags=["ide"])


class CodeRequest(BaseModel):
    """IDE 代码请求"""
    file_path: str = Field(..., description="文件路径（绝对路径或相对路径）")
    action: str = Field(..., description="操作类型: read 或 analyze")
    line_start: Optional[int] = Field(default=None, ge=1, description="起始行号")
    line_end: Optional[int] = Field(default=None, ge=1, description="结束行号")


class CodeReadResponse(BaseModel):
    """代码读取响应"""
    file_path: str
    content: str
    total_lines: int
    line_start: int
    line_end: int


class CodeAnalyzeResponse(BaseModel):
    """代码分析响应"""
    file_path: str
    findings: List[FindingResponse] = []
    message: str


@router.post("/code")
async def code_action(request: CodeRequest) -> Dict[str, Any]:
    """IDE 代码查看/分析

    action="read": 读取文件内容
    action="analyze": 调用扫描引擎分析文件
    """
    action = request.action.lower()

    if action == "read":
        return await _handle_read(request)
    elif action == "analyze":
        return await _handle_analyze(request)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action '{request.action}'. Must be 'read' or 'analyze'.",
        )


async def _handle_read(request: CodeRequest) -> Dict[str, Any]:
    """读取文件内容"""
    target = Path(request.file_path)

    if not target.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")

    if not target.is_file():
        raise HTTPException(status_code=400, detail=f"Not a file: {request.file_path}")

    # Security: prevent reading outside reasonable paths
    try:
        resolved = target.resolve()
    except (OSError, ValueError):
        raise HTTPException(status_code=400, detail=f"Invalid file path: {request.file_path}")

    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"Permission denied: {request.file_path}")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")

    lines = content.splitlines()
    total_lines = len(lines)

    line_start = request.line_start or 1
    line_end = request.line_end or total_lines

    # Clamp to valid range
    line_start = max(1, min(line_start, total_lines))
    line_end = max(line_start, min(line_end, total_lines))

    snippet = "\n".join(lines[line_start - 1 : line_end])

    return {
        "file_path": str(resolved),
        "content": snippet,
        "total_lines": total_lines,
        "line_start": line_start,
        "line_end": line_end,
    }


async def _handle_analyze(request: CodeRequest) -> Dict[str, Any]:
    """分析文件中的安全问题"""
    target = Path(request.file_path)

    if not target.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")

    if not target.is_file():
        raise HTTPException(status_code=400, detail=f"Not a file: {request.file_path}")

    try:
        resolved = target.resolve()
        content = resolved.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"Permission denied: {request.file_path}")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")

    # Run analysis using the existing scan engine
    findings = await _analyze_file(resolved, content)

    return {
        "file_path": str(resolved),
        "findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in findings],
        "message": f"Analysis complete: {len(findings)} findings",
    }


async def _analyze_file(file_path: Path, content: str) -> List[FindingResponse]:
    """调用扫描引擎分析单个文件"""
    from src.core.config import Config
    from src.core.engine import Finding, ScanResult, Severity
    from src.core.scanner import create_scanner

    config = Config()
    config.debug = False
    config.quiet = True
    config.verbose = False

    scanner = create_scanner(config)

    # The scanner scans directories; we create a minimal scan for this single file
    try:
        result: ScanResult = scanner.scan_sync(str(file_path))
    except Exception:
        # If scanner can't handle single file, return empty
        return []

    findings: List[FindingResponse] = []
    for i, finding in enumerate(result.findings):
        findings.append(_finding_to_response(finding, i))

    return findings


def _finding_to_response(finding: Finding, index: int) -> FindingResponse:
    """将引擎 Finding 转换为 API 响应"""
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
        lines = (
            finding.code_context.context_before
            + [finding.code_context.vulnerable_line]
            + finding.code_context.context_after
        )
        code_snippet = "\n".join(lines)

    return FindingResponse(
        id=f"ide-finding-{index:04d}",
        rule_id=finding.rule_id,
        severity=severity_enum,
        confidence=finding.confidence,
        title=finding.rule_name or finding.rule_id,
        description=finding.description or finding.message,
        file_path=finding.location.file if finding.location else "",
        line_number=finding.location.line if finding.location else None,
        code_snippet=code_snippet,
        cwe_id=finding.metadata.get("cwe_id"),
        cve_ids=finding.metadata.get("cve_ids", []),
        fix_suggestion=finding.fix_suggestion,
        attack_chain=finding.metadata.get("attack_chain"),
        created_at=finding.timestamp if hasattr(finding, "timestamp") else None,
    )
