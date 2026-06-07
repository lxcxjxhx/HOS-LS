"""Sessions API — manage scan/pentest/chat sessions."""

from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException

from src.web.models import SessionResponse, TaskStatusEnum
from src.web.schemas import SessionCreateRequest

router = APIRouter(prefix="/sessions", tags=["sessions"])

# In-memory sessions store
_sessions: dict[str, SessionResponse] = {}


@router.post("", response_model=SessionResponse)
async def create_session(request: SessionCreateRequest) -> SessionResponse:
    """创建新会话"""
    import uuid

    session_id = str(uuid.uuid4())
    session = SessionResponse(
        session_id=session_id,
        name=request.name,
        type=request.type,
        status=TaskStatusEnum.pending,
        metadata=request.metadata or {},
    )
    _sessions[session_id] = session
    return session


@router.get("", response_model=List[SessionResponse])
async def list_sessions(
    type: str | None = None,
    status: TaskStatusEnum | None = None,
    limit: int = 50,
) -> List[SessionResponse]:
    """列出会话"""
    results = list(_sessions.values())

    if type:
        results = [s for s in results if s.type == type]
    if status:
        results = [s for s in results if s.status == status]

    return results[:limit]


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str) -> SessionResponse:
    """获取会话详情"""
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return session


@router.delete("/{session_id}")
async def delete_session(session_id: str) -> dict:
    """删除会话"""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    del _sessions[session_id]
    return {"message": f"Session {session_id} deleted"}
