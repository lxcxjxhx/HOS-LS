"""Chat API — AI conversational interface."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from src.web.models import ChatMessage, ChatResponse, ChatSessionResponse
from src.web.schemas import ChatRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["chat"])

# ── Agent singleton (lazy init) ─────────────────────────────────────
_agent: Any = None
_agent_lock: bool = False

# In-memory chat sessions: session_id → list of ChatMessage
_chat_sessions: dict[str, list[ChatMessage]] = {}


def _to_session_response(session_id: str) -> ChatSessionResponse:
    """Convert internal chat session to API response."""
    messages = _chat_sessions.get(session_id, [])
    return ChatSessionResponse(
        session_id=session_id,
        name=_get_session_name(session_id),
        message_count=len(messages),
        created_at=messages[0].timestamp if messages else "",
    )


def _get_session_name(session_id: str) -> str:
    """Infer session name from first user message."""
    messages = _chat_sessions.get(session_id, [])
    for msg in messages:
        if msg.role == "user":
            return msg.content[:40] or "新对话"
    return "新对话"


@router.get("/sessions", response_model=list[ChatSessionResponse])
async def list_chat_sessions() -> list[ChatSessionResponse]:
    """列出所有对话会话"""
    return [_to_session_response(sid) for sid in _chat_sessions]


def _get_agent() -> Any:
    """Lazy-initialize the ConversationalSecurityAgent singleton."""
    global _agent, _agent_lock
    if _agent is not None:
        return _agent
    if _agent_lock:
        # Still initializing in another request; return None caller handles
        return None
    try:
        _agent_lock = True
        from src.core.chat import ConversationalSecurityAgent

        _agent = ConversationalSecurityAgent()
        _agent.set_ai_enabled(True)
        return _agent
    except Exception:
        logger.warning("Failed to initialize ConversationalSecurityAgent", exc_info=True)
        return None
    finally:
        _agent_lock = False


def _ensure_session(session_id: str) -> list[ChatMessage]:
    """Ensure session exists and return its message list."""
    if session_id not in _chat_sessions:
        _chat_sessions[session_id] = []
    return _chat_sessions[session_id]


@router.post("", response_model=ChatResponse)
async def send_message(request: ChatRequest) -> ChatResponse:
    """发送对话消息，调用真实 AI 对话引擎。"""
    session_id = request.session_id or str(uuid.uuid4())
    messages = _ensure_session(session_id)

    # Store user message
    messages.append(ChatMessage(role="user", content=request.message))

    agent = _get_agent()
    if agent is None:
        # AI agent unavailable — inform user with clear error, no fake responses
        logger.warning(
            "ConversationalSecurityAgent not available. "
            "Ensure AI dependencies are installed and API key is configured."
        )
        assistant_msg = ChatMessage(
            role="assistant",
            content=(
                "⚠️ AI 对话引擎未就绪。\n\n"
                "可能原因：\n"
                "1. 缺少 AI 依赖（如 langgraph, litellm 等）\n"
                "2. 未配置 API 密钥（环境变量）\n"
                "3. AI 服务初始化失败\n\n"
                "请查看后端日志获取详细错误信息。\n"
                "此功能需要配置 AI 模型后才能使用。"
            ),
        )
        messages.append(assistant_msg)
        return ChatResponse(
            message=assistant_msg,
            session_id=session_id,
            context={"agent_available": False},
        )

    try:
        response_text = await agent.process_message(request.message)
    except Exception as exc:
        logger.error("Agent process_message failed: %s", exc, exc_info=True)
        response_text = f"处理消息时出错: {exc}"

    assistant_msg = ChatMessage(role="assistant", content=response_text)
    messages.append(assistant_msg)

    return ChatResponse(
        message=assistant_msg,
        session_id=session_id,
        context={"intent": _extract_last_intent(session_id)},
    )


def _extract_last_intent(session_id: str) -> str | None:
    """从 session 最近一条 AI 消息的 metadata 中提取 intent。"""
    messages = _chat_sessions.get(session_id, [])
    for msg in reversed(messages):
        if msg.role == "assistant":
            return msg.metadata.get("intent")
    return None


@router.get("/{session_id}/history", response_model=list[ChatMessage])
async def get_history(session_id: str) -> list[ChatMessage]:
    """获取对话历史"""
    history = _chat_sessions.get(session_id)
    if not history:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return history


@router.delete("/{session_id}")
async def delete_session(session_id: str) -> dict:
    """删除对话会话"""
    if session_id not in _chat_sessions:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    del _chat_sessions[session_id]
    return {"message": f"Session {session_id} deleted"}


@router.post("/stream")
async def stream_message(request: ChatRequest):
    """流式对话 — SSE 输出。

    使用 Server-Sent Events 逐步返回 AI 响应。
    """
    session_id = request.session_id or str(uuid.uuid4())
    _ensure_session(session_id)

    # Store user message immediately
    _chat_sessions[session_id].append(ChatMessage(role="user", content=request.message))

    agent = _get_agent()

    async def _event_stream() -> AsyncIterator[str]:
        if agent is None:
            yield f"event: error\ndata: {{\"error\": \"AI 引擎未就绪\"}}\n\n"
            return

        try:
            response_text = await agent.process_message(request.message)
        except Exception as exc:
            logger.error("Agent stream process failed: %s", exc, exc_info=True)
            yield f"event: error\ndata: {{\"error\": \"{exc}\"}}\n\n"
            return

        yield f"event: message\ndata: {json.dumps({'content': response_text, 'session_id': session_id}, ensure_ascii=False)}\n\n"
        yield f"event: done\ndata: {json.dumps({'session_id': session_id})}\n\n"

        # Save assistant message after streaming
        _chat_sessions[session_id].append(
            ChatMessage(role="assistant", content=response_text)
        )

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
