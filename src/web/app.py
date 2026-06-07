"""FastAPI 应用入口

创建并配置 HOS-LS Web GUI 的 FastAPI 应用实例。
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.core.config import Config, ConfigManager

logger = logging.getLogger(__name__)

# Module-level global for ws_manager (set in create_app, read by API modules)
_ws_manager: Optional[WebSocketManager] = None


def _get_ws_manager() -> Optional[WebSocketManager]:
    """获取全局 WebSocketManager 实例"""
    return _ws_manager


class WebSocketManager:
    """WebSocket 连接管理器 — 支持频道订阅与跨线程推送"""

    def __init__(self) -> None:
        # client_id -> list[WebSocket]
        self._connections: dict[str, list[WebSocket]] = {}
        # channel -> set[WebSocket]  （如 "scan/abc-123", "pentest/def-456"）
        self._channels: dict[str, set[WebSocket]] = {}
        # ws -> set[channel]  反向索引，用于断开时清理
        self._ws_channels: dict[WebSocket, set[str]] = {}
        # asyncio event loop 引用（用于线程安全推送）
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ── Lifecycle ─────────────────────────────────────────────────────

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """设置 asyncio 事件循环，供非 async 线程调用推送"""
        self._loop = loop

    # ── Connection ────────────────────────────────────────────────────

    async def connect(self, websocket: WebSocket, client_id: str) -> None:
        await websocket.accept()
        self._connections.setdefault(client_id, []).append(websocket)
        self._ws_channels[websocket] = set()

    def disconnect(self, websocket: WebSocket, client_id: str) -> None:
        # 清理频道
        for ch in self._ws_channels.pop(websocket, set()):
            ch_set = self._channels.get(ch)
            if ch_set:
                ch_set.discard(websocket)
                if not ch_set:
                    self._channels.pop(ch, None)
        # 清理连接
        clients = self._connections.get(client_id, [])
        if websocket in clients:
            clients.remove(websocket)
        if not clients:
            self._connections.pop(client_id, None)

    # ── Channel Subscription ─────────────────────────────────────────

    async def subscribe(self, websocket: WebSocket, channel: str) -> None:
        """订阅一个频道"""
        self._channels.setdefault(channel, set()).add(websocket)
        self._ws_channels.setdefault(websocket, set()).add(channel)

    async def unsubscribe(self, websocket: WebSocket, channel: str) -> None:
        """退订一个频道"""
        self._ws_channels.get(websocket, set()).discard(channel)
        ch_set = self._channels.get(channel)
        if ch_set:
            ch_set.discard(websocket)
            if not ch_set:
                self._channels.pop(channel, None)

    def get_channel_subscribers(self, channel: str) -> set[WebSocket]:
        """返回频道当前的所有订阅者（非 async）"""
        return self._channels.get(channel, set()).copy()

    # ── Push ─────────────────────────────────────────────────────────

    async def send_to(self, client_id: str, message: dict) -> None:
        dead = []
        for ws in self._connections.get(client_id, []):
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            # 查找 client_id
            for cid, ws_list in list(self._connections.items()):
                if ws in ws_list:
                    self.disconnect(ws, cid)
                    break

    async def broadcast(self, message: dict) -> None:
        for client_id in list(self._connections):
            await self.send_to(client_id, message)

    async def send_to_channel(self, channel: str, message: dict) -> None:
        """广播消息到特定频道的所有客户端"""
        dead = []
        for ws in self._channels.get(channel, set()):
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._cleanup_ws(ws)

    def push_to_channel_threadsafe(self, channel: str, message: dict) -> None:
        """从非 async 线程安全地向频道推送消息"""
        if self._loop is None:
            logger.warning("WebSocketManager: _loop not set, cannot push from thread")
            return
        coro = self.send_to_channel(channel, message)
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    def _cleanup_ws(self, websocket: WebSocket) -> None:
        """清理失效的 WebSocket 所有引用"""
        for ch in self._ws_channels.pop(websocket, set()):
            ch_set = self._channels.get(ch)
            if ch_set:
                ch_set.discard(websocket)
                if not ch_set:
                    self._channels.pop(ch, None)
        for cid, ws_list in list(self._connections.items()):
            if websocket in ws_list:
                ws_list.remove(websocket)
                if not ws_list:
                    self._connections.pop(cid, None)


def create_app(config: Optional[Config] = None) -> FastAPI:
    """创建 FastAPI 应用实例

    Args:
        config: HOS-LS 配置对象，为 None 时自动加载

    Returns:
        配置好的 FastAPI 应用
    """
    if config is None:
        config = ConfigManager().auto_load()

    # ── App ──────────────────────────────────────────────────────────
    app = FastAPI(
        title="HOS-LS Web GUI",
        description="HOS-LS AI 代码安全扫描工具 — Web 管理界面",
        version=config.version,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # ── CORS ─────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # 生产环境应限制具体域名
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── WebSocket Manager ────────────────────────────────────────────
    ws_manager = WebSocketManager()
    global _ws_manager
    _ws_manager = ws_manager
    app.state.ws_manager = ws_manager

    @app.on_event("startup")
    async def _startup_set_loop() -> None:
        """记录当前事件循环，供后台线程推送使用"""
        ws_manager.set_loop(asyncio.get_running_loop())

    @app.websocket("/ws/{client_id}")
    async def websocket_endpoint(websocket: WebSocket, client_id: str) -> None:
        await ws_manager.connect(websocket, client_id)
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    msg = json.loads(data)
                    msg_type = msg.get("type", "")
                    # 频道订阅
                    if msg_type == "subscribe":
                        channel = msg.get("channel", "")
                        if channel:
                            await ws_manager.subscribe(websocket, channel)
                            await ws_manager.send_to(client_id, {
                                "type": "subscribed", "channel": channel,
                            })
                    # 频道退订
                    elif msg_type == "unsubscribe":
                        channel = msg.get("channel", "")
                        if channel:
                            await ws_manager.unsubscribe(websocket, channel)
                            await ws_manager.send_to(client_id, {
                                "type": "unsubscribed", "channel": channel,
                            })
                    else:
                        await ws_manager.send_to(client_id, {"type": "echo", "data": data})
                except json.JSONDecodeError:
                    await ws_manager.send_to(client_id, {"type": "echo", "data": data})
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket, client_id)

    # ── Router Registration ──────────────────────────────────────────
    from src.web.api import (
        chat,
        findings,
        health,
        ide,
        pentest,
        scan,
        sessions,
        star_map,
        tasks,
    )

    api_prefix = "/api"

    app.include_router(health.router, prefix=api_prefix)
    app.include_router(scan.router, prefix=api_prefix)
    app.include_router(findings.router, prefix=api_prefix)
    app.include_router(pentest.router, prefix=api_prefix)
    app.include_router(chat.router, prefix=api_prefix)
    app.include_router(star_map.router, prefix=api_prefix)
    app.include_router(sessions.router, prefix=api_prefix)
    app.include_router(tasks.router, prefix=api_prefix)
    app.include_router(ide.router, prefix=api_prefix)

    # ── Static Files ─────────────────────────────────────────────────
    # Priority: web-static (manual override) > web/dist (built frontend)
    static_dir = Path(__file__).parent.parent.parent / "web-static"
    if not static_dir.is_dir():
        static_dir = Path(__file__).parent.parent.parent / "web" / "dist"
    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    # ── Root ─────────────────────────────────────────────────────────
    @app.get("/")
    async def root() -> dict:
        return {"name": "HOS-LS Web GUI", "version": config.version}

    return app
