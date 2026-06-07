"""聊天会话持久化管理器"""

import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict, field


@dataclass
class ChatMessage:
    """单条对话消息"""
    role: str  # "user" or "assistant"
    content: str
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ChatSession:
    """聊天会话"""
    session_id: str
    topic: str  # 会话主题/主题提取
    target_path: str = ""  # 关联的扫描目标
    created_at: str = ""
    updated_at: str = ""
    messages: List[ChatMessage] = field(default_factory=list)
    scan_results: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        now = datetime.now().isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'topic': self.topic,
            'target_path': self.target_path,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'messages': [asdict(m) for m in self.messages],
            'scan_results': self.scan_results,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ChatSession':
        messages = [ChatMessage(**m) for m in data.get('messages', [])]
        return cls(
            session_id=data['session_id'],
            topic=data.get('topic', 'Unknown'),
            target_path=data.get('target_path', ''),
            created_at=data.get('created_at', ''),
            updated_at=data.get('updated_at', ''),
            messages=messages,
            scan_results=data.get('scan_results', []),
        )
    
    def add_message(self, role: str, content: str, metadata: Dict[str, Any] = None) -> ChatMessage:
        msg = ChatMessage(role=role, content=content, metadata=metadata or {})
        self.messages.append(msg)
        self.updated_at = datetime.now().isoformat()
        return msg
    
    def get_summary(self) -> str:
        """获取会话摘要"""
        msg_count = len(self.messages)
        last_msg = self.messages[-1].content[:80] if self.messages else ""
        return f"[{self.topic}] {msg_count}条消息 | 最后: {last_msg}"


class ChatSessionManager:
    """聊天会话持久化管理器"""
    
    def __init__(self, cache_dir: Optional[str] = None):
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path('.hos-ls-cache') / 'chat_sessions'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._current_session: Optional[ChatSession] = None
    
    def _get_session_path(self, session_id: str) -> Path:
        return self.cache_dir / f"{session_id}.json"
    
    def create_session(self, topic: str = "", target_path: str = "") -> ChatSession:
        """创建新会话"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        session_id = f"{timestamp}_{uuid.uuid4().hex[:6]}"
        
        # 自动提取主题
        if not topic:
            topic = self._extract_topic(target_path or "new_session")
        
        session = ChatSession(
            session_id=session_id,
            topic=topic,
            target_path=target_path,
        )
        self._current_session = session
        self.save_session(session)
        return session
    
    def save_session(self, session: ChatSession) -> None:
        """保存会话到磁盘"""
        session.updated_at = datetime.now().isoformat()
        path = self._get_session_path(session.session_id)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(session.to_dict(), f, ensure_ascii=False, indent=2)
    
    def load_session(self, session_id: str) -> Optional[ChatSession]:
        """加载会话"""
        path = self._get_session_path(session_id)
        if not path.exists():
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            session = ChatSession.from_dict(data)
            self._current_session = session
            return session
        except Exception:
            return None
    
    def list_sessions(self) -> List[ChatSession]:
        """列出所有会话，按时间倒序"""
        sessions = []
        for path in self.cache_dir.glob('*.json'):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                sessions.append(ChatSession.from_dict(data))
            except Exception:
                continue
        sessions.sort(key=lambda s: s.updated_at, reverse=True)
        return sessions
    
    def delete_session(self, session_id: str) -> bool:
        """删除会话"""
        path = self._get_session_path(session_id)
        if path.exists():
            path.unlink()
            if self._current_session and self._current_session.session_id == session_id:
                self._current_session = None
            return True
        return False
    
    def clear_all(self) -> int:
        """清除所有会话，返回删除数量"""
        count = 0
        for path in self.cache_dir.glob('*.json'):
            path.unlink()
            count += 1
        self._current_session = None
        return count
    
    @property
    def current_session(self) -> Optional[ChatSession]:
        return self._current_session
    
    @current_session.setter
    def current_session(self, session: ChatSession):
        self._current_session = session
    
    def _extract_topic(self, name: str) -> str:
        """从名称中提取主题"""
        # 路径提取最后一段
        parts = name.replace('\\', '/').split('/')
        last = parts[-1] if parts else name
        # 清理特殊字符
        topic = re.sub(r'[^a-zA-Z0-9\u4e00-\u9fff_-]', '_', last)[:30]
        return topic or "new_session"
