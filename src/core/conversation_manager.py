"""会话管理器

增强版会话管理，支持：
- 多轮对话上下文
- Plan状态追踪
- Pipeline执行历史
- 代码库上下文
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from pathlib import Path
import json
import os
from datetime import datetime

from src.core.config import Config


@dataclass
class Message:
    """消息对象"""
    role: str  # "user" or "assistant"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class ConversationHistory:
    """对话历史"""
    messages: List[Message] = field(default_factory=list)
    max_length: int = 100
    
    def add_message(self, role: str, content: str, metadata: Dict[str, Any] = None):
        """添加消息"""
        if len(self.messages) >= self.max_length:
            self.messages.pop(0)  # 移除最旧的消息
            
        message = Message(
            role=role,
            content=content,
            metadata=metadata or {}
        )
        self.messages.append(message)
    
    def get_recent(self, count: int = 10) -> List[Message]:
        """获取最近的消息"""
        return self.messages[-count:] if len(self.messages) > count else self.messages
    
    def to_list(self) -> List[Dict[str, str]]:
        """转换为列表格式（用于AI Prompt）"""
        return [
            {"role": msg.role, "content": msg.content}
            for msg in self.messages
        ]
    
    def clear(self):
        """清空历史"""
        self.messages.clear()


@dataclass
class PlanState:
    """Plan状态追踪"""
    current_plan: Optional[Any] = None  # Plan对象
    plan_history: List[Dict[str, Any]] = field(default_factory=list)
    last_modified: Optional[datetime] = None
    
    def update_plan(self, plan):
        """更新当前Plan"""
        self.current_plan = plan
        self.last_modified = datetime.now()
        
        if plan:
            self.plan_history.append({
                "timestamp": self.last_modified.isoformat(),
                "goal": getattr(plan, 'goal', 'Unknown'),
                "steps_count": len(getattr(plan, 'steps', []))
            })
            
            # 限制历史长度
            if len(self.plan_history) > 20:
                self.plan_history.pop(0)
    
    def get_summary(self) -> Dict[str, Any]:
        """获取Plan状态摘要"""
        if not self.current_plan:
            return {"has_plan": False}
            
        return {
            "has_plan": True,
            "goal": getattr(self.current_plan, 'goal', 'Unknown'),
            "steps": [
                {
                    "type": step.type.value if hasattr(step.type, 'value') else str(step.type),
                    "config": step.config
                }
                for step in getattr(self.current_plan, 'steps', [])
            ],
            "last_modified": self.last_modified.isoformat() if self.last_modified else None
        }


@dataclass
class ProjectContext:
    """项目上下文信息"""
    root_path: str = "."
    file_tree: Dict[str, Any] = None
    key_files: List[Dict[str, Any]] = field(default_factory=list)
    total_files: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    
    def generate_summary(self) -> str:
        """生成项目摘要文本"""
        parts = [f"项目根目录: {self.root_path}"]
        
        if self.total_files > 0:
            parts.append(f"文件总数: {self.total_files}")
            
        if self.languages:
            top_langs = sorted(self.languages.items(), key=lambda x: x[1], reverse=True)[:5]
            lang_str = ", ".join([f"{lang}({count})" for lang, count in top_langs])
            parts.append(f"主要语言: {lang_str}")
            
        if self.key_files:
            parts.append(f"关键文件数: {len(self.key_files)}")
            
        return "\n".join(parts)


class ConversationManager:
    """增强版会话管理器
    
    管理：
    - 对话历史
    - Plan状态
    - 项目上下文
    - 执行结果缓存
    """
    
    def __init__(self, config: Config, session_name: Optional[str] = None):
        self.config = config
        self.session_name = session_name or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.history = ConversationHistory()
        self.plan_state = PlanState()
        self.project_context = ProjectContext(root_path=os.getcwd())
        
        self._execution_cache: Dict[str, Any] = {}
        self._session_dir = Path.home() / ".hos-ls" / "sessions"
        self._session_dir.mkdir(parents=True, exist_ok=True)
        
        # 加载已有会话或初始化项目上下文
        if session_name:
            self.load_session()
        else:
            self._init_project_context()
    
    def add_user_message(self, content: str, metadata: Dict[str, Any] = None):
        """添加用户消息"""
        self.history.add_message("user", content, metadata)
    
    def add_assistant_message(self, content: str, metadata: Dict[str, Any] = None):
        """添加助手消息"""
        self.history.add_message("assistant", content, metadata)
    
    def update_context(self, result: Dict[str, Any]):
        """根据执行结果更新上下文"""
        result_type = result.get("type", "")
        
        # 缓存执行结果
        result_key = f"{result_type}_{datetime.now().isoformat()}"
        self._execution_cache[result_key] = {
            "result": result,
            "timestamp": datetime.now().isoformat()
        }
        
        # 更新Plan状态（如果是Plan相关操作）
        if "plan" in result_type.lower():
            plan = result.get("plan")
            if plan:
                self.plan_state.update_plan(plan)
    
    def get_context_summary(self) -> str:
        """获取当前上下文摘要（用于AI Prompt）"""
        parts = []
        
        # 最近对话
        recent_messages = self.history.get_recent(5)
        if recent_messages:
            parts.append("=== 最近对话 ===")
            for msg in recent_messages[-3:]:  # 只取最近3条
                role_label = "用户" if msg.role == "user" else "助手"
                parts.append(f"[{role_label}]: {msg.content[:100]}...")
        
        # Plan状态
        plan_summary = self.plan_state.get_summary()
        if plan_summary.get("has_plan"):
            parts.append("\n=== 当前方案 ===")
            parts.append(f"目标: {plan_summary['goal']}")
            steps_info = ", ".join([f"{s['type']}" for s in plan_summary.get('steps', [])])
            if steps_info:
                parts.append(f"步骤: {steps_info}")
        
        # 项目上下文
        project_summary = self.project_context.generate_summary()
        if project_summary:
            parts.append("\n=== 项目信息 ===")
            parts.append(project_summary)
        
        return "\n".join(parts)
    
    def get_recent_results(self, count: int = 5) -> List[Dict[str, Any]]:
        """获取最近的执行结果"""
        results = sorted(
            self._execution_cache.values(),
            key=lambda x: x['timestamp'],
            reverse=True
        )
        return [r['result'] for r in results[:count]]
    
    def save_session(self):
        """保存会话到磁盘"""
        session_file = self._session_dir / f"{self.session_name}.json"
        
        data = {
            "session_name": self.session_name,
            "history": [
                {
                    "role": msg.role,
                    "content": msg.content,
                    "timestamp": msg.timestamp.isoformat(),
                    "metadata": msg.metadata
                }
                for msg in self.history.messages
            ],
            "plan_state": self.plan_state.get_summary(),
            "project_context": {
                "root_path": self.project_context.root_path,
                "total_files": self.project_context.total_files,
                "languages": self.project_context.languages
            },
            "saved_at": datetime.now().isoformat()
        }
        
        try:
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            pass  # 静默失败
    
    def load_session(self):
        """从磁盘加载会话"""
        session_file = self._session_dir / f"{self.session_name}.json"
        
        if not session_file.exists():
            self._init_project_context()
            return
            
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # 恢复对话历史
            self.history.messages.clear()
            for msg_data in data.get("history", []):
                timestamp = datetime.fromisoformat(msg_data["timestamp"])
                message = Message(
                    role=msg_data["role"],
                    content=msg_data["content"],
                    timestamp=timestamp,
                    metadata=msg_data.get("metadata", {})
                )
                self.history.messages.append(message)
                
            # 恢复项目上下文
            pc_data = data.get("project_context", {})
            self.project_context.root_path = pc_data.get("root_path", ".")
            self.project_context.total_files = pc_data.get("total_files", 0)
            self.project_context.languages = pc_data.get("languages", {})
            
        except Exception as e:
            self._init_project_context()
    
    def _init_project_context(self):
        """初始化项目上下文"""
        try:
            root = Path(".")
            self.project_context.root_path = str(root.absolute())
            self.project_context.file_tree = self._build_file_tree(root, max_depth=3)
            self.project_context.key_files = self._identify_key_files(root)
            self.project_context.total_files = self._count_files(root)
            self.project_context.languages = self._detect_languages(root)
        except Exception as e:
            self.project_context.root_path = "."
    
    def _build_file_tree(self, path: Path, max_depth: int = 3, current_depth: int = 0) -> Dict[str, Any]:
        """构建文件树"""
        tree = {
            "name": path.name,
            "type": "directory",
            "children": []
        }
        
        if current_depth >= max_depth or not path.exists():
            return tree
        
        try:
            for item in sorted(path.iterdir()):
                if item.name.startswith('.'):
                    continue
                    
                if item.is_dir():
                    child = self._build_file_tree(item, max_depth, current_depth + 1)
                    tree["children"].append(child)
                else:
                    tree["children"].append({
                        "name": item.name,
                        "type": "file",
                        "size": item.stat().st_size
                    })
        except Exception:
            pass
            
        return tree
    
    def _identify_key_files(self, path: Path) -> List[Dict[str, Any]]:
        """识别关键文件"""
        key_patterns = {
            "配置文件": ["requirements.txt", "pyproject.toml", "setup.py", "package.json"],
            "主文件": ["main.py", "app.py", "index.js", "__main__.py"],
            "源码目录": ["src", "lib", "app"],
            "测试目录": ["tests", "test"],
            "文档": ["README.md", "README.rst", "docs"]
        }
        
        key_files = []
        for category, patterns in key_patterns.items():
            for pattern in patterns:
                target = path / pattern
                if target.exists():
                    key_files.append({
                        "path": str(target),
                        "category": category,
                        "type": "directory" if target.is_dir() else "file"
                    })
                    
        return key_files[:15]
    
    def _count_files(self, path: Path) -> int:
        """统计文件数量"""
        count = 0
        try:
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                count += len(files)
        except Exception:
            pass
        return count
    
    def _detect_languages(self, path: Path) -> Dict[str, int]:
        """检测项目语言"""
        extensions = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++'
        }
        
        languages = {}
        try:
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for file in files:
                    ext = Path(file).suffix.lower()
                    if ext in extensions:
                        lang = extensions[ext]
                        languages[lang] = languages.get(lang, 0) + 1
        except Exception:
            pass
            
        return languages
    
    def clear(self):
        """清空当前会话数据（不删除磁盘文件）"""
        self.history.clear()
        self.plan_state = PlanState()
        self._execution_cache.clear()
    
    def list_available_sessions(self) -> List[str]:
        """列出所有可用会话"""
        sessions = []
        for file in self._session_dir.glob("*.json"):
            sessions.append(file.stem)
        return sorted(sessions)
