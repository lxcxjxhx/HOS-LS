"""远程控制模块

支持远程执行扫描任务。
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class RemoteTask:
    """远程任务"""
    
    id: str
    command: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class RemoteExecutor:
    """远程执行器
    
    支持远程执行扫描任务。
    """
    
    def __init__(self) -> None:
        self.tasks: Dict[str, RemoteTask] = {}
        self._task_counter = 0
    
    def create_task(
        self,
        command: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> RemoteTask:
        """创建任务
        
        Args:
            command: 命令
            parameters: 参数
            
        Returns:
            任务对象
        """
        self._task_counter += 1
        task_id = f"task_{self._task_counter:06d}"
        
        task = RemoteTask(
            id=task_id,
            command=command,
            parameters=parameters or {},
        )
        
        self.tasks[task_id] = task
        return task
    
    async def execute_task(self, task_id: str) -> Dict[str, Any]:
        """执行任务
        
        Args:
            task_id: 任务 ID
            
        Returns:
            执行结果
        """
        task = self.tasks.get(task_id)
        if not task:
            return {"error": f"任务 {task_id} 不存在"}
        
        task.status = "running"
        task.started_at = datetime.now()
        
        try:
            # 根据命令执行不同操作
            if task.command == "scan":
                result = await self._execute_scan(task.parameters)
            elif task.command == "status":
                result = await self._execute_status(task.parameters)
            elif task.command == "cancel":
                result = await self._execute_cancel(task.parameters)
            else:
                result = {"error": f"未知命令: {task.command}"}
            
            task.result = result
            task.status = "completed"
            
        except Exception as e:
            task.error = str(e)
            task.status = "failed"
            result = {"error": str(e)}
        
        task.completed_at = datetime.now()
        return task.result or {"error": task.error}
    
    async def _execute_scan(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """执行扫描"""
        from src.core.scanner import create_scanner
        
        target = parameters.get("target", ".")
        config = parameters.get("config", {})
        
        scanner = create_scanner()
        result = scanner.scan_sync(target)
        
        return result.to_dict()
    
    async def _execute_status(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """获取状态"""
        return {
            "status": "running",
            "tasks": len(self.tasks),
            "pending": len([t for t in self.tasks.values() if t.status == "pending"]),
            "running": len([t for t in self.tasks.values() if t.status == "running"]),
            "completed": len([t for t in self.tasks.values() if t.status == "completed"]),
        }
    
    async def _execute_cancel(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """取消任务"""
        task_id = parameters.get("task_id")
        if task_id and task_id in self.tasks:
            task = self.tasks[task_id]
            if task.status in ["pending", "running"]:
                task.status = "cancelled"
                return {"message": f"任务 {task_id} 已取消"}
            return {"error": f"任务 {task_id} 无法取消"}
        return {"error": f"任务 {task_id} 不存在"}
    
    def get_task(self, task_id: str) -> Optional[RemoteTask]:
        """获取任务"""
        return self.tasks.get(task_id)
    
    def list_tasks(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[RemoteTask]:
        """列出任务"""
        tasks = list(self.tasks.values())
        
        if status:
            tasks = [t for t in tasks if t.status == status]
        
        return tasks[:limit]
    
    def clear_completed_tasks(self) -> int:
        """清理已完成任务"""
        completed_ids = [
            task_id for task_id, task in self.tasks.items()
            if task.status in ["completed", "failed", "cancelled"]
        ]
        
        for task_id in completed_ids:
            del self.tasks[task_id]
        
        return len(completed_ids)


class BackgroundSession:
    """后台会话
    
    管理后台运行的扫描会话。
    """
    
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.created_at = datetime.now()
        self.tasks: List[str] = []
        self.status = "active"
        self._executor = RemoteExecutor()
    
    async def add_task(
        self,
        command: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """添加任务"""
        task = self._executor.create_task(command, parameters)
        self.tasks.append(task.id)
        return task.id
    
    async def run_all(self) -> List[Dict[str, Any]]:
        """运行所有任务"""
        results = []
        for task_id in self.tasks:
            result = await self._executor.execute_task(task_id)
            results.append(result)
        return results
    
    def get_status(self) -> Dict[str, Any]:
        """获取会话状态"""
        return {
            "session_id": self.session_id,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "task_count": len(self.tasks),
        }


class SessionManager:
    """会话管理器"""
    
    _instance: Optional["SessionManager"] = None
    
    def __new__(cls) -> "SessionManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._sessions: Dict[str, BackgroundSession] = {}
            cls._instance._counter = 0
        return cls._instance
    
    def create_session(self) -> BackgroundSession:
        """创建会话"""
        self._counter += 1
        session_id = f"session_{self._counter:06d}"
        session = BackgroundSession(session_id)
        self._sessions[session_id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[BackgroundSession]:
        """获取会话"""
        return self._sessions.get(session_id)
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """列出所有会话"""
        return [s.get_status() for s in self._sessions.values()]
    
    def close_session(self, session_id: str) -> bool:
        """关闭会话"""
        if session_id in self._sessions:
            self._sessions[session_id].status = "closed"
            return True
        return False
