"""断点续扫管理器（Checkpoint Manager）

提供任务中断恢复能力，支持：
- 步骤级/文件级/Agent级三级Checkpoint
- 自动保存策略（每N个文件或关键步骤）
- 轻量级状态快照（< 100KB，< 50ms）
- 完整的恢复流程

性能目标：
- Checkpoint创建: < 50ms
- Checkpoint恢复: < 200ms
- 并发支持: 多任务同时运行
"""

import uuid
import json
import os
import time
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class CheckpointStatus(Enum):
    """Checkpoint状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass
class FailedFileInfo:
    """失败文件信息"""
    file_path: str
    error_message: str
    timestamp: datetime = field(default_factory=datetime.now)
    retry_count: int = 0


@dataclass
class ScanProgress:
    """扫描进度详情
    
    跟踪文件级别的扫描状态，用于精确恢复。
    
    Attributes:
        total_files: 总文件数
        processed_files: 已处理文件数
        current_file: 当前正在处理的文件
        file_queue: 待处理文件队列
        completed_files: 已完成文件列表
        failed_files: 失败文件列表
        issues_found: 发现的问题总数
        estimated_time_remaining: 预估剩余时间（秒）
        start_time: 扫描开始时间
        last_update_time: 最后更新时间
    """
    total_files: int = 0
    processed_files: int = 0
    current_file: Optional[str] = None
    file_queue: List[str] = field(default_factory=list)
    completed_files: List[str] = field(default_factory=list)
    failed_files: List[FailedFileInfo] = field(default_factory=list)
    issues_found: int = 0
    estimated_time_remaining: float = 0.0
    start_time: datetime = field(default_factory=datetime.now)
    last_update_time: datetime = field(default_factory=datetime.now)
    
    def to_summary(self) -> str:
        """生成人类可读的进度摘要"""
        progress_pct = (self.processed_files / self.total_files * 100) if self.total_files > 0 else 0
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        return (
            f"📊 扫描进度: {self.processed_files}/{self.total_files} ({progress_pct:.1f}%)\n"
            f"📁 当前文件: {self.current_file or 'N/A'}\n"
            f"🐛 发现问题: {self.issues_found}\n"
            f"⏱️ 已用时间: {elapsed:.1f}秒\n"
            f"⏳ 预计剩余: {self.estimated_time_remaining:.0f}秒"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于序列化）"""
        return {
            'total_files': self.total_files,
            'processed_files': self.processed_files,
            'current_file': self.current_file,
            'file_queue': self.file_queue,
            'completed_files': self.completed_files,
            'failed_files': [asdict(f) for f in self.failed_files],
            'issues_found': self.issues_found,
            'estimated_time_remaining': self.estimated_time_remaining,
            'start_time': self.start_time.isoformat(),
            'last_update_time': self.last_update_time.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanProgress':
        """从字典创建实例（反序列化）"""
        failed_files = [
            FailedFileInfo(**f) if isinstance(f, dict) else f
            for f in data.get('failed_files', [])
        ]
        
        return cls(
            total_files=data.get('total_files', 0),
            processed_files=data.get('processed_files', 0),
            current_file=data.get('current_file'),
            file_queue=data.get('file_queue', []),
            completed_files=data.get('completed_files', []),
            failed_files=failed_files,
            issues_found=data.get('issues_found', 0),
            estimated_time_remaining=data.get('estimated_time_remaining', 0.0),
            start_time=datetime.fromisoformat(data['start_time']) if data.get('start_time') else datetime.now(),
            last_update_time=datetime.fromisoformat(data['last_update_time']) if data.get('last_update_time') else datetime.now()
        )


@dataclass
class CheckpointData:
    """检查点数据结构
    
    包含任务执行的完整状态快照，用于中断后恢复。
    
    Attributes:
        checkpoint_id: 唯一ID (UUID)
        timestamp: 创建时间
        session_id: 会话ID
        task_type: 任务类型 ("scan", "analyze", "exploit")
        plan_id: 关联的Plan ID
        current_step_index: 当前步骤索引
        total_steps: 总步骤数
        step_status: 步骤状态
        scan_progress: 扫描进度详情
        completed_results: 已完成的中间结果
        metadata: 额外元数据
    """
    checkpoint_id: str = field(default_factory=lambda: f"ckpt_{uuid.uuid4().hex[:12]}")
    timestamp: datetime = field(default_factory=datetime.now)
    session_id: str = ""
    task_type: str = ""
    plan_id: str = ""
    current_step_index: int = 0
    total_steps: int = 0
    step_status: str = CheckpointStatus.PENDING.value
    scan_progress: Optional[ScanProgress] = None
    completed_results: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于JSON序列化）"""
        return {
            'checkpoint_id': self.checkpoint_id,
            'timestamp': self.timestamp.isoformat(),
            'session_id': self.session_id,
            'task_info': {
                'type': self.task_type,
                'plan_id': self.plan_id
            },
            'step_state': {
                'current_step_index': self.current_step_index,
                'total_steps': self.total_steps,
                'step_status': self.step_status
            },
            'scan_progress': self.scan_progress.to_dict() if self.scan_progress else None,
            'completed_results': self.completed_results,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CheckpointData':
        """从字典创建实例（反序列化）"""
        scan_progress_data = data.get('scan_progress')
        scan_progress = ScanProgress.from_dict(scan_progress_data) if scan_progress_data else None
        
        task_info = data.get('task_info', {})
        step_state = data.get('step_state', {})
        
        return cls(
            checkpoint_id=data.get('checkpoint_id', f"ckpt_{uuid.uuid4().hex[:12]}"),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else datetime.now(),
            session_id=data.get('session_id', ''),
            task_type=task_info.get('type', ''),
            plan_id=task_info.get('plan_id', ''),
            current_step_index=step_state.get('current_step_index', 0),
            total_steps=step_state.get('total_steps', 0),
            step_status=step_state.get('step_status', CheckpointStatus.PENDING.value),
            scan_progress=scan_progress,
            completed_results=data.get('completed_results', {}),
            metadata=data.get('metadata', {})
        )


@dataclass
class RestoreResult:
    """恢复结果
    
    Attributes:
        success: 是否成功恢复
        checkpoint: 恢复的Checkpoint数据
        message: 恢复信息/错误消息
        resumed_step_index: 从哪个步骤继续
        skipped_steps: 跳过的已完成步骤列表
    """
    success: bool
    checkpoint: Optional[CheckpointData]
    message: str
    resumed_step_index: int = 0
    skipped_steps: List[int] = field(default_factory=list)


class CheckpointManager:
    """断点续扫管理器
    
    管理任务执行过程中的状态保存和恢复，确保中断后可无缝继续。
    
    使用示例:
        manager = CheckpointManager()
        
        # 创建checkpoint
        ckpt_id = await manager.create_checkpoint(
            task_type="scan",
            plan_id="plan_123",
            step_index=2,
            scan_progress=progress,
            results={"partial": data}
        )
        
        # 恢复执行
        result = await manager.restore_from_checkpoint(ckpt_id)
        if result.success:
            print(f"从第{result.resumed_step_index + 1}步继续...")
    """
    
    def __init__(self, checkpoint_dir: str = ".hos-ls/checkpoints"):
        """
        Args:
            checkpoint_dir: Checkpoint存储目录
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        self._current_checkpoint: Optional[CheckpointData] = None
        self._auto_save_counter: int = 0
        self._auto_save_interval: int = 5  # 每5个文件自动保存一次
        
        # 性能统计
        self._save_count: int = 0
        self._restore_count: int = 0
        self._total_save_time: float = 0.0
        self._total_restore_time: float = 0.0
    
    async def create_checkpoint(
        self,
        task_type: str,
        plan_id: str,
        step_index: int,
        total_steps: int = 0,
        step_status: str = CheckpointStatus.RUNNING.value,
        scan_progress: Optional[ScanProgress] = None,
        results: Dict[str, Any] = None,
        metadata: Dict[str, Any] = None,
        session_id: str = ""
    ) -> str:
        """创建新的检查点
        
        Args:
            task_type: 任务类型
            plan_id: 关联的Plan ID
            step_index: 当前步骤索引
            total_steps: 总步骤数
            step_status: 步骤状态
            scan_progress: 扫描进度对象
            results: 已完成的结果
            metadata: 额外元数据
            session_id: 会话ID
            
        Returns:
            checkpoint_id (str)
        """
        start_time = time.time()
        
        # 创建Checkpoint对象
        self._current_checkpoint = CheckpointData(
            session_id=session_id or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            task_type=task_type,
            plan_id=plan_id,
            current_step_index=step_index,
            total_steps=total_steps,
            step_status=step_status,
            scan_progress=scan_progress,
            completed_results=results or {},
            metadata=metadata or {}
        )
        
        # 保存到磁盘
        await self._save_to_disk(self._current_checkpoint)
        
        # 更新统计
        self._save_count += 1
        elapsed = time.time() - start_time
        self._total_save_time += elapsed
        
        # 重置自动保存计数器
        self._auto_save_counter = 0
        
        return self._current_checkpoint.checkpoint_id
    
    async def load_latest_checkpoint(self, plan_id: str) -> Optional[CheckpointData]:
        """加载指定Plan的最新检查点
        
        Args:
            plan_id: Plan ID
            
        Returns:
            最新的CheckpointData，如果不存在则返回None
        """
        checkpoints = await self._list_checkpoints_for_plan(plan_id)
        
        if not checkpoints:
            return None
        
        # 返回最新的（按时间排序取最后一个）
        latest_path = checkpoints[-1]
        return await self._load_from_disk(latest_path)
    
    async def load_checkpoint(self, checkpoint_id: str) -> Optional[CheckpointData]:
        """根据ID加载检查点
        
        Args:
            checkpoint_id: Checkpoint ID
            
        Returns:
            CheckpointData，如果不存在则返回None
        """
        checkpoint_path = self.checkpoint_dir / f"{checkpoint_id}.json"
        
        if not checkpoint_path.exists():
            return None
        
        return await self._load_from_disk(checkpoint_path)
    
    async def restore_from_checkpoint(self, checkpoint_id: str) -> RestoreResult:
        """从检查点恢复执行状态
        
        Args:
            checkpoint_id: Checkpoint ID
            
        Returns:
            RestoreResult 包含恢复后的完整状态
        """
        start_time = time.time()
        
        try:
            # 加载Checkpoint
            checkpoint = await self.load_checkpoint(checkpoint_id)
            
            if not checkpoint:
                return RestoreResult(
                    success=False,
                    checkpoint=None,
                    message=f"❌ Checkpoint '{checkpoint_id}' 不存在"
                )
            
            # 更新当前Checkpoint引用
            self._current_checkpoint = checkpoint
            
            # 计算跳过的步骤
            skipped_steps = list(range(0, checkpoint.current_step_index))
            
            # 更新统计
            self._restore_count += 1
            elapsed = time.time() - start_time
            self._total_restore_time += elapsed
            
            # 设置为运行状态
            checkpoint.step_status = CheckpointStatus.RUNNING.value
            if checkpoint.scan_progress:
                checkpoint.scan_progress.last_update_time = datetime.now()
            
            return RestoreResult(
                success=True,
                checkpoint=checkpoint,
                message=f"✅ 成功从CheckPoint恢复 (步骤{checkpoint.current_step_index + 1}/{checkpoint.total_steps})",
                resumed_step_index=checkpoint.current_step_index,
                skipped_steps=skipped_steps
            )
            
        except Exception as e:
            return RestoreResult(
                success=False,
                checkpoint=None,
                message=f"❌ 恢复失败: {str(e)}"
            )
    
    async def update_scan_progress(
        self,
        current_file: str,
        processed_count: int,
        total_files: int = 0,
        issues_found: int = 0,
        file_queue: List[str] = None,
        completed_files: List[str] = None,
        failed_files: List[FailedFileInfo] = None
    ):
        """更新扫描进度（轻量级操作，不写磁盘）
        
        Args:
            current_file: 当前正在处理的文件
            processed_count: 已处理文件数
            total_files: 总文件数
            issues_found: 发现的问题数
            file_queue: 待处理队列
            completed_files: 已完成列表
            failed_files: 失败列表
        """
        if not self._current_checkpoint or not self._current_checkpoint.scan_progress:
            # 如果没有当前的Checkpoint，创建一个默认的
            if not self._current_checkpoint:
                self._current_checkpoint = CheckpointData(task_type="scan")
            
            self._current_checkpoint.scan_progress = ScanProgress(
                total_files=total_files,
                start_time=datetime.now()
            )
        
        progress = self._current_checkpoint.scan_progress
        progress.current_file = current_file
        progress.processed_files = processed_count
        
        if total_files > 0:
            progress.total_files = total_files
        
        progress.issues_found = issues_found
        progress.last_update_time = datetime.now()
        
        if file_queue is not None:
            progress.file_queue = file_queue
        
        if completed_files is not None:
            progress.completed_files = completed_files
        
        if failed_files is not None:
            progress.failed_files = failed_files
        
        # 估算剩余时间（简单算法：基于已用时间和已处理比例）
        if progress.processed_files > 0 and progress.total_files > 0:
            elapsed = (datetime.now() - progress.start_time).total_seconds()
            rate = progress.processed_files / elapsed  # 文件/秒
            remaining_files = progress.total_files - progress.processed_files
            progress.estimated_time_remaining = remaining_files / rate if rate > 0 else 0
        
        # 增加自动保存计数器
        self._auto_save_counter += 1
    
    def should_auto_save(self) -> bool:
        """判断是否应该自动保存checkpoint
        
        Returns:
            bool 是否应该保存
        """
        return self._auto_save_counter >= self._auto_save_interval
    
    async def auto_save_if_needed(self) -> Optional[str]:
        """如果需要则自动保存
        
        Returns:
            checkpoint_id 或 None
        """
        if self.should_auto_save() and self._current_checkpoint:
            return await self.create_checkpoint(
                task_type=self._current_checkpoint.task_type,
                plan_id=self._current_checkpoint.plan_id,
                step_index=self._current_checkpoint.current_step_index,
                total_steps=self._current_checkpoint.total_steps,
                scan_progress=self._current_checkpoint.scan_progress,
                results=self._current_checkpoint.completed_results,
                session_id=self._current_checkpoint.session_id
            )
        return None
    
    def get_progress_summary(self) -> str:
        """获取当前进度摘要
        
        Returns:
            人类可读的进度字符串
        """
        if not self._current_checkpoint or not self._current_checkpoint.scan_progress:
            return "⏸️ 无进行中的任务"
        
        return self._current_checkpoint.scan_progress.to_summary()
    
    def get_current_checkpoint_id(self) -> Optional[str]:
        """获取当前Checkpoint ID"""
        return self._current_checkpoint.checkpoint_id if self._current_checkpoint else None
    
    def has_active_checkpoint(self) -> bool:
        """是否有活跃的Checkpoint"""
        return self._current_checkpoint is not None
    
    async def cleanup_old_checkpoints(self, keep_recent: int = 5):
        """清理旧的Checkpoint文件
        
        Args:
            keep_recent: 保留最近的数量
        """
        if not self.checkpoint_dir.exists():
            return
        
        # 获取所有Checkpoint文件
        checkpoint_files = sorted(
            self.checkpoint_dir.glob("ckpt_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True  # 最新的在前
        )
        
        # 删除超出保留数量的旧文件
        for old_file in checkpoint_files[keep_recent:]:
            try:
                old_file.unlink()
            except Exception as e:
                print(f"⚠️ 删除旧Checkpoint失败: {old_file.name} - {e}")
    
    async def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """删除指定的Checkpoint
        
        Args:
            checkpoint_id: Checkpoint ID
            
        Returns:
            bool 是否删除成功
        """
        checkpoint_path = self.checkpoint_dir / f"{checkpoint_id}.json"
        
        try:
            if checkpoint_path.exists():
                checkpoint_path.unlink()
                
                # 如果删除的是当前Checkpoint，清除引用
                if self._current_checkpoint and self._current_checkpoint.checkpoint_id == checkpoint_id:
                    self._current_checkpoint = None
                
                return True
            return False
        except Exception as e:
            print(f"❌ 删除Checkpoint失败: {e}")
            return False
    
    def list_all_checkpoints(self) -> List[Dict[str, Any]]:
        """列出所有Checkpoint的信息
        
        Returns:
            Checkpoint信息列表
        """
        checkpoints = []
        
        if not self.checkpoint_dir.exists():
            return checkpoints
        
        for ckpt_file in sorted(self.checkpoint_dir.glob("ckpt_*.json"), 
                                key=lambda p: p.stat().st_mtime,
                                reverse=True):
            try:
                with open(ckpt_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                checkpoints.append({
                    'id': data.get('checkpoint_id'),
                    'timestamp': data.get('timestamp'),
                    'task_type': data.get('task_info', {}).get('type'),
                    'step': f"{data.get('step_state', {}).get('current_step_index', 0) + 1}/{data.get('step_state', {}).get('total_steps', 0)}",
                    'status': data.get('step_state', {}).get('step_status'),
                    'file_size': f"{ckpt_file.stat().st_size / 1024:.1f}KB"
                })
            except Exception:
                continue
        
        return checkpoints
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息
        
        Returns:
            统计数据字典
        """
        avg_save_time = (self._total_save_time / self._save_count) if self._save_count > 0 else 0
        avg_restore_time = (self._total_restore_time / self._restore_count) if self._restore_count > 0 else 0
        
        return {
            'total_saves': self._save_count,
            'total_restores': self._restore_count,
            'avg_save_time_ms': avg_save_time * 1000,
            'avg_restore_time_ms': avg_restore_time * 1000,
            'has_active_checkpoint': self.has_active_checkpoint(),
            'current_checkpoint_id': self.get_current_checkpoint_id(),
            'checkpoint_dir': str(self.checkpoint_dir),
            'auto_save_interval': self._auto_save_interval
        }
    
    # ========== 私有方法 ==========
    
    async def _save_to_disk(self, checkpoint: CheckpointData):
        """保存Checkpoint到磁盘"""
        checkpoint_path = self.checkpoint_dir / f"{checkpoint.checkpoint_id}.json"
        
        data = checkpoint.to_dict()
        
        with open(checkpoint_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    
    async def _load_from_disk(self, path: Path) -> CheckpointData:
        """从磁盘加载Checkpoint"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return CheckpointData.from_dict(data)
    
    async def _list_checkpoints_for_plan(self, plan_id: str) -> List[Path]:
        """列出指定Plan的所有Checkpoint文件"""
        checkpoints = []
        
        if not self.checkpoint_dir.exists():
            return checkpoints
        
        for ckpt_file in self.checkpoint_dir.glob("ckpt_*.json"):
            try:
                with open(ckpt_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if data.get('task_info', {}).get('plan_id') == plan_id:
                    checkpoints.append(ckpt_file)
                    
            except Exception:
                continue
        
        # 按时间排序
        checkpoints.sort(key=lambda p: p.stat().st_mtime)
        
        return checkpoints


# ========== 全局单例 ==========
_global_checkpoint_manager: Optional[CheckpointManager] = None


def get_checkpoint_manager() -> CheckpointManager:
    """获取全局CheckpointManager实例（单例模式）
    
    Returns:
        CheckpointManager实例
    """
    global _global_checkpoint_manager
    
    if _global_checkpoint_manager is None:
        _global_checkpoint_manager = CheckpointManager()
    
    return _global_checkpoint_manager


# ========== 测试代码 ==========
if __name__ == "__main__":
    import asyncio
    
    async def test_checkpoint_system():
        """测试Checkpoint系统"""
        manager = CheckpointManager(test_dir=".test_checkpoints")
        
        print("=== 🧪 Checkpoint系统测试 ===\n")
        
        # 创建扫描进度
        progress = ScanProgress(
            total_files=100,
            processed_files=45,
            current_file="src/auth/login.py",
            file_queue=["src/api/users.py", "src/utils/helper.py"],
            completed_files=["src/main.py", "src/config.py"],
            issues_found=12
        )
        
        print("📊 原始进度:")
        print(progress.to_summary())
        print()
        
        # 创建Checkpoint
        print("💾 创建Checkpoint...")
        ckpt_id = await manager.create_checkpoint(
            task_type="scan",
            plan_id="plan_test_001",
            step_index=2,
            total_steps=4,
            step_status="running",
            scan_progress=progress,
            results={"info_result": "测试信息"},
            metadata={"mode": "pure-ai", "target": "./project"}
        )
        print(f"   ✅ Checkpoint已创建: {ckpt_id}")
        print()
        
        # 更新进度
        print("📝 更新进度...")
        await manager.update_scan_progress(
            current_file="src/api/users.py",
            processed_count=46,
            issues_found=13
        )
        print(f"   当前进度: {manager.get_progress_summary()}")
        print()
        
        # 恢复Checkpoint
        print("🔄 恢复Checkpoint...")
        restore_result = await manager.restore_from_checkpoint(ckpt_id)
        
        if restore_result.success:
            print(f"   {restore_result.message}")
            print(f"   从第{restore_result.resumed_step_index + 1}步继续")
            print(f"   跳过步骤: {restore_result.skipped_steps}")
            print()
            
            # 显示恢复后的进度
            if restore_result.checkpoint and restore_result.checkpoint.scan_progress:
                print("   恢复后的进度:")
                print("   " + restore_result.checkpoint.scan_progress.to_summary().replace('\n', '\n   '))
        else:
            print(f"   ❌ {restore_result.message}")
        print()
        
        # 列出所有Checkpoint
        print("📋 所有Checkpoint:")
        all_ckpts = manager.list_all_checkpoints()
        for ckpt in all_ckpts[:5]:
            print(f"   • [{ckpt['id'][:16]}...] {ckpt['task_type']} - 步骤{ckpt['step']} ({ckpt['status']})")
        print()
        
        # 统计信息
        print("📈 统计信息:")
        stats = manager.get_statistics()
        for key, value in stats.items():
            print(f"   {key}: {value}")
        print()
        
        # 清理
        print("🧹 清理测试数据...")
        import shutil
        if Path(".test_checkpoints").exists():
            shutil.rmtree(".test_checkpoints")
        print("   ✅ 清理完成")
    
    asyncio.run(test_checkpoint_system())
