#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
执行链管理器 v1.0

功能：
1. 管理扫描执行链的所有阶段
2. 确保任何子模块失败导致全局BLOCK
3. 维护执行状态机
4. 禁止"假成功"
"""

from enum import Enum, auto
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime


class ExecutionStatus(Enum):
    """执行状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL_FAIL = "partial_fail"
    BLOCKED = "blocked"
    INVALID_RESULT = "invalid_result"


class ExecutionStage(Enum):
    """执行阶段"""
    INITIALIZATION = "initialization"
    RULE_LOADING = "rule_loading"
    SCANNING = "scanning"
    AI_ANALYSIS = "ai_analysis"
    PROVENANCE_TRACKING = "provenance_tracking"
    FINDINGS_FILTER = "findings_filter"
    ATTACK_CHAIN = "attack_chain"
    REPORTING = "reporting"


@dataclass
class StageResult:
    """阶段执行结果"""
    stage: ExecutionStage
    status: ExecutionStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    data: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    
    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


@dataclass
class ExecutionContext:
    """执行上下文"""
    target_path: str
    config: Dict[str, Any]
    findings: List[Dict[str, Any]] = field(default_factory=list)
    filtered_findings: List[Dict[str, Any]] = field(default_factory=list)
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExecutionChainManager:
    """执行链管理器"""
    
    def __init__(self):
        self.status = ExecutionStatus.PENDING
        self.current_stage: Optional[ExecutionStage] = None
        self.stage_results: Dict[ExecutionStage, StageResult] = {}
        self.context: Optional[ExecutionContext] = None
        self._block_reason: str = ""
        self._execution_log: List[str] = []
    
    def initialize(self, target_path: str, config: Dict[str, Any]) -> bool:
        """初始化执行链
        
        Args:
            target_path: 扫描目标路径
            config: 配置字典
            
        Returns:
            是否成功
        """
        self._log("初始化执行链")
        self.context = ExecutionContext(target_path=target_path, config=config)
        self.status = ExecutionStatus.RUNNING
        return True
    
    def execute_stage(self, 
                     stage: ExecutionStage, 
                     stage_func: Callable[[ExecutionContext], tuple[bool, Dict[str, Any], str]],
                     block_on_failure: bool = True) -> bool:
        """执行单个阶段
        
        Args:
            stage: 执行阶段
            stage_func: 阶段执行函数，返回 (成功, 数据, 错误信息)
            block_on_failure: 失败时是否BLOCK
            
        Returns:
            是否成功
        """
        self.current_stage = stage
        self._log(f"开始执行阶段: {stage.value}")
        
        stage_result = StageResult(
            stage=stage,
            status=ExecutionStatus.RUNNING,
            start_time=datetime.now()
        )
        
        try:
            success, data, error_msg = stage_func(self.context)
            
            stage_result.end_time = datetime.now()
            stage_result.data = data
            
            if success:
                stage_result.status = ExecutionStatus.SUCCESS
                self._log(f"阶段执行成功: {stage.value} ({stage_result.duration_seconds:.2f}s)")
            else:
                stage_result.status = ExecutionStatus.BLOCKED if block_on_failure else ExecutionStatus.PARTIAL_FAIL
                stage_result.error_message = error_msg
                self._log(f"阶段执行失败: {stage.value} - {error_msg}")
                
                if block_on_failure:
                    self._block(f"阶段 {stage.value} 失败: {error_msg}")
                    return False
            
            self.stage_results[stage] = stage_result
            return success
            
        except Exception as e:
            stage_result.end_time = datetime.now()
            stage_result.status = ExecutionStatus.BLOCKED if block_on_failure else ExecutionStatus.PARTIAL_FAIL
            stage_result.error_message = str(e)
            self.stage_results[stage] = stage_result
            
            self._log(f"阶段执行异常: {stage.value} - {str(e)}")
            
            if block_on_failure:
                self._block(f"阶段 {stage.value} 异常: {str(e)}")
                return False
            
            return False
    
    def _block(self, reason: str):
        """设置BLOCK状态
        
        Args:
            reason: 阻塞原因
        """
        self.status = ExecutionStatus.BLOCKED
        self._block_reason = reason
        self._log(f"执行链被BLOCK: {reason}")
    
    def _log(self, message: str):
        """记录执行日志"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {message}"
        self._execution_log.append(log_entry)
        print(log_entry)
    
    def is_blocked(self) -> bool:
        """检查是否被BLOCK"""
        return self.status == ExecutionStatus.BLOCKED
    
    def get_block_reason(self) -> str:
        """获取BLOCK原因"""
        return self._block_reason
    
    def get_execution_report(self) -> Dict[str, Any]:
        """获取执行报告"""
        return {
            "status": self.status.value,
            "current_stage": self.current_stage.value if self.current_stage else None,
            "block_reason": self._block_reason,
            "stage_results": {
                stage.value: {
                    "status": result.status.value,
                    "duration_seconds": result.duration_seconds,
                    "error_message": result.error_message,
                    "data_keys": list(result.data.keys()) if result.data else []
                }
                for stage, result in self.stage_results.items()
            },
            "context_summary": {
                "target_path": self.context.target_path if self.context else None,
                "findings_count": len(self.context.findings) if self.context else 0,
                "filtered_findings_count": len(self.context.filtered_findings) if self.context else 0,
                "attack_chains_count": len(self.context.attack_chains) if self.context else 0
            },
            "execution_log": self._execution_log
        }
    
    def validate_result_integrity(self) -> tuple[bool, str]:
        """验证结果完整性
        
        Returns:
            (是否有效, 错误信息)
        """
        if not self.context:
            return False, "执行上下文为空"
        
        # 验证必须有至少一个发现
        if not self.context.filtered_findings:
            return False, "过滤后的发现列表为空"
        
        # 验证所有发现都有元数据
        for finding in self.context.filtered_findings:
            if '_filter_metadata' not in finding:
                return False, f"发现缺少过滤元数据: {finding.get('issue', 'unknown')}"
        
        # 验证必须有攻击链（如果配置了）
        if self.context.config.get('require_attack_chain', False):
            if not self.context.attack_chains:
                return False, "攻击链为空但配置要求必须有攻击链"
        
        return True, ""
    
    def finalize(self) -> Dict[str, Any]:
        """完成执行链并返回最终结果
        
        Returns:
            执行结果
        """
        if self.is_blocked():
            return {
                "success": False,
                "status": "BLOCKED",
                "reason": self._block_reason,
                "report": self.get_execution_report()
            }
        
        # 验证结果完整性
        valid, error_msg = self.validate_result_integrity()
        if not valid:
            self.status = ExecutionStatus.INVALID_RESULT
            return {
                "success": False,
                "status": "INVALID_RESULT",
                "reason": error_msg,
                "report": self.get_execution_report()
            }
        
        self.status = ExecutionStatus.SUCCESS
        return {
            "success": True,
            "status": "SUCCESS",
            "findings": self.context.filtered_findings if self.context else [],
            "attack_chains": self.context.attack_chains if self.context else [],
            "report": self.get_execution_report()
        }


# 全局执行链管理器实例
execution_chain_manager = ExecutionChainManager()
