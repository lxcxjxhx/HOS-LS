"""Plan DSL核心结构

定义Plan的核心类和数据结构，支持Plan的创建、修改和执行。
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class PlanProfile(Enum):
    """Plan配置文件枚举"""
    STANDARD = "standard"
    FULL = "full"
    FAST = "fast"
    DEEP = "deep"
    STEALTH = "stealth"


class PlanStepType(Enum):
    """Plan步骤类型枚举"""
    SCAN = "scan"
    AUTH_ANALYSIS = "auth_analysis"
    POC = "poc"
    REASON = "reason"
    ATTACK_CHAIN = "attack_chain"
    VERIFY = "verify"
    FIX = "fix"
    REPORT = "report"


@dataclass
class PlanStep:
    """Plan步骤"""
    type: PlanStepType
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlanConstraints:
    """Plan约束条件"""
    max_time: Optional[str] = None
    safe_mode: bool = True
    max_workers: Optional[int] = None
    timeout: Optional[int] = None


@dataclass
class Plan:
    """Plan核心类"""
    goal: str
    profile: PlanProfile = PlanProfile.STANDARD
    steps: List[PlanStep] = field(default_factory=list)
    constraints: PlanConstraints = field(default_factory=PlanConstraints)
    plan_version: str = "v1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_step(self, step_type: PlanStepType, config: Dict[str, Any] = None) -> 'Plan':
        """添加步骤"""
        if config is None:
            config = {}
        step = PlanStep(type=step_type, config=config)
        self.steps.append(step)
        return self
    
    def remove_step(self, step_type: PlanStepType) -> 'Plan':
        """移除步骤"""
        self.steps = [step for step in self.steps if step.type != step_type]
        return self
    
    def update_step(self, step_type: PlanStepType, config: Dict[str, Any]) -> 'Plan':
        """更新步骤"""
        for step in self.steps:
            if step.type == step_type:
                step.config.update(config)
                break
        else:
            self.add_step(step_type, config)
        return self
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "plan": {
                "goal": self.goal,
                "profile": self.profile.value,
                "steps": [
                    {
                        step.type.value: step.config
                    }
                    for step in self.steps
                ],
                "constraints": {
                    "max_time": self.constraints.max_time,
                    "safe_mode": self.constraints.safe_mode,
                    "max_workers": self.constraints.max_workers,
                    "timeout": self.constraints.timeout
                },
                "plan_version": self.plan_version,
                "metadata": self.metadata
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Plan':
        """从字典创建Plan"""
        plan_data = data.get("plan", {})
        
        # 解析基本字段
        goal = plan_data.get("goal", "")
        profile = PlanProfile(plan_data.get("profile", "standard"))
        plan_version = plan_data.get("plan_version", "v1.0")
        metadata = plan_data.get("metadata", {})
        
        # 解析步骤
        steps = []
        for step_data in plan_data.get("steps", []):
            for step_type_str, config in step_data.items():
                step_type = PlanStepType(step_type_str)
                step = PlanStep(type=step_type, config=config)
                steps.append(step)
        
        # 解析约束条件
        constraints_data = plan_data.get("constraints", {})
        constraints = PlanConstraints(
            max_time=constraints_data.get("max_time"),
            safe_mode=constraints_data.get("safe_mode", True),
            max_workers=constraints_data.get("max_workers"),
            timeout=constraints_data.get("timeout")
        )
        
        return cls(
            goal=goal,
            profile=profile,
            steps=steps,
            constraints=constraints,
            plan_version=plan_version,
            metadata=metadata
        )
    
    def validate(self) -> bool:
        """验证Plan有效性"""
        if not self.goal:
            return False
        if not self.steps:
            return False
        return True
    
    def get_step(self, step_type: PlanStepType) -> Optional[PlanStep]:
        """获取指定类型的步骤"""
        for step in self.steps:
            if step.type == step_type:
                return step
        return None
    
    def has_step(self, step_type: PlanStepType) -> bool:
        """检查是否包含指定类型的步骤"""
        return any(step.type == step_type for step in self.steps)
    
    def get_profile_config(self) -> Dict[str, Any]:
        """获取配置文件的默认配置"""
        profiles = {
            PlanProfile.STANDARD: {
                "scan": {"depth": "medium"},
                "auth_analysis": {"detect": ["jwt", "session", "oauth"]},
                "poc": {"generate": False}
            },
            PlanProfile.FULL: {
                "scan": {"depth": "high"},
                "auth_analysis": {"detect": ["jwt", "session", "oauth", "basic"]},
                "poc": {"generate": True},
                "attack_chain": {"enabled": True}
            },
            PlanProfile.FAST: {
                "scan": {"depth": "low"},
                "auth_analysis": {"detect": ["jwt", "session"]},
                "poc": {"generate": False}
            },
            PlanProfile.DEEP: {
                "scan": {"depth": "high"},
                "auth_analysis": {"detect": ["jwt", "session", "oauth", "basic", "api_key"]},
                "poc": {"generate": True},
                "attack_chain": {"enabled": True},
                "verify": {"enabled": True}
            },
            PlanProfile.STEALTH: {
                "scan": {"depth": "medium", "stealth": True},
                "auth_analysis": {"detect": ["jwt", "session"]},
                "poc": {"generate": False}
            }
        }
        return profiles.get(self.profile, {})
    
    def apply_profile(self) -> 'Plan':
        """应用配置文件"""
        profile_config = self.get_profile_config()
        
        for step_type_str, config in profile_config.items():
            step_type = PlanStepType(step_type_str)
            self.update_step(step_type, config)
        
        return self
