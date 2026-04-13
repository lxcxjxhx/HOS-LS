"""AI驱动的规划器核心结构

基于LLM的智能规划系统，支持动态生成和调整执行计划。
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import os


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
    CODE_ANALYSIS = "code_analysis"
    EXPLOIT = "exploit"
    INFO_GATHERING = "info_gathering"


@dataclass
class PlanStep:
    """Plan步骤"""
    type: PlanStepType
    config: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    estimated_tokens: int = 0
    risk_level: str = "low"  # low, medium, high


@dataclass
class PlanConstraints:
    """Plan约束条件"""
    max_time: Optional[str] = None
    safe_mode: bool = True
    max_workers: Optional[int] = None
    timeout: Optional[int] = None
    max_tokens: Optional[int] = None
    risk_threshold: str = "medium"


@dataclass
class Plan:
    """Plan核心类"""
    goal: str
    profile: PlanProfile = PlanProfile.STANDARD
    steps: List[PlanStep] = field(default_factory=list)
    constraints: PlanConstraints = field(default_factory=PlanConstraints)
    plan_version: str = "v2.0"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_step(self, step_type: PlanStepType, config: Dict[str, Any] = None, 
                 description: str = "", estimated_tokens: int = 0, 
                 risk_level: str = "low") -> 'Plan':
        """添加步骤"""
        if config is None:
            config = {}
        step = PlanStep(
            type=step_type, 
            config=config, 
            description=description, 
            estimated_tokens=estimated_tokens, 
            risk_level=risk_level
        )
        self.steps.append(step)
        return self
    
    def remove_step(self, step_type: PlanStepType) -> 'Plan':
        """移除步骤"""
        self.steps = [step for step in self.steps if step.type != step_type]
        return self
    
    def update_step(self, step_type: PlanStepType, config: Dict[str, Any],
                    description: str = None, estimated_tokens: int = None,
                    risk_level: str = None) -> 'Plan':
        """更新步骤"""
        for step in self.steps:
            if step.type == step_type:
                step.config.update(config)
                if description:
                    step.description = description
                if estimated_tokens is not None:
                    step.estimated_tokens = estimated_tokens
                if risk_level:
                    step.risk_level = risk_level
                break
        else:
            self.add_step(step_type, config, description, estimated_tokens, risk_level)
        return self
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "plan": {
                "goal": self.goal,
                "profile": self.profile.value,
                "steps": [
                    {
                        "type": step.type.value,
                        "config": step.config,
                        "description": step.description,
                        "estimated_tokens": step.estimated_tokens,
                        "risk_level": step.risk_level
                    }
                    for step in self.steps
                ],
                "constraints": {
                    "max_time": self.constraints.max_time,
                    "safe_mode": self.constraints.safe_mode,
                    "max_workers": self.constraints.max_workers,
                    "timeout": self.constraints.timeout,
                    "max_tokens": self.constraints.max_tokens,
                    "risk_threshold": self.constraints.risk_threshold
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
        plan_version = plan_data.get("plan_version", "v2.0")
        metadata = plan_data.get("metadata", {})
        
        # 解析步骤
        steps = []
        for step_data in plan_data.get("steps", []):
            step_type = PlanStepType(step_data.get("type"))
            step = PlanStep(
                type=step_type,
                config=step_data.get("config", {}),
                description=step_data.get("description", ""),
                estimated_tokens=step_data.get("estimated_tokens", 0),
                risk_level=step_data.get("risk_level", "low")
            )
            steps.append(step)
        
        # 解析约束条件
        constraints_data = plan_data.get("constraints", {})
        constraints = PlanConstraints(
            max_time=constraints_data.get("max_time"),
            safe_mode=constraints_data.get("safe_mode", True),
            max_workers=constraints_data.get("max_workers"),
            timeout=constraints_data.get("timeout"),
            max_tokens=constraints_data.get("max_tokens"),
            risk_threshold=constraints_data.get("risk_threshold", "medium")
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
        
        # 验证风险级别
        risk_levels = {"low": 0, "medium": 1, "high": 2}
        threshold = risk_levels.get(self.constraints.risk_threshold, 1)
        
        for step in self.steps:
            step_risk = risk_levels.get(step.risk_level, 0)
            if step_risk > threshold:
                return False
        
        # 验证token预算
        if self.constraints.max_tokens:
            total_tokens = sum(step.estimated_tokens for step in self.steps)
            if total_tokens > self.constraints.max_tokens:
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


class AIPlanner:
    """AI驱动的规划器"""
    
    def __init__(self, ai_client=None):
        """初始化规划器"""
        self.ai_client = ai_client
    
    def generate_plan(self, goal: str, context: Dict[str, Any] = None, 
                      constraints: PlanConstraints = None) -> Plan:
        """基于LLM生成执行计划"""
        if context is None:
            context = {}
        if constraints is None:
            constraints = PlanConstraints()
        
        # 构建提示词
        prompt = self._build_planning_prompt(goal, context, constraints)
        
        # 调用LLM生成计划
        if self.ai_client:
            response = self.ai_client.generate(prompt)
            plan = self._parse_llm_response(response, goal, constraints)
        else:
            #  fallback to basic plan
            plan = self._create_basic_plan(goal, constraints)
        
        return plan
    
    def _build_planning_prompt(self, goal: str, context: Dict[str, Any], 
                              constraints: PlanConstraints) -> str:
        """构建规划提示词"""
        file_system_context = context.get("file_system", {})
        tools_available = context.get("tools", [])
        
        prompt = f"""
你是HOS-LS的AI规划专家，需要根据用户目标生成最优执行计划。

用户目标:
{goal}

上下文信息:
- 文件系统: {json.dumps(file_system_context, ensure_ascii=False)}
- 可用工具: {', '.join(tools_available)}
- 约束条件: 
  - 安全模式: {constraints.safe_mode}
  - 最大token: {constraints.max_tokens or '无限制'}
  - 风险阈值: {constraints.risk_threshold}

请生成一个详细的执行计划，包括:
1. 步骤列表，每个步骤包含:
   - 类型 (scan, auth_analysis, poc, exploit, code_analysis等)
   - 配置参数
   - 描述
   - 预估token消耗
   - 风险级别 (low, medium, high)

2. 步骤顺序应合理，考虑依赖关系
3. 确保计划在约束条件范围内
4. 针对用户目标选择最适合的工具和方法

输出格式应为JSON，包含plan字段，结构如下:
{{
  "plan": {{
    "goal": "{goal}",
    "steps": [
      {{
        "type": "步骤类型",
        "config": {{步骤配置}},
        "description": "步骤描述",
        "estimated_tokens": 预估token数,
        "risk_level": "风险级别"
      }}
    ]
  }}
}}
"""
        return prompt
    
    def _parse_llm_response(self, response: str, goal: str, 
                           constraints: PlanConstraints) -> Plan:
        """解析LLM响应"""
        try:
            # 提取JSON部分
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
                plan = Plan.from_dict(data)
                plan.goal = goal
                plan.constraints = constraints
                return plan
        except Exception:
            pass
        
        # 解析失败时返回基础计划
        return self._create_basic_plan(goal, constraints)
    
    def _create_basic_plan(self, goal: str, constraints: PlanConstraints) -> Plan:
        """创建基础计划"""
        plan = Plan(goal=goal, constraints=constraints)
        
        # 根据目标创建基本步骤
        if "扫描" in goal or "scan" in goal.lower():
            plan.add_step(
                PlanStepType.SCAN,
                config={"depth": "medium"},
                description="执行代码安全扫描",
                estimated_tokens=500,
                risk_level="low"
            )
        elif "分析" in goal or "analyze" in goal.lower():
            plan.add_step(
                PlanStepType.CODE_ANALYSIS,
                config={"depth": "medium"},
                description="执行深度代码分析",
                estimated_tokens=800,
                risk_level="low"
            )
        elif "exploit" in goal.lower() or "利用" in goal:
            plan.add_step(
                PlanStepType.INFO_GATHERING,
                config={},
                description="收集目标信息",
                estimated_tokens=300,
                risk_level="low"
            )
            plan.add_step(
                PlanStepType.EXPLOIT,
                config={},
                description="生成利用代码",
                estimated_tokens=1000,
                risk_level="medium"
            )
        elif "修复" in goal or "fix" in goal.lower():
            plan.add_step(
                PlanStepType.SCAN,
                config={"depth": "high"},
                description="扫描漏洞",
                estimated_tokens=600,
                risk_level="low"
            )
            plan.add_step(
                PlanStepType.FIX,
                config={},
                description="生成修复方案",
                estimated_tokens=800,
                risk_level="low"
            )
        
        # 默认添加报告步骤
        plan.add_step(
            PlanStepType.REPORT,
            config={},
            description="生成执行报告",
            estimated_tokens=400,
            risk_level="low"
        )
        
        return plan
    
    def optimize_plan(self, plan: Plan, context: Dict[str, Any] = None) -> Plan:
        """优化现有计划"""
        if context is None:
            context = {}
        
        # 分析当前计划
        total_tokens = sum(step.estimated_tokens for step in plan.steps)
        high_risk_steps = [step for step in plan.steps if step.risk_level == "high"]
        
        # 优化建议
        optimizations = []
        
        # Token预算优化
        if plan.constraints.max_tokens and total_tokens > plan.constraints.max_tokens:
            # 压缩高token步骤
            for step in plan.steps:
                if step.estimated_tokens > 500:
                    step.estimated_tokens = int(step.estimated_tokens * 0.8)
                    optimizations.append(f"压缩{step.type.value}步骤的token消耗")
        
        # 风险优化
        if plan.constraints.risk_threshold == "low":
            for step in high_risk_steps:
                step.risk_level = "medium"
                optimizations.append(f"降低{step.type.value}步骤的风险级别")
        
        # 添加优化记录
        if optimizations:
            plan.metadata["optimizations"] = optimizations
        
        return plan
    
    def adapt_plan(self, plan: Plan, execution_results: Dict[str, Any]) -> Plan:
        """根据执行结果调整计划"""
        # 分析执行结果
        failed_steps = [step for step, result in execution_results.items() if not result.get("success")]
        
        # 调整计划
        for step_name in failed_steps:
            # 查找对应的步骤
            for i, step in enumerate(plan.steps):
                if step.type.value == step_name:
                    # 调整失败步骤
                    step.config["retry"] = True
                    step.config["timeout"] = step.config.get("timeout", 30) * 2
                    # 在失败步骤后添加备选步骤
                    if step.type == PlanStepType.SCAN:
                        plan.steps.insert(i + 1, PlanStep(
                            type=PlanStepType.CODE_ANALYSIS,
                            config={"depth": "low"},
                            description="备选代码分析",
                            estimated_tokens=400,
                            risk_level="low"
                        ))
                    break
        
        return plan
