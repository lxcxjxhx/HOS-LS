"""Agent Pipeline 构建器

实现Agent编排语言的核心逻辑，包括：
- Agent节点抽象
- Pipeline构建
- 自动补全
- 宏命令
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum

from src.core.plan import Plan, PlanStepType


class AgentType(Enum):
    """Agent类型枚举"""
    SCANNER = "scan"
    REASONER = "reason"
    ATTACK_CHAIN = "attack-chain"
    POC = "poc"
    VERIFIER = "verify"
    FIX = "fix"
    REPORT = "report"


@dataclass
class AgentNode:
    """Agent节点"""
    type: AgentType
    params: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.params is None:
            self.params = {}


class PipelineBuilder:
    """Pipeline构建器"""
    
    # 宏命令映射
    MACROS = {
        "full-audit": ["scan", "reason", "attack-chain", "poc", "verify", "report"],
        "quick-scan": ["scan", "reason", "report"],
        "deep-audit": ["scan", "reason=deep", "attack-chain", "poc", "verify"],
        "red-team": ["scan", "reason", "attack-chain", "poc", "verify"],
        "bug-bounty": ["scan", "reason", "poc", "report"],
        "compliance": ["scan", "reason", "report"]
    }
    
    # 自动补全规则
    AUTO_COMPLETE_RULES = {
        "scan": ["reason", "report"],
        "reason": ["report"],
        "poc": ["scan", "reason"],
        "verify": ["scan", "reason", "poc"],
        "attack-chain": ["scan", "reason"],
        "fix": ["scan", "reason"],
        "report": ["scan", "reason"]
    }
    
    # Agent依赖关系
    DEPENDENCIES = {
        "reason": ["scan"],
        "attack-chain": ["scan", "reason"],
        "poc": ["scan", "reason"],
        "verify": ["scan", "reason", "poc"],
        "fix": ["scan", "reason"],
        "report": ["scan", "reason"]
    }
    
    @classmethod
    def parse_flag(cls, flag: str) -> AgentNode:
        """解析单个flag
        
        支持格式：
        - --scan
        - --reason=deep
        """
        # 移除前缀
        if flag.startswith("--"):
            flag = flag[2:]
        
        # 解析权重参数
        if "=" in flag:
            name, value = flag.split("=", 1)
            params = {"strategy": value}
        else:
            name = flag
            params = {}
        
        # 转换为AgentType
        try:
            agent_type = AgentType(name)
        except ValueError:
            raise ValueError(f"Unknown agent type: {name}")
        
        return AgentNode(type=agent_type, params=params)
    
    @classmethod
    def parse_chain_flag(cls, flag: str) -> List[AgentNode]:
        """解析链式flag
        
        支持格式：--scan+reason+attack-chain
        """
        # 移除前缀
        if flag.startswith("--"):
            flag = flag[2:]
        
        # 分割链式命令
        parts = flag.split("+")
        nodes = []
        
        for part in parts:
            nodes.append(cls.parse_flag(part))
        
        return nodes
    
    @classmethod
    def expand_macros(cls, flags: List[str]) -> List[str]:
        """展开宏命令"""
        expanded = []
        
        for flag in flags:
            # 移除前缀
            if flag.startswith("--"):
                flag_name = flag[2:]
            else:
                flag_name = flag
            
            # 检查是否是宏命令
            if flag_name in cls.MACROS:
                # 展开宏命令
                expanded.extend(cls.MACROS[flag_name])
            else:
                expanded.append(flag)
        
        return expanded
    
    @classmethod
    def build_pipeline(cls, flags: List[str]) -> List[AgentNode]:
        """构建Agent Pipeline
        
        步骤：
        1. 展开宏命令
        2. 解析flags
        3. 自动补全缺失的依赖
        4. 去重并保持顺序
        """
        # 展开宏命令
        expanded_flags = cls.expand_macros(flags)
        
        # 解析flags
        nodes = []
        for flag in expanded_flags:
            if "+" in flag:
                # 处理链式flag
                chain_nodes = cls.parse_chain_flag(flag)
                nodes.extend(chain_nodes)
            else:
                # 处理单个flag
                nodes.append(cls.parse_flag(flag))
        
        # 自动补全
        completed_nodes = cls.auto_complete(nodes)
        
        # 去重并保持顺序
        unique_nodes = cls.deduplicate(completed_nodes)
        
        return unique_nodes
    
    @classmethod
    def auto_complete(cls, nodes: List[AgentNode]) -> List[AgentNode]:
        """自动补全Pipeline
        
        根据依赖关系补全缺失的Agent
        """
        # 提取当前Agent类型
        current_types = {node.type for node in nodes}
        
        # 检查并添加缺失的依赖
        for node in nodes:
            dependencies = cls.DEPENDENCIES.get(node.type.value, [])
            for dep in dependencies:
                dep_type = AgentType(dep)
                if dep_type not in current_types:
                    # 添加依赖Agent
                    nodes.insert(0, AgentNode(type=dep_type))
                    current_types.add(dep_type)
        
        # 确保基本流程完整性
        if not current_types:
            # 空Pipeline，默认添加基本扫描
            return [AgentNode(type=AgentType.SCANNER), AgentNode(type=AgentType.REASONER), AgentNode(type=AgentType.REPORT)]
        
        # 确保有报告节点（如果需要）
        if AgentType.REPORT not in current_types and AgentType.SCANNER in current_types:
            nodes.append(AgentNode(type=AgentType.REPORT))
        
        return nodes
    
    @classmethod
    def deduplicate(cls, nodes: List[AgentNode]) -> List[AgentNode]:
        """去重并保持顺序"""
        seen = set()
        unique = []
        
        for node in nodes:
            if node.type not in seen:
                seen.add(node.type)
                unique.append(node)
        
        return unique
    
    @classmethod
    def generate_explanation(cls, nodes: List[AgentNode]) -> str:
        """生成执行流程说明"""
        steps = []
        for i, node in enumerate(nodes, 1):
            step_desc = f"{i}. {node.type.value}"
            if node.params:
                step_desc += f" ({node.params.get('strategy', 'default')})"
            steps.append(step_desc)
        
        return "执行流程：\n" + "\n".join(steps)
    
    @classmethod
    def create_execution_plan(cls, nodes: List[AgentNode], config: Any) -> Dict[str, Any]:
        """创建执行计划"""
        plan = {
            "pipeline": [
                {
                    "agent": node.type.value,
                    "params": node.params
                }
                for node in nodes
            ],
            "total_steps": len(nodes)
        }
        
        return plan
    
    @classmethod
    def from_plan(cls, plan: Plan) -> List[AgentNode]:
        """从Plan创建Pipeline"""
        # 映射PlanStepType到AgentType
        step_type_map = {
            PlanStepType.SCAN: AgentType.SCANNER,
            PlanStepType.AUTH_ANALYSIS: AgentType.REASONER,
            PlanStepType.POC: AgentType.POC,
            PlanStepType.REASON: AgentType.REASONER,
            PlanStepType.ATTACK_CHAIN: AgentType.ATTACK_CHAIN,
            PlanStepType.VERIFY: AgentType.VERIFIER,
            PlanStepType.FIX: AgentType.FIX,
            PlanStepType.REPORT: AgentType.REPORT
        }
        
        nodes = []
        for step in plan.steps:
            if step.type in step_type_map:
                agent_type = step_type_map[step.type]
                params = step.config.copy()
                # 处理特殊参数
                if step.type == PlanStepType.SCAN and "depth" in params:
                    params["strategy"] = params.pop("depth")
                nodes.append(AgentNode(type=agent_type, params=params))
        
        # 自动补全和去重
        completed_nodes = cls.auto_complete(nodes)
        unique_nodes = cls.deduplicate(completed_nodes)
        
        return unique_nodes
