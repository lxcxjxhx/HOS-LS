"""Plan可视化器

可视化Plan的执行流程，支持文本和图形展示。
"""

from typing import List, Dict, Any
from src.core.plan import Plan, PlanStepType


class PlanVisualizer:
    """Plan可视化器"""
    
    @staticmethod
    def visualize_text(plan: Plan) -> str:
        """文本可视化
        
        Args:
            plan: 要可视化的Plan对象
            
        Returns:
            文本可视化结果
        """
        lines = []
        
        # 标题
        lines.append("# Plan 执行流程")
        lines.append("")
        
        # 基本信息
        lines.append(f"## 目标: {plan.goal}")
        lines.append(f"## 配置: {plan.profile.value}")
        lines.append("")
        
        # 执行流程
        lines.append("## 执行流程")
        
        if not plan.steps:
            lines.append("无执行步骤")
        else:
            # 生成流程链
            steps = [step.type.value for step in plan.steps]
            flow_chain = " → ".join(steps)
            lines.append(flow_chain)
            lines.append("")
            
            # 详细步骤
            lines.append("## 详细步骤")
            for i, step in enumerate(plan.steps, 1):
                step_type = step.type.value
                config = step.config
                
                lines.append(f"### {i}. {step_type}")
                if config:
                    for key, value in config.items():
                        lines.append(f"  - {key}: {value}")
                lines.append("")
        
        # 约束条件
        lines.append("## 约束条件")
        constraints = plan.constraints
        
        constraints_list = []
        if constraints.safe_mode:
            constraints_list.append("安全模式: 启用")
        else:
            constraints_list.append("安全模式: 禁用")
        
        if constraints.max_time:
            constraints_list.append(f"最大时间: {constraints.max_time}")
        
        if constraints.max_workers:
            constraints_list.append(f"最大工作线程: {constraints.max_workers}")
        
        if constraints.timeout:
            constraints_list.append(f"超时时间: {constraints.timeout}秒")
        
        if constraints_list:
            for constraint in constraints_list:
                lines.append(f"- {constraint}")
        else:
            lines.append("无特殊约束")
        
        lines.append("")
        lines.append(f"## 版本: {plan.plan_version}")
        
        return "\n".join(lines)
    
    @staticmethod
    def visualize_graph(plan: Plan) -> str:
        """图形可视化
        
        Args:
            plan: 要可视化的Plan对象
            
        Returns:
            图形可视化结果（ASCII图形）
        """
        if not plan.steps:
            return "无执行步骤"
        
        lines = []
        
        # 标题
        lines.append("Plan 执行流程图")
        lines.append("=" * 40)
        lines.append("")
        
        # 生成流程图
        steps = plan.steps
        
        for i, step in enumerate(steps):
            step_type = step.type.value
            
            # 步骤框
            lines.append(f"┌{'─' * (len(step_type) + 4)}┐")
            lines.append(f"│  {step_type}  │")
            lines.append(f"└{'─' * (len(step_type) + 4)}┘")
            
            # 箭头
            if i < len(steps) - 1:
                lines.append("    │")
                lines.append("    ▼")
                lines.append("")
        
        # 添加约束信息
        lines.append("=" * 40)
        lines.append("约束条件:")
        
        constraints = plan.constraints
        constraints_list = []
        if constraints.safe_mode:
            constraints_list.append("安全模式: 启用")
        else:
            constraints_list.append("安全模式: 禁用")
        
        if constraints.max_time:
            constraints_list.append(f"最大时间: {constraints.max_time}")
        
        for constraint in constraints_list:
            lines.append(f"- {constraint}")
        
        return "\n".join(lines)
    
    @staticmethod
    def visualize_mermaid(plan: Plan) -> str:
        """生成Mermaid流程图代码
        
        Args:
            plan: 要可视化的Plan对象
            
        Returns:
            Mermaid流程图代码
        """
        lines = []
        lines.append("flowchart TD")
        lines.append("")
        
        # 生成节点
        for i, step in enumerate(plan.steps):
            step_type = step.type.value
            node_id = f"step{i}"
            lines.append(f"  {node_id}[{step_type}]")
        
        # 生成连接
        for i in range(len(plan.steps) - 1):
            from_node = f"step{i}"
            to_node = f"step{i+1}"
            lines.append(f"  {from_node} --> {to_node}")
        
        # 添加约束信息
        if plan.constraints:
            lines.append("")
            lines.append("  subgraph 约束条件")
            
            constraints = plan.constraints
            constraint_lines = []
            if constraints.safe_mode:
                constraint_lines.append("安全模式: 启用")
            else:
                constraint_lines.append("安全模式: 禁用")
            
            if constraints.max_time:
                constraint_lines.append(f"最大时间: {constraints.max_time}")
            
            if constraints.max_workers:
                constraint_lines.append(f"最大工作线程: {constraints.max_workers}")
            
            if constraints.timeout:
                constraint_lines.append(f"超时时间: {constraints.timeout}秒")
            
            for i, constraint in enumerate(constraint_lines):
                lines.append(f"    constraint{i}[{constraint}]")
            
            lines.append("  end")
        
        return "\n".join(lines)
    
    @staticmethod
    def visualize_json(plan: Plan) -> str:
        """JSON格式可视化
        
        Args:
            plan: 要可视化的Plan对象
            
        Returns:
            JSON格式的Plan
        """
        import json
        return json.dumps(plan.to_dict(), ensure_ascii=False, indent=2)
    
    @staticmethod
    def generate_summary(plan: Plan) -> str:
        """生成执行流程摘要
        
        Args:
            plan: 要可视化的Plan对象
            
        Returns:
            执行流程摘要
        """
        lines = []
        
        # 目标
        lines.append(f"目标: {plan.goal}")
        
        # 配置
        lines.append(f"配置: {plan.profile.value}")
        
        # 步骤
        if plan.steps:
            steps = [step.type.value for step in plan.steps]
            lines.append(f"步骤: {' → '.join(steps)}")
        else:
            lines.append("步骤: 无")
        
        # 约束
        constraints = plan.constraints
        constraint_info = []
        if not constraints.safe_mode:
            constraint_info.append("非安全模式")
        if constraints.max_time:
            constraint_info.append(f"最大时间: {constraints.max_time}")
        
        if constraint_info:
            lines.append(f"约束: {', '.join(constraint_info)}")
        
        # 版本
        lines.append(f"版本: {plan.plan_version}")
        
        return " | ".join(lines)
