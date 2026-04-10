"""Plan解释器

解释Plan的决策过程，包括配置选择、步骤选择和约束设置的理由。
"""

from typing import List, Dict, Any
from src.core.plan import Plan, PlanStepType, PlanProfile


class PlanExplainer:
    """Plan解释器"""
    
    @staticmethod
    def explain_plan(plan: Plan) -> Dict[str, str]:
        """解释完整的Plan
        
        Args:
            plan: 要解释的Plan对象
            
        Returns:
            解释结果，包含各个部分的解释
        """
        explanation = {
            "goal": PlanExplainer._explain_goal(plan),
            "profile": PlanExplainer._explain_profile(plan),
            "steps": PlanExplainer._explain_steps(plan),
            "constraints": PlanExplainer._explain_constraints(plan),
            "overall": PlanExplainer._explain_overall(plan)
        }
        return explanation
    
    @staticmethod
    def _explain_goal(plan: Plan) -> str:
        """解释目标
        
        Args:
            plan: Plan对象
            
        Returns:
            目标解释
        """
        return f"目标: {plan.goal}"
    
    @staticmethod
    def _explain_profile(plan: Plan) -> str:
        """解释配置文件选择
        
        Args:
            plan: Plan对象
            
        Returns:
            配置文件解释
        """
        profile_explanations = {
            PlanProfile.STANDARD: "选择标准配置，平衡扫描深度和速度，适合大多数场景",
            PlanProfile.FULL: "选择完整配置，进行深度扫描和全面分析，适合重要项目的安全审计",
            PlanProfile.FAST: "选择快速配置，进行浅层扫描，节省时间，适合日常快速检查",
            PlanProfile.DEEP: "选择深度配置，进行全面深入的安全分析，适合高安全性要求的项目",
            PlanProfile.STEALTH: "选择 stealth 模式，减少扫描痕迹，适合需要低调扫描的场景"
        }
        return profile_explanations.get(plan.profile, f"选择配置: {plan.profile.value}")
    
    @staticmethod
    def _explain_steps(plan: Plan) -> str:
        """解释步骤选择
        
        Args:
            plan: Plan对象
            
        Returns:
            步骤解释
        """
        step_explanations = []
        
        for step in plan.steps:
            explanation = PlanExplainer._explain_step(step)
            step_explanations.append(explanation)
        
        if not step_explanations:
            return "未指定执行步骤"
        
        return "\n".join(step_explanations)
    
    @staticmethod
    def _explain_step(step) -> str:
        """解释单个步骤
        
        Args:
            step: PlanStep对象
            
        Returns:
            步骤解释
        """
        step_type = step.type
        config = step.config
        
        if step_type == PlanStepType.SCAN:
            depth = config.get("depth", "medium")
            path = config.get("path", ".")
            return f"扫描: 在路径 '{path}' 上使用 {depth} 深度进行代码扫描"
        
        elif step_type == PlanStepType.AUTH_ANALYSIS:
            detect = config.get("detect", ["jwt", "session", "oauth"])
            return f"认证分析: 检测 {', '.join(detect)} 等认证方式的漏洞"
        
        elif step_type == PlanStepType.POC:
            generate = config.get("generate", False)
            return f"POC生成: {'启用' if generate else '禁用'}漏洞利用代码生成"
        
        elif step_type == PlanStepType.REASON:
            strategy = config.get("strategy", "default")
            return f"漏洞推理: 使用 {strategy} 策略进行漏洞分析"
        
        elif step_type == PlanStepType.ATTACK_CHAIN:
            enabled = config.get("enabled", True)
            return f"攻击链分析: {'启用' if enabled else '禁用'}攻击路径分析"
        
        elif step_type == PlanStepType.VERIFY:
            enabled = config.get("enabled", True)
            return f"漏洞验证: {'启用' if enabled else '禁用'}漏洞验证"
        
        elif step_type == PlanStepType.FIX:
            enabled = config.get("enabled", True)
            return f"修复建议: {'启用' if enabled else '禁用'}修复建议生成"
        
        elif step_type == PlanStepType.REPORT:
            format = config.get("format", "html")
            output = config.get("output", "")
            output_str = f"到文件 '{output}'" if output else "到标准输出"
            return f"报告生成: 生成 {format} 格式的报告 {output_str}"
        
        else:
            return f"步骤: {step_type.value}"
    
    @staticmethod
    def _explain_constraints(plan: Plan) -> str:
        """解释约束条件
        
        Args:
            plan: Plan对象
            
        Returns:
            约束条件解释
        """
        constraints = plan.constraints
        explanations = []
        
        if constraints.safe_mode:
            explanations.append("安全模式: 启用，避免生成危险的POC")
        else:
            explanations.append("安全模式: 禁用，允许生成完整的POC")
        
        if constraints.max_time:
            explanations.append(f"最大时间: {constraints.max_time}，限制扫描时间")
        
        if constraints.max_workers:
            explanations.append(f"最大工作线程: {constraints.max_workers}，控制并行度")
        
        if constraints.timeout:
            explanations.append(f"超时时间: {constraints.timeout}秒，避免单个任务卡住")
        
        if not explanations:
            return "无特殊约束"
        
        return "\n".join(explanations)
    
    @staticmethod
    def _explain_overall(plan: Plan) -> str:
        """解释整体决策
        
        Args:
            plan: Plan对象
            
        Returns:
            整体解释
        """
        # 分析Plan的特点
        has_scan = plan.has_step(PlanStepType.SCAN)
        has_auth = plan.has_step(PlanStepType.AUTH_ANALYSIS)
        has_poc = plan.has_step(PlanStepType.POC)
        has_attack_chain = plan.has_step(PlanStepType.ATTACK_CHAIN)
        has_report = plan.has_step(PlanStepType.REPORT)
        
        # 生成整体解释
        explanations = []
        
        if has_scan:
            explanations.append("首先进行代码扫描，发现潜在漏洞")
        
        if has_auth:
            explanations.append("然后进行认证分析，检测认证相关漏洞")
        
        if has_poc:
            poc_step = plan.get_step(PlanStepType.POC)
            if poc_step.config.get("generate", False):
                explanations.append("生成漏洞利用代码，验证漏洞的可利用性")
        
        if has_attack_chain:
            explanations.append("分析攻击链，评估漏洞的实际影响")
        
        if has_report:
            explanations.append("最后生成详细的安全报告")
        
        if not explanations:
            return "执行基本的安全扫描流程"
        
        return " → ".join(explanations)
    
    @staticmethod
    def generate_verbose_explanation(plan: Plan) -> str:
        """生成详细的解释
        
        Args:
            plan: Plan对象
            
        Returns:
            详细的解释文本
        """
        explanation = PlanExplainer.explain_plan(plan)
        
        lines = []
        lines.append("# Plan 执行方案解释")
        lines.append("")
        lines.append("## 目标")
        lines.append(explanation["goal"])
        lines.append("")
        lines.append("## 配置选择")
        lines.append(explanation["profile"])
        lines.append("")
        lines.append("## 执行步骤")
        lines.append(explanation["steps"])
        lines.append("")
        lines.append("## 约束条件")
        lines.append(explanation["constraints"])
        lines.append("")
        lines.append("## 执行流程")
        lines.append(explanation["overall"])
        lines.append("")
        lines.append(f"## 版本信息")
        lines.append(f"Plan 版本: {plan.plan_version}")
        
        return "\n".join(lines)
    
    @staticmethod
    def generate_summary_explanation(plan: Plan) -> str:
        """生成摘要解释
        
        Args:
            plan: Plan对象
            
        Returns:
            摘要解释文本
        """
        explanation = PlanExplainer.explain_plan(plan)
        
        lines = []
        lines.append(explanation["goal"])
        lines.append(explanation["profile"])
        lines.append("")
        lines.append("执行步骤:")
        for line in explanation["steps"].split("\n"):
            if line:
                lines.append(f"  - {line}")
        lines.append("")
        lines.append("约束条件:")
        for line in explanation["constraints"].split("\n"):
            if line:
                lines.append(f"  - {line}")
        
        return "\n".join(lines)
