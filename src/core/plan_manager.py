"""计划管理器

管理执行计划的加载、保存和执行。
"""

from typing import Optional, Dict, Any
import json
import os
from pathlib import Path

from src.core.plan import Plan


class PlanManager:
    """计划管理器"""
    
    def __init__(self, config: Any = None):
        """初始化计划管理器"""
        self.config = config
        self.plan_dir = Path("./plans")
        self.plan_dir.mkdir(exist_ok=True)
    
    def load_plan(self, plan_path: str) -> Plan:
        """加载计划
        
        Args:
            plan_path: 计划文件路径
            
        Returns:
            加载的计划
        """
        plan_file = Path(plan_path)
        if not plan_file.exists():
            # 尝试从计划目录加载
            plan_file = self.plan_dir / plan_path
            if not plan_file.exists():
                raise FileNotFoundError(f"计划文件不存在: {plan_path}")
        
        with open(plan_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return Plan.from_dict(data)
    
    def save_plan(self, plan: Plan, name: str) -> str:
        """保存计划
        
        Args:
            plan: 计划对象
            name: 计划名称
            
        Returns:
            保存的文件路径
        """
        plan_file = self.plan_dir / f"{name}.json"
        data = plan.to_dict()
        
        with open(plan_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        return str(plan_file)
    
    async def execute_plan(self, plan: Plan) -> Dict[str, Any]:
        """执行计划
        
        Args:
            plan: 要执行的计划
            
        Returns:
            执行结果
        """
        # 模拟执行计划
        results = {}
        
        for i, step in enumerate(plan.steps, 1):
            # 模拟执行每个步骤
            step_result = {
                "type": step.type.value,
                "message": f"执行步骤 {i}: {step.description}",
                "status": "success",
                "is_success": True,
                "confidence": 1.0,
                "execution_time": 0.1
            }
            results[step.type.value] = step_result
        
        # 生成执行结果
        execution_result = {
            "success": True,
            "plan_name": plan.goal,
            "steps": [step.description for step in plan.steps],
            "results": results,
            "message": "计划执行完成",
            "total_findings": 0,
            "pipeline_used": [step.type.value for step in plan.steps],
            "mode": "auto",
            "execution_time": 0.0
        }
        
        return execution_result
