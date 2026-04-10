"""Plan DSL解析器

解析和序列化Plan DSL，支持YAML和JSON格式。
"""

import yaml
import json
from typing import Dict, Any, Optional
from pathlib import Path

from src.core.plan import Plan


class PlanDSLParser:
    """Plan DSL解析器"""
    
    @staticmethod
    def parse_file(file_path: str) -> Plan:
        """从文件解析Plan"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Plan文件不存在: {file_path}")
        
        file_ext = path.suffix.lower()
        
        if file_ext in [".yaml", ".yml"]:
            return PlanDSLParser._parse_yaml(file_path)
        elif file_ext == ".json":
            return PlanDSLParser._parse_json(file_path)
        else:
            raise ValueError(f"不支持的文件格式: {file_ext}")
    
    @staticmethod
    def _parse_yaml(file_path: str) -> Plan:
        """解析YAML格式的Plan"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return Plan.from_dict(data)
    
    @staticmethod
    def _parse_json(file_path: str) -> Plan:
        """解析JSON格式的Plan"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return Plan.from_dict(data)
    
    @staticmethod
    def save_to_file(plan: Plan, file_path: str) -> None:
        """保存Plan到文件"""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        file_ext = path.suffix.lower()
        
        if file_ext in [".yaml", ".yml"]:
            PlanDSLParser._save_yaml(plan, file_path)
        elif file_ext == ".json":
            PlanDSLParser._save_json(plan, file_path)
        else:
            raise ValueError(f"不支持的文件格式: {file_ext}")
    
    @staticmethod
    def _save_yaml(plan: Plan, file_path: str) -> None:
        """保存为YAML格式"""
        data = plan.to_dict()
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
    
    @staticmethod
    def _save_json(plan: Plan, file_path: str) -> None:
        """保存为JSON格式"""
        data = plan.to_dict()
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    @staticmethod
    def to_yaml(plan: Plan) -> str:
        """转换为YAML字符串"""
        data = plan.to_dict()
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)
    
    @staticmethod
    def to_json(plan: Plan) -> str:
        """转换为JSON字符串"""
        data = plan.to_dict()
        return json.dumps(data, ensure_ascii=False, indent=2)
    
    @staticmethod
    def from_yaml(yaml_str: str) -> Plan:
        """从YAML字符串解析Plan"""
        data = yaml.safe_load(yaml_str)
        return Plan.from_dict(data)
    
    @staticmethod
    def from_json(json_str: str) -> Plan:
        """从JSON字符串解析Plan"""
        data = json.loads(json_str)
        return Plan.from_dict(data)
    
    @staticmethod
    def validate_plan_file(file_path: str) -> bool:
        """验证Plan文件的有效性"""
        try:
            plan = PlanDSLParser.parse_file(file_path)
            return plan.validate()
        except Exception:
            return False
    
    @staticmethod
    def get_plan_summary(plan: Plan) -> Dict[str, Any]:
        """获取Plan摘要"""
        summary = {
            "goal": plan.goal,
            "profile": plan.profile.value,
            "steps": [step.type.value for step in plan.steps],
            "constraints": {
                "safe_mode": plan.constraints.safe_mode,
                "max_time": plan.constraints.max_time
            },
            "version": plan.plan_version
        }
        return summary
    
    @staticmethod
    def format_plan_for_display(plan: Plan) -> str:
        """格式化Plan用于显示"""
        lines = []
        lines.append(f"目标: {plan.goal}")
        lines.append(f"配置: {plan.profile.value}")
        lines.append("步骤:")
        
        for step in plan.steps:
            step_info = f"  - {step.type.value}"
            if step.config:
                step_info += f": {step.config}"
            lines.append(step_info)
        
        lines.append("约束:")
        lines.append(f"  安全模式: {'启用' if plan.constraints.safe_mode else '禁用'}")
        if plan.constraints.max_time:
            lines.append(f"  最大时间: {plan.constraints.max_time}")
        if plan.constraints.max_workers:
            lines.append(f"  最大工作线程: {plan.constraints.max_workers}")
        
        lines.append(f"版本: {plan.plan_version}")
        
        return "\n".join(lines)
