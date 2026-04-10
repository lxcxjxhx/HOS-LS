"""Plan验证器

验证Plan的有效性和合理性。
"""

from typing import Dict, Any, List, Optional
from src.core.plan import Plan, PlanStepType, PlanProfile


class PlanValidator:
    """Plan验证器"""
    
    def validate(self, plan: Plan) -> bool:
        """验证Plan的有效性
        
        Args:
            plan: 要验证的Plan对象
            
        Returns:
            是否有效
        """
        # 验证基本结构
        if not self._validate_basic_structure(plan):
            return False
        
        # 验证步骤
        if not self._validate_steps(plan):
            return False
        
        # 验证约束条件
        if not self._validate_constraints(plan):
            return False
        
        # 验证配置文件
        if not self._validate_profile(plan):
            return False
        
        return True
    
    def _validate_basic_structure(self, plan: Plan) -> bool:
        """验证基本结构
        
        Args:
            plan: 要验证的Plan对象
            
        Returns:
            是否有效
        """
        # 验证目标
        if not plan.goal or not isinstance(plan.goal, str):
            return False
        
        # 验证版本
        if not plan.plan_version or not isinstance(plan.plan_version, str):
            return False
        
        # 验证步骤列表
        if not plan.steps or not isinstance(plan.steps, list):
            return False
        
        return True
    
    def _validate_steps(self, plan: Plan) -> bool:
        """验证步骤
        
        Args:
            plan: 要验证的Plan对象
            
        Returns:
            是否有效
        """
        for step in plan.steps:
            # 验证步骤类型
            if not hasattr(step, 'type') or not isinstance(step.type, PlanStepType):
                return False
            
            # 验证步骤配置
            if not hasattr(step, 'config') or not isinstance(step.config, dict):
                return False
            
            # 验证特定步骤的配置
            if not self._validate_step_config(step.type, step.config):
                return False
        
        # 确保至少有一个步骤
        if len(plan.steps) == 0:
            return False
        
        return True
    
    def _validate_step_config(self, step_type: PlanStepType, config: Dict[str, Any]) -> bool:
        """验证步骤配置
        
        Args:
            step_type: 步骤类型
            config: 步骤配置
            
        Returns:
            是否有效
        """
        if step_type == PlanStepType.SCAN:
            # 验证扫描步骤配置
            if 'path' not in config:
                return False
            if not isinstance(config['path'], str):
                return False
            if 'depth' in config and config['depth'] not in ['low', 'medium', 'high']:
                return False
        
        elif step_type == PlanStepType.AUTH_ANALYSIS:
            # 验证认证分析步骤配置
            if 'detect' in config and not isinstance(config['detect'], list):
                return False
        
        elif step_type == PlanStepType.POC:
            # 验证POC步骤配置
            if 'generate' in config and not isinstance(config['generate'], bool):
                return False
        
        elif step_type == PlanStepType.REPORT:
            # 验证报告步骤配置
            if 'format' in config and config['format'] not in ['html', 'markdown', 'json', 'sarif']:
                return False
        
        return True
    
    def _validate_constraints(self, plan: Plan) -> bool:
        """验证约束条件
        
        Args:
            plan: 要验证的Plan对象
            
        Returns:
            是否有效
        """
        constraints = plan.constraints
        
        # 验证安全模式
        if not isinstance(constraints.safe_mode, bool):
            return False
        
        # 验证最大时间
        if constraints.max_time and not isinstance(constraints.max_time, str):
            return False
        
        # 验证最大工作线程
        if constraints.max_workers and (not isinstance(constraints.max_workers, int) or constraints.max_workers <= 0):
            return False
        
        # 验证超时时间
        if constraints.timeout and (not isinstance(constraints.timeout, int) or constraints.timeout <= 0):
            return False
        
        return True
    
    def _validate_profile(self, plan: Plan) -> bool:
        """验证配置文件
        
        Args:
            plan: 要验证的Plan对象
            
        Returns:
            是否有效
        """
        # 验证配置文件类型
        if not isinstance(plan.profile, PlanProfile):
            return False
        
        return True
    
    def validate_plan_data(self, plan_data: Dict[str, Any]) -> bool:
        """验证Plan数据
        
        Args:
            plan_data: Plan的字典表示
            
        Returns:
            是否有效
        """
        try:
            # 尝试从数据创建Plan
            plan = Plan.from_dict(plan_data)
            # 验证Plan
            return self.validate(plan)
        except Exception:
            return False
    
    def get_validation_errors(self, plan: Plan) -> List[str]:
        """获取验证错误
        
        Args:
            plan: 要验证的Plan对象
            
        Returns:
            错误列表
        """
        errors = []
        
        # 验证基本结构
        if not self._validate_basic_structure(plan):
            errors.append("基本结构验证失败")
        
        # 验证步骤
        if not self._validate_steps(plan):
            errors.append("步骤验证失败")
        
        # 验证约束条件
        if not self._validate_constraints(plan):
            errors.append("约束条件验证失败")
        
        # 验证配置文件
        if not self._validate_profile(plan):
            errors.append("配置文件验证失败")
        
        return errors
    
    def validate_plan_file(self, file_path: str) -> bool:
        """验证Plan文件
        
        Args:
            file_path: Plan文件路径
            
        Returns:
            是否有效
        """
        try:
            from src.core.plan_dsl import PlanDSLParser
            plan = PlanDSLParser.parse_file(file_path)
            return self.validate(plan)
        except Exception:
            return False
    
    def is_valid_step_type(self, step_type: str) -> bool:
        """验证步骤类型是否有效
        
        Args:
            step_type: 步骤类型字符串
            
        Returns:
            是否有效
        """
        try:
            PlanStepType(step_type)
            return True
        except ValueError:
            return False
    
    def is_valid_profile(self, profile: str) -> bool:
        """验证配置文件是否有效
        
        Args:
            profile: 配置文件字符串
            
        Returns:
            是否有效
        """
        try:
            PlanProfile(profile)
            return True
        except ValueError:
            return False
