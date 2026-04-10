"""AI驱动的Plan生成器

使用AI来理解用户意图并生成合适的Plan。
"""

import asyncio
import json
from typing import Dict, Any, Optional

from src.core.plan import Plan, PlanProfile, PlanStepType
from src.core.plan_dsl import PlanDSLParser
from src.core.config import Config, get_config
from src.ai.client import get_model_manager
from src.ai.models import AIRequest
from src.core.plan_prompt_templates import get_plan_generation_prompt, get_plan_modification_prompt
from src.core.plan_validator import PlanValidator
import logging

# 配置日志
logger = logging.getLogger(__name__)


class AIPlanGenerator:
    """AI Plan生成器"""
    
    def __init__(self, config: Optional[Config] = None):
        # 如果未提供配置，使用默认配置
        self.config = config or get_config()
        self.validator = PlanValidator()
        logger.debug(f"AI Plan Generator initialized with config: {self.config.ai.provider}")
    
    async def generate_plan(self, natural_language: str) -> Plan:
        """使用AI生成Plan
        
        Args:
            natural_language: 用户的自然语言输入
            
        Returns:
            生成的Plan对象
        """
        try:
            # 确保AI功能启用
            if not self.config.ai.enabled:
                logger.info("强制启用AI功能")
                self.config.ai.enabled = True
            
            # 确保API密钥配置
            if not self.config.ai.api_key:
                logger.error("API密钥未配置，无法使用AI生成方案")
                raise ValueError("API密钥未配置，请在配置文件中设置ai.api_key")
            
            # 获取AI模型管理器
            logger.debug("获取AI模型管理器")
            model_manager = await get_model_manager(self.config)
            
            # 获取Prompt模板
            logger.debug("生成Plan Prompt")
            prompt = get_plan_generation_prompt(natural_language)
            
            # 创建AI请求
            request = AIRequest(
                prompt=prompt,
                system_prompt="你是一个专业的安全扫描Plan生成器，能够根据用户的需求生成合理的安全扫描计划。",
                max_tokens=1000,
                temperature=0.7
            )
            
            # 调用AI生成
            logger.info("调用AI生成Plan")
            response = await model_manager.generate(request)
            
            # 解析AI输出
            logger.debug("解析AI输出")
            plan_data = self._parse_ai_output(response.content)
            
            # 创建Plan对象
            plan = Plan.from_dict(plan_data)
            
            # 验证Plan
            if not self.validator.validate(plan):
                # 如果验证失败，重新生成
                logger.warning("Plan验证失败，重新生成")
                # 重新生成Plan
                response = await model_manager.generate(request)
                plan_data = self._parse_ai_output(response.content)
                plan = Plan.from_dict(plan_data)
            
            logger.info("Plan生成成功")
            return plan
            
        except Exception as e:
            # 发生错误时抛出异常，不使用回退机制
            logger.error(f"AI Plan生成失败: {e}")
            raise
    
    async def modify_plan(self, plan: Plan, modification: str) -> Plan:
        """使用AI修改Plan
        
        Args:
            plan: 原始Plan对象
            modification: 用户的修改请求
            
        Returns:
            修改后的Plan对象
        """
        try:
            # 确保AI功能启用
            if not self.config.ai.enabled:
                logger.info("强制启用AI功能")
                self.config.ai.enabled = True
            
            # 确保API密钥配置
            if not self.config.ai.api_key:
                logger.error("API密钥未配置，无法使用AI修改方案")
                raise ValueError("API密钥未配置，请在配置文件中设置ai.api_key")
            
            # 获取AI模型管理器
            logger.debug("获取AI模型管理器")
            model_manager = await get_model_manager(self.config)
            
            # 获取当前Plan的JSON表示
            plan_json = plan.to_dict()
            
            # 获取Prompt模板
            logger.debug("生成Plan修改Prompt")
            prompt = get_plan_modification_prompt(plan_json, modification)
            
            # 创建AI请求
            request = AIRequest(
                prompt=prompt,
                system_prompt="你是一个专业的安全扫描Plan修改器，能够根据用户的修改请求更新安全扫描计划。",
                max_tokens=1000,
                temperature=0.7
            )
            
            # 调用AI生成
            logger.info("调用AI修改Plan")
            response = await model_manager.generate(request)
            
            # 解析AI输出
            logger.debug("解析AI输出")
            modified_plan_data = self._parse_ai_output(response.content)
            
            # 创建修改后的Plan对象
            modified_plan = Plan.from_dict(modified_plan_data)
            
            # 验证Plan
            if not self.validator.validate(modified_plan):
                # 如果验证失败，重新生成
                logger.warning("Plan验证失败，重新生成")
                # 重新生成Plan
                response = await model_manager.generate(request)
                modified_plan_data = self._parse_ai_output(response.content)
                modified_plan = Plan.from_dict(modified_plan_data)
            
            logger.info("Plan修改成功")
            return modified_plan
            
        except Exception as e:
            # 发生错误时抛出异常，不返回原始Plan
            logger.error(f"AI Plan修改失败: {e}")
            raise
    
    def _parse_ai_output(self, content: str) -> Dict[str, Any]:
        """解析AI的输出
        
        Args:
            content: AI的输出内容
            
        Returns:
            解析后的Plan数据
        """
        # 提取JSON部分
        import re
        json_match = re.search(r'```json\n(.*?)\n```', content, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # 如果没有JSON标记，尝试直接解析
            json_str = content
        
        try:
            # 解析JSON
            data = json.loads(json_str)
            return data
        except json.JSONDecodeError:
            # 如果解析失败，返回默认结构
            return {
                "plan": {
                    "goal": "安全扫描",
                    "profile": "standard",
                    "steps": [
                        {
                            "scan": {
                                "path": ".",
                                "depth": "medium"
                            }
                        },
                        {
                            "report": {
                                "format": "html"
                            }
                        }
                    ],
                    "constraints": {
                        "safe_mode": True
                    },
                    "plan_version": "v1.0"
                }
            }
    
    def _fallback_plan(self, natural_language: str) -> Plan:
        """回退机制，当AI生成失败时使用
        
        Args:
            natural_language: 用户的自然语言输入
            
        Returns:
            回退的Plan对象
        """
        # 简单的规则匹配作为回退
        goal = natural_language
        profile = PlanProfile.STANDARD
        
        # 基本步骤
        steps = [
            {
                "type": PlanStepType.SCAN,
                "config": {"path": ".", "depth": "medium"}
            },
            {
                "type": PlanStepType.REPORT,
                "config": {"format": "html"}
            }
        ]
        
        # 创建Plan
        plan = Plan(goal=goal, profile=profile)
        
        # 添加步骤
        for step_data in steps:
            plan.add_step(step_data["type"], step_data["config"])
        
        return plan
    
    async def generate_plan_async(self, natural_language: str) -> Plan:
        """异步生成Plan
        
        Args:
            natural_language: 用户的自然语言输入
            
        Returns:
            生成的Plan对象
        """
        return await self.generate_plan(natural_language)
    
    def generate_plan_sync(self, natural_language: str) -> Plan:
        """同步生成Plan
        
        Args:
            natural_language: 用户的自然语言输入
            
        Returns:
            生成的Plan对象
        """
        return asyncio.run(self.generate_plan(natural_language))
    
    def modify_plan_sync(self, plan: Plan, modification: str) -> Plan:
        """同步修改Plan
        
        Args:
            plan: 原始Plan对象
            modification: 用户的修改请求
            
        Returns:
            修改后的Plan对象
        """
        return asyncio.run(self.modify_plan(plan, modification))
