"""AI计划生成器

基于用户命令和解析后的意图，使用AI生成详细的执行计划。
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from src.core.intent_parser import ParsedIntent
from src.core.module_capabilities import get_module_capabilities
from src.core.config import get_config
from src.ai.client import get_model_manager
from src.ai.models import AIRequest


@dataclass
class PlanStep:
    """计划步骤"""
    id: str  # 步骤ID
    name: str  # 步骤名称
    description: str  # 步骤描述
    module: str  # 使用的模块
    parameters: Dict[str, Any]  # 模块参数
    dependencies: List[str]  # 依赖的步骤
    estimated_time: int  # 估计执行时间（秒）


@dataclass
class ExecutionPlan:
    """执行计划"""
    id: str  # 计划ID
    name: str  # 计划名称
    description: str  # 计划描述
    steps: List[PlanStep]  # 计划步骤
    estimated_total_time: int  # 估计总执行时间（秒）
    pure_ai: bool  # 是否使用纯AI模式
    test_mode: bool  # 是否为测试模式
    test_file_count: int  # 测试模式下扫描的文件数量
    user_input: str  # 用户原始输入


class AIPlanGenerator:
    """AI计划生成器"""
    
    def __init__(self, config=None):
        """初始化AI计划生成器
        
        Args:
            config: 配置对象（可选）
        """
        from src.core.config import get_config
        self.config = config if config else get_config()
        self.ai_client = None  # 延迟初始化
        self.module_capabilities = get_module_capabilities()
    
    async def _get_ai_client(self):
        """获取AI客户端"""
        if not self.ai_client:
            manager = await get_model_manager(self.config)
            self.ai_client = manager.get_default_client()
        return self.ai_client
    
    def _generate_default_plan(self, intent: ParsedIntent, user_input: str) -> ExecutionPlan:
        """生成默认执行计划
        
        Args:
            intent: 解析后的意图
            user_input: 用户原始输入
            
        Returns:
            默认执行计划
        """
        import uuid
        plan_id = str(uuid.uuid4())
        
        # 生成默认步骤
        steps = self._generate_default_steps(intent)
        estimated_total_time = sum(step.estimated_time for step in steps)
        
        # 创建默认执行计划
        plan = ExecutionPlan(
            id=plan_id,
            name="默认执行计划",
            description="基于用户输入生成的默认执行计划",
            steps=steps,
            estimated_total_time=estimated_total_time,
            pure_ai=False,
            test_mode=False,
            test_file_count=1,
            user_input=user_input
        )
        
        return plan
    
    async def generate_plan(self, intent: ParsedIntent, user_input: str) -> ExecutionPlan:
        """生成执行计划
        
        Args:
            intent: 解析后的意图
            user_input: 用户原始输入
            
        Returns:
            生成的执行计划
        """
        try:
            # 获取模块能力信息
            available_modules = list(self.module_capabilities.get_all_capabilities().keys())
            
            # 构建计划生成提示词
            prompt = self._build_plan_prompt(intent, user_input, available_modules)
            
            # 生成AI请求
            request = AIRequest(
                prompt=prompt,
                system_prompt="你是一个专业的安全扫描计划生成专家，能够根据用户的需求生成详细、合理的执行计划。",
                max_tokens=1000,
                temperature=0.1
            )
            
            # 获取AI客户端
            ai_client = await self._get_ai_client()
            if not ai_client:
                # 如果AI客户端不可用，返回默认计划
                return self._generate_default_plan(intent, user_input)
            
            # 发送AI请求
            response = await ai_client.generate(request)
            
            # 解析AI响应
            plan_data = self._parse_ai_response(response.content)
            
            # 构建执行计划
            plan = self._build_execution_plan(plan_data, user_input, intent)
            
            return plan
        except Exception as e:
            # 如果发生错误，返回默认计划
            return self._generate_default_plan(intent, user_input)
    
    def _build_plan_prompt(self, intent: ParsedIntent, user_input: str, available_modules: List[str]) -> str:
        """构建计划生成提示词
        
        Args:
            intent: 解析后的意图
            user_input: 用户原始输入
            available_modules: 可用模块列表
            
        Returns:
            构建的提示词
        """
        # 构建任务信息
        tasks_info = ""
        if 'tasks' in intent.entities:
            tasks = intent.entities['tasks']
            for i, task in enumerate(tasks, 1):
                task_type = task.get('type', 'unknown')
                task_content = task.get('content', 'unknown')
                tasks_info += f"{i}. 任务类型: {task_type}, 内容: {task_content}\n"
        
        # 构建实体信息
        entities_info = ""
        for key, value in intent.entities.items():
            if key != 'tasks':
                entities_info += f"{key}: {value}\n"
        
        # 使用format方法构建提示词
        prompt = """你是一个专业的安全扫描计划生成专家。根据用户的需求，生成详细的执行计划。

用户输入: {user_input}

解析后的意图: {intent_type}

识别到的任务:
{tasks_info}

识别到的实体:
{entities_info}

可用的功能模块:
{available_modules}

请生成一个详细的执行计划，包括：
1. 计划名称和描述
2. 执行步骤（按顺序）
3. 每个步骤使用的模块和参数
4. 步骤之间的依赖关系
5. 每个步骤的估计执行时间
6. 是否使用纯AI模式
7. 是否为测试模式及文件数量

重要提示：
- 对于相关的任务，如"分析扫描结果并生成报告"，应该合并为一个步骤，而不是拆分成多个步骤
- 避免创建不必要的步骤，确保计划简洁明了
- 优先使用已有的功能模块，不要创建不存在的模块

请返回JSON格式:
{
  "name": "计划名称",
  "description": "计划描述",
  "steps": [
    {
      "id": "step1",
      "name": "步骤名称",
      "description": "步骤描述",
      "module": "使用的模块",
      "parameters": {
        "参数名": "参数值"
      },
      "dependencies": ["依赖的步骤ID"],
      "estimated_time": 60
    }
  ],
  "estimated_total_time": 300,
  "pure_ai": true/false,
  "test_mode": true/false,
  "test_file_count": 1
}

只返回JSON，不要其他内容。""".format(
            user_input=user_input,
            intent_type=intent.type.value,
            tasks_info=tasks_info,
            entities_info=entities_info,
            available_modules=', '.join(available_modules)
        )
        
        return prompt
    
    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """解析AI响应
        
        Args:
            content: AI响应内容
            
        Returns:
            解析后的计划数据
        """
        import json
        import re
        
        # 清理内容
        content = content.strip()
        
        # 尝试直接解析整个内容
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # 提取JSON部分
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            json_str = json_match.group(0)
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                # 尝试清理JSON字符串
                json_str = json_str.strip()
                # 移除可能的多余字符
                json_str = re.sub(r'[^\{\}\[\]"\\:,.\w\s\-/]', '', json_str)
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    pass
        
        # 如果解析失败，返回默认计划
        return {
            "name": "默认执行计划",
            "description": "基于用户输入生成的默认执行计划",
            "steps": [
                {
                    "id": "step1",
                    "name": "分析扫描结果并生成报告",
                    "description": "分析扫描结果并生成简洁的测试报告",
                    "module": "report",
                    "parameters": {"format": "brief", "output": "./security-report"},
                    "dependencies": [],
                    "estimated_time": 60
                }
            ],
            "estimated_total_time": 60,
            "pure_ai": True,
            "test_mode": True,
            "test_file_count": 1
        }
    
    def _build_execution_plan(self, plan_data: Dict[str, Any], user_input: str, intent: ParsedIntent) -> ExecutionPlan:
        """构建执行计划
        
        Args:
            plan_data: 解析后的计划数据
            user_input: 用户原始输入
            intent: 解析后的意图
            
        Returns:
            构建的执行计划
        """
        # 生成计划ID
        import uuid
        plan_id = str(uuid.uuid4())
        
        # 提取计划信息
        name = plan_data.get("name", "执行计划")
        description = plan_data.get("description", "基于用户输入生成的执行计划")
        steps_data = plan_data.get("steps", [])
        estimated_total_time = plan_data.get("estimated_total_time", 300)
        pure_ai = plan_data.get("pure_ai", intent.entities.get("pure_ai", False) if intent and hasattr(intent, 'entities') else False)
        test_mode = plan_data.get("test_mode", intent.entities.get("test_mode", False) if intent and hasattr(intent, 'entities') else False)
        test_file_count = plan_data.get("test_file_count", intent.entities.get("test_file_count", 1) if intent and hasattr(intent, 'entities') else 1)
        
        # 构建计划步骤
        steps = []
        for step_data in steps_data:
            step = PlanStep(
                id=step_data.get("id", f"step{len(steps) + 1}"),
                name=step_data.get("name", f"步骤{len(steps) + 1}"),
                description=step_data.get("description", ""),
                module=step_data.get("module", "scan"),
                parameters=step_data.get("parameters", {}),
                dependencies=step_data.get("dependencies", []),
                estimated_time=step_data.get("estimated_time", 60)
            )
            steps.append(step)
        
        # 如果没有步骤，根据意图生成默认步骤
        if not steps:
            steps = self._generate_default_steps(intent)
            estimated_total_time = sum(step.estimated_time for step in steps)
        
        # 创建执行计划
        plan = ExecutionPlan(
            id=plan_id,
            name=name,
            description=description,
            steps=steps,
            estimated_total_time=estimated_total_time,
            pure_ai=pure_ai,
            test_mode=test_mode,
            test_file_count=test_file_count,
            user_input=user_input
        )
        
        return plan
    
    def _generate_default_steps(self, intent: ParsedIntent) -> List[PlanStep]:
        """生成默认步骤
        
        Args:
            intent: 解析后的意图
            
        Returns:
            默认步骤列表
        """
        steps = []
        
        # 根据意图类型生成默认步骤
        if intent.type.value == "scan":
            steps.append(PlanStep(
                id="step1",
                name="初始化扫描",
                description="初始化扫描环境和配置",
                module="scan",
                parameters={"target": ".", "mode": "auto"},
                dependencies=[],
                estimated_time=30
            ))
            steps.append(PlanStep(
                id="step2",
                name="执行扫描",
                description="执行代码安全扫描",
                module="scan",
                parameters={"target": ".", "mode": "auto"},
                dependencies=["step1"],
                estimated_time=120
            ))
            steps.append(PlanStep(
                id="step3",
                name="生成报告",
                description="生成安全扫描报告",
                module="report",
                parameters={"format": "html", "output": "./security-report"},
                dependencies=["step2"],
                estimated_time=60
            ))
        elif intent.type.value == "info":
            steps.append(PlanStep(
                id="step1",
                name="信息查询",
                description="查询相关信息",
                module="info",
                parameters={"topic": "漏洞扫描工作原理"},
                dependencies=[],
                estimated_time=30
            ))
        elif 'tasks' in intent.entities:
            # 为多任务生成步骤
            tasks = intent.entities['tasks']
            for i, task in enumerate(tasks, 1):
                task_type = task.get('type', 'unknown')
                task_content = task.get('content', 'unknown')
                
                if task_type == 'explain':
                    steps.append(PlanStep(
                        id=f"step{i}",
                        name=f"讲解 {task_content}",
                        description=f"讲解{task_content}",
                        module="info",
                        parameters={"topic": task_content},
                        dependencies=[f"step{i-1}"] if i > 1 else [],
                        estimated_time=60
                    ))
                elif task_type == 'scan':
                    steps.append(PlanStep(
                        id=f"step{i}",
                        name=f"执行扫描",
                        description=f"执行{task_content}",
                        module="scan",
                        parameters={"target": ".", "mode": "pure-ai"},
                        dependencies=[f"step{i-1}"] if i > 1 else [],
                        estimated_time=120
                    ))
        
        return steps
    
    def generate_human_friendly_plan(self, plan: ExecutionPlan) -> str:
        """生成人类友好的计划表述
        
        Args:
            plan: 执行计划
            
        Returns:
            人类友好的计划表述
        """
        try:
            plan_text = f"# 执行计划: {getattr(plan, 'name', '未命名计划')}\n\n"
            plan_text += f"## 计划描述\n{getattr(plan, 'description', '无描述')}\n\n"
            plan_text += f"## 计划设置\n"
            plan_text += f"- 纯AI模式: {'启用' if getattr(plan, 'pure_ai', False) else '禁用'}\n"
            plan_text += f"- 测试模式: {'启用' if getattr(plan, 'test_mode', False) else '禁用'}\n"
            if getattr(plan, 'test_mode', False):
                plan_text += f"- 测试文件数量: {getattr(plan, 'test_file_count', 1)}\n"
            plan_text += f"- 估计总执行时间: {getattr(plan, 'estimated_total_time', 0)}秒\n\n"
            plan_text += "## 执行步骤\n"
            
            steps = getattr(plan, 'steps', [])
            for step in steps:
                plan_text += f"### {getattr(step, 'name', '未命名步骤')}\n"
                plan_text += f"- 描述: {getattr(step, 'description', '无描述')}\n"
                plan_text += f"- 使用模块: {getattr(step, 'module', '未知模块')}\n"
                plan_text += f"- 参数: {getattr(step, 'parameters', {})}\n"
                dependencies = getattr(step, 'dependencies', [])
                if dependencies:
                    plan_text += f"- 依赖步骤: {', '.join(dependencies)}\n"
                plan_text += f"- 估计执行时间: {getattr(step, 'estimated_time', 0)}秒\n\n"
            
            plan_text += "## 执行确认\n"
            plan_text += "请确认是否执行此计划？ (yes/no/modify)\n"
            
            return plan_text
        except Exception as e:
            return f"生成计划表述时出错: {str(e)}"
    
    async def adjust_plan(self, plan: ExecutionPlan, user_feedback: str) -> ExecutionPlan:
        """根据用户反馈调整计划
        
        Args:
            plan: 原始执行计划
            user_feedback: 用户反馈
            
        Returns:
            调整后的执行计划
        """
        # 构建调整提示词
        prompt = """你是一个专业的安全扫描计划调整专家。根据用户的反馈，调整执行计划。

原始计划:
{plan}

用户反馈:
{user_feedback}

请根据用户反馈调整计划，返回调整后的计划JSON格式:
{
  "name": "计划名称",
  "description": "计划描述",
  "steps": [
    {
      "id": "step1",
      "name": "步骤名称",
      "description": "步骤描述",
      "module": "使用的模块",
      "parameters": {
        "参数名": "参数值"
      },
      "dependencies": ["依赖的步骤ID"],
      "estimated_time": 60
    }
  ],
  "estimated_total_time": 300,
  "pure_ai": true/false,
  "test_mode": true/false,
  "test_file_count": 1
}

只返回JSON，不要其他内容。""".format(
            plan=self.generate_human_friendly_plan(plan),
            user_feedback=user_feedback
        )
        
        # 生成AI请求
        request = AIRequest(
            prompt=prompt,
            system_prompt="你是一个专业的安全扫描计划调整专家，能够根据用户的反馈调整执行计划。",
            max_tokens=1000,
            temperature=0.1
        )
        
        # 发送AI请求
        response = await self.ai_client.generate(request)
        
        # 解析AI响应
        plan_data = self._parse_ai_response(response.content)
        
        # 构建调整后的执行计划
        adjusted_plan = self._build_execution_plan(plan_data, plan.user_input, None)
        
        return adjusted_plan


def get_ai_plan_generator() -> AIPlanGenerator:
    """获取AI计划生成器实例
    
    Returns:
        AI计划生成器实例
    """
    return AIPlanGenerator()
