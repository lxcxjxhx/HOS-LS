"""AI驱动的智能计划生成器

核心设计理念：
- 移除所有硬编码的默认值和模板
- 完全依赖AI根据用户实际输入生成动态计划
- 新增ai_chat模块类型，用于处理通用知识问答
- 对于通用问题，直接让AI回答，不再强行映射到固定主题
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from src.core.intent_parser import ParsedIntent, IntentType
from src.core.module_capabilities import get_module_capabilities
from src.core.config import get_config
from src.ai.client import get_model_manager
from src.ai.models import AIRequest


@dataclass
class PlanStep:
    """计划步骤"""
    id: str
    name: str
    description: str
    module: str  # 可选值: scan, report, code_tool, info, ai_chat (新增)
    parameters: Dict[str, Any]
    dependencies: List[str]
    estimated_time: int


@dataclass
class ExecutionPlan:
    """执行计划"""
    id: str
    name: str
    description: str
    steps: List[PlanStep]
    estimated_total_time: int
    pure_ai: bool
    test_mode: bool
    test_file_count: int
    user_input: str


class AIPlanGenerator:
    """AI计划生成器（动态版本）
    
    不再使用硬编码的默认值，
    所有计划内容都由AI根据用户实际输入动态生成。
    """
    
    def __init__(self, config=None):
        from src.core.config import get_config
        self.config = config if config else get_config()
        self.ai_client = None
        self.module_capabilities = get_module_capabilities()
    
    async def _get_ai_client(self):
        """获取AI客户端"""
        if not self.ai_client:
            manager = await get_model_manager(self.config)
            self.ai_client = manager.get_default_client()
        return self.ai_client
    
    async def generate_plan(self, intent: ParsedIntent, user_input: str) -> ExecutionPlan:
        """生成执行计划
        
        Args:
            intent: 解析后的意图（来自AI意图解析器）
            user_input: 用户原始输入
            
        Returns:
            生成的执行计划
        """
        try:
            available_modules = list(self.module_capabilities.get_all_capabilities().keys())
            
            # 根据意图类型选择不同的提示策略
            if intent.type == IntentType.AI_CHAT or intent.type == IntentType.GENERAL:
                plan = await self._generate_ai_chat_plan(intent, user_input)
            else:
                plan = await self._generate_action_plan(intent, user_input, available_modules)
            
            return plan
            
        except Exception as e:
            return self._generate_fallback_plan(intent, user_input)
    
    async def _generate_ai_chat_plan(self, intent: ParsedIntent, user_input: str) -> ExecutionPlan:
        """生成AI对话类型的计划
        
        对于通用知识问答、闲聊等场景，
        直接生成ai_chat步骤，让AI自由发挥。
        """
        import uuid
        plan_id = str(uuid.uuid4())
        
        user_question = intent.entities.get('user_question', user_input)
        
        step = PlanStep(
            id="step1",
            name="AI智能回答",
            description=f"使用AI回答用户的问题: {user_question[:100]}",
            module="ai_chat",  # 新增的模块类型
            parameters={
                'question': user_question,
                'context': user_input,
                'max_tokens': 2000
            },
            dependencies=[],
            estimated_time=10  # AI响应通常很快
        )
        
        return ExecutionPlan(
            id=plan_id,
            name="AI智能对话",
            description=f"使用AI回答用户关于'{user_question[:50]}'的问题",
            steps=[step],
            estimated_total_time=10,
            pure_ai=True,
            test_mode=False,
            test_file_count=0,
            user_input=user_input
        )
    
    async def _generate_action_plan(self, intent: ParsedIntent, user_input: str, 
                                    available_modules: List[str]) -> ExecutionPlan:
        """生成功能操作类型的计划"""
        
        prompt = self._build_action_plan_prompt(intent, user_input, available_modules)
        
        request = AIRequest(
            prompt=prompt,
            system_prompt="你是HOS-LS的安全扫描计划生成专家。根据用户需求和AI识别出的意图，生成最优的执行计划。",
            max_tokens=1200,
            temperature=0.1
        )
        
        ai_client = await self._get_ai_client()
        if not ai_client:
            return self._generate_fallback_plan(intent, user_input)
        
        response = await ai_client.generate(request)
        plan_data = self._parse_ai_response(response.content)
        
        return self._build_execution_plan(plan_data, user_input, intent)
    
    def _build_action_plan_prompt(self, intent: ParsedIntent, user_input: str, 
                                  available_modules: List[str]) -> str:
        """构建功能操作计划的提示词"""
        
        entities_info = ""
        for key, value in intent.entities.items():
            entities_info += f"- {key}: {value}\n"
        
        prompt = f"""你是一个**资深安全扫描专家**，请根据用户需求生成**最优、最简洁**的执行计划。

## 📥 用户输入
{user_input}

## 🔍 AI意图分析结果
- **意图类型**: {intent.type.value}
- **置信度**: {intent.confidence:.0%}
- **提取的实体**:
{entities_info if entities_info else '  （无特殊实体）'}

## 🛠️ 可用功能模块
{', '.join(available_modules)}

---

## 📋 模块使用指南

### scan模块（代码安全扫描）
- 适用：漏洞检测、安全检查、代码审计
- 参数：target(路径), mode("auto"/"pure-ai"), test_mode, test_file_count

### report模块（报告生成）  
- 适用：用户明确要求生成报告时
- 参数：format(html/json/markdown), output(路径)

### code_tool模块（代码工具）
- 适用：创建测试文件、准备测试数据
- 参数：action, file_count

### info模块（信息查询）
- ⚠️ **重要**: 只有当用户明确询问HOS-LS工具的功能/用法时才使用此模块
- 如果用户问的是通用技术知识（如"C语言安全问题"），应使用 **ai_chat** 模块
- 参数：topic（必须是用户真正关心的主题，不要硬编码）

### ai_chat模块（AI直接回答）⭐新增
- 适用：通用知识问答、技术讲解、工具介绍、闲聊
- 示例场景：
  * "C语言有哪些安全问题？" → ai_chat
  * "什么是SQL注入？" → ai_chat  
  * "HOS-LS能做什么？" → ai_chat
  * "介绍一下缓冲区溢出" → ai_chat
- 参数：question（用户的问题）, max_tokens

---

## 🎯 输出要求

返回严格的JSON格式：

```json
{{
  "name": "计划名称",
  "description": "一句话描述",
  "steps": [
    {{
      "id": "step1",
      "name": "步骤名称",
      "description": "详细描述",
      "module": "scan|report|code_tool|info|ai_chat",
      "parameters": {{
        "参数名": "值"
      }},
      "dependencies": [],
      "estimated_time": 秒数
    }}
  ],
  "estimated_total_time": 总秒数,
  "pure_ai": true/false,
  "test_mode": true/false,
  "test_file_count": 数字
}}
```

⚠️ **关键提醒**:
1. 步骤数量控制在2-4个
2. **绝对不要硬编码topic参数**，必须从用户输入中提取真实主题
3. 对于知识类问题，优先使用ai_chat模块
4. 合理估计时间"""
        
        return prompt
    
    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """解析AI响应（增强容错能力）"""
        import json
        import re
        
        content = content.strip()
        
        # 尝试直接解析整个内容
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # 尝试提取JSON部分（处理markdown代码块等情况）
        patterns = [
            r'```json\s*([\s\S]*?)\s*```',  # markdown json代码块
            r'```\s*([\s\S]*?)\s*```',       # 通用代码块
            r'\{[\s\S]*\}',                    # 直接匹配花括号
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                json_str = match.group(1) if match.groups() else match.group(0)
                try:
                    return json.loads(json_str.strip())
                except json.JSONDecodeError:
                    continue
        
        # 最终回退
        return {
            "name": "默认计划",
            "description": "AI解析失败，使用默认配置",
            "steps": [{
                "id": "step1",
                "name": "AI智能处理",
                "description": "由AI直接处理用户请求",
                "module": "ai_chat",
                "parameters": {"question": "auto"},
                "dependencies": [],
                "estimated_time": 15
            }],
            "estimated_total_time": 15,
            "pure_ai": True,
            "test_mode": False,
            "test_file_count": 0
        }
    
    def _build_execution_plan(self, plan_data: Dict[str, Any], user_input: str, 
                              intent: ParsedIntent) -> ExecutionPlan:
        """构建执行计划对象"""
        import uuid
        plan_id = str(uuid.uuid4())
        
        name = plan_data.get("name", "执行计划")
        description = plan_data.get("description", "基于用户输入生成的执行计划")
        steps_data = plan_data.get("steps", [])
        estimated_total_time = plan_data.get("estimated_total_time", 300)
        pure_ai = plan_data.get("pure_ai", intent.entities.get("pure_ai", False))
        test_mode = plan_data.get("test_mode", intent.entities.get("test_mode", False))
        test_file_count = plan_data.get("test_file_count", intent.entities.get("test_file_count", 1))
        
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
        
        if not steps:
            steps = [PlanStep(
                id="step1",
                name="AI智能处理",
                description="由AI直接处理用户请求",
                module="ai_chat",
                parameters={"question": user_input},
                dependencies=[],
                estimated_time=15
            )]
        
        return ExecutionPlan(
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
    
    def _generate_fallback_plan(self, intent: ParsedIntent, user_input: str) -> ExecutionPlan:
        """生成回退计划（当AI完全不可用时）"""
        import uuid
        plan_id = str(uuid.uuid4())
        
        step = PlanStep(
            id="step1",
            name="AI智能处理",
            description="由AI直接处理用户请求（回退模式）",
            module="ai_chat",
            parameters={"question": user_input},
            dependencies=[],
            estimated_time=15
        )
        
        return ExecutionPlan(
            id=plan_id,
            name="默认AI对话",
            description="AI服务暂时不可用时的回退方案",
            steps=[step],
            estimated_total_time=15,
            pure_ai=True,
            test_mode=False,
            test_file_count=0,
            user_input=user_input
        )
    
    def generate_human_friendly_plan(self, plan: ExecutionPlan) -> str:
        """生成人类友好的计划表述"""
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
                
                params = getattr(step, 'parameters', {})
                if params:
                    param_str = ', '.join(f'{k}={v}' for k, v in list(params.items())[:5])
                    plan_text += f"- 参数: {param_str}\n"
                
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
        """根据用户反馈调整计划（增强容错能力）"""
        
        prompt = f"""你是一个专业的计划调整专家。根据用户的反馈调整执行计划。

原始计划:
{self.generate_human_friendly_plan(plan)}

用户反馈/修改建议:
{user_feedback}

⚠️ **重要**: 用户反馈可能是自然语言描述，不一定是JSON格式。
请理解用户的真实意图，然后返回调整后的完整计划JSON:

```json
{{
  "name": "调整后的计划名称",
  "description": "计划描述",
  "steps": [
    {{
      "id": "step1",
      "name": "步骤名称",
      "description": "步骤描述",
      "module": "scan|report|info|ai_chat",
      "parameters": {{}},
      "dependencies": [],
      "estimated_time": 60
    }}
  ],
  "estimated_total_time": 300,
  "pure_ai": true/false,
  "test_mode": true/false,
  "test_file_count": 1
}}
```

只返回JSON格式，不要其他内容。"""
        
        request = AIRequest(
            prompt=prompt,
            system_prompt="你擅长理解用户的修改意图，并据此调整执行计划。即使反馈是口语化的也能准确理解。",
            max_tokens=1200,
            temperature=0.1
        )
        
        response = await self.ai_client.generate(request)
        plan_data = self._parse_ai_response(response.content)
        
        return self._build_execution_plan(plan_data, plan.user_input, None)


def get_ai_plan_generator() -> AIPlanGenerator:
    """获取AI计划生成器实例"""
    return AIPlanGenerator()
