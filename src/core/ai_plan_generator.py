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
from src.core.prompt_rulebook import HOSLSRulebookFactory, PromptRulebook


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
    """AI计划生成器（规则书优化版本）
    
    不再使用硬编码的默认值，
    所有计划内容都由AI根据用户实际输入动态生成。
    
    Token优化：使用规则书后，prompt从~900t降至~400t
    """
    
    def __init__(self, config=None):
        from src.core.config import get_config
        self.config = config if config else get_config()
        self.ai_client = None
        self.module_capabilities = get_module_capabilities()
        self.rulebook: PromptRulebook = HOSLSRulebookFactory.create_plan_generator_rulebook()
    
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
            # 检查是否包含多个意图
            if intent.has_multiple_intents() and len(intent.sub_intents) > 0:
                return await self._generate_multi_intent_plan(intent, user_input)
            
            # 检查是否需要扫描（即使没有识别为多意图）
            if any(keyword in user_input for keyword in ['扫描', 'scan', '检测', '漏洞', '安全检查']):
                # 尝试生成包含扫描步骤的计划
                return await self._generate_scan_plan(intent, user_input)
            
            available_modules = list(self.module_capabilities.get_all_capabilities().keys())
            
            # 根据意图类型选择不同的提示策略
            if intent.type == IntentType.AI_CHAT or intent.type == IntentType.GENERAL:
                plan = await self._generate_ai_chat_plan(intent, user_input)
            else:
                plan = await self._generate_action_plan(intent, user_input, available_modules)
            
            return plan
            
        except Exception as e:
            return self._generate_fallback_plan(intent, user_input)
    
    async def _generate_scan_plan(self, intent: ParsedIntent, user_input: str) -> ExecutionPlan:
        """生成包含扫描步骤的计划
        
        Args:
            intent: 解析后的意图
            user_input: 用户原始输入
            
        Returns:
            包含扫描步骤的执行计划
        """
        import uuid
        plan_id = str(uuid.uuid4())
        
        steps = []
        estimated_total_time = 0
        
        # 检查是否需要AI回答
        if any(keyword in user_input for keyword in ['解释', '回答', '说明', '介绍', '什么是', '如何', '怎样']):
            # 添加AI回答步骤
            ai_step = PlanStep(
                id="step1",
                name="AI智能回答",
                description=f"使用AI回答用户的问题: {user_input[:100]}",
                module="ai_chat",
                parameters={
                    'question': user_input,
                    'context': user_input,
                    'max_tokens': 2000
                },
                dependencies=[],
                estimated_time=10
            )
            steps.append(ai_step)
            estimated_total_time += 10
        
        # 添加扫描步骤
        target_path = "."
        pure_ai = True
        test_mode = True
        test_file_count = 1
        
        # 提取目标路径
        import re
        path_match = re.search(r'目录\s*(.+?)\s*下', user_input)
        if path_match:
            target_path = path_match.group(1).strip()
        
        # 提取文件数量
        count_match = re.search(r'(?:扫|扫描)\s*(\d+)\s*个文件', user_input)
        if count_match:
            test_file_count = int(count_match.group(1))
        
        scan_step = PlanStep(
            id="step2" if steps else "step1",
            name="纯净AI模式扫描",
            description=f"使用纯净AI模式扫描 {target_path} 目录下的 {test_file_count} 个文件",
            module="scan",
            parameters={
                'target': target_path,
                'mode': 'pure-ai',
                'test_mode': test_mode,
                'test_file_count': test_file_count
            },
            dependencies=[steps[-1].id] if steps else [],
            estimated_time=30
        )
        steps.append(scan_step)
        estimated_total_time += 30
        
        return ExecutionPlan(
            id=plan_id,
            name="AI回答 + 扫描计划",
            description=f"使用AI回答问题并进行纯净AI模式扫描",
            steps=steps,
            estimated_total_time=estimated_total_time,
            pure_ai=True,
            test_mode=True,
            test_file_count=test_file_count,
            user_input=user_input
        )
    
    async def _generate_multi_intent_plan(self, intent: ParsedIntent, user_input: str) -> ExecutionPlan:
        """生成多意图执行计划
        
        当用户请求包含多个步骤时，为每个子意图生成相应的步骤。
        """
        import uuid
        plan_id = str(uuid.uuid4())
        
        steps = []
        estimated_total_time = 0
        
        # 处理主要意图
        if intent.type != IntentType.GENERAL:
            main_step = await self._generate_step_for_intent(intent, user_input, 1)
            if main_step:
                steps.append(main_step)
                estimated_total_time += main_step.estimated_time
        
        # 处理子意图
        for i, sub_intent in enumerate(intent.sub_intents, start=len(steps) + 1):
            sub_step = await self._generate_step_for_intent(sub_intent, user_input, i)
            if sub_step:
                # 设置依赖关系
                if steps:
                    sub_step.dependencies = [steps[-1].id]
                steps.append(sub_step)
                estimated_total_time += sub_step.estimated_time
        
        # 如果没有生成任何步骤，使用回退方案
        if not steps:
            return self._generate_fallback_plan(intent, user_input)
        
        return ExecutionPlan(
            id=plan_id,
            name="多步骤执行计划",
            description=f"根据用户请求生成的多步骤执行计划: {user_input[:50]}",
            steps=steps,
            estimated_total_time=estimated_total_time,
            pure_ai=True,
            test_mode=True,
            test_file_count=1,
            user_input=user_input
        )
    
    async def _generate_step_for_intent(self, intent: ParsedIntent, user_input: str, step_index: int) -> Optional[PlanStep]:
        """为单个意图生成步骤
        
        Args:
            intent: 解析后的意图
            user_input: 用户原始输入
            step_index: 步骤索引
            
        Returns:
            生成的步骤，如果无法生成则返回None
        """
        step_id = f"step{step_index}"
        
        if intent.type == IntentType.AI_CHAT:
            user_question = intent.entities.get('user_question', user_input)
            return PlanStep(
                id=step_id,
                name="AI智能回答",
                description=f"使用AI回答用户的问题: {user_question[:100]}",
                module="ai_chat",
                parameters={
                    'question': user_question,
                    'context': user_input,
                    'max_tokens': 2000
                },
                dependencies=[],
                estimated_time=10
            )
        elif intent.type == IntentType.SCAN:
            target_path = intent.entities.get('target_path', '.')
            pure_ai = intent.entities.get('pure_ai', True)
            test_mode = intent.entities.get('test_mode', True)
            test_file_count = intent.entities.get('test_file_count', 1)
            
            return PlanStep(
                id=step_id,
                name="纯净AI模式扫描",
                description=f"使用纯净AI模式扫描 {target_path} 目录下的 {test_file_count} 个文件",
                module="scan",
                parameters={
                    'target': target_path,
                    'mode': 'pure-ai',
                    'test_mode': test_mode,
                    'test_file_count': test_file_count
                },
                dependencies=[],
                estimated_time=30
            )
        elif intent.type == IntentType.INFO:
            topic = intent.entities.get('topic', 'HOS-LS功能')
            return PlanStep(
                id=step_id,
                name="工具信息查询",
                description=f"查询关于 {topic} 的信息",
                module="info",
                parameters={
                    'topic': topic
                },
                dependencies=[],
                estimated_time=5
            )
        
        return None
    
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
        """生成功能操作类型的计划（规则书版本）"""
        
        assembled = self.rulebook.assemble_prompt(
            user_input=user_input,
            intent_type=intent.type.value,
            max_system_tokens=800
        )
        
        entities_info = ""
        for key, value in intent.entities.items():
            entities_info += f"- {key}: {value}\n"
        
        prompt = f"""你是一个专业的安全扫描专家，负责根据用户的需求生成最优的执行计划。

## 📥 用户输入
{user_input}

## 🔍 AI意图分析结果
- **意图类型**: {intent.type.value}
- **置信度**: {intent.confidence:.0%}
- **提取的实体**:
{entities_info if entities_info else '  （无特殊实体）'}

## 🛠️ 可用功能模块
{', '.join(available_modules)}

## 🎯 任务要求
1. 使用AI语义理解来识别用户需求，不要使用固定编码识别
2. 生成详细的执行方案，确保包含所有用户要求的步骤
3. 清洗方案，确保输出符合用户的需求
4. 按照读取的参数打印在屏幕上让用户可以看到

## 📋 输出格式
请返回JSON格式的执行计划（只返回JSON）:
```json
{
  "name": "计划名称",
  "description": "计划描述",
  "steps": [
    {
      "id": "step1",
      "name": "步骤名称",
      "description": "详细描述",
      "module": "scan|report|code_tool|info|ai_chat",
      "parameters": {
        "参数名": "值"
      },
      "dependencies": [],
      "estimated_time": 秒数
    }
  ],
  "estimated_total_time": 总秒数,
  "pure_ai": true/false,
  "test_mode": true/false,
  "test_file_count": 数字
}
```

## ⚠️ 重要提醒
1. 确保识别所有的用户需求，不要遗漏任何步骤
2. 准确提取用户提到的参数，如文件数量、目标路径等
3. 按照用户指定的顺序生成步骤
4. 为每个步骤设置合理的参数和执行时间
5. 确保方案的可行性和准确性"""

        request = AIRequest(
            prompt=prompt,
            system_prompt=assembled['system'],
            max_tokens=1200,
            temperature=0.1
        )
        
        ai_client = await self._get_ai_client()
        if not ai_client:
            return self._generate_fallback_plan(intent, user_input)
        
        response = await ai_client.generate(request)
        plan_data = self._parse_ai_response(response.content)
        
        # 清洗方案，确保符合用户需求
        cleaned_plan_data = self._clean_plan_data(plan_data, user_input, intent)
        
        return self._build_execution_plan(cleaned_plan_data, user_input, intent)
    
    def _clean_plan_data(self, plan_data: Dict[str, Any], user_input: str, intent: ParsedIntent) -> Dict[str, Any]:
        """清洗方案数据，确保符合用户需求
        
        Args:
            plan_data: AI生成的方案数据
            user_input: 用户原始输入
            intent: 解析后的意图
            
        Returns:
            清洗后的方案数据
        """
        import re
        
        # 确保计划名称和描述存在
        if 'name' not in plan_data or not plan_data['name']:
            plan_data['name'] = "执行计划"
        
        if 'description' not in plan_data or not plan_data['description']:
            plan_data['description'] = f"基于用户输入生成的执行计划: {user_input[:50]}"
        
        # 确保步骤存在
        if 'steps' not in plan_data or not plan_data['steps']:
            plan_data['steps'] = []
        
        # 确保扫描步骤的参数正确
        for step in plan_data['steps']:
            if step.get('module') == 'scan':
                # 确保target参数存在
                if 'parameters' not in step:
                    step['parameters'] = {}
                if 'target' not in step['parameters']:
                    step['parameters']['target'] = intent.entities.get('target_path', '.')
                # 确保mode参数存在
                if 'mode' not in step['parameters']:
                    step['parameters']['mode'] = 'pure-ai'
                # 确保test_mode参数存在
                if 'test_mode' not in step['parameters']:
                    step['parameters']['test_mode'] = intent.entities.get('test_mode', True)
                # 确保test_file_count参数存在
                if 'test_file_count' not in step['parameters']:
                    # 从用户输入中提取文件数量
                    count_match = re.search(r'(?:扫|扫描)\s*(\d+)\s*个文件', user_input)
                    if count_match:
                        step['parameters']['test_file_count'] = int(count_match.group(1))
                    else:
                        step['parameters']['test_file_count'] = intent.entities.get('test_file_count', 1)
        
        # 确保AI回答步骤的参数正确
        for step in plan_data['steps']:
            if step.get('module') == 'ai_chat':
                # 确保question参数存在
                if 'parameters' not in step:
                    step['parameters'] = {}
                if 'question' not in step['parameters']:
                    step['parameters']['question'] = intent.entities.get('user_question', user_input)
                # 确保max_tokens参数存在
                if 'max_tokens' not in step['parameters']:
                    step['parameters']['max_tokens'] = 2000
        
        # 确保estimated_total_time存在
        if 'estimated_total_time' not in plan_data or not plan_data['estimated_total_time']:
            # 计算总执行时间
            total_time = sum(step.get('estimated_time', 60) for step in plan_data['steps'])
            plan_data['estimated_total_time'] = total_time
        
        # 确保pure_ai存在
        if 'pure_ai' not in plan_data:
            plan_data['pure_ai'] = intent.entities.get('pure_ai', True)
        
        # 确保test_mode存在
        if 'test_mode' not in plan_data:
            plan_data['test_mode'] = intent.entities.get('test_mode', True)
        
        # 确保test_file_count存在
        if 'test_file_count' not in plan_data:
            # 从用户输入中提取文件数量
            count_match = re.search(r'(?:扫|扫描)\s*(\d+)\s*个文件', user_input)
            if count_match:
                plan_data['test_file_count'] = int(count_match.group(1))
            else:
                plan_data['test_file_count'] = intent.entities.get('test_file_count', 1)
        
        return plan_data
    
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
