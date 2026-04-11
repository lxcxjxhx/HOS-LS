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
        
        # 使用format方法构建提示词（智能增强版）
        prompt = """你是一个**资深安全扫描专家兼AI助手**，具有丰富的实战经验。你的任务是根据用户需求生成**最优、最简洁、最高效**的执行计划。

## 📥 用户输入
{user_input}

## 🔍 意图分析
- **意图类型**: {intent_type}
- **识别到的任务**:
{tasks_info}
- **关键实体**:
{entities_info}

## 🛠️ 可用功能模块
{available_modules}

---

## 🎯 核心设计原则（必须严格遵守）

### 1️⃣ **步骤精简原则**
✅ **推荐**: 将相关操作合并为单个步骤
- "扫描并生成报告" → 1个步骤（module: scan, 参数包含 auto_report: true）
- "创建测试文件然后扫描" → 2个步骤（code_tool → scan）
  
❌ **禁止**: 不必要的步骤拆分
- 不要将"扫描结果分析"拆成"获取结果→解析结果→展示结果"3个步骤
- 不要添加"初始化环境"、"准备配置"等无实质操作的步骤

### 2️⃣ **意图推断规则**
当用户使用以下表达时，自动推断隐含参数：

| 用户表达 | 推断的参数 |
|---------|-----------|
| "快速"、"简单"、"试试"、"测试一下" | test_mode=true, file_count=1 |
| "纯AI"、"AI模式"、"深度分析" | pure_ai=true |
| "全面"、"完整"、"详细" | test_mode=false, 扫描全部文件 |
| "帮我看看"、"查查有没有问题" | 默认scan + 简要报告 |

### 3️⃣ **模块选择指南**

#### scan模块（代码安全扫描）
- **适用场景**: 所有涉及漏洞检测、安全检查、代码审计的任务
- **参数说明**:
  - target: 目标路径（默认"."）
  - mode: "auto"(标准) / "pure-ai"(纯净AI)
  - test_mode: 是否测试模式
  - test_file_count: 测试模式下扫描的文件数

#### report模块（报告生成）
- **适用场景**: 用户明确要求生成报告时
- **注意**: 如果用户说"扫描并报告"，优先在scan步骤中设置 auto_report=true，而非单独添加report步骤
- **参数**: format (html/json/markdown), output (输出路径)

#### code_tool模块（代码工具）
- **适用场景**: 需要创建测试文件、准备测试数据
- **参数**: action ("prepare_test_file"), file_count

#### info模块（信息查询）
- **适用场景**: 解释原理、提供帮助、教学性内容
- **参数**: topic (主题)

### 4️⃣ **典型场景示例**

#### 示例1: "帮我快速测试一下这个项目"
```json
{
  "name": "快速安全测试",
  "steps": [
    {
      "id": "step1",
      "name": "快速安全扫描",
      "description": "使用纯净AI模式对项目进行快速安全测试",
      "module": "scan",
      "parameters": {
        "target": ".",
        "mode": "pure-ai",
        "test_mode": true,
        "test_file_count": 1,
        "auto_report": true
      },
      "dependencies": [],
      "estimated_time": 30
    }
  ],
  "pure_ai": true,
  "test_mode": true,
  "test_file_count": 1
}
```

#### 示例2: "解释漏洞扫描原理然后扫描当前目录"
```json
{
  "name": "原理讲解与安全扫描",
  "steps": [
    {
      "id": "step1", 
      "name": "讲解漏洞扫描原理",
      "description": "详细解释HOS-LS的漏洞扫描实现机制",
      "module": "info",
      "parameters": {"topic": "漏洞扫描工作原理"},
      "dependencies": [],
      "estimated_time": 30
    },
    {
      "id": "step2",
      "name": "执行项目安全扫描",
      "description": "对当前目录进行全面的安全扫描",
      "module": "scan",
      "parameters": {"target": ".", "mode": "auto"},
      "dependencies": ["step1"],
      "estimated_time": 120
    }
  ],
  "pure_ai": false,
  "test_mode": false
}
```

#### 示例3: "分析扫描结果并生成简洁报告"
```json
{
  "name": "扫描分析与报告生成",
  "steps": [
    {
      "id": "step1",
      "name": "扫描并生成报告",
      "description": "执行安全扫描并自动生成简洁的报告",
      "module": "scan",
      "parameters": {
        "target": ".",
        "mode": "pure-ai",
        "auto_report": true,
        "report_format": "brief",
        "output_path": "./security-report"
      },
      "dependencies": [],
      "estimated_time": 60
    }
  ],
  "pure_ai": true,
  "test_mode": false
}
```

---

## 📤 输出格式要求

请返回**严格的JSON格式**（不要包含任何其他文字、注释或markdown标记）:

```json
{
  "name": "计划名称（简洁明了）",
  "description": "一句话描述计划目标",
  "steps": [
    {
      "id": "step1",
      "name": "步骤名称（动词开头）",
      "description": "详细描述该步骤要做什么",
      "module": "从可用模块中选择",
      "parameters": {
        "参数名": "根据模块文档填写"
      },
      "dependencies": ["依赖的前置步骤ID，无依赖则为空数组"],
      "estimated_time": 预估秒数（参考：info=30s, scan=60-180s, report=30s）
    }
  ],
  "estimated_total_time": 总时间（所有步骤时间之和）,
  "pure_ai": true/false,
  "test_mode": true/false,
  "test_file_count": 数字
}
```

⚠️ **最后提醒**:
1. 步骤数量控制在2-4个以内（除非确实需要更多）
2. 每个步骤必须有明确的实际操作意义
3. 不要创造不存在的模块或参数
4. 合理估计执行时间
5. 优先考虑用户体验和执行效率""".format(
            user_input=user_input,
            intent_type=intent.type.value,
            tasks_info=tasks_info if tasks_info else "  （未识别到具体子任务，请根据用户输入推断）",
            entities_info=entities_info if entities_info else "  （未识别到特殊实体）",
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
