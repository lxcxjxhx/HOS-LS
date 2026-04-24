"""AI Pipeline 配置器

使用AI模型将自然语言描述转换为Pipeline配置，支持CLI/Chat双向转换。
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from src.ai.models import AIRequest
from src.ai.client import AIModelManager, get_model_manager
from src.core.config import Config, get_config
from src.core.chat.pipeline_builder import PipelineBuilder, AgentType, PipelineConfig
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PipelineConfigResult:
    """Pipeline配置结果"""
    agent_types: List[AgentType]
    cli_flags: str
    chat_description: str
    confidence: float
    method: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def pipeline_config(self) -> PipelineConfig:
        """获取Pipeline配置"""
        builder = PipelineBuilder()
        return builder.build_pipeline(self.agent_types)


class AIPipelineConfigurator:
    """AI Pipeline配置器

    使用AI模型将自然语言描述转换为Pipeline配置。
    """

    SYSTEM_PROMPT = """你是一个安全聊天中心的Pipeline配置专家。根据用户需求生成合适的Agent流水线配置。

可用Agent类型：
- SCAN: 扫描代理 - 执行代码安全扫描
- CONTEXT: 上下文代理 - 收集项目上下文信息
- UNDERSTAND: 理解代理 - 深度理解代码结构和漏洞
- RISK: 风险评估代理 - 评估漏洞风险等级
- VERIFY: 验证代理 - 验证漏洞是否存在
- ATTACK: 攻击代理 - 执行攻击测试
- ADVERSARIAL: 对抗性代理 - 执行对抗性测试
- POC: POC生成代理 - 生成漏洞证明代码
- FINAL: 最终决策代理 - 综合分析生成最终结论
- REPORT: 报告代理 - 生成安全报告

宏命令：
- quick-scan: 快速扫描 = scan + context + final
- deep-scan: 深度扫描 = scan + context + understand + risk + verify + attack + adversarial + final
- full-audit: 完整审计 = scan + context + understand + risk + verify + attack + adversarial + final + poc + report

依赖关系：
- CONTEXT依赖SCAN
- UNDERSTAND依赖CONTEXT
- RISK依赖UNDERSTAND
- VERIFY依赖RISK
- ATTACK依赖VERIFY
- ADVERSARIAL依赖ATTACK
- POC依赖ATTACK
- FINAL依赖POC和ADVERSARIAL
- REPORT依赖FINAL

请以JSON格式返回结果：
{
    "agent_types": ["AGENT1", "AGENT2", ...],
    "cli_flags": "--agent1+agent2+...",
    "chat_description": "自然语言描述",
    "confidence": 0.0-1.0,
    "reasoning": "配置理由"
}

只返回JSON，不要有其他内容。"""

    FEW_SHOT_EXAMPLES = """
示例：
输入: "帮我深度审计一下项目的安全问题"
输出: {
    "agent_types": ["SCAN", "CONTEXT", "UNDERSTAND", "RISK", "VERIFY", "ATTACK", "ADVERSARIAL", "FINAL", "REPORT"],
    "cli_flags": "--deep-scan+adversarial+poc+report",
    "chat_description": "执行深度安全审计，生成完整报告和POC",
    "confidence": 0.95,
    "reasoning": "深度审计需要完整的Agent链"
}

输入: "快速检查一下这个目录"
输出: {
    "agent_types": ["SCAN", "CONTEXT", "FINAL"],
    "cli_flags": "--quick-scan",
    "chat_description": "执行快速安全扫描",
    "confidence": 0.9,
    "reasoning": "快速检查使用quick-scan宏"
}

输入: "扫描src目录，看看有没有SQL注入"
输出: {
    "agent_types": ["SCAN", "CONTEXT", "FINAL"],
    "cli_flags": "--scan+context+final",
    "chat_description": "扫描src目录，执行上下文分析",
    "confidence": 0.85,
    "reasoning": "针对SQL注入的扫描需要基础流水线"
}"""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._manager: Optional[AIModelManager] = None
        self._builder = PipelineBuilder()
        self._initialized = False

    async def initialize(self) -> None:
        """初始化配置器"""
        if not self._initialized:
            self._manager = await get_model_manager(self.config)
            self._initialized = True

    async def configure_from_natural_language(
        self, user_description: str
    ) -> PipelineConfigResult:
        """从自然语言描述生成Pipeline配置

        Args:
            user_description: 用户的自然语言描述

        Returns:
            Pipeline配置结果
        """
        if not self._initialized:
            await self.initialize()

        if not user_description or not user_description.strip():
            return self._get_default_config()

        try:
            result = await self._ai_configure(user_description)

            if result.confidence >= 0.7:
                return result

            fallback_result = self._fallback_configure(user_description)
            if fallback_result:
                return fallback_result

            return result

        except Exception as e:
            logger.warning(f"AI pipeline configuration failed: {e}, using fallback")
            fallback_result = self._fallback_configure(user_description)
            if fallback_result:
                return fallback_result

            return self._get_default_config()

    async def _ai_configure(self, user_description: str) -> PipelineConfigResult:
        """使用AI模型配置Pipeline"""
        prompt = self._build_configuration_prompt(user_description)

        request = AIRequest(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1,
            max_tokens=512,
            model=self.config.ai.model,
        )

        response = await self._manager.generate(request)

        return self._parse_configuration_response(response.content, user_description)

    def _build_configuration_prompt(self, user_description: str) -> str:
        """构建配置提示"""
        return f"{self.FEW_SHOT_EXAMPLES}\n\n用户需求: \"{user_description}\"\n输出:"

    def _parse_configuration_response(
        self, content: str, original_input: str
    ) -> PipelineConfigResult:
        """解析AI配置响应"""
        try:
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
            else:
                data = json.loads(content)

            agent_types_str = data.get("agent_types", [])
            agent_types = []
            for at_str in agent_types_str:
                try:
                    agent_type = AgentType(at_str.lower())
                    agent_types.append(agent_type)
                except ValueError:
                    logger.warning(f"Unknown agent type: {at_str}")

            cli_flags = data.get("cli_flags", "")
            chat_description = data.get("chat_description", "")
            confidence = float(data.get("confidence", 0.0))

            return PipelineConfigResult(
                agent_types=agent_types,
                cli_flags=cli_flags,
                chat_description=chat_description,
                confidence=confidence,
                method="ai_model",
                metadata={"reasoning": data.get("reasoning", "")}
            )

        except Exception as e:
            logger.error(f"Failed to parse configuration response: {e}")
            return self._get_default_config()

    def _fallback_configure(self, user_description: str) -> Optional[PipelineConfigResult]:
        """使用规则进行fallback配置"""
        user_lower = user_description.lower()

        if any(kw in user_lower for kw in ["完整审计", "full audit", "全面审计"]):
            return self._build_result_from_macro("full-audit")

        if any(kw in user_lower for kw in ["深度", "deep"]):
            return self._build_result_from_macro("deep-scan")

        if any(kw in user_lower for kw in ["快速", "quick", "简单"]):
            return self._build_result_from_macro("quick-scan")

        if any(kw in user_lower for kw in ["poc", "证明", "漏洞证明"]):
            return PipelineConfigResult(
                agent_types=[AgentType.SCAN, AgentType.CONTEXT, AgentType.ATTACK, AgentType.POC, AgentType.FINAL],
                cli_flags="--scan+context+attack+poc+final",
                chat_description="执行扫描并生成POC",
                confidence=0.6,
                method="fallback_rules"
            )

        if any(kw in user_lower for kw in ["报告", "report"]):
            return PipelineConfigResult(
                agent_types=[AgentType.SCAN, AgentType.CONTEXT, AgentType.FINAL, AgentType.REPORT],
                cli_flags="--scan+context+final+report",
                chat_description="执行扫描并生成报告",
                confidence=0.6,
                method="fallback_rules"
            )

        return None

    def _build_result_from_macro(self, macro_name: str) -> PipelineConfigResult:
        """从宏名称构建配置"""
        macro_map = {
            "quick-scan": ("--quick-scan", "执行快速安全扫描"),
            "deep-scan": ("--deep-scan", "执行深度安全扫描"),
            "full-audit": ("--full-audit", "执行完整安全审计"),
        }

        cli_flags, chat_desc = macro_map.get(macro_name, ("--scan+context+final", "执行标准扫描"))

        if macro_name == "quick-scan":
            agents = [AgentType.SCAN, AgentType.CONTEXT, AgentType.FINAL]
        elif macro_name == "deep-scan":
            agents = [AgentType.SCAN, AgentType.CONTEXT, AgentType.UNDERSTAND, AgentType.RISK,
                     AgentType.VERIFY, AgentType.ATTACK, AgentType.ADVERSARIAL, AgentType.FINAL]
        else:
            agents = [AgentType.SCAN, AgentType.CONTEXT, AgentType.UNDERSTAND, AgentType.RISK,
                     AgentType.VERIFY, AgentType.ATTACK, AgentType.ADVERSARIAL, AgentType.FINAL,
                     AgentType.POC, AgentType.REPORT]

        return PipelineConfigResult(
            agent_types=agents,
            cli_flags=cli_flags,
            chat_description=chat_desc,
            confidence=0.7,
            method="fallback_macro"
        )

    def _get_default_config(self) -> PipelineConfigResult:
        """获取默认配置"""
        return PipelineConfigResult(
            agent_types=[AgentType.SCAN, AgentType.CONTEXT, AgentType.FINAL],
            cli_flags="--scan+context+final",
            chat_description="执行标准安全扫描",
            confidence=0.5,
            method="default"
        )

    async def cli_to_chat(self, cli_command: str) -> str:
        """CLI命令转Chat描述

        Args:
            cli_command: CLI命令，如 "--scan+context+attack"

        Returns:
            Chat格式的自然语言描述
        """
        if not self._initialized:
            await self.initialize()

        if not cli_command or not cli_command.strip():
            return "执行标准安全扫描"

        try:
            return await self._ai_cli_to_chat(cli_command)
        except Exception as e:
            logger.warning(f"AI cli_to_chat failed: {e}")
            return self._fallback_cli_to_chat(cli_command)

    async def _ai_cli_to_chat(self, cli_command: str) -> str:
        """使用AI将CLI转为Chat"""
        prompt = f"""将以下CLI命令转换为自然语言描述：

CLI命令: {cli_command}

只返回自然语言描述，不要有其他内容。"""

        request = AIRequest(
            prompt=prompt,
            temperature=0.1,
            max_tokens=128,
            model=self.config.ai.model,
        )

        response = await self._manager.generate(request)
        return response.content.strip()

    def _fallback_cli_to_chat(self, cli_command: str) -> str:
        """Fallback CLI转Chat"""
        cli_lower = cli_command.lower()

        if "full-audit" in cli_lower:
            return "执行完整安全审计"
        if "deep-scan" in cli_lower:
            return "执行深度安全扫描"
        if "quick-scan" in cli_lower:
            return "执行快速安全扫描"

        agent_descriptions = {
            "scan": "扫描",
            "context": "上下文分析",
            "understand": "深度理解",
            "risk": "风险评估",
            "verify": "漏洞验证",
            "attack": "攻击测试",
            "adversarial": "对抗性测试",
            "poc": "POC生成",
            "final": "最终决策",
            "report": "报告生成",
        }

        parts = []
        for agent, desc in agent_descriptions.items():
            if agent in cli_lower:
                parts.append(desc)

        if parts:
            return "执行" + " + ".join(parts) + "流程"

        return "执行标准安全扫描"

    async def chat_to_cli(self, chat_input: str) -> str:
        """Chat描述转CLI命令

        Args:
            chat_input: Chat格式的描述

        Returns:
            CLI格式的命令
        """
        if not self._initialized:
            await self.initialize()

        if not chat_input or not chat_input.strip():
            return "--scan+context+final"

        try:
            config_result = await self.configure_from_natural_language(chat_input)
            return config_result.cli_flags
        except Exception as e:
            logger.warning(f"AI chat_to_cli failed: {e}")
            fallback_result = self._fallback_configure(chat_input)
            if fallback_result:
                return fallback_result.cli_flags
            return "--scan+context+final"

    async def describe_pipeline(self, pipeline_config: PipelineConfig) -> str:
        """生成Pipeline的描述

        Args:
            pipeline_config: Pipeline配置

        Returns:
            Pipeline的自然语言描述
        """
        if not self._initialized:
            await self.initialize()

        agent_names = []
        for node in pipeline_config.nodes:
            name_map = {
                AgentType.SCAN: "扫描",
                AgentType.CONTEXT: "上下文分析",
                AgentType.UNDERSTAND: "深度理解",
                AgentType.RISK: "风险评估",
                AgentType.VERIFY: "漏洞验证",
                AgentType.ATTACK: "攻击测试",
                AgentType.ADVERSARIAL: "对抗性测试",
                AgentType.POC: "POC生成",
                AgentType.FINAL: "最终决策",
                AgentType.REPORT: "报告生成",
            }
            name = name_map.get(node.agent_type, node.agent_type.value)
            if node.enabled:
                agent_names.append(name)

        if not agent_names:
            return "空流水线"

        return "执行" + " + ".join(agent_names) + "流程"
