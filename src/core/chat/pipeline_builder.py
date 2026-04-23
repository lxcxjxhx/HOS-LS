"""Agent Pipeline Builder for Security Chat Center

提供安全聊天中心的Agent流水线构建器，支持命令行标志解析、宏展开、
节点链表达式、自动补全和CLI/Chat双向转换功能。
"""

from typing import Dict, List, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import re

from src.ai.pipeline.configurator import AIPipelineConfigurator


class AgentType(Enum):
    SCAN = "scan"
    CONTEXT = "context"
    UNDERSTAND = "understand"
    RISK = "risk"
    VERIFY = "verify"
    ATTACK = "attack"
    ADVERSARIAL = "adversarial"
    FINAL = "final"
    POC = "poc"
    REPORT = "report"


class AgentNode:
    def __init__(self, agent_type: AgentType, enabled: bool = True,
                 config: Optional[Dict[str, Any]] = None):
        self.agent_type = agent_type
        self.enabled = enabled
        self.config = config or {}
        self.input_schema: Optional[type] = None
        self.output_schema: Optional[type] = None
        self.dependencies: Set[AgentType] = set()

    def __repr__(self) -> str:
        status = "✓" if self.enabled else "✗"
        return f"[{status}] {self.agent_type.value}"


@dataclass
class PipelineConfig:
    nodes: List[AgentNode] = field(default_factory=list)
    enable_parallel: bool = False
    max_retries: int = 3


class PipelineBuilder:
    FLAG_PATTERN = re.compile(r'--([a-zA-Z0-9_-]+)(?:\+([a-zA-Z0-9_+-]+))?')
    CHAIN_PATTERN = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_]*)(?:\+([a-zA-Z_][a-zA-Z0-9_+-]*))*$')

    MACRO_COMMANDS: Dict[str, List[AgentType]] = {
        "full-audit": [AgentType.SCAN, AgentType.CONTEXT, AgentType.UNDERSTAND,
                       AgentType.RISK, AgentType.VERIFY, AgentType.ATTACK,
                       AgentType.ADVERSARIAL, AgentType.FINAL, AgentType.POC, AgentType.REPORT],
        "quick-scan": [AgentType.SCAN, AgentType.CONTEXT, AgentType.FINAL],
        "deep-scan": [AgentType.SCAN, AgentType.CONTEXT, AgentType.UNDERSTAND,
                      AgentType.RISK, AgentType.VERIFY, AgentType.ATTACK,
                      AgentType.ADVERSARIAL, AgentType.FINAL],
    }

    DEPENDENCY_GRAPH: Dict[AgentType, Set[AgentType]] = {
        AgentType.CONTEXT: {AgentType.SCAN},
        AgentType.UNDERSTAND: {AgentType.CONTEXT},
        AgentType.RISK: {AgentType.UNDERSTAND},
        AgentType.VERIFY: {AgentType.RISK},
        AgentType.ATTACK: {AgentType.VERIFY},
        AgentType.ADVERSARIAL: {AgentType.ATTACK},
        AgentType.POC: {AgentType.ATTACK},
        AgentType.FINAL: {AgentType.POC, AgentType.ADVERSARIAL},
        AgentType.REPORT: {AgentType.FINAL},
    }

    FLAG_TO_AGENT: Dict[str, AgentType] = {
        "scan": AgentType.SCAN,
        "context": AgentType.CONTEXT,
        "understand": AgentType.UNDERSTAND,
        "risk": AgentType.RISK,
        "verify": AgentType.VERIFY,
        "attack": AgentType.ATTACK,
        "adversarial": AgentType.ADVERSARIAL,
        "final": AgentType.FINAL,
        "poc": AgentType.POC,
        "report": AgentType.REPORT,
    }

    AGENT_TO_FLAG: Dict[AgentType, str] = {v: k for k, v in FLAG_TO_AGENT.items()}

    CHAT_DESCRIPTIONS: Dict[AgentType, Dict[str, str]] = {
        AgentType.SCAN: {"name": "扫描代理", "desc": "执行代码安全扫描"},
        AgentType.CONTEXT: {"name": "上下文代理", "desc": "收集项目上下文信息"},
        AgentType.UNDERSTAND: {"name": "理解代理", "desc": "深度理解代码结构和漏洞"},
        AgentType.RISK: {"name": "风险评估代理", "desc": "评估漏洞风险等级"},
        AgentType.VERIFY: {"name": "验证代理", "desc": "验证漏洞是否存在"},
        AgentType.ATTACK: {"name": "攻击代理", "desc": "执行攻击测试"},
        AgentType.ADVERSARIAL: {"name": "对抗性代理", "desc": "执行对抗性测试"},
        AgentType.POC: {"name": "POC生成代理", "desc": "生成漏洞证明代码"},
        AgentType.FINAL: {"name": "最终决策代理", "desc": "综合分析生成最终结论"},
        AgentType.REPORT: {"name": "报告代理", "desc": "生成安全报告"},
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._nodes: Dict[AgentType, AgentNode] = {}
        self._macro_commands: Dict[str, List[AgentType]] = self.MACRO_COMMANDS.copy()
        self._ai_configurator: Optional[AIPipelineConfigurator] = None
        self._use_ai = True
        self._initialize_default_nodes()

    def set_ai_enabled(self, enabled: bool) -> None:
        """设置是否启用AI增强"""
        self._use_ai = enabled

    async def _get_ai_configurator(self) -> AIPipelineConfigurator:
        """获取AI配置器（延迟初始化）"""
        if self._ai_configurator is None:
            self._ai_configurator = AIPipelineConfigurator()
            await self._ai_configurator.initialize()
        return self._ai_configurator

    def _initialize_default_nodes(self) -> None:
        for agent_type in AgentType:
            self._nodes[agent_type] = AgentNode(
                agent_type=agent_type,
                enabled=True,
                config=self.config.get(agent_type.value, {})
            )

    def register_macro(self, name: str, agents: List[AgentType]) -> None:
        self._macro_commands[name] = agents

    def unregister_macro(self, name: str) -> bool:
        if name in self._macro_commands:
            del self._macro_commands[name]
            return True
        return False

    def list_macros(self) -> List[str]:
        return list(self._macro_commands.keys())

    def parse_flags(self, flags: str) -> PipelineConfig:
        if not flags or not flags.strip():
            return self.build_pipeline([AgentType.SCAN, AgentType.CONTEXT, AgentType.FINAL])

        flags = flags.strip()
        enabled_agents: List[AgentType] = []

        for match in self.FLAG_PATTERN.finditer(flags):
            flag_name = match.group(1)
            chain_content = match.group(2)

            if flag_name in self._macro_commands:
                expanded = self.expand_macro(flag_name)
                enabled_agents.extend(expanded)
            elif flag_name in self.FLAG_TO_AGENT:
                enabled_agents.append(self.FLAG_TO_AGENT[flag_name])
            else:
                raise ValueError(f"Unknown flag: --{flag_name}")

            if chain_content:
                chain_agents = self.parse_chain_flags(chain_content)
                for agent in chain_agents:
                    if agent not in enabled_agents:
                        enabled_agents.append(agent)

        if not enabled_agents:
            enabled_agents = [AgentType.SCAN, AgentType.CONTEXT, AgentType.FINAL]

        enabled_agents = self.auto_complete(enabled_agents)
        return self.build_pipeline(enabled_agents)

    def expand_macro(self, macro_name: str) -> List[AgentType]:
        if macro_name not in self._macro_commands:
            raise ValueError(f"Unknown macro: {macro_name}")
        return self._macro_commands[macro_name].copy()

    def parse_chain_flags(self, chain: str) -> List[AgentType]:
        if not chain:
            return []

        agents: List[AgentType] = []
        parts = chain.split('+')

        for part in parts:
            part = part.strip()
            if not part:
                continue

            if part in self.FLAG_TO_AGENT:
                agents.append(self.FLAG_TO_AGENT[part])
            else:
                raise ValueError(f"Unknown agent type in chain: {part}")

        return agents

    def auto_complete(self, enabled_agents: List[AgentType]) -> List[AgentType]:
        result = enabled_agents.copy()
        added = True

        while added:
            added = False
            for agent in result[:]:
                required = self.DEPENDENCY_GRAPH.get(agent, set())
                for dep in required:
                    if dep not in result:
                        result.append(dep)
                        added = True

        execution_order = self._get_execution_order(result)
        return execution_order

    def _get_execution_order(self, agents: List[AgentType]) -> List[AgentType]:
        visited: Set[AgentType] = set()
        order: List[AgentType] = []

        def visit(agent: AgentType) -> None:
            if agent in visited:
                return
            visited.add(agent)

            for dep in self.DEPENDENCY_GRAPH.get(agent, set()):
                if dep in agents:
                    visit(dep)

            if agent not in order:
                order.append(agent)

        for agent in agents:
            visit(agent)

        return order

    def build_pipeline(self, agent_types: List[AgentType]) -> PipelineConfig:
        nodes = []
        for agent_type in agent_types:
            if agent_type in self._nodes:
                node = AgentNode(
                    agent_type=agent_type,
                    enabled=True,
                    config=self._nodes[agent_type].config.copy()
                )
                node.dependencies = self.DEPENDENCY_GRAPH.get(agent_type, set()).copy()
                nodes.append(node)
            else:
                node = AgentNode(agent_type=agent_type, enabled=True)
                nodes.append(node)

        return PipelineConfig(
            nodes=nodes,
            enable_parallel=self.config.get("enable_parallel", False),
            max_retries=self.config.get("max_retries", 3)
        )

    def cli_to_chat(self, cli_command: str) -> str:
        if not cli_command or not cli_command.strip():
            return "执行标准安全扫描"

        cli_command = cli_command.strip()
        parts: List[str] = []
        agent_names = []

        for match in self.FLAG_PATTERN.finditer(cli_command):
            flag_name = match.group(1)
            chain_content = match.group(2)

            if flag_name in self._macro_commands:
                macro_desc = self._get_macro_description(flag_name)
                parts.append(macro_desc)
            elif flag_name in self.FLAG_TO_AGENT:
                agent_type = self.FLAG_TO_AGENT[flag_name]
                desc = self.CHAT_DESCRIPTIONS.get(agent_type, {})
                agent_names.append(desc.get("name", flag_name))

            if chain_content:
                chain_parts = self.parse_chain_flags(chain_content)
                for at in chain_parts:
                    desc = self.CHAT_DESCRIPTIONS.get(at, {})
                    name = desc.get("name", self.AGENT_TO_FLAG.get(at, at.value))
                    if name not in agent_names:
                        agent_names.append(name)

        if parts and agent_names:
            return f"{' + '.join(parts)}，包括{'、'.join(agent_names)}"
        elif agent_names:
            return f"执行{'、'.join(agent_names)}流程"
        else:
            return "执行标准安全扫描"

    def _get_macro_description(self, macro_name: str) -> str:
        descriptions = {
            "full-audit": "完整安全审计",
            "quick-scan": "快速安全扫描",
            "deep-scan": "深度安全扫描",
        }
        return descriptions.get(macro_name, macro_name)

    def chat_to_cli(self, chat_input: str) -> str:
        if not chat_input or not chat_input.strip():
            return "--scan+context+final"

        if self._use_ai:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    future = asyncio.ensure_future(self._get_ai_configurator())
                    configurator = asyncio.get_event_loop().run_until_complete(future)
                else:
                    configurator = loop.run_until_complete(self._get_ai_configurator())
                result = loop.run_until_complete(configurator.chat_to_cli(chat_input))
                return result
            except Exception:
                pass

        return self._fallback_chat_to_cli(chat_input)

    def _fallback_chat_to_cli(self, chat_input: str) -> str:
        """Fallback chat转cli（保留原有逻辑）"""
        chat_input_lower = chat_input.lower()
        flags: List[str] = []

        chat_keywords: Dict[str, str] = {
            "扫描": "scan",
            "上下文": "context",
            "理解": "understand",
            "风险": "risk",
            "验证": "verify",
            "攻击": "attack",
            "对抗": "adversarial",
            "最终": "final",
            "poc": "poc",
            "报告": "report",
            "完整审计": "full-audit",
            "快速扫描": "quick-scan",
            "深度扫描": "deep-scan",
        }

        for keyword, flag in chat_keywords.items():
            if keyword in chat_input_lower:
                if flag in self._macro_commands and flag not in flags:
                    flags.append(flag)
                elif flag in self.FLAG_TO_AGENT and flag not in flags:
                    flags.append(flag)

        if not flags:
            return "--scan+context+final"

        return "--" + "+".join(flags)

    def validate_pipeline(self, pipeline: PipelineConfig) -> bool:
        if not pipeline.nodes:
            return False

        for node in pipeline.nodes:
            if not node.enabled:
                continue

            for dep in node.dependencies:
                dep_exists = any(n.agent_type == dep and n.enabled for n in pipeline.nodes)
                if not dep_exists:
                    return False

        return True

    def get_pipeline_summary(self, pipeline: PipelineConfig) -> str:
        if not pipeline.nodes:
            return "空流水线"

        lines = ["=" * 50, "Agent 流水线概览", "=" * 50, ""]

        for i, node in enumerate(pipeline.nodes, 1):
            desc = self.CHAT_DESCRIPTIONS.get(node.agent_type, {})
            name = desc.get("name", node.agent_type.value)
            status = "启用" if node.enabled else "禁用"

            deps = ""
            if node.dependencies:
                dep_names = [self.AGENT_TO_FLAG.get(d, d.value) for d in node.dependencies]
                deps = f" (依赖: {', '.join(dep_names)})"

            lines.append(f"{i}. {name}{deps} - {status}")

        lines.append("")
        lines.append(f"并行执行: {'是' if pipeline.enable_parallel else '否'}")
        lines.append(f"最大重试次数: {pipeline.max_retries}")
        lines.append("=" * 50)

        return "\n".join(lines)

    def get_enabled_agents(self, pipeline: PipelineConfig) -> List[AgentType]:
        return [node.agent_type for node in pipeline.nodes if node.enabled]

    def get_disabled_agents(self) -> List[AgentType]:
        return [at for at, node in self._nodes.items() if not node.enabled]

    def enable_agent(self, agent_type: AgentType) -> None:
        if agent_type in self._nodes:
            self._nodes[agent_type].enabled = True

    def disable_agent(self, agent_type: AgentType) -> None:
        if agent_type in self._nodes:
            self._nodes[agent_type].enabled = False

    def set_agent_config(self, agent_type: AgentType, config: Dict[str, Any]) -> None:
        if agent_type in self._nodes:
            self._nodes[agent_type].config.update(config)

    def get_agent_config(self, agent_type: AgentType) -> Dict[str, Any]:
        if agent_type in self._nodes:
            return self._nodes[agent_type].config.copy()
        return {}

    def visualize_pipeline(self, pipeline: PipelineConfig) -> str:
        if not pipeline.nodes:
            return "空流水线"

        lines = ["digraph Pipeline {", "  rankdir=TB;", "  node [shape=box, style=rounded];"]

        for i, node in enumerate(pipeline.nodes):
            color = "lightgreen" if node.enabled else "lightgray"
            label = node.agent_type.value
            lines.append(f'  node{i} [label="{label}", fillcolor={color}];')

        for i, node in enumerate(pipeline.nodes):
            for dep in node.dependencies:
                dep_idx = None
                for j, n in enumerate(pipeline.nodes):
                    if n.agent_type == dep:
                        dep_idx = j
                        break
                if dep_idx is not None:
                    lines.append(f"  node{dep_idx} -> node{i};")

        lines.append("}")
        return "\n".join(lines)
