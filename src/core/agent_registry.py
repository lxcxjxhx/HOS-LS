"""Agent 能力注册表

提供 Agent 的动态注册、发现和生命周期管理功能。
这是统一 Agent 能力系统的核心组件，支持：
- 动态注册/注销 Agent
- 依赖关系管理
- 自动补全 Pipeline
- 宏命令展开
- CLI flag 自动生成
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type, Set, Callable
import inspect

from .base_agent import BaseAgent, AgentCapabilities


@dataclass
class AgentCapability:
    """Agent 能力描述信息"""
    name: str                           # 唯一标识符，如 "scan", "reason"
    agent_class: Type[BaseAgent]        # Agent 类
    category: str = "behavior"          # 分类：behavior | mode | control | macro
    description: str = ""               # 描述文本
    dependencies: List[str] = field(default_factory=list)  # 依赖的 Agent 名称列表
    flags: List[str] = field(default_factory=list)         # CLI flags，如 ["--scan"]
    aliases: List[str] = field(default_factory=list)       # 别名，如 ["s"]
    priority: int = 0                   # 优先级（数字越小越优先）
    metadata: Dict[str, Any] = field(default_factory=dict)  # 扩展元数据

    @property
    def primary_flag(self) -> Optional[str]:
        """获取主要 flag"""
        return self.flags[0] if self.flags else None

    def matches_flag(self, flag: str) -> bool:
        """检查是否匹配指定的 flag 或别名"""
        flag_clean = flag.lstrip('-')
        return (flag_clean in self.flags or
                flag in self.flags or
                flag_clean in self.aliases or
                flag in self.aliases or
                flag_clean == self.name)


class AgentCapabilityRegistry:
    """Agent 能力注册表（单例）

    管理所有可用的 Agent 能力，提供：
    - 注册/注销 API
    - 查询和过滤
    - 依赖关系解析
    - Pipeline 构建
    - CLI 集成支持
    """

    _instance: Optional['AgentCapabilityRegistry'] = None
    _agents: Dict[str, AgentCapability] = {}
    _flag_map: Dict[str, str] = {}  # flag → agent_name 映射
    _initialized: bool = False

    def __new__(cls) -> 'AgentCapabilityRegistry':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._agents = {}
            self._flag_map = {}
            self._initialized = True

    def register(
        self,
        name: str,
        agent_class: Type[BaseAgent],
        category: str = "behavior",
        description: str = "",
        dependencies: List[str] = None,
        flags: List[str] = None,
        aliases: List[str] = None,
        priority: int = 0,
        **metadata
    ) -> Type[BaseAgent]:
        """注册 Agent 能力

        Args:
            name: Agent 唯一名称（如 "scan", "reason"）
            agent_class: Agent 类（必须继承 BaseAgent）
            category: 分类（behavior/mode/control/macro）
            description: 描述文本
            dependencies: 依赖的 Agent 列表
            flags: CLI flags 列表
            aliases: 别名列表
            priority: 优先级
            **metadata: 其他元数据

        Returns:
            注册的 agent_class（用于装饰器模式）

        Raises:
            ValueError: 如果 name 已存在或 agent_class 不合法
        """
        if name in self._agents:
            raise ValueError(f"Agent '{name}' 已注册")

        # 🔥 允许宏命令的 agent_class 为 None（宏命令没有对应的 Agent 类）
        if agent_class is not None:
            if not (inspect.isclass(agent_class) and issubclass(agent_class, BaseAgent)):
                raise ValueError(f"{agent_class} 必须是 BaseAgent 的子类")

        capability = AgentCapability(
            name=name,
            agent_class=agent_class,
            category=category,
            description=description,
            dependencies=dependencies or [],
            flags=flags or [],
            aliases=aliases or [],
            priority=priority,
            metadata=metadata
        )

        self._agents[name] = capability

        # 建立 flag 映射
        for flag in capability.flags:
            self._flag_map[flag.lstrip('-')] = name
        for alias in capability.aliases:
            self._flag_map[alias] = name

        return agent_class

    def unregister(self, name: str) -> None:
        """注销 Agent

        Args:
            name: Agent 名称
        """
        if name in self._agents:
            capability = self._agents[name]
            # 清理 flag 映射
            for flag in capability.flags:
                self._flag_map.pop(flag.lstrip('-', None), None)
            for alias in capability.aliases:
                self._flag_map.pop(alias, None)
            del self._agents[name]

    def get(self, name: str) -> Optional[AgentCapability]:
        """根据名称获取 Agent 能力

        Args:
            name: Agent 名称

        Returns:
            AgentCapability 或 None
        """
        return self._agents.get(name)

    def get_by_flag(self, flag: str) -> Optional[AgentCapability]:
        """根据 flag 获取 Agent 能力

        支持多种格式：
        - "--scan"
        - "-s"
        - "scan"

        Args:
            flag: CLI flag

        Returns:
            AgentCapability 或 None
        """
        flag_clean = flag.lstrip('-')
        agent_name = self._flag_map.get(flag_clean)
        if agent_name:
            return self._agents.get(agent_name)

        # 直接按名称查找
        return self._agents.get(flag_clean)

    def get_agent_instance(self, name: str, config=None) -> Optional[BaseAgent]:
        """创建 Agent 实例

        Args:
            name: Agent 名称
            config: 配置对象（可选）

        Returns:
            Agent 实例或 None
        """
        capability = self.get(name)
        if capability:
            try:
                return capability.agent_class(config=config)
            except Exception as e:
                print(f"[ERROR] 创建 Agent '{name}' 实例失败: {e}")
                return None
        return None

    def has(self, name: str) -> bool:
        """检查 Agent 是否已注册

        Args:
            name: Agent 名称

        Returns:
            bool
        """
        return name in self._agents

    def list_agents(
        self,
        category: Optional[str] = None,
        sort_by_priority: bool = True
    ) -> List[AgentCapability]:
        """列出所有已注册的 Agent

        Args:
            category: 过滤分类（可选）
            sort_by_priority: 是否按优先级排序

        Returns:
            AgentCapability 列表
        """
        agents = list(self._agents.values())

        if category:
            agents = [a for a in agents if a.category == category]

        if sort_by_priority:
            agents.sort(key=lambda x: x.priority)

        return agents

    def get_available_flags(self) -> Dict[str, str]:
        """获取所有可用的 CLI flags

        Returns:
            {flag: agent_name} 字典
        """
        result = {}
        for capability in self._agents.values():
            for flag in capability.flags:
                result[flag] = capability.name
        return result

    def resolve_dependencies(self, agent_names: List[str]) -> List[str]:
        """解析依赖关系，返回完整的执行顺序

        如果请求 ["poc"]，且 poc 依赖 scan 和 reason，
        则返回 ["scan", "reason", "poc"]

        Args:
            agent_names: 请求的 Agent 名称列表

        Returns:
            解析后的完整 Agent 列表（保持顺序）
        """
        resolved = []
        visited = set()

        def _resolve(name: str):
            if name in visited:
                return
            visited.add(name)

            capability = self.get(name)
            if capability:
                # 先解析依赖
                for dep in capability.dependencies:
                    _resolve(dep)
                # 再添加自身
                if name not in resolved:
                    resolved.append(name)

        for name in agent_names:
            _resolve(name)

        return resolved

    def build_pipeline_from_flags(
        self,
        flags: List[str],
        auto_complete: bool = True,
        expand_macros: bool = True
    ) -> List[str]:
        """从 CLI flags 构建 Pipeline

        步骤：
        1. 展开宏命令
        2. 解析 flags 为 Agent 名称
        3. 解析依赖关系
        4. 自动补全缺失步骤（可选）

        Args:
            flags: CLI flags 列表（如 ["--scan", "--reason"]）
            auto_complete: 是否自动补全依赖
            expand_macros: 是否展开宏命令

        Returns:
            排序后的 Agent 名称列表（Pipeline）
        """
        pipeline = []

        # 1. 展开 macro 类型
        if expand_macros:
            expanded = []
            for flag in flags:
                capability = self.get_by_flag(flag)
                if capability and capability.category == "macro":
                    # 宏命令：从 metadata 中获取展开规则
                    expands_to = capability.metadata.get('expands_to', [])
                    expanded.extend(expands_to)
                else:
                    expanded.append(flag)
            flags = expanded

        # 2. 解析 flags 为 agent names
        for flag in flags:
            capability = self.get_by_flag(flag)
            if capability and capability.category == "behavior":
                pipeline.append(capability.name)

        # 3. 解析依赖关系
        if auto_complete:
            pipeline = self.resolve_dependencies(pipeline)

        # 4. 去重并保持顺序
        seen = set()
        unique_pipeline = []
        for name in pipeline:
            if name not in seen:
                seen.add(name)
                unique_pipeline.append(name)

        return unique_pipeline

    def suggest_completion(self, partial_pipeline: List[str]) -> List[str]:
        """建议补全 Pipeline

        根据当前 Pipeline 的最后一个 Agent，建议可能的后继步骤。

        Args:
            partial_pipeline: 当前的部分 Pipeline

        Returns:
            建议的后续 Agent 列表
        """
        if not partial_pipeline:
            # 空 Pipeline，建议基础步骤
            suggestions = [a.name for a in self.list_agents(category="behavior")
                          if not a.dependencies][:3]
            return suggestions

        last_agent = partial_pipeline[-1]
        suggestions = []

        for capability in self.list_agents(category="behavior"):
            if (capability.name != last_agent and
                capability.name not in partial_pipeline):
                # 检查是否可以作为后继
                if (not capability.dependencies or
                    all(dep in partial_pipeline for dep in capability.dependencies)):
                    suggestions.append(capability.name)

        return suggestions[:5]  # 最多返回5个建议

    def validate_pipeline(self, pipeline: List[str]) -> tuple:
        """验证 Pipeline 的有效性

        Args:
            pipeline: Agent 名称列表

        Returns:
            (is_valid: bool, errors: List[str])
        """
        errors = []

        # 检查所有 Agent 都已注册
        for name in pipeline:
            if not self.has(name):
                errors.append(f"未知的 Agent: {name}")

        # 检查依赖关系是否满足
        satisfied = set()
        for name in pipeline:
            capability = self.get(name)
            if capability:
                for dep in capability.dependencies:
                    if dep not in satisfied:
                        errors.append(
                            f"依赖未满足: {name} 需要 {dep} 在其之前执行"
                        )
            satisfied.add(name)

        return (len(errors) == 0, errors)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计字典
        """
        categories = {}
        for capability in self._agents.values():
            cat = capability.category
            categories[cat] = categories.get(cat, 0) + 1

        return {
            'total_agents': len(self._agents),
            'by_category': categories,
            'total_flags': len(self._flag_map),
            'agent_names': sorted(self._agents.keys())
        }

    def clear(self) -> None:
        """清空所有注册"""
        self._agents.clear()
        self._flag_map.clear()

    def decorator(
        self,
        name: Optional[str] = None,
        category: str = "behavior",
        description: str = "",
        dependencies: List[str] = None,
        flags: List[str] = None,
        aliases: List[str] = None,
        priority: int = 0,
        **metadata
    ) -> Callable[[Type[BaseAgent]], Type[BaseAgent]]:
        """装饰器模式注册 Agent

        用法:
            @registry.decorator(
                name="scan",
                flags=["--scan"],
                dependencies=[]
            )
            class ScannerAgent(BaseAgent):
                pass

        Args:
            name: Agent 名称（默认使用类名）
            其他参数同 register()

        Returns:
            装饰器函数
        """

        def decorator(cls: Type[BaseAgent]) -> Type[BaseAgent]:
            agent_name = name or cls.__name__.lower().replace('agent', '')
            self.register(
                name=agent_name,
                agent_class=cls,
                category=category,
                description=description,
                dependencies=dependencies,
                flags=flags,
                aliases=aliases,
                priority=priority,
                **metadata
            )
            return cls

        return decorator

    def __repr__(self) -> str:
        stats = self.get_statistics()
        return (
            f"AgentCapabilityRegistry("
            f"agents={stats['total_agents']}, "
            f"categories={stats['by_category']})"
        )


# 全局单例
_registry_instance: Optional[AgentCapabilityRegistry] = None


def get_agent_registry() -> AgentCapabilityRegistry:
    """获取全局 Agent Registry 单例

    Returns:
        AgentCapabilityRegistry 全局实例
    """
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = AgentCapabilityRegistry()
    return _registry_instance


def register_agent(
    name: Optional[str] = None,
    category: str = "behavior",
    description: str = "",
    dependencies: List[str] = None,
    flags: List[str] = None,
    aliases: List[str] = None,
    priority: int = 0,
    **metadata
) -> Callable[[Type[BaseAgent]], Type[BaseAgent]]:
    """便捷装饰器：注册 Agent 到全局 Registry

    用法:
        @register_agent(
            name="scan",
            flags=["--scan", "-s"],
            description="代码扫描"
        )
        class ScannerAgent(BaseAgent):
            async def execute(self, context):
                # ...
                pass

    Returns:
        装饰器函数
    """
    return get_agent_registry().decorator(
        name=name,
        category=category,
        description=description,
        dependencies=dependencies,
        flags=flags,
        aliases=aliases,
        priority=priority,
        **metadata
    )
