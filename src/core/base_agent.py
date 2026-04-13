"""Agent 基础抽象类和数据模型

定义所有 Agent 必须遵循的接口规范，以及执行上下文和结果的数据结构。
这是统一 Agent 能力系统的核心基础设施。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from datetime import datetime
from enum import Enum


class AgentStatus(Enum):
    """Agent 执行状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AgentCapabilities:
    """Agent 能力描述"""
    name: str
    description: str = ""
    input_types: List[str] = field(default_factory=list)
    output_types: List[str] = field(default_factory=list)
    supported_modes: List[str] = field(default_factory=lambda: ["standard", "pure-ai"])
    estimated_time: float = 0.0  # 预估执行时间（秒）
    required_resources: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionContext:
    """Agent 执行上下文

    在 Pipeline 中传递的共享状态，包含：
    - 用户请求信息
    - 前序 Agent 的执行结果
    - 配置信息
    - 项目上下文
    """
    target: str = "."
    code: str = ""
    config: Optional[Any] = None
    user_intent: str = ""
    user_query: Optional[str] = None
    focus: Optional[str] = None

    results: Dict[str, 'AgentResult'] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_previous_result(self, agent_name: str) -> Optional['AgentResult']:
        """获取指定 Agent 的执行结果"""
        return self.results.get(agent_name)

    def add_result(self, agent_name: str, result: 'AgentResult') -> None:
        """添加 Agent 执行结果"""
        self.results[agent_name] = result

    def get_all_results(self) -> Dict[str, 'AgentResult']:
        """获取所有已完成的 Agent 结果"""
        return self.results.copy()

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'target': self.target,
            'code': self.code[:1000] if self.code else "",  # 截断长代码
            'user_intent': self.user_intent,
            'user_query': self.user_query,
            'focus': self.focus,
            'completed_agents': list(self.results.keys()),
            'metadata': self.metadata
        }


@dataclass
class AgentResult:
    """Agent 执行结果

    统一的返回格式，包含：
    - 执行状态
    - 数据内容
    - 质量评估
    - 元信息
    """
    agent_name: str = ""
    status: AgentStatus = AgentStatus.PENDING
    data: Any = None
    message: str = ""
    confidence: float = 0.0
    error: Optional[str] = None
    execution_time: float = 0.0
    findings: List[Any] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        """是否成功完成"""
        return self.status == AgentStatus.COMPLETED

    @property
    def has_findings(self) -> bool:
        """是否发现了问题"""
        return len(self.findings) > 0

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            'agent_name': self.agent_name,
            'status': self.status.value,
            'message': self.message,
            'confidence': self.confidence,
            'error': self.error,
            'execution_time': self.execution_time,
            'findings_count': len(self.findings),
            'metadata': self.metadata
        }


@dataclass
class ExecutionRequest:
    """统一执行请求

    支持多种输入方式：
    - CLI flags: ["--scan", "--reason", "--poc"]
    - 自然语言: "扫描认证模块并生成POC"
    - Plan DSL 对象
    """
    target: str = "."
    flags: Optional[List[str]] = None
    natural_language: Optional[str] = None
    plan: Optional[Any] = None
    mode: str = "auto"  # auto | pure-ai | standard | langgraph
    context: Dict[str, Any] = field(default_factory=dict)
    test_mode: bool = False
    test_file_count: int = 1

    @property
    def request_type(self) -> str:
        """判断请求类型"""
        if self.flags:
            return "flags"
        elif self.natural_language:
            return "natural_language"
        elif self.plan:
            return "plan"
        else:
            return "unknown"


@dataclass
class ExecutionResult:
    """统一执行结果"""
    success: bool = False
    mode: str = ""
    results: Dict[str, AgentResult] = field(default_factory=dict)
    pipeline_used: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    total_findings: int = 0
    message: str = ""
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_result(self, agent_name: str) -> Optional[AgentResult]:
        """获取指定 Agent 的结果"""
        return self.results.get(agent_name)

    def get_all_findings(self) -> List[Any]:
        """获取所有发现的问题"""
        all_findings = []
        for result in self.results.values():
            if result.findings:
                all_findings.extend(result.findings)
        return all_findings

    def summary(self) -> str:
        """生成结果摘要"""
        lines = [
            f"✅ 执行完成 (模式: {self.mode})",
            f"   Pipeline: {' → '.join(self.pipeline_used)}",
            f"   耗时: {self.execution_time:.2f}秒",
            f"   发现问题: {self.total_findings}个"
        ]
        return '\n'.join(lines)


class BaseAgent(ABC):
    """Agent 基类

    所有 Agent 必须继承此类并实现核心方法。
    提供统一的接口规范，确保 Agent 可以在统一的执行引擎中运行。

    设计原则：
    1. 单一职责：每个 Agent 只做一件事
    2. 标准化：统一的输入输出格式
    3. 可组合：支持 Pipeline 串联
    4. 可观测：完整的生命周期钩子
    """

    def __init__(self, config=None):
        """初始化 Agent

        Args:
            config: 配置对象（可选）
        """
        self.config = config
        self._status = AgentStatus.PENDING
        self._start_time: Optional[datetime] = None
        self._capabilities: Optional[AgentCapabilities] = None

    @property
    def status(self) -> AgentStatus:
        """当前执行状态"""
        return self._status

    @property
    def capabilities(self) -> AgentCapabilities:
        """Agent 能力描述（子类可重写）"""
        if self._capabilities is None:
            self._capabilities = self._define_capabilities()
        return self._capabilities

    @abstractmethod
    async def execute(self, context: ExecutionContext) -> AgentResult:
        """执行 Agent 的核心逻辑（必须实现）

        Args:
            context: 执行上下文，包含前序 Agent 的结果和配置

        Returns:
            AgentResult: 执行结果
        """
        pass

    def validate_input(self, context: ExecutionContext) -> bool:
        """验证输入是否满足要求（可重写）

        默认实现检查依赖的 Agent 是否已完成。

        Args:
            context: 执行上下文

        Returns:
            bool: 输入是否有效
        """
        return True

    async def pre_process(self, context: ExecutionContext) -> ExecutionContext:
        """预处理钩子（可重写）

        在 execute() 之前调用，可用于：
        - 数据转换
        - 参数校验
        - 缓存检查

        Args:
            context: 原始上下文

        Returns:
            ExecutionContext: 处理后的上下文
        """
        return context

    async def post_process(self, result: AgentResult, context: ExecutionContext) -> AgentResult:
        """后处理钩子（可重写）

        在 execute() 之后调用，可用于：
        - 结果格式化
        - 日志记录
        - 指标收集

        Args:
            result: 原始结果
            context: 执行上下文

        Returns:
            AgentResult: 处理后的结果
        """
        return result

    async def execute_with_hooks(self, context: ExecutionContext) -> AgentResult:
        """带钩子的完整执行流程

        自动处理预处理、执行、后处理的完整生命周期。

        Args:
            context: 执行上下文

        Returns:
            AgentResult: 最终执行结果
        """
        from src.core.utils.time_utils import Timer
        from src.core.utils.error_handling import create_error_result

        self._status = AgentStatus.RUNNING
        timer = Timer()
        timer.start()

        try:
            # 1. 验证输入
            if not self.validate_input(context):
                return create_error_result(
                    agent_name=self.__class__.__name__,
                    error_message="输入验证失败",
                    error_type="ValidationError",
                    metadata={
                        'agent_name': self.__class__.__name__,
                        'context': context.to_dict() if hasattr(context, 'to_dict') else {}
                    }
                )

            # 2. 预处理
            processed_context = await self.pre_process(context)

            # 3. 核心 execute
            result = await self.execute(processed_context)
            result.agent_name = self.__class__.__name__

            # 4. 后处理
            final_result = await self.post_process(result, processed_context)
            final_result.status = AgentStatus.COMPLETED
            self._status = AgentStatus.COMPLETED

            # 记录执行时间
            final_result.execution_time = timer.stop()

            return final_result

        except Exception as e:
            self._status = AgentStatus.FAILED
            execution_time = timer.stop()
            error_result = create_error_result(
                agent_name=self.__class__.__name__,
                error_message=str(e),
                error_type=type(e).__name__,
                metadata={
                    'agent_name': self.__class__.__name__,
                    'execution_time': execution_time
                }
            )
            error_result.execution_time = execution_time
            return error_result

    def _define_capabilities(self) -> AgentCapabilities:
        """定义 Agent 能力（子类应重写此方法）"""
        return AgentCapabilities(
            name=self.__class__.__name__,
            description=f"{self.__class__.__name__} Agent"
        )


class PureAIAgentMixin:
    """纯 AI 模式 Mixin

    为 Agent 提供 pure-ai 模式的特殊实现。
    Agent 可选择性地继承此 Mixin 以支持增强的 AI 模式。
    """

    async def execute_ai_mode(self, context: ExecutionContext) -> AgentResult:
        """纯 AI 模式执行（可重写）

        默认实现调用标准 execute()，子类可以重写以提供更强大的 AI 能力。

        Args:
            context: 执行上下文

        Returns:
            AgentResult: AI 模式执行结果
        """
        if isinstance(self, BaseAgent):
            return await self.execute(context)
        raise NotImplementedError("PureAIAgentMixin must be used with BaseAgent")
