"""Agent工具函数

提供Agent相关的工具函数，包括依赖检查、Agent实例获取等。
"""

from typing import Optional, Dict, Any
from src.core.base_agent import BaseAgent, ExecutionContext, AgentResult
from src.core.agent_registry import AgentCapabilityRegistry, get_agent_registry


def check_agent_dependencies(
    agent: BaseAgent,
    context: ExecutionContext
) -> bool:
    """检查Agent的依赖关系

    Args:
        agent: Agent实例
        context: 执行上下文

    Returns:
        bool: 依赖检查是否通过
    """
    if hasattr(agent, 'validate_input'):
        return agent.validate_input(context)
    return True


def get_agent_instance(
    agent_name: str,
    config: Optional[Any] = None,
    registry: Optional[AgentCapabilityRegistry] = None
) -> Optional[BaseAgent]:
    """获取Agent实例

    Args:
        agent_name: Agent名称
        config: 配置对象
        registry: Agent注册表

    Returns:
        Optional[BaseAgent]: Agent实例，如果获取失败则返回None
    """
    if registry is None:
        registry = get_agent_registry()
    return registry.get_agent_instance(agent_name, config)


def validate_agent_pipeline(
    pipeline: list,
    registry: Optional[AgentCapabilityRegistry] = None
) -> tuple[bool, list]:
    """验证Agent Pipeline是否有效

    Args:
        pipeline: Agent名称列表
        registry: Agent注册表

    Returns:
        tuple[bool, list]: (是否有效, 错误信息列表)
    """
    if registry is None:
        registry = get_agent_registry()
    
    errors = []
    for agent_name in pipeline:
        if not registry.get(agent_name):
            errors.append(f"Agent '{agent_name}' 未注册")
    
    return len(errors) == 0, errors


def get_agent_dependencies(
    agent_name: str,
    registry: Optional[AgentCapabilityRegistry] = None
) -> list:
    """获取Agent的依赖关系

    Args:
        agent_name: Agent名称
        registry: Agent注册表

    Returns:
        list: 依赖的Agent名称列表
    """
    if registry is None:
        registry = get_agent_registry()
    
    agent_info = registry.get(agent_name)
    if not agent_info:
        return []
    
    # 从Agent信息中获取依赖
    # 这里需要根据实际的Agent信息结构来实现
    # 暂时返回空列表
    return []