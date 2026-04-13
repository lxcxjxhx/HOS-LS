"""错误处理工具函数

提供统一的错误处理逻辑，包括错误结果创建、错误信息格式化等。
"""

from typing import Dict, Optional
from src.core.base_agent import AgentResult, AgentStatus


def create_error_result(
    agent_name: str,
    error_message: str,
    error_type: str,
    metadata: Optional[Dict] = None
) -> AgentResult:
    """创建错误结果

    Args:
        agent_name: Agent名称
        error_message: 错误消息
        error_type: 错误类型
        metadata: 额外的元数据

    Returns:
        AgentResult: 错误结果对象
    """
    error_details = {
        'error_type': error_type,
        'error_message': error_message,
        'suggestion': _get_suggestion_for_error(error_type)
    }
    
    final_metadata = metadata or {}
    final_metadata['error_details'] = error_details
    
    return AgentResult(
        agent_name=agent_name,
        status=AgentStatus.FAILED,
        error=error_message,
        confidence=0.0,
        metadata=final_metadata
    )


def format_error_message(
    error_type: str,
    error_message: str,
    context: Optional[Dict] = None
) -> str:
    """格式化错误消息

    Args:
        error_type: 错误类型
        error_message: 原始错误消息
        context: 错误上下文

    Returns:
        str: 格式化后的错误消息
    """
    formatted_message = f"{error_type}: {error_message}"
    if context:
        context_str = ", ".join([f"{k}={v}" for k, v in context.items()])
        formatted_message = f"{formatted_message} (上下文: {context_str})"
    return formatted_message


def get_error_details(error: Exception) -> Dict[str, str]:
    """获取错误详情

    Args:
        error: 异常对象

    Returns:
        Dict[str, str]: 错误详情字典
    """
    return {
        'error_type': type(error).__name__,
        'error_message': str(error),
        'suggestion': _get_suggestion_for_error(type(error).__name__)
    }


def _get_suggestion_for_error(error_type: str) -> str:
    """根据错误类型获取建议

    Args:
        error_type: 错误类型

    Returns:
        str: 建议信息
    """
    suggestions = {
        'FileNotFoundError': '请检查文件路径是否正确',
        'PermissionError': '请检查文件权限',
        'ImportError': '请检查依赖是否安装',
        'ValueError': '请检查输入参数是否正确',
        'ConnectionError': '请检查网络连接',
        'TimeoutError': '操作超时，请尝试重试',
        'AIError': 'AI服务出错，请检查API密钥和网络连接',
        'DependencyError': '依赖检查失败，请确保依赖的Agent已成功执行'
    }
    return suggestions.get(error_type, '请检查相关配置和环境')