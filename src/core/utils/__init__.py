"""工具函数模块

提供共享的工具函数，减少代码重复，提高代码复用性。
"""

from .error_handling import (
    create_error_result,
    format_error_message,
    get_error_details
)
from .time_utils import (
    calculate_execution_time,
    format_execution_time
)
from .result_utils import (
    aggregate_findings,
    generate_summary,
    validate_result
)
from .agent_utils import (
    check_agent_dependencies,
    get_agent_instance
)

__all__ = [
    'create_error_result',
    'format_error_message',
    'get_error_details',
    'calculate_execution_time',
    'format_execution_time',
    'aggregate_findings',
    'generate_summary',
    'validate_result',
    'check_agent_dependencies',
    'get_agent_instance'
]