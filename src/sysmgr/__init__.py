"""sysmgr - 系统依赖管理模块

统一管理系统依赖，包括 PyPI 包、Go 工具、系统工具的安装/卸载/检测。
支持自动换源、代理配置和一键安装。

用法:
    from src.sysmgr import SystemManager

    mgr = SystemManager()
    mgr.auto_detect_mirrors()
    mgr.install_all()
"""

from .discovery import (
    ToolInfo,
    ToolRegistry,
    build_default_registry,
    check_tool_installed,
    discover_tools,
    print_tool_status,
)
from .go_manager import GoManager
from .manager import SystemManager
from .mirror import (
    MirrorManager,
    check_connectivity,
    detect_network_status,
    find_fastest_goproxy_mirror,
    find_fastest_mirror,
    find_fastest_pypi_mirror,
    get_proxy_env,
    set_proxy_env,
)
from .network_env import NetworkConfig, NetworkEnvManager, NetworkMode
from .pypi_manager import PyPIManager

__all__ = [
    "SystemManager",
    "PyPIManager",
    "GoManager",
    "MirrorManager",
    "ToolRegistry",
    "ToolInfo",
    "build_default_registry",
    "check_tool_installed",
    "discover_tools",
    "print_tool_status",
    "check_connectivity",
    "detect_network_status",
    "find_fastest_goproxy_mirror",
    "find_fastest_mirror",
    "find_fastest_pypi_mirror",
    "get_proxy_env",
    "set_proxy_env",
    "NetworkEnvManager",
    "NetworkMode",
    "NetworkConfig",
]
