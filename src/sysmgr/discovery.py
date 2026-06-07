"""系统工具发现器

检测系统中已安装/缺失的安全工具，提供统一的工具注册表。
"""

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """工具信息"""

    name: str
    description: str
    category: str  # "system" | "go" | "pypi"
    install_cmd: Optional[str] = None
    version_cmd: str = "--version"
    required: bool = True
    installed: bool = False
    version: Optional[str] = None
    install_notes: str = ""


@dataclass
class ToolRegistry:
    """工具注册表 - 定义所有需要的安全工具"""

    tools: dict[str, ToolInfo] = field(default_factory=dict)

    def register(self, tool: ToolInfo) -> None:
        """注册工具"""
        self.tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolInfo]:
        """获取工具信息"""
        return self.tools.get(name)

    def get_all(self) -> list[ToolInfo]:
        """获取所有工具"""
        return list(self.tools.values())

    @property
    def installed(self) -> list[ToolInfo]:
        """获取已安装工具列表"""
        return [t for t in self.tools.values() if t.installed]

    @property
    def missing(self) -> list[ToolInfo]:
        """获取缺失工具列表"""
        return [t for t in self.tools.values() if not t.installed]

    @property
    def required_missing(self) -> list[ToolInfo]:
        """获取缺失的必需工具列表"""
        return [t for t in self.missing if t.required]


def build_default_registry() -> ToolRegistry:
    """构建默认工具注册表

    包含所有安全扫描需要的工具定义。
    """
    registry = ToolRegistry()

    # 系统工具 (apt/yum/pacman 安装) - 设为可选，因Windows安装需管理员权限
    registry.register(
        ToolInfo(
            name="nmap",
            description="网络扫描和主机发现工具",
            category="system",
            install_cmd="sudo apt install -y nmap  # 或使用 yum/pacman",
            version_cmd="--version",
            required=False,  # Windows 可选，有内置端口扫描回退
        )
    )
    registry.register(
        ToolInfo(
            name="sqlmap",
            description="SQL 注入检测和利用工具",
            category="system",
            install_cmd="pip install sqlmap",
            version_cmd="--version",
            required=False,  # 可选
        )
    )

    # Go 工具 (通过 go install 安装)
    registry.register(
        ToolInfo(
            name="nuclei",
            description="快速可定制漏洞扫描器",
            category="go",
            install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            version_cmd="-version",
        )
    )
    registry.register(
        ToolInfo(
            name="httpx",
            description="快速 HTTP 探测工具",
            category="go",
            install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            version_cmd="-version",
        )
    )
    registry.register(
        ToolInfo(
            name="ffuf",
            description="快速 web 模糊测试工具",
            category="go",
            install_cmd="go install -v github.com/ffuf/ffuf/v2@latest",
            version_cmd="-version",
        )
    )
    registry.register(
        ToolInfo(
            name="subfinder",
            description="子域名发现工具",
            category="go",
            install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            version_cmd="-version",
        )
    )

    return registry


def check_tool_installed(name: str, version_arg: str = "--version") -> tuple[bool, Optional[str]]:
    """检查工具是否已安装

    Args:
        name: 工具名称/可执行文件名
        version_arg: 获取版本号的参数

    Returns:
        (是否已安装, 版本号)
    """
    # 扩展 PATH 包含 Go 工具路径
    import os as _os
    import platform as _platform

    extra_paths = []
    if _platform.system() == "Windows":
        go_bin = _os.path.join(_os.environ.get("USERPROFILE", ""), "go", "bin")
        extra_paths = [go_bin, r"C:\Go\bin"]
    else:
        extra_paths = ["/usr/local/go/bin", _os.path.expanduser("~/go/bin")]

    # 检查 PATH 中是否有该工具
    path = shutil.which(name)
    if not path:
        # 尝试在额外路径中查找
        for extra_dir in extra_paths:
            extra_path = shutil.which(name, path=extra_dir)
            if extra_path:
                path = extra_path
                # 临时添加到 PATH
                old_path = _os.environ.get("PATH", "")
                _os.environ["PATH"] = f"{extra_dir}{_os.pathsep}{old_path}"
                break

    if not path:
        return False, None

    try:
        result = subprocess.run(
            [name, version_arg],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = (result.stdout or result.stderr).strip().split("\n")[0] if result.returncode == 0 else "unknown"
        return True, version
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return True, "unknown"


def discover_tools(registry: Optional[ToolRegistry] = None) -> ToolRegistry:
    """发现并检测所有已注册的工具

    Args:
        registry: 工具注册表，为 None 时使用默认注册表

    Returns:
        更新后的工具注册表
    """
    if registry is None:
        registry = build_default_registry()

    logger.info("[DISCOVERY] 开始检测系统工具...")

    for tool in registry.get_all():
        installed, version = check_tool_installed(tool.name, tool.version_cmd)
        tool.installed = installed
        tool.version = version

        if installed:
            logger.info("[DISCOVERY] ✓ %s 已安装 (版本: %s)", tool.name, version)
        else:
            status = "必需" if tool.required else "可选"
            logger.warning("[DISCOVERY] ✗ %s 未安装 (%s)", tool.name, status)

    missing_count = len(registry.missing)
    installed_count = len(registry.installed)

    logger.info(
        "[DISCOVERY] 检测完成: %d 已安装, %d 缺失",
        installed_count,
        missing_count,
    )

    return registry


def print_tool_status(registry: Optional[ToolRegistry] = None) -> str:
    """生成工具状态报告

    Args:
        registry: 工具注册表，为 None 时使用默认注册表

    Returns:
        格式化的状态报告字符串
    """
    if registry is None:
        registry = discover_tools()

    lines = ["", "=" * 60, "工具安装状态报告", "=" * 60, ""]

    for tool in registry.get_all():
        status = "✓ 已安装" if tool.installed else "✗ 未安装"
        version = f" ({tool.version})" if tool.version and tool.installed else ""
        lines.append(f"  [{status:10s}] {tool.name:15s} {version}")
        if not tool.installed and tool.install_cmd:
            lines.append(f"                 安装: {tool.install_cmd}")
        lines.append("")

    lines.append("-" * 60)
    lines.append(
        f"  总计: {len(registry.installed)}/{len(registry.get_all())} 已安装"
    )
    if registry.required_missing:
        lines.append(
            f"  警告: {len(registry.required_missing)} 个必需工具缺失"
        )
    lines.append("=" * 60)

    return "\n".join(lines)
