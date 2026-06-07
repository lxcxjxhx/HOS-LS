"""统一包管理器主类

聚合 PyPI/Go/系统工具管理，提供一键安装所有依赖的能力。
"""

import logging
import sys
from typing import Optional

from tqdm import tqdm

from .discovery import ToolRegistry, build_default_registry, discover_tools, print_tool_status
from .go_manager import DEFAULT_GO_VERSION, GO_TOOLS, GoManager
from .mirror import MirrorManager, get_proxy_env
from .pypi_manager import PyPIManager

logger = logging.getLogger(__name__)


class SystemManager:
    """系统依赖统一管理器

    聚合 PyPI 包管理、Go 工具管理、系统工具检测，
    提供一键安装所有依赖的能力。
    """

    def __init__(
        self,
        mirror_manager: Optional[MirrorManager] = None,
        pypi_index_url: Optional[str] = None,
        go_proxy: Optional[str] = None,
        go_version: str = DEFAULT_GO_VERSION,
        registry: Optional[ToolRegistry] = None,
        proxy_url: Optional[str] = None,
    ):
        self.mirror_manager = mirror_manager or MirrorManager()
        self.pypi = PyPIManager(
            mirror_manager=self.mirror_manager,
            pip_index_url=pypi_index_url,
        )
        self.go = GoManager(
            mirror_manager=self.mirror_manager,
            go_proxy=go_proxy,
            go_version=go_version,
        )
        self.registry = registry or build_default_registry()

        # 代理设置
        if proxy_url:
            self._proxy_url = proxy_url
        else:
            self._proxy_url = get_proxy_env()

    def setup_proxy(self) -> None:
        """设置代理"""
        if self._proxy_url:
            self.mirror_manager.apply_proxy(self._proxy_url)
            logger.info("[SYSMGR] 代理已配置: %s", self._proxy_url)
        else:
            logger.debug("[SYSMGR] 未检测到代理，使用直连")

    def auto_detect_mirrors(self, timeout: float = 5.0) -> None:
        """自动检测并切换最快镜像"""
        logger.info("[SYSMGR] 开始自动检测镜像...")
        self.mirror_manager.detect_all()

        pypi_mirror = self.mirror_manager.pypi_mirror
        if pypi_mirror:
            logger.info("[SYSMGR] PyPI 镜像: %s", pypi_mirror)

        go_proxy = self.mirror_manager.goproxy_mirror
        if go_proxy:
            logger.info("[SYSMGR] Go 代理: %s", go_proxy)

    def discover(self) -> ToolRegistry:
        """检测当前工具安装状态"""
        return discover_tools(self.registry)

    def install_go_runtime(self) -> bool:
        """安装 Go 运行时"""
        if self.go.is_go_installed():
            logger.info("[SYSMGR] Go 已安装 (%s)", self.go.get_go_version())
            return True
        return self.go.install_go()

    def install_go_tools(self, tools: Optional[list[str]] = None) -> dict[str, bool]:
        """安装 Go 安全工具

        Args:
            tools: 工具名列表，None 时安装全部

        Returns:
            {工具名: 是否成功}
        """
        return self.go.install_go_tools(tools)

    def install_pypi_packages(
        self,
        packages: list[str],
        upgrade: bool = False,
    ) -> bool:
        """安装 PyPI 包

        Args:
            packages: 包名列表
            upgrade: 是否升级

        Returns:
            是否成功
        """
        return self.pypi.install(packages, upgrade=upgrade)

    def ensure_pypi_packages(
        self,
        packages: list[str],
        upgrade: bool = False,
    ) -> list[str]:
        """确保 PyPI 包已安装（只安装缺失的）

        Args:
            packages: 包名列表
            upgrade: 是否升级

        Returns:
            已安装/更新的包名列表
        """
        return self.pypi.ensure_packages(packages, upgrade=upgrade)

    def install_system_tools(self) -> dict[str, bool]:
        """尝试安装系统工具

        检测操作系统并执行对应的安装命令。

        Returns:
            {工具名: 是否成功}
        """
        results = {}

        for tool in self.registry.missing:
            if tool.category != "system":
                continue

            logger.info("[SYSMGR] 尝试安装系统工具: %s", tool.name)
            success = self._install_system_package(tool.name)
            results[tool.name] = success

        return results

    def _install_system_package(self, name: str) -> bool:
        """安装系统包（跨平台）"""
        import subprocess

        if sys.platform == "linux":
            pkg_map = {
                "nmap": "nmap",
                "sqlmap": "sqlmap",
            }
            pkg = pkg_map.get(name, name)
            cmd = ["sudo", "apt", "install", "-y", pkg]
        elif sys.platform == "darwin":
            cmd = ["brew", "install", name]
        elif sys.platform == "win32":
            logger.warning("[SYSMGR] Windows 不支持自动安装系统工具: %s", name)
            return False
        else:
            logger.warning("[SYSMGR] 不支持的平台: %s", sys.platform)
            return False

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info("[SYSMGR] ✓ %s 安装成功", name)
                return True
            logger.error("[SYSMGR] ✗ %s 安装失败: %s", name, result.stderr)
            return False
        except subprocess.TimeoutExpired:
            logger.error("[SYSMGR] ✗ %s 安装超时", name)
            return False
        except FileNotFoundError:
            logger.error("[SYSMGR] ✗ 找不到包管理器，请手动安装: %s", name)
            return False

    def install_all(
        self,
        go_tools: Optional[list[str]] = None,
        pypi_packages: Optional[list[str]] = None,
        skip_go: bool = False,
        skip_pypi: bool = False,
        skip_system: bool = False,
    ) -> dict:
        """一键安装所有依赖

        Args:
            go_tools: 要安装的 Go 工具列表，None 时安装全部
            pypi_packages: 要安装的 PyPI 包列表，None 时使用默认
            skip_go: 是否跳过 Go 工具安装
            skip_pypi: 是否跳过 PyPI 包安装
            skip_system: 是否跳过系统工具安装

        Returns:
            安装结果摘要
        """
        logger.info("=" * 60)
        logger.info("[SYSMGR] 开始一键安装所有依赖")
        logger.info("=" * 60)

        results = {
            "proxy": False,
            "mirrors": False,
            "go_runtime": False,
            "go_tools": {},
            "pypi": False,
            "system": {},
            "errors": [],
        }

        # 1. 设置代理
        logger.info("[SYSMGR] [1/6] 配置代理...")
        self.setup_proxy()
        results["proxy"] = self._proxy_url is not None

        # 2. 自动检测镜像
        logger.info("[SYSMGR] [2/6] 检测最快镜像...")
        try:
            self.auto_detect_mirrors()
            results["mirrors"] = True
        except Exception as e:
            logger.warning("[SYSMGR] 镜像检测失败: %s", e)
            results["errors"].append(f"mirror_detection: {e}")

        # 3. 安装 Go 运行时
        if not skip_go:
            logger.info("[SYSMGR] [3/6] 安装 Go 运行时...")
            try:
                results["go_runtime"] = self.install_go_runtime()
            except Exception as e:
                logger.warning("[SYSMGR] Go 安装失败: %s", e)
                results["errors"].append(f"go_runtime: {e}")

            # 4. 安装 Go 工具
            if results["go_runtime"]:
                logger.info("[SYSMGR] [4/6] 安装 Go 安全工具...")
                try:
                    results["go_tools"] = self.install_go_tools(go_tools)
                except Exception as e:
                    logger.warning("[SYSMGR] Go 工具安装失败: %s", e)
                    results["errors"].append(f"go_tools: {e}")

        # 5. 安装 PyPI 包
        if not skip_pypi:
            logger.info("[SYSMGR] [5/6] 安装 PyPI 包...")
            default_packages = list(GO_TOOLS.keys())  # 占位，实际可根据需要配置
            packages = pypi_packages or default_packages
            try:
                results["pypi"] = bool(self.ensure_pypi_packages(packages))
            except Exception as e:
                logger.warning("[SYSMGR] PyPI 包安装失败: %s", e)
                results["errors"].append(f"pypi: {e}")

        # 6. 安装系统工具
        if not skip_system:
            logger.info("[SYSMGR] [6/6] 安装系统工具...")
            try:
                results["system"] = self.install_system_tools()
            except Exception as e:
                logger.warning("[SYSMGR] 系统工具安装失败: %s", e)
                results["errors"].append(f"system: {e}")

        # 汇总
        self._print_install_summary(results)
        return results

    def _print_install_summary(self, results: dict) -> None:
        """打印安装结果摘要"""
        logger.info("=" * 60)
        logger.info("[SYSMGR] 安装完成摘要")
        logger.info("=" * 60)

        logger.info("[SYSMGR] 代理: %s", "已配置" if results["proxy"] else "未配置")
        logger.info("[SYSMGR] 镜像: %s", "已检测" if results["mirrors"] else "失败")
        logger.info("[SYSMGR] Go: %s", "已安装" if results["go_runtime"] else "未安装/跳过")

        if results["go_tools"]:
            ok = sum(1 for v in results["go_tools"].values() if v)
            total = len(results["go_tools"])
            logger.info("[SYSMGR] Go 工具: %d/%d 成功", ok, total)

        if results["system"]:
            ok = sum(1 for v in results["system"].values() if v)
            total = len(results["system"])
            logger.info("[SYSMGR] 系统工具: %d/%d 成功", ok, total)

        if results["errors"]:
            logger.warning("[SYSMGR] 错误 (%d):", len(results["errors"]))
            for err in results["errors"]:
                logger.warning("  - %s", err)

        logger.info("=" * 60)

    def status(self) -> str:
        """获取完整状态报告"""
        registry = self.discover()
        return print_tool_status(registry)
