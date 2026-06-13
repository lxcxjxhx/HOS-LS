"""PyPI 包管理器

负责 Python 包的安装/卸载/检测/换源，带 tqdm 进度条。
"""

import importlib.metadata
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

from tqdm import tqdm

from .mirror import MirrorManager, find_fastest_pypi_mirror

logger = logging.getLogger(__name__)

PIP_PROGRESS_RE = re.compile(r"(\d+)%\s*\|")


class PyPIManager:
    """PyPI 包管理器"""

    def __init__(
        self,
        mirror_manager: Optional[MirrorManager] = None,
        pip_index_url: Optional[str] = None,
    ):
        self.mirror_manager = mirror_manager or MirrorManager()
        self._pip_index_url = pip_index_url

    @property
    def pip_index_url(self) -> Optional[str]:
        """获取 pip index-url"""
        if self._pip_index_url:
            return self._pip_index_url
        return self.mirror_manager.get_pip_index_url()

    def _build_pip_cmd(
        self,
        action: str,
        packages: list[str],
        extra_args: Optional[list[str]] = None,
    ) -> list[str]:
        """构建 pip 命令

        Args:
            action: install / uninstall
            packages: 包名列表
            extra_args: 额外参数

        Returns:
            pip 命令参数列表
        """
        cmd = [
            sys.executable,
            "-m",
            "pip",
            action,
        ]

        if self.pip_index_url:
            cmd.extend(["--index-url", self.pip_index_url])

        cmd.append("--no-cache-dir")
        cmd.append("--quiet")

        if extra_args:
            cmd.extend(extra_args)

        cmd.extend(packages)
        return cmd

    def _run_pip(self, cmd: list[str], description: str = "pip") -> bool:
        """执行 pip 命令（带进度条）

        Args:
            cmd: 命令参数列表
            description: 进度条描述

        Returns:
            是否成功
        """
        logger.info("[PYPI] 执行: %s", " ".join(cmd))
        logger.debug("[PYPI] 环境变量: PIP_INDEX_URL=%s", self.pip_index_url)

        env = os.environ.copy()
        if self.pip_index_url:
            env["PIP_INDEX_URL"] = self.pip_index_url

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                encoding="utf-8",
                errors="replace",
            )

            with tqdm(desc=description, unit="step", leave=True) as pbar:
                pbar.update(0)
                for line in process.stdout:
                    line = line.strip()
                    if line:
                        logger.debug("[PYPI] %s", line)
                    pbar.update(1)

            process.wait()
            return process.returncode == 0

        except FileNotFoundError:
            logger.error("[PYPI] 找不到 pip 可执行文件")
            return False
        except Exception as e:
            logger.error("[PYPI] 执行失败: %s", e)
            return False

    def install(
        self,
        packages: list[str],
        upgrade: bool = False,
        user: bool = False,
    ) -> bool:
        """安装 Python 包

        Args:
            packages: 包名列表（可包含版本约束，如 requests==2.31.0）
            upgrade: 是否升级已有包
            user: 是否安装到用户目录

        Returns:
            是否成功
        """
        extra_args = []
        if upgrade:
            extra_args.append("--upgrade")
        if user:
            extra_args.append("--user")

        desc = f"安装 {len(packages)} 个包"
        cmd = self._build_pip_cmd("install", packages, extra_args)
        return self._run_pip(cmd, description=desc)

    def uninstall(self, packages: list[str], yes: bool = True) -> bool:
        """卸载 Python 包

        Args:
            packages: 包名列表
            yes: 是否自动确认

        Returns:
            是否成功
        """
        extra_args = ["--yes"] if yes else []
        desc = f"卸载 {len(packages)} 个包"
        cmd = self._build_pip_cmd("uninstall", packages, extra_args)
        return self._run_pip(cmd, description=desc)

    def is_installed(self, package: str) -> bool:
        """检测包是否已安装

        Args:
            package: 包名

        Returns:
            是否已安装
        """
        try:
            importlib.metadata.version(package)
            return True
        except importlib.metadata.PackageNotFoundError:
            return False

    def get_version(self, package: str) -> Optional[str]:
        """获取已安装包的版本

        Args:
            package: 包名

        Returns:
            版本号，未安装时返回 None
        """
        try:
            return importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return None

    def list_installed(self, packages: list[str]) -> dict[str, Optional[str]]:
        """批量检测包安装状态

        Args:
            packages: 包名列表

        Returns:
            {包名: 版本号或None}
        """
        result = {}
        for pkg in packages:
            result[pkg] = self.get_version(pkg)
        return result

    def auto_detect_mirror(self, timeout: float = 5.0) -> bool:
        """自动检测最快镜像并切换

        Args:
            timeout: 超时时间（秒）

        Returns:
            是否成功找到可用镜像
        """
        logger.info("[PYPI] 自动检测最快 PyPI 镜像...")
        fastest = find_fastest_pypi_mirror(timeout=timeout)
        if fastest:
            self._pip_index_url = fastest
            logger.info("[PYPI] 已切换到镜像: %s", fastest)
            return True
        logger.warning("[PYPI] 未找到可用镜像，将使用默认源")
        return False

    def install_requirements(
        self,
        requirements_file: str,
        upgrade: bool = False,
    ) -> bool:
        """从 requirements 文件安装依赖

        Args:
            requirements_file: requirements.txt 路径
            upgrade: 是否升级

        Returns:
            是否成功
        """
        req_path = Path(requirements_file)
        if not req_path.exists():
            logger.error("[PYPI] 文件不存在: %s", requirements_file)
            return False

        extra_args = []
        if upgrade:
            extra_args.append("--upgrade")

        desc = f"安装依赖: {req_path.name}"
        cmd = self._build_pip_cmd(
            "install",
            ["-r", str(req_path)],
            extra_args,
        )
        return self._run_pip(cmd, description=desc)

    def ensure_packages(
        self,
        packages: list[str],
        upgrade: bool = False,
    ) -> list[str]:
        """确保包已安装（只安装缺失的）

        Args:
            packages: 包名列表
            upgrade: 是否升级已有包

        Returns:
            已安装/更新的包名列表
        """
        installed_now = []
        to_install = []

        for pkg in packages:
            pkg_name = re.split(r"[<>=!]", pkg)[0].strip()
            if self.is_installed(pkg_name) and not upgrade:
                logger.debug("[PYPI] %s 已安装，跳过", pkg_name)
                installed_now.append(pkg_name)
            else:
                to_install.append(pkg)

        if to_install:
            if self.install(to_install, upgrade=upgrade):
                installed_now.extend(
                    [re.split(r"[<>=!]", p)[0].strip() for p in to_install]
                )

        return installed_now
