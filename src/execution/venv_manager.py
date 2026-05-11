"""虚拟环境管理器模块

自动创建和管理隔离的 Python 虚拟环境，支持缓存和自动清理。
"""

import os
import shutil
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from src.utils.logger import get_logger

logger = get_logger(__name__)


class VenvManager:
    """虚拟环境管理器"""

    DEFAULT_BASE_PACKAGES = ["requests", "urllib3", "certifi", "charset-normalizer"]

    def __init__(
        self,
        venv_root: Optional[str] = None,
        cache_dir: Optional[str] = None,
        config_path: Optional[str] = None,
    ):
        if config_path is None:
            project_root = Path(__file__).parent.parent.parent.parent
            config_path = project_root / "dynamic_code" / "config.yaml"

        self._config = self._load_config(config_path)

        sandbox_root = self._config.get("global", {}).get("sandbox_root", "temp/sandboxes")
        if venv_root is None:
            project_root = Path(__file__).parent.parent.parent.parent
            venv_root = project_root / sandbox_root / "venvs"

        self.venv_root = Path(venv_root)
        self.venv_root.mkdir(parents=True, exist_ok=True)

        if cache_dir is None:
            project_root = Path(__file__).parent.parent.parent.parent
            cache_dir = project_root / "temp" / "venv_cache"

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.base_packages = self.DEFAULT_BASE_PACKAGES

        self._sandbox_enabled = self._config.get("global", {}).get("sandbox_enabled", True)
        self._auto_cleanup = self._config.get("global", {}).get("auto_cleanup", True)

        self._venv_cache: Dict[str, str] = {}

    def _load_config(self, config_path: Path) -> dict:
        """加载配置文件"""
        try:
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
        return {}

    def _get_venv_hash(self, dependencies: Optional[List[str]] = None) -> str:
        """计算虚拟环境的哈希值"""
        deps = sorted(dependencies or [])
        deps_str = ",".join(deps)
        return str(abs(hash(deps_str)))

    def _get_venv_path(self, env_name: str) -> Path:
        """获取虚拟环境路径"""
        return self.venv_root / env_name

    def _get_cache_path(self, venv_hash: str) -> Path:
        """获取缓存路径"""
        return self.cache_dir / f"venv_{venv_hash}"

    def create_venv(self, env_name: str, dependencies: Optional[List[str]] = None) -> str:
        """创建虚拟环境

        Args:
            env_name: 环境名称
            dependencies: 依赖包列表

        Returns:
            虚拟环境路径
        """
        if not self._sandbox_enabled:
            logger.warning("Sandbox is disabled, cannot create venv")
            return ""

        venv_path = self._get_venv_path(env_name)

        if venv_path.exists():
            logger.info(f"Virtual environment already exists: {venv_path}")
            return str(venv_path)

        try:
            logger.info(f"Creating virtual environment: {env_name}")
            result = subprocess.run(
                ["python", "-m", "venv", str(venv_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                logger.error(f"Failed to create venv: {result.stderr}")
                return ""

            self.install_packages(str(venv_path), self.base_packages)

            if dependencies:
                self.install_packages(str(venv_path), dependencies)

            logger.info(f"Virtual environment created: {venv_path}")
            return str(venv_path)

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while creating venv: {env_name}")
            if venv_path.exists():
                shutil.rmtree(venv_path, ignore_errors=True)
            return ""
        except Exception as e:
            logger.error(f"Failed to create venv {env_name}: {e}")
            if venv_path.exists():
                shutil.rmtree(venv_path, ignore_errors=True)
            return ""

    def get_or_create_venv(
        self, env_name: str, dependencies: Optional[List[str]] = None
    ) -> str:
        """获取或创建虚拟环境

        Args:
            env_name: 环境名称
            dependencies: 依赖包列表

        Returns:
            虚拟环境路径
        """
        venv_path = self._get_venv_path(env_name)

        if venv_path.exists():
            logger.debug(f"Reusing existing virtual environment: {env_path}")
            return str(venv_path)

        venv_hash = self._get_venv_hash(dependencies)
        cache_path = self._get_cache_path(venv_hash)

        if cache_path.exists() and self._auto_cleanup:
            try:
                logger.info(f"Restoring venv from cache: {cache_path}")
                shutil.copytree(cache_path, venv_path, dirs_exist_ok=False)
                return str(venv_path)
            except Exception as e:
                logger.warning(f"Failed to restore from cache: {e}")

        created_path = self.create_venv(env_name, dependencies)

        if created_path and cache_path.exists() is False and self._auto_cleanup:
            try:
                logger.info(f"Caching venv: {cache_path}")
                shutil.copytree(venv_path, cache_path)
            except Exception as e:
                logger.warning(f"Failed to cache venv: {e}")

        return created_path

    def install_packages(self, venv_path: str, packages: List[str]) -> bool:
        """安装包到虚拟环境

        Args:
            venv_path: 虚拟环境路径
            packages: 包列表

        Returns:
            是否成功
        """
        if not packages:
            return True

        python_path = self.get_venv_python(venv_path)
        if not python_path:
            logger.error(f"Invalid venv path: {venv_path}")
            return False

        try:
            logger.info(f"Installing packages to {venv_path}: {packages}")

            pip_path = Path(venv_path) / "Scripts" / "pip.exe"
            if not pip_path.exists():
                pip_path = Path(venv_path) / "bin" / "pip"

            result = subprocess.run(
                [str(pip_path), "install", "--quiet", "-U"] + packages,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                logger.error(f"Failed to install packages: {result.stderr}")
                return False

            logger.info(f"Packages installed successfully")
            return True

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while installing packages")
            return False
        except Exception as e:
            logger.error(f"Failed to install packages: {e}")
            return False

    def list_venvs(self) -> List[Dict]:
        """列出所有虚拟环境

        Returns:
            虚拟环境信息列表
        """
        venvs = []

        if not self.venv_root.exists():
            return venvs

        for venv_dir in self.venv_root.iterdir():
            if venv_dir.is_dir():
                python_path = venv_dir / "Scripts" / "python.exe"
                if not python_path.exists():
                    python_path = venv_dir / "bin" / "python"

                stat = venv_dir.stat()
                created_time = datetime.fromtimestamp(stat.st_mtime)

                venvs.append(
                    {
                        "name": venv_dir.name,
                        "path": str(venv_dir),
                        "python_path": str(python_path) if python_path.exists() else "",
                        "created_time": created_time.isoformat(),
                        "age_days": (datetime.now() - created_time).days,
                    }
                )

        return sorted(venvs, key=lambda x: x["name"])

    def delete_venv(self, env_name: str) -> bool:
        """删除虚拟环境

        Args:
            env_name: 环境名称

        Returns:
            是否成功
        """
        venv_path = self._get_venv_path(env_name)

        if not venv_path.exists():
            logger.warning(f"Virtual environment not found: {env_name}")
            return False

        try:
            shutil.rmtree(venv_path)
            logger.info(f"Virtual environment deleted: {env_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete venv {env_name}: {e}")
            return False

    def cleanup_old_venvs(self, max_age_days: int = 7) -> int:
        """清理旧虚拟环境

        Args:
            max_age_days: 最大保留天数

        Returns:
            清理的环境数量
        """
        if not self._auto_cleanup:
            logger.info("Auto cleanup is disabled")
            return 0

        if not self.venv_root.exists():
            return 0

        cleaned = 0
        cutoff_time = datetime.now() - timedelta(days=max_age_days)

        for venv_dir in self.venv_root.iterdir():
            if venv_dir.is_dir():
                try:
                    stat = venv_dir.stat()
                    created_time = datetime.fromtimestamp(stat.st_mtime)

                    if created_time < cutoff_time:
                        shutil.rmtree(venv_dir)
                        logger.info(f"Cleaned up old venv: {venv_dir.name}")
                        cleaned += 1
                except Exception as e:
                    logger.warning(f"Failed to clean up {venv_dir.name}: {e}")

        if self.cache_dir.exists():
            for cache_dir in self.cache_dir.iterdir():
                if cache_dir.is_dir():
                    try:
                        stat = cache_dir.stat()
                        created_time = datetime.fromtimestamp(stat.st_mtime)

                        if created_time < cutoff_time:
                            shutil.rmtree(cache_dir)
                            logger.info(f"Cleaned up old cache: {cache_dir.name}")
                    except Exception as e:
                        logger.warning(f"Failed to clean up cache {cache_dir.name}: {e}")

        return cleaned

    def get_venv_python(self, venv_path: str) -> str:
        """获取虚拟环境的 Python 路径

        Args:
            venv_path: 虚拟环境路径

        Returns:
            Python 可执行文件路径
        """
        venv_path_obj = Path(venv_path)

        if not venv_path_obj.exists():
            return ""

        python_exe = venv_path_obj / "Scripts" / "python.exe"
        if not python_exe.exists():
            python_exe = venv_path_obj / "bin" / "python"

        if python_exe.exists():
            return str(python_exe)

        return ""


_venv_manager_instance: Optional[VenvManager] = None


def get_venv_manager() -> VenvManager:
    """获取虚拟环境管理器单例实例"""
    global _venv_manager_instance
    if _venv_manager_instance is None:
        _venv_manager_instance = VenvManager()
    return _venv_manager_instance
