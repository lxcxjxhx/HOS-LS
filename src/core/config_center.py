"""配置中心模块

统一管理所有配置，支持 YAML 配置文件加载和热更新。
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from functools import lru_cache

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigCenter:
    """配置中心"""

    _instance: Optional['ConfigCenter'] = None

    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir is None:
            project_root = Path(__file__).parent.parent.parent
            config_dir = project_root / "config"

        self.config_dir = Path(config_dir)
        self._configs: Dict[str, Any] = {}
        self._load_all_configs()

    @classmethod
    def get_instance(cls) -> 'ConfigCenter':
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_all_configs(self) -> None:
        """加载所有配置文件"""
        config_files = ["llm_config.yaml", "prompt_config.yaml", "default.yaml"]

        for config_file in config_files:
            config_path = self.config_dir / config_file
            if config_path.exists():
                self._load_yaml(config_path)
                logger.info(f"Loaded config: {config_path}")

    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        """加载 YAML 文件"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                config_name = path.stem
                self._configs[config_name] = data
                return data
        except Exception as e:
            logger.error(f"Failed to load {path}: {e}")
            return {}

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值，支持点号路径

        Args:
            key: 配置键，支持 "llm_config.temperature" 格式
            default: 默认值

        Returns:
            配置值
        """
        keys = key.split('.')
        config_name = keys[0]

        if config_name not in self._configs:
            return default

        value = self._configs[config_name]
        for k in keys[1:]:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_llm_config(self) -> Dict[str, Any]:
        """获取 LLM 配置"""
        return self._configs.get("llm_config", {}).get("llm", {})

    def get_provider_config(self, provider: str) -> Dict[str, Any]:
        """获取指定 provider 配置"""
        return self._configs.get("llm_config", {}).get("providers", {}).get(provider, {})

    def get_prompt_config(self) -> Dict[str, Any]:
        """获取 Prompt 配置"""
        return self._configs.get("prompt_config", {}).get("prompt", {})

    def get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        """获取指定 Agent 配置"""
        return self._configs.get("prompt_config", {}).get("agents", {}).get(agent_name, {})

    def reload(self) -> None:
        """重新加载所有配置"""
        self._configs.clear()
        self._load_all_configs()
        logger.info("Configs reloaded")


@lru_cache(maxsize=1)
def get_config_center() -> ConfigCenter:
    """获取配置中心实例（带缓存）"""
    return ConfigCenter.get_instance()
