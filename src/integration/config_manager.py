"""HOS-LS Configuration Manager - YAML-based config management with fallback."""

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """Manages HOS-LS configuration with YAML support and JSON fallback."""

    CONFIG_DIR = Path.home() / '.hos-ls'
    CONFIG_FILE = CONFIG_DIR / 'config.yaml'

    DEFAULT_CONFIG = {
        'proxy': {
            'enabled': True,
            'url': 'http://127.0.0.1:7897',
            'domestic_bypass': True,
        },
        'sources': {
            'priority': [
                'NVD NIST',
                'GitHub Mirror',
                'CNNVD',
                'CNVD RSS',
                'OpenCVE API',
            ],
            'enabled': [
                'NVD NIST',
                'GitHub Mirror',
                'CNNVD',
                'CNVD RSS',
            ],
        },
        'update': {
            'auto_check_days': 15,
            'last_sync_time': None,
        },
        'scan': {
            'max_concurrent_files': 5,
            'confidence_threshold': 0.60,
        },
    }

    def __init__(self, config_path: Optional[str] = None):
        if config_path:
            self.config_file = Path(config_path)
        else:
            self.config_file = self.CONFIG_FILE
        self._config: Dict[str, Any] = {}
        self._load_or_create_config()

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Merge override into base recursively, preserving base keys not in override."""
        result = copy.deepcopy(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result

    def _load_yaml(self, file_path: str) -> Dict[str, Any]:
        """Load YAML config file."""
        if HAS_YAML:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
        else:
            logger.warning("PyYAML not available, using JSON fallback parser")
            return self._load_json_fallback(file_path)

    def _load_json_fallback(self, file_path: str) -> Dict[str, Any]:
        """Fallback: parse simple YAML-like config as JSON."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            json_path = str(Path(file_path).with_suffix('.json'))
            if Path(json_path).exists():
                with open(json_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            logger.error(f"Cannot parse config without PyYAML: {file_path}")
            return {}
        except Exception as e:
            logger.error(f"JSON fallback failed: {e}")
            return {}

    def _save_yaml(self, file_path: str, data: Dict[str, Any]) -> None:
        """Save config as YAML file."""
        if HAS_YAML:
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        else:
            json_path = str(Path(file_path).with_suffix('.json'))
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.warning(f"Saved as JSON fallback: {json_path}")

    def _load_or_create_config(self) -> None:
        """Load existing config or create default."""
        config_path_str = str(self.config_file)

        try:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create config directory: {e}")
            self._config = copy.deepcopy(self.DEFAULT_CONFIG)
            return

        if Path(config_path_str).exists():
            try:
                loaded = self._load_yaml(config_path_str)
                if loaded:
                    self._config = self._deep_merge(self.DEFAULT_CONFIG, loaded)
                    logger.info(f"Config loaded: {config_path_str}")
                else:
                    logger.warning(f"Empty/invalid config, using defaults")
                    self._config = copy.deepcopy(self.DEFAULT_CONFIG)
            except Exception as e:
                logger.error(f"Failed to load config: {e}, using defaults")
                self._config = copy.deepcopy(self.DEFAULT_CONFIG)
        else:
            logger.info(f"Config not found, creating default: {config_path_str}")
            self._config = copy.deepcopy(self.DEFAULT_CONFIG)
            try:
                self.save()
            except Exception as e:
                logger.error(f"Failed to save default config: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value by dot-separated key (e.g., 'proxy.url')."""
        keys = key.split('.')
        current = self._config
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def set(self, key: str, value: Any) -> None:
        """Set config value by dot-separated key and save."""
        keys = key.split('.')
        current = self._config
        for k in keys[:-1]:
            if k not in current or not isinstance(current[k], dict):
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
        self.save()

    def save(self) -> None:
        """Save config to YAML file."""
        config_path_str = str(self.config_file)
        try:
            self._save_yaml(config_path_str, self._config)
            logger.info(f"Config saved: {config_path_str}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def get_proxy_url(self) -> Optional[str]:
        """Get proxy URL if proxy is enabled, else None."""
        if self.get('proxy.enabled'):
            return self.get('proxy.url')
        return None

    def use_proxy_for_source(self, source_region: str) -> bool:
        """Check if proxy should be used for a source based on region."""
        if source_region == 'domestic' and self.get('proxy.domestic_bypass'):
            return False
        return self.get('proxy.enabled', True)

    def get_enabled_sources(self) -> List[str]:
        """Get list of enabled source names."""
        return self.get('sources.enabled', [])

    def get_source_priority(self) -> List[str]:
        """Get source priority list."""
        return self.get('sources.priority', [])


# 全局单例
_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """获取全局 ConfigManager 单例"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager
