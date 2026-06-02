"""i18n 语言环境管理模块

管理当前语言设置，从配置文件读取语言偏好。
"""

import os
import yaml
from typing import Optional

DEFAULT_LANGUAGE = "zh"
SUPPORTED_LANGUAGES = ["zh", "en"]
CONFIG_FILE = "hos-ls.yaml"


class LocaleManager:
    """语言环境管理器

    管理当前语言设置，支持从配置文件读取和程序化设置。
    """

    _current_language: str = DEFAULT_LANGUAGE
    _initialized: bool = False

    @classmethod
    def get_language(cls) -> str:
        """获取当前语言

        Returns:
            当前语言代码 (zh/en)
        """
        if not cls._initialized:
            cls._load_from_config()
            cls._initialized = True
        return cls._current_language

    @classmethod
    def set_language(cls, lang: str) -> bool:
        """设置当前语言

        Args:
            lang: 语言代码 (zh/en)

        Returns:
            是否设置成功
        """
        if lang not in SUPPORTED_LANGUAGES:
            return False
        cls._current_language = lang
        cls._initialized = True
        return True

    @classmethod
    def _load_from_config(cls) -> None:
        """从配置文件加载语言设置"""
        config_path = cls._find_config_file()
        if not config_path:
            cls._current_language = DEFAULT_LANGUAGE
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if config and isinstance(config, dict):
                prompt_config = config.get("prompt", {})
                if isinstance(prompt_config, dict):
                    language = prompt_config.get("language")
                    if language and language in SUPPORTED_LANGUAGES:
                        cls._current_language = language
                        return

                i18n_config = config.get("i18n", {})
                if isinstance(i18n_config, dict):
                    language = i18n_config.get("language")
                    if language and language in SUPPORTED_LANGUAGES:
                        cls._current_language = language
                        return

                language = config.get("language")
                if language and language in SUPPORTED_LANGUAGES:
                    cls._current_language = language
        except Exception:
            pass

        cls._current_language = DEFAULT_LANGUAGE

    @classmethod
    def _find_config_file(cls) -> Optional[str]:
        """查找配置文件

        Returns:
            配置文件路径，如果未找到则返回None
        """
        if os.path.exists(CONFIG_FILE):
            return CONFIG_FILE

        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
        config_path = os.path.join(project_root, CONFIG_FILE)
        if os.path.exists(config_path):
            return config_path

        return None

    @classmethod
    def reset(cls) -> None:
        """重置语言设置到默认值"""
        cls._current_language = DEFAULT_LANGUAGE
        cls._initialized = False


def get_current_language() -> str:
    """获取当前语言

    Returns:
        当前语言代码 (zh/en)
    """
    return LocaleManager.get_language()


def set_language(lang: str) -> bool:
    """设置当前语言

    Args:
        lang: 语言代码 (zh/en)

    Returns:
        是否设置成功
    """
    return LocaleManager.set_language(lang)


def reset_language() -> None:
    """重置语言设置到默认值"""
    LocaleManager.reset()
