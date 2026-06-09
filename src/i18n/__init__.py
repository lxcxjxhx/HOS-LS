"""i18n 多语言支持模块

提供中英文翻译支持，统一日志和消息的语言输出。
"""

from .translations import (
    TRANSLATIONS,
    STATE_TRANSLATIONS,
    SEVERITY_TRANSLATIONS,
    get_translation,
    get_state_translation,
    get_severity_translation,
    translate_boolean,
)
from .locale import (
    LocaleManager,
    get_current_language,
    set_language,
    reset_language,
)

__all__ = [
    "TRANSLATIONS",
    "STATE_TRANSLATIONS",
    "SEVERITY_TRANSLATIONS",
    "get_translation",
    "get_state_translation",
    "get_severity_translation",
    "translate_boolean",
    "LocaleManager",
    "get_current_language",
    "set_language",
    "reset_language",
]


def t(key: str, lang: str = None, **kwargs) -> str:
    """翻译函数

    Args:
        key: 翻译键
        lang: 语言代码，默认从配置读取
        **kwargs: 格式化参数

    Returns:
        翻译后的字符串
    """
    current_lang = lang or get_current_language()
    template = get_translation(current_lang, key)
    if kwargs:
        try:
            return template.format(**kwargs)
        except (KeyError, ValueError):
            return template
    return template


def t_state(state: str, lang: str = None) -> str:
    """翻译状态值

    Args:
        state: 状态值 (UNCERTAIN/CONFIRMED/REJECTED/REFINED/NEW)
        lang: 语言代码，默认从配置读取

    Returns:
        翻译后的状态值
    """
    current_lang = lang or get_current_language()
    return get_state_translation(current_lang, state)


def t_severity(severity: str, lang: str = None) -> str:
    """翻译严重程度

    Args:
        severity: 严重程度 (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        lang: 语言代码，默认从配置读取

    Returns:
        翻译后的严重程度
    """
    current_lang = lang or get_current_language()
    return get_severity_translation(current_lang, severity)


def t_bool(value: bool, lang: str = None) -> str:
    """翻译布尔值

    Args:
        value: 布尔值
        lang: 语言代码，默认从配置读取

    Returns:
        翻译后的布尔值字符串
    """
    current_lang = lang or get_current_language()
    return translate_boolean(value, current_lang)
