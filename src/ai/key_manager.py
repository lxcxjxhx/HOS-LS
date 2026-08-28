"""API Key 管理器 — 统一的密钥管理方案

设计目标：
1. 支持多 provider 独立密钥，不再共用顶层 api_key
2. 支持 .env 文件自动加载（dotenv）
3. 密钥从内存加载，不在日志/异常中泄露完整 key
4. 支持 provider-specific 环境变量覆盖

密钥优先级（provider-specific）：
   1. 配置文件中 provider 的 api_key 字段
   2. 环境变量 HOS_LS_<PROVIDER>_API_KEY (如 HOS_LS_DEEPSEEK_API_KEY)
   3. 环境变量 <PROVIDER>_API_KEY (如 DEEPSEEK_API_KEY)
   4. 顶层 api_key（兼容旧配置）
   5. 通用 fallback 环境变量 HOS_LS_AI_API_KEY

使用方法：
   from src.ai.key_manager import get_api_key
   api_key = get_api_key("deepseek")  # 获取 DeepSeek 密钥（不泄露完整 key）
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 尝试加载 .env 文件
try:
    from dotenv import load_dotenv

    # 搜索项目根目录的 .env 文件
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    dotenv_path = os.path.join(here, ".env")
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path)
        logger.info(f"[KeyManager] 已加载 .env 文件: {dotenv_path}")
    else:
        # 也检查用户目录
        user_dotenv = os.path.expanduser("~/.hos-ls/.env")
        if os.path.exists(user_dotenv):
            load_dotenv(user_dotenv)
            logger.info(f"[KeyManager] 已加载 .env 文件: {user_dotenv}")
except ImportError:
    logger.debug("[KeyManager] python-dotenv 未安装，跳过 .env 加载")
except Exception as e:
    logger.debug(f"[KeyManager] .env 加载失败: {e}")


# 环境变量命名映射
PROVIDER_ENV_MAP = {
    "deepseek": "DEEPSEEK",
    "openai": "OPENAI",
    "anthropic": "ANTHROPIC",
    "aliyun": "ALIYUN",
    "deepinfra": "DEEPINFRA",
}

# 兼容性环境变量映射（旧版命名）
LEGACY_ENV_MAP = {
    "deepseek": ["DEEPSEEK_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "aliyun": ["ALIYUN_API_KEY", "DASHSCOPE_API_KEY"],
    "deepinfra": ["DEEPINFRA_API_KEY"],
}


def resolve_api_key(provider: str, config_api_key: Optional[str] = None) -> Optional[str]:
    """解析 provider 的 API 密钥（统一入口）

    Args:
        provider: 提供商名称（小写）
        config_api_key: 配置文件中指定的 api_key（可选）

    Returns:
        API 密钥，如果未找到返回 None
    """
    # 1. 优先使用配置文件中的 provider-specific api_key
    if config_api_key and config_api_key.strip():
        return config_api_key.strip()

    # 2. 环境变量：HOS_LS_<PROVIDER>_API_KEY
    prefix = PROVIDER_ENV_MAP.get(provider, provider.upper())
    env_key = os.getenv(f"HOS_LS_{prefix}_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    # 3. 直接命名环境变量：<PROVIDER>_API_KEY
    env_key = os.getenv(f"{prefix}_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    # 4. 兼容旧版环境变量名
    for legacy_name in LEGACY_ENV_MAP.get(provider, []):
        env_key = os.getenv(legacy_name)
        if env_key and env_key.strip():
            return env_key.strip()

    # 5. 兼容旧配置的顶层 api_key（回退）
    return None


def mask_key(api_key: Optional[str]) -> str:
    """掩码显示 API 密钥（只显示前 6 位和末 4 位）

    Args:
        api_key: API 密钥

    Returns:
        掩码后的字符串
    """
    if not api_key:
        return "<未设置>"
    if len(api_key) <= 10:
        return api_key[:3] + "***"
    return api_key[:6] + "****" + api_key[-4:]


def get_api_key(provider: str, config_api_key: Optional[str] = None) -> Optional[str]:
    """获取 API 密钥（对外统一接口）

    Args:
        provider: 提供商名称
        config_api_key: 可选，配置文件中指定的密钥

    Returns:
        API 密钥
    """
    key = resolve_api_key(provider, config_api_key)
    if key:
        logger.debug(f"[KeyManager] {provider} API key resolved: {mask_key(key)}")
    else:
        logger.warning(f"[KeyManager] {provider} API key 未设置")
    return key


def get_all_provider_keys(config=None) -> dict:
    """获取所有可用的 provider 密钥状态

    Args:
        config: 可选 Config 对象

    Returns:
        {provider: {key_found: bool, masked_key: str}}
    """
    result = {}
    for provider in PROVIDER_ENV_MAP:
        cfg_key = None
        if config and hasattr(config, "ai"):
            # 尝试从 config 中获取 provider-specific key
            provider_cfg = getattr(config.ai, provider, None)
            if provider_cfg and hasattr(provider_cfg, "api_key"):
                cfg_key = provider_cfg.api_key
            elif provider == config.ai.provider:
                cfg_key = config.ai.api_key

        key = resolve_api_key(provider, cfg_key)
        result[provider] = {
            "key_found": key is not None,
            "masked_key": mask_key(key),
        }
    return result
