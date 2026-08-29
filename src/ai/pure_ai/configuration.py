"""Pure-AI configuration validation shared by CLI and runtime entry points."""

import os
from typing import Optional

from src.core.config import Config


class PureAIConfigurationError(RuntimeError):
    """Raised when an explicit Pure-AI scan cannot be configured safely."""


class PureAIInitializationError(RuntimeError):
    """Raised when an explicit Pure-AI scan cannot initialize its provider."""


_PROVIDER_ENV_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "deepinfra": "DEEPINFRA_API_KEY",
    "aliyun": "DASHSCOPE_API_KEY",
}


def resolve_pure_ai_api_key(config: Config) -> Optional[str]:
    """Resolve the API key for the selected Pure-AI provider only.

    A key for a different provider must not be used as a fallback. Doing so
    obscures configuration errors and can make an explicit ``--pure-ai`` scan
    appear to succeed without executing AI analysis.
    """
    provider = config.ai.get_provider("pure_ai").lower()
    candidates = (
        config.ai.api_key,
        os.getenv("HOS_LS_AI_API_KEY"),
        os.getenv(f"HOS_LS_{provider.upper()}_API_KEY"),
        (
            config.ai.aliyun.api_key
            if provider == "aliyun"
            else None
        ),
        os.getenv(_PROVIDER_ENV_VARS.get(provider, "")),
    )
    for candidate in candidates:
        if candidate and candidate.strip():
            return candidate.strip()
    return None


def require_pure_ai_api_key(config: Config) -> str:
    """Return the selected provider key or raise a user-actionable error."""
    api_key = resolve_pure_ai_api_key(config)
    if api_key:
        return api_key

    provider = config.ai.get_provider("pure_ai").lower()
    provider_env = _PROVIDER_ENV_VARS.get(provider)
    accepted = ["ai.api_key", "HOS_LS_AI_API_KEY", f"HOS_LS_{provider.upper()}_API_KEY"]
    if provider == "aliyun":
        accepted.append("ai.aliyun.api_key")
    if provider_env:
        accepted.append(provider_env)

    raise PureAIConfigurationError(
        "--pure-ai requires an API key for provider "
        f"'{provider}'. Configure one of: {', '.join(accepted)}. "
        "Use the default scan without --pure-ai for static-only analysis."
    )
