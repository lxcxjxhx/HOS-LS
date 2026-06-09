"""OpenAI 客户端（简化版）

保留 provider-specific 默认配置，实际 API 调用通过 LiteLLM 网关。
"""

from src.core.config import Config
from src.ai.models import AIProvider

# Provider 默认配置
DEFAULT_MODEL = "gpt-4"
DEFAULT_MAX_TOKENS = 4096
ENV_API_KEY = "OPENAI_API_KEY"


class OpenAIClient:
    """OpenAI 配置占位符（实际调用由 LiteLLMClient 处理）

    保留此类以保持向后兼容，提供 provider 默认配置。
    """

    provider = AIProvider.OPENAI
    default_model = DEFAULT_MODEL

    def __init__(self, config: Config = None):
        self.config = config
