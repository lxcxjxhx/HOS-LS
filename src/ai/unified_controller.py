"""AI API 统一控制器

提供 DeepSeek V4 和阿里云百炼的统一接口，支持自由切换模型。
"""

from typing import Any, Dict, List, Optional

from src.ai.models import AIProvider, AIRequest, AIResponse
from src.ai.providers.deepseek import DeepSeekClient
from src.ai.providers.aliyun import AliyunClient
from src.ai.providers.openai import OpenAIClient
from src.ai.providers.anthropic import AnthropicClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


MODEL_REGISTRY: Dict[str, Dict[str, List[str]]] = {
    "deepseek": {
        "v4": [
            "deepseek-v4-flash",
            "deepseek-v4-pro",
        ],
    },
    "aliyun": {
        "qwen3": [
            "qwen3-7b-instruct",
            "qwen3-14b-instruct",
            "qwen3-32b-instruct",
            "qwen3-4b-instruct",
            "qwen3-8b-instruct",
            "qwen3-57b-instruct",
            "qwen3-140b-instruct",
        ],
        "qwen3-coder": [
            "qwen3-coder-7b-instruct",
            "qwen3-coder-14b-instruct",
            "qwen3-coder-32b-instruct",
            "qwen3-coder-next",
        ],
        "qwen3.6": [
            "qwen3.6-plus",
            "qwen3.6-plus-2026-04-02",
            "qwen3.6-max",
            "qwen3.6-max-preview",
        ],
        "qwen2.5": [
            "qwen2.5-7b-instruct",
            "qwen2.5-14b-instruct",
            "qwen2.5-32b-instruct",
            "qwen2.5-72b-instruct",
            "qwen2.5-14b-instruct-32k",
            "qwen2.5-7b-instruct-fp8",
            "qwen2.5-14b-instruct-fp8",
        ],
        "qwen-max": [
            "qwen-max",
            "qwen-max-2025-01-25",
            "qwen3-max-preview",
            "qwen3-max-2025-09-23",
            "qwen3.5-max-preview",
        ],
        "qwen-plus": [
            "qwen-plus",
            "qwen-plus-2025-06-06",
            "qwen-plus-latest",
        ],
        "qwen-turbo": [
            "qwen-turbo",
            "qwen-turbo-2025-07-07",
            "qwen-turbo-latest",
        ],
        "deepseek-r1": [
            "deepseek-r1-distill-qwen-32b",
            "deepseek-r1-distill-llama-70b",
            "deepseek-r1-distill-qwen-14b",
            "deepseek-r1-distill-llama-8b",
        ],
        "embedding": [
            "text-embedding-v3",
            "Qwen/Qwen3-Embedding-0.6B",
            "text-embedding-v1",
            "text-embedding-v2",
        ],
        "rerank": [
            "bge-reranker-large",
            "bge-reranker-base",
        ],
        "kimi": [
            "kimi-k2.6",
        ],
        "minimax": [
            "MiniMax/MiniMax-M2.7",
        ],
    },
    "openai": {
        "gpt-4": [
            "gpt-4",
            "gpt-4-0613",
            "gpt-4-turbo",
            "gpt-4-turbo-2024-04-09",
            "gpt-4o",
            "gpt-4o-mini",
        ],
        "gpt-3.5": [
            "gpt-3.5-turbo",
            "gpt-3.5-turbo-0613",
        ],
    },
    "anthropic": {
        "claude-3": [
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
        ],
        "claude-3.5": [
            "claude-3.5-sonnet-20240620",
            "claude-3.5-sonnet-latest",
            "claude-3.5-haiku-20241022",
        ],
        "claude-2": [
            "claude-2.1",
            "claude-2.0",
        ],
    },
}


class UnifiedAIController:
    """AI API 统一控制器

    支持 DeepSeek V4 和阿里云百炼自由切换模型。
    """

    _instance: Optional['UnifiedAIController'] = None

    def __init__(self):
        self._current_provider: AIProvider = AIProvider.DEEPSEEK
        self._current_model: str = "deepseek-chat"
        self._clients: Dict[str, Any] = {}
        self._initialized: bool = False

    @classmethod
    def get_instance(cls) -> 'UnifiedAIController':
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def initialize(
        self,
        provider: str = "deepseek",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        **kwargs
    ) -> None:
        """初始化控制器

        Args:
            provider: 提供商 (deepseek/aliyun/openai/anthropic)
            model: 模型名称
            api_key: API密钥
            **kwargs: 其他配置
        """
        provider = provider.lower()

        if provider == "deepseek":
            self._current_provider = AIProvider.DEEPSEEK
            client = DeepSeekClient()
        elif provider == "aliyun":
            self._current_provider = AIProvider.ALIYUN
            client = AliyunClient()
        elif provider == "openai":
            self._current_provider = AIProvider.OPENAI
            client = OpenAIClient()
        elif provider == "anthropic":
            self._current_provider = AIProvider.ANTHROPIC
            client = AnthropicClient()
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        await client.initialize()
        self._clients[provider] = client
        self._current_model = model or self._get_default_model(provider)
        self._initialized = True
        logger.info(f"UnifiedAIController initialized: provider={provider}, model={self._current_model}")

    def _get_default_model(self, provider: str) -> str:
        """获取提供商默认模型"""
        defaults = {
            "deepseek": "deepseek-chat",
            "aliyun": "qwen3-coder-next",
            "openai": "gpt-4o",
            "anthropic": "claude-3.5-sonnet-latest",
        }
        return defaults.get(provider, "deepseek-chat")

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        **kwargs
    ) -> AIResponse:
        """统一生成接口

        Args:
            prompt: 用户 prompt
            system_prompt: 系统 prompt
            model: 模型名称 (如不指定使用当前模型)
            temperature: 温度参数
            max_tokens: 最大 token 数
            **kwargs: 其他参数

        Returns:
            AI 响应
        """
        if not self._initialized:
            await self.initialize()

        request = AIRequest(
            prompt=prompt,
            system_prompt=system_prompt,
            model=model or self._current_model,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        provider_name = self._current_provider.value
        client = self._clients.get(provider_name)

        if not client:
            raise RuntimeError(f"Client for provider {provider_name} not initialized")

        return await client.generate(request)

    def set_provider(self, provider: str) -> None:
        """动态切换提供商

        Args:
            provider: 提供商名称
        """
        provider = provider.lower()
        if provider == "deepseek":
            self._current_provider = AIProvider.DEEPSEEK
        elif provider == "aliyun":
            self._current_provider = AIProvider.ALIYUN
        elif provider == "openai":
            self._current_provider = AIProvider.OPENAI
        elif provider == "anthropic":
            self._current_provider = AIProvider.ANTHROPIC
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        self._current_model = self._get_default_model(provider)
        logger.info(f"Provider switched to: {provider}, default model: {self._current_model}")

    def set_model(self, model: str) -> None:
        """动态切换模型

        Args:
            model: 模型名称
        """
        self._current_model = model
        logger.info(f"Model switched to: {model}")

    def get_current_config(self) -> Dict[str, str]:
        """获取当前配置"""
        return {
            "provider": self._current_provider.value,
            "model": self._current_model,
        }

    @staticmethod
    def list_providers() -> List[str]:
        """列出所有支持的提供商"""
        return list(MODEL_REGISTRY.keys())

    @staticmethod
    def list_models(provider: str) -> List[str]:
        """列出提供商支持的所有模型

        Args:
            provider: 提供商名称

        Returns:
            模型列表
        """
        provider_models = MODEL_REGISTRY.get(provider.lower(), {})
        all_models = []
        for category_models in provider_models.values():
            all_models.extend(category_models)
        return all_models

    @staticmethod
    def list_models_by_category(provider: str) -> Dict[str, List[str]]:
        """按类别列出模型

        Args:
            provider: 提供商名称

        Returns:
            分类模型字典
        """
        return MODEL_REGISTRY.get(provider.lower(), {})

    @staticmethod
    def is_model_supported(provider: str, model: str) -> bool:
        """检查模型是否支持

        Args:
            provider: 提供商名称
            model: 模型名称

        Returns:
            是否支持
        """
        supported_models = UnifiedAIController.list_models(provider)
        return model in supported_models

    async def close(self) -> None:
        """关闭所有客户端"""
        for client in self._clients.values():
            await client.close()
        self._clients.clear()
        self._initialized = False


def get_unified_controller() -> UnifiedAIController:
    """获取统一控制器实例"""
    return UnifiedAIController.get_instance()
