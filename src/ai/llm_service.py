"""LLM 服务层

统一封装所有 LLM 调用，提供标准化接口。
"""

import asyncio
from typing import Any, Dict, List, Optional

from src.ai.models import AIProvider, AIRequest, AIResponse
from src.ai.providers.openai import OpenAIClient
from src.ai.providers.deepseek import DeepSeekClient
from src.ai.providers.anthropic import AnthropicClient
from src.core.config_center import get_config_center
from src.utils.logger import get_logger

logger = get_logger(__name__)


class LLMService:
    """LLM 统一服务层"""

    _instance: Optional['LLMService'] = None

    def __init__(self):
        self._config_center = get_config_center()
        self._clients: Dict[AIProvider, Any] = {}
        self._initialized = False

    @classmethod
    def get_instance(cls) -> 'LLMService':
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def initialize(self) -> None:
        """初始化所有客户端"""
        if self._initialized:
            return

        llm_config = self._config_center.get_llm_config()
        provider_name = llm_config.get('provider', 'deepseek')

        provider = AIProvider(provider_name)

        if provider == AIProvider.OPENAI:
            self._clients[provider] = OpenAIClient()
        elif provider == AIProvider.DEEPSEEK:
            self._clients[provider] = DeepSeekClient()
        elif provider == AIProvider.ANTHROPIC:
            self._clients[provider] = AnthropicClient()
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        await self._clients[provider].initialize()
        self._initialized = True
        logger.info(f"LLMService initialized with provider: {provider}")

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
    ) -> AIResponse:
        """生成响应

        Args:
            prompt: 用户 prompt
            system_prompt: 系统 prompt
            temperature: 温度参数
            max_tokens: 最大 token 数
            model: 模型名称

        Returns:
            AI 响应
        """
        if not self._initialized:
            await self.initialize()

        llm_config = self._config_center.get_llm_config()

        request = AIRequest(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature if temperature is not None else llm_config.get('temperature', 0.0),
            max_tokens=max_tokens if max_tokens is not None else llm_config.get('max_tokens', 4096),
            model=model,
        )

        provider = AIProvider(llm_config.get('provider', 'deepseek'))
        client = self._clients.get(provider)

        if not client:
            raise RuntimeError(f"Client for provider {provider} not initialized")

        return await client.generate(request)

    async def generate_with_retry(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> AIResponse:
        """带重试的生成响应

        Args:
            prompt: 用户 prompt
            system_prompt: 系统 prompt
            max_retries: 最大重试次数
            **kwargs: 其他参数

        Returns:
            AI 响应
        """
        last_error = None

        for attempt in range(max_retries):
            try:
                return await self.generate(prompt, system_prompt, **kwargs)
            except Exception as e:
                last_error = e
                logger.warning(f"LLM generate attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        raise last_error

    async def close(self) -> None:
        """关闭所有客户端"""
        for client in self._clients.values():
            await client.close()
        self._clients.clear()
        self._initialized = False


def get_llm_service() -> LLMService:
    """获取 LLMService 实例"""
    return LLMService.get_instance()
