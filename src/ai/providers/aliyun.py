"""Aliyun (百炼) 客户端

提供与阿里云百炼 API 的集成，支持 Qwen 系列模型。
"""

import os
from typing import Optional, Tuple

from openai import AsyncOpenAI
from openai import APIStatusError as OpenAIAPIStatusError
import asyncio
from aiohttp import ClientError as AiohttpClientError

from src.ai.client import AIClient
from src.ai.models import AIProvider, AIRequest, AIResponse
from src.core.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AliyunClient(AIClient):
    """阿里云百炼 客户端"""

    DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    DEFAULT_MODEL = "qwen3-coder-next"

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(config)
        self._client: Optional[AsyncOpenAI] = None

    @property
    def provider(self) -> AIProvider:
        return AIProvider.ALIYUN

    async def initialize(self) -> None:
        """初始化客户端"""
        if self._initialized:
            return

        aliyun_config = getattr(self.config.ai, 'aliyun', None) if self.config else None

        if aliyun_config and getattr(aliyun_config, 'enabled', False):
            api_key = getattr(aliyun_config, 'api_key', None) or os.getenv("ALIYUN_API_KEY")
            base_url = getattr(aliyun_config, 'base_url', None) or self.DEFAULT_BASE_URL
            model = getattr(aliyun_config, 'model', None) or self.DEFAULT_MODEL
        else:
            api_key = os.getenv("ALIYUN_API_KEY")
            base_url = self.DEFAULT_BASE_URL
            model = self.DEFAULT_MODEL

        if not api_key:
            raise ValueError("Aliyun API 密钥未设置，请设置 ALIYUN_API_KEY 环境变量或配置 aliyun.api_key")

        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url
        )
        self._initialized = True

    async def close(self) -> None:
        """关闭客户端"""
        self._client = None
        self._initialized = False

    async def generate(self, request: AIRequest) -> AIResponse:
        """生成响应

        Args:
            request: AI 请求

        Returns:
            AI 响应

        Raises:
            APIError: 当API返回错误（402/429/500等）时
        """
        if not self._client:
            raise RuntimeError("客户端未初始化")

        aliyun_config = getattr(self.config.ai, 'aliyun', None) if self.config else None
        if aliyun_config and getattr(aliyun_config, 'enabled', False):
            model = request.model or getattr(aliyun_config, 'model', None) or self.DEFAULT_MODEL
        else:
            model = request.model or self.DEFAULT_MODEL

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})

        if request.multimodal_content:
            content = request.prompt
            for item in request.multimodal_content:
                if item.type == "image":
                    content += "\n[包含图像内容]"
            messages.append({"role": "user", "content": content})
        else:
            messages.append({"role": "user", "content": request.prompt})

        logger.info(f"Aliyun API 调用，使用模型: {model}")

        try:
            response = await self._client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                stream=False
            )

            choice = response.choices[0]

            return AIResponse(
                content=choice.message.content,
                model=model,
                provider=AIProvider.DEEPSEEK,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                },
                raw_response=response
            )
        except OpenAIAPIStatusError as e:
            api_error = APIError.from_exception(e)
            logger.error(f"Aliyun API 错误: {api_error.message}")
            raise api_error
        except asyncio.TimeoutError as e:
            api_error = APIError.from_exception(e)
            logger.error(f"Aliyun API 超时: {api_error.message}")
            raise api_error
        except (AiohttpClientError, ConnectionError, OSError) as e:
            api_error = APIError.from_exception(e)
            logger.error(f"Aliyun API 连接错误: {api_error.message}")
            raise api_error

    def is_available(self) -> bool:
        """检查客户端是否可用"""
        return self._client is not None and self._initialized

    async def validate_api_access(self) -> Tuple[bool, str]:
        """验证 API 访问

        Returns:
            Tuple[bool, str]: (是否成功, 错误信息)
        """
        try:
            if not self._client:
                return False, "Client not initialized"

            response = await self._client.chat.completions.create(
                model=self.DEFAULT_MODEL,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10,
                stream=False
            )

            logger.info("Aliyun API access validated successfully")
            return True, ""
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Aliyun API validation failed: {error_msg}")
            return False, f"API validation failed: {error_msg}"
