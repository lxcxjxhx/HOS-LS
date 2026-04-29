"""OpenAI 客户端

提供与 OpenAI API 的集成。
"""

import os
from typing import Optional, Tuple

from openai import AsyncOpenAI

from src.ai.client import AIClient
from src.ai.models import AIProvider, AIRequest, AIResponse
from src.core.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class OpenAIClient(AIClient):
    """OpenAI 客户端"""

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(config)
        self._client: Optional[AsyncOpenAI] = None

    @property
    def provider(self) -> AIProvider:
        return AIProvider.OPENAI

    async def initialize(self) -> None:
        """初始化客户端"""
        if self._initialized:
            return

        api_key = self.config.ai.api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API 密钥未设置")

        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=self.config.ai.base_url,
        )
        self._initialized = True

    async def close(self) -> None:
        """关闭客户端"""
        if self._client:
            await self._client.close()
            self._client = None
        self._initialized = False

    async def generate(self, request: AIRequest) -> AIResponse:
        """生成响应

        Args:
            request: AI 请求

        Returns:
            AI 响应
        """
        if not self._client:
            raise RuntimeError("客户端未初始化")

        model = request.model or self.config.ai.model or "gpt-4"

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        
        # 处理多模态内容
        if request.multimodal_content:
            content = []
            # 添加文本提示
            content.append({"type": "text", "text": request.prompt})
            # 添加图像内容
            for item in request.multimodal_content:
                if item.type == "image":
                    content.append({"type": "image_url", "image_url": {"url": f"data:image/png;base64,{item.content}"}})
            messages.append({"role": "user", "content": content})
        else:
            # 普通文本提示
            messages.append({"role": "user", "content": request.prompt})

        response = await self._client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )

        return AIResponse(
            content=response.choices[0].message.content or "",
            model=model,
            provider=AIProvider.OPENAI,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            },
            raw_response=response,
        )

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

            # 简单的测试调用以验证 API 访问
            response = await self._client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10,
                timeout=10
            )

            logger.info("OpenAI API access validated successfully")
            return True, ""
        except Exception as e:
            error_msg = str(e)
            logger.error(f"OpenAI API validation failed: {error_msg}")
            return False, f"API validation failed: {error_msg}"
