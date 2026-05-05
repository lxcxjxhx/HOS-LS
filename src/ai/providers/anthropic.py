"""Anthropic Claude 客户端

提供与 Claude API 的集成。
"""

import os
from typing import Optional, Tuple

from anthropic import AsyncAnthropic

from src.ai.client import AIClient
from src.ai.models import AIProvider, AIRequest, AIResponse
from src.core.config import Config


class AnthropicClient(AIClient):
    """Anthropic Claude 客户端"""

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(config)
        self._client: Optional[AsyncAnthropic] = None

    @property
    def provider(self) -> AIProvider:
        return AIProvider.ANTHROPIC

    async def initialize(self) -> None:
        """初始化客户端"""
        if self._initialized:
            return

        api_key = self.config.ai.api_key or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("Anthropic API 密钥未设置")

        self._client = AsyncAnthropic(
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

        model = request.model or self.config.ai.model or "claude-3-5-sonnet-20241022"

        # 构建消息
        messages = []
        
        # 处理多模态内容
        if request.multimodal_content:
            content = []
            # 添加文本提示
            content.append({"type": "text", "text": request.prompt})
            # 添加图像内容
            for item in request.multimodal_content:
                if item.type == "image":
                    content.append({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": item.content}})
            messages.append({"role": "user", "content": content})
        else:
            # 普通文本提示
            messages.append({"role": "user", "content": request.prompt})

        response = await self._client.messages.create(
            model=model,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            system=request.system_prompt,
            messages=messages,
        )

        return AIResponse(
            content=response.content[0].text if response.content else "",
            model=model,
            provider=AIProvider.ANTHROPIC,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
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
            response = await self._client.messages.create(
                model="claude-3-5-haiku-20241022",
                max_tokens=10,
                messages=[{"role": "user", "content": "Hello"}],
                timeout=10
            )

            logger.info("Anthropic API access validated successfully")
            return True, ""
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Anthropic API validation failed: {error_msg}")
            return False, f"API validation failed: {error_msg}"
