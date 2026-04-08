"""DeepSeek 客户端

提供与 DeepSeek API 的集成。
"""

import os
from typing import Optional, Tuple

from openai import OpenAI

from src.ai.client import AIClient
from src.ai.models import AIProvider, AIRequest, AIResponse
from src.core.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DeepSeekClient(AIClient):
    """DeepSeek 客户端"""

    DEFAULT_BASE_URL = "https://api.deepseek.com"

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(config)
        self._client: Optional[OpenAI] = None

    @property
    def provider(self) -> AIProvider:
        return AIProvider.DEEPSEEK

    async def initialize(self) -> None:
        """初始化客户端"""
        if self._initialized:
            return

        # 优先使用配置中的 API 密钥
        api_key = self.config.ai.api_key
        
        # 其次尝试从环境变量获取（与正式模式一致）
        if not api_key:
            api_key = os.getenv("HOS_LS_AI_API_KEY")
        
        # 最后尝试 DEEPSEEK_API_KEY 作为兼容
        if not api_key:
            api_key = os.getenv("DEEPSEEK_API_KEY")

        if not api_key:
            raise ValueError("DeepSeek API 密钥未设置")

        base_url = self.config.ai.base_url or self.DEFAULT_BASE_URL

        # 使用 OpenAI SDK 创建客户端
        self._client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )
        self._initialized = True

    async def close(self) -> None:
        """关闭客户端"""
        # OpenAI SDK 客户端不需要显式关闭
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

        model = request.model or self.config.ai.model or "deepseek-chat"

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        
        # 处理多模态内容
        if request.multimodal_content:
            # DeepSeek 暂时不支持多模态，使用文本描述
            content = request.prompt
            for item in request.multimodal_content:
                if item.type == "image":
                    content += "\n[包含图像内容]"
            messages.append({"role": "user", "content": content})
        else:
            # 普通文本提示
            messages.append({"role": "user", "content": request.prompt})

        # 使用 OpenAI SDK 调用 API
        response = self._client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            stream=False
        )

        # 处理响应
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
            response = self._client.chat.completions.create(
                model="deepseek-chat",
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10,
                stream=False
            )

            logger.info("DeepSeek API access validated successfully")
            return True, ""
        except Exception as e:
            error_msg = str(e)
            logger.error(f"DeepSeek API validation failed: {error_msg}")
            return False, f"API validation failed: {error_msg}"
