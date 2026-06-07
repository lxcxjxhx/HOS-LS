"""LiteLLM 统一网关客户端

使用 LiteLLM 作为统一网关，替代各 provider 的直接 SDK 调用。
支持 OpenAI、Anthropic、DeepSeek、Aliyun 等所有 LiteLLM 兼容的 provider。
"""

import os
from typing import Optional, Tuple

import litellm
from litellm import acompletion

from src.ai.client import AIClient
from src.ai.models import AIProvider, AIRequest, AIResponse
from src.core.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Provider 到 LiteLLM model prefix 的映射
LITELLM_PROVIDER_PREFIX = {
    AIProvider.OPENAI: "openai",
    AIProvider.ANTHROPIC: "anthropic",
    AIProvider.DEEPSEEK: "deepseek",
    AIProvider.ALIYUN: "aliyun",
}


class LiteLLMClient(AIClient):
    """LiteLLM 统一网关客户端

    通过 LiteLLM 调用所有 AI provider，使用统一的 ac
    ompletion() 接口。
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        provider: Optional[AIProvider] = None,
    ) -> None:
        super().__init__(config)
        self._provider = provider or AIProvider.OPENAI
        self._api_key: Optional[str] = None
        self._base_url: Optional[str] = None

    @property
    def provider(self) -> AIProvider:
        return self._provider

    async def initialize(self) -> None:
        """初始化客户端"""
        if self._initialized:
            return

        self._resolve_credentials()
        self._initialized = True
        logger.info(
            f"LiteLLM client initialized for provider={self._provider.value}, "
            f"base_url={self._base_url or 'default'}"
        )

    def _resolve_credentials(self) -> None:
        """解析 API key 和 base_url"""
        cfg = self.config.ai

        # API Key 解析逻辑（按优先级）
        api_key = cfg.api_key
        if not api_key:
            env_map = {
                AIProvider.OPENAI: "OPENAI_API_KEY",
                AIProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
                AIProvider.DEEPSEEK: "DEEPSEEK_API_KEY",
                AIProvider.ALIYUN: "ALIYUN_API_KEY",
            }
            env_var = env_map.get(self._provider, "OPENAI_API_KEY")
            api_key = os.getenv(env_var)
            if not api_key:
                api_key = os.getenv("HOS_LS_AI_API_KEY")

        if not api_key:
            raise ValueError(
                f"{self._provider.value} API key not set. "
                f"Set config ai.api_key or environment variable."
            )

        self._api_key = api_key

        # Base URL 解析
        base_url = cfg.base_url
        if not base_url:
            provider_defaults = {
                AIProvider.DEEPSEEK: "https://api.deepseek.com",
                AIProvider.ALIYUN: "https://dashscope.aliyuncs.com/compatible-mode/v1",
            }
            base_url = provider_defaults.get(self._provider)

        self._base_url = base_url

        # Proxy 支持：通过环境变量设置，避免传递 http_client 导致序列化错误
        if self._provider in (AIProvider.DEEPSEEK, AIProvider.ALIYUN):
            try:
                from src.utils.proxy_detection import get_proxy_with_fallback

                proxy_url = cfg.proxy_url if hasattr(cfg, 'proxy_url') else None
                proxy_url = proxy_url or get_proxy_with_fallback()
                if proxy_url:
                    os.environ["HTTPS_PROXY"] = proxy_url
                    os.environ["HTTP_PROXY"] = proxy_url
                    if not self.config.quiet:
                        from rich.console import Console
                        console = Console()
                        console.print(f"[bold cyan][PROXY] 使用代理: {proxy_url}[/bold cyan]")
            except Exception:
                pass

    async def close(self) -> None:
        """关闭客户端"""
        self._initialized = False

    def _build_litellm_model(self, request: AIRequest) -> str:
        """构建 LiteLLM model 字符串

        格式: "provider/model_name"
        例如: "openai/gpt-4", "anthropic/claude-3-5-sonnet-20241022",
              "deepseek/deepseek-chat", "aliyun/qwen3-coder-next"
        """
        prefix = LITELLM_PROVIDER_PREFIX.get(self._provider, self._provider.value)
        model_name = request.model or self.config.ai.model

        # 默认模型
        if not model_name:
            default_models = {
                AIProvider.OPENAI: "gpt-4",
                AIProvider.ANTHROPIC: "claude-3-5-sonnet-20241022",
                AIProvider.DEEPSEEK: "deepseek-chat",
                AIProvider.ALIYUN: "qwen3-coder-next",
            }
            model_name = default_models.get(self._provider, "gpt-4")

        # Aliyun 特殊处理：LiteLLM 对 dashscope 使用 dashscope/ 前缀
        if self._provider == AIProvider.ALIYUN:
            prefix = "dashscope"

        return f"{prefix}/{model_name}"

    async def generate(self, request: AIRequest) -> AIResponse:
        """生成响应

        Args:
            request: AI 请求

        Returns:
            AI 响应
        """
        if not self._initialized:
            raise RuntimeError("客户端未初始化")

        litellm_model = self._build_litellm_model(request)

        # 构建 messages
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})

        if request.multimodal_content:
            # 多模态内容处理
            content = self._build_multimodal_content(request)
            messages.append({"role": "user", "content": content})
        else:
            messages.append({"role": "user", "content": request.prompt})

        # 构建 extra_body（用于 base_url 等自定义参数）
        extra_body = {}
        if self._base_url:
            extra_body["api_base"] = self._base_url

        logger.info(f"LiteLLM API call: model={litellm_model}, provider={self._provider.value}")

        try:
            response = await acompletion(
                model=litellm_model,
                messages=messages,
                api_key=self._api_key,
                api_base=self._base_url,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
            )

            # 提取 usage 信息
            usage = {}
            if response and hasattr(response, 'usage') and response.usage:
                usage = {
                    "prompt_tokens": getattr(response.usage, 'prompt_tokens', 0) or 0,
                    "completion_tokens": getattr(response.usage, 'completion_tokens', 0) or 0,
                    "total_tokens": getattr(response.usage, 'total_tokens', 0) or 0,
                }
                # Anthropic 使用不同的字段名
                if not usage.get("prompt_tokens"):
                    input_tokens = getattr(response.usage, 'input_tokens', 0) or 0
                    output_tokens = getattr(response.usage, 'output_tokens', 0) or 0
                    if input_tokens or output_tokens:
                        usage = {
                            "prompt_tokens": input_tokens,
                            "completion_tokens": output_tokens,
                            "total_tokens": input_tokens + output_tokens,
                        }

            # 提取内容
            content = ""
            if response and hasattr(response, 'choices') and response.choices:
                choice = response.choices[0]
                if hasattr(choice, 'message') and hasattr(choice.message, 'content'):
                    content = choice.message.content or ""

            return AIResponse(
                content=content,
                model=litellm_model,
                provider=self._provider,
                usage=usage,
                raw_response=response,
            )

        except Exception as e:
            logger.error(f"LiteLLM API call failed: {e}")
            raise

    def _build_multimodal_content(self, request: AIRequest) -> list:
        """构建多模态内容"""
        content = []
        content.append({"type": "text", "text": request.prompt})

        for item in request.multimodal_content:
            if item.type == "image":
                if self._provider == AIProvider.ANTHROPIC:
                    # Anthropic 格式
                    content.append({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": item.content,
                        }
                    })
                else:
                    # OpenAI 兼容格式
                    content.append({
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{item.content}"
                        }
                    })

        return content

    def is_available(self) -> bool:
        """检查客户端是否可用"""
        return self._initialized and self._api_key is not None

    async def validate_api_access(self) -> Tuple[bool, str]:
        """验证 API 访问

        Returns:
            Tuple[bool, str]: (是否成功, 错误信息)
        """
        try:
            if not self._initialized:
                return False, "Client not initialized"

            # 构建最小测试请求
            test_model = self._build_litellm_model(AIRequest(
                prompt="Hello",
                max_tokens=10,
                temperature=0.0,
            ))

            response = await acompletion(
                model=test_model,
                messages=[{"role": "user", "content": "Hello"}],
                api_key=self._api_key,
                api_base=self._base_url,
                max_tokens=10,
                timeout=10,
            )

            logger.info(f"LiteLLM API access validated for {self._provider.value}")
            return True, ""
        except Exception as e:
            error_msg = str(e)
            logger.error(f"LiteLLM API validation failed for {self._provider.value}: {error_msg}")
            return False, f"API validation failed: {error_msg}"
