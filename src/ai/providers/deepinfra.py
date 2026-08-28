"""DeepInfra 客户端

提供与 DeepInfra API 的集成，支持 flex 模式（通过请求头启用）。
DeepInfra 的 flex 模式允许使用非标准模型（如自定义/社区模型）。

关于 flex 模式：
- 标准模式：仅使用 DeepInfra 官方托管的模型
- flex 模式：允许使用社区/自定义模型，通过请求头 X-DeepInfra-Flex: true 启用
- 用户要求在请求头中加入 flex 模式开启选择，仅 DeepInfra 支持
"""

import asyncio
import os
from typing import Any, Dict, List, Optional, Tuple, cast

from aiohttp import ClientError as AiohttpClientError
from openai import APIStatusError as OpenAIAPIStatusError
from openai import AsyncOpenAI

from src.ai.client import AIClient
from src.ai.key_manager import get_api_key
from src.ai.models import AIProvider, AIRequest, AIResponse
from src.core.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class APIError(Exception):
    """API错误异常"""

    def __init__(self, code: int, message: str, should_truncate: bool = True):
        self.code = code
        self.message = message
        self.should_truncate = should_truncate
        super().__init__(f"[{code}] {message}")

    @classmethod
    def from_exception(cls, error: Exception) -> "APIError":
        """从异常创建APIError"""
        if isinstance(error, OpenAIAPIStatusError):
            code = error.status_code if hasattr(error, "status_code") else 0
            message = str(error)
            if code == 402:
                return cls(code, "API余额不足 (Insufficient Balance)", should_truncate=True)
            elif code == 429:
                return cls(code, "API限流 (Rate Limit)", should_truncate=True)
            elif code >= 500:
                return cls(code, f"API服务器错误 ({code})", should_truncate=True)
            else:
                return cls(code, f"API错误 ({code}): {message}", should_truncate=False)
        elif isinstance(error, asyncio.TimeoutError):
            return cls(0, "API请求超时 (Timeout)", should_truncate=True)
        elif isinstance(error, (AiohttpClientError, ConnectionError, OSError)):
            return cls(0, f"API连接失败: {str(error)}", should_truncate=True)
        else:
            return cls(0, f"未知错误: {str(error)}", should_truncate=False)


class DeepInfraClient(AIClient):
    """DeepInfra 客户端

    DeepInfra 提供灵活的模型托管服务，通过 flex 模式支持社区模型。
    所有请求自动添加 flex 模式请求头，兼容 OpenAI SDK。
    """

    DEFAULT_BASE_URL = "https://api.deepinfra.com/v1/openai"

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(config)
        self._client: Optional[AsyncOpenAI] = None
        self._flex_mode: bool = True  # 默认开启 flex 模式（用户要求）

    @property
    def provider(self) -> AIProvider:
        return AIProvider.DEEPINFRA

    async def initialize(self) -> None:
        """初始化客户端"""
        if self._initialized:
            return

        # 使用 key_manager 获取 API 密钥（支持 .env 和多层 fallback）
        api_key = get_api_key("deepinfra", self._get_config_api_key())

        if not api_key:
            raise ValueError("DeepInfra API 密钥未设置")

        base_url = self._get_base_url()

        # 检查 flex 模式配置
        flex_mode = self._get_flex_mode()

        self._flex_mode = flex_mode

        # 使用 OpenAI SDK 创建客户端
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=getattr(self.config.ai, "request_timeout", 180) if self.config else 180,
            max_retries=0,
            # DeepInfra 需要自定义请求头来启用 flex 模式
            default_headers={
                "X-DeepInfra-Flex": "true" if flex_mode else "false",
                "User-Agent": "HOS-LS/1.0",
            } if flex_mode else {
                "User-Agent": "HOS-LS/1.0",
            },
        )
        self._initialized = True

        mode_str = "flex" if flex_mode else "standard"
        logger.info(f"DeepInfra 客户端初始化完成 (base_url={base_url}, mode={mode_str})")

    def _get_config_api_key(self) -> Optional[str]:
        """从配置中获取 DeepInfra 专属 api_key"""
        if self.config is None:
            return None
        # 优先读取 config.deepinfra.api_key（DeepInfra 专属配置节）
        deepinfra_cfg = getattr(self.config, "deepinfra", None) or getattr(self.config.ai, "deepinfra", None)
        if deepinfra_cfg and hasattr(deepinfra_cfg, "api_key"):
            return deepinfra_cfg.api_key
        return None

    def _get_base_url(self) -> str:
        """获取 base_url（支持 provider 专属配置）"""
        if self.config is None:
            return self.DEFAULT_BASE_URL

        # 读取 deepinfra 专属配置的 base_url
        deepinfra_cfg = getattr(self.config, "deepinfra", None) or getattr(self.config.ai, "deepinfra", None)
        if deepinfra_cfg and hasattr(deepinfra_cfg, "base_url") and deepinfra_cfg.base_url:
            return deepinfra_cfg.base_url

        # 兼容旧配置
        if getattr(self.config.ai, "base_url", None):
            return self.config.ai.base_url

        return self.DEFAULT_BASE_URL

    def _get_flex_mode(self) -> bool:
        """获取 flex 模式配置（默认开启）"""
        if self.config is None:
            return True
        deepinfra_cfg = getattr(self.config, "deepinfra", None) or getattr(self.config.ai, "deepinfra", None)
        if deepinfra_cfg and hasattr(deepinfra_cfg, "flex_mode"):
            return bool(deepinfra_cfg.flex_mode)
        return True  # 默认开启 flex 模式

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
            APIError: 当API返回错误时
        """
        if not self._client:
            raise RuntimeError("客户端未初始化")

        model = request.model or self._get_default_model()

        messages: List[Dict[str, Any]] = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})

        # 普通文本提示
        messages.append({"role": "user", "content": request.prompt})

        logger.info(f"DeepInfra API 调用，使用模型: {model} (flex={'true' if self._flex_mode else 'false'})")

        request_timeout = (
            request.timeout
            or (getattr(self.config.ai, "request_timeout", 180) if self.config else 180)
            or 180
        )

        try:
            kwargs: Dict[str, Any] = {
                "model": model,
                "messages": cast(Any, messages),
                "max_tokens": request.max_tokens,
                "temperature": request.temperature,
                "stream": False,
                "timeout": request_timeout,
            }
            if request.response_format:
                kwargs["response_format"] = request.response_format

            response = await self._client.chat.completions.create(**kwargs)

            assert hasattr(response, "choices")
            assert hasattr(response, "usage")
            assert response.usage is not None

            choice = response.choices[0]
            content = choice.message.content or ""

            return AIResponse(
                content=content,
                model=model,
                provider=AIProvider.DEEPINFRA,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                },
                raw_response=response,
            )
        except OpenAIAPIStatusError as e:
            # 兼容性回退：若模型不支持 response_format，去掉该参数重试一次
            if request.response_format and e.status_code in (400, 422):
                try:
                    logger.warning(f"response_format 不被支持，回退为普通模式重试: {str(e)[:120]}")
                    response = await self._client.chat.completions.create(
                        model=model,
                        messages=cast(Any, messages),
                        max_tokens=request.max_tokens,
                        temperature=request.temperature,
                        stream=False,
                        timeout=request_timeout,
                    )
                    choice = response.choices[0]
                    return AIResponse(
                        content=choice.message.content or "",
                        model=model,
                        provider=AIProvider.DEEPINFRA,
                        usage={
                            "prompt_tokens": response.usage.prompt_tokens,
                            "completion_tokens": response.usage.completion_tokens,
                            "total_tokens": response.usage.total_tokens,
                        },
                        raw_response=response,
                    )
                except Exception:
                    pass
            api_error = APIError.from_exception(e)
            logger.error(f"DeepInfra API 错误: {api_error.message}")
            raise api_error
        except asyncio.TimeoutError as e:
            api_error = APIError.from_exception(e)
            logger.error(f"DeepInfra API 超时: {api_error.message}")
            raise api_error
        except (AiohttpClientError, ConnectionError, OSError) as e:
            api_error = APIError.from_exception(e)
            logger.error(f"DeepInfra API 连接错误: {api_error.message}")
            raise api_error

    def _get_default_model(self) -> str:
        """获取默认模型"""
        if self.config is None:
            return "mistralai/Mixtral-8x22B-Instruct-v0.1"
        deepinfra_cfg = getattr(self.config, "deepinfra", None) or getattr(self.config.ai, "deepinfra", None)
        if deepinfra_cfg and hasattr(deepinfra_cfg, "model") and deepinfra_cfg.model:
            return deepinfra_cfg.model
        if getattr(self.config.ai, "model", None):
            return self.config.ai.model
        return "mistralai/Mixtral-8x22B-Instruct-v0.1"

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

            await self._client.chat.completions.create(
                model=self._get_default_model(),
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10,
                stream=False,
            )

            logger.info("DeepInfra API access validated successfully")
            return True, ""
        except Exception as e:
            error_msg = str(e)
            logger.error(f"DeepInfra API validation failed: {error_msg}")
            return False, f"API validation failed: {error_msg}"
