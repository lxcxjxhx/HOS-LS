"""AI 客户端模块

提供统一的 AI 客户端接口和多模型支持。
"""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type, Tuple

from src.ai.models import AIProvider, AIRequest, AIResponse
from src.core.config import Config, get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AIClient(ABC):
    """AI 客户端基类"""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()
        self._initialized = False

    @property
    @abstractmethod
    def provider(self) -> AIProvider:
        """提供商"""
        pass

    @abstractmethod
    async def initialize(self) -> None:
        """初始化客户端"""
        pass

    @abstractmethod
    async def close(self) -> None:
        """关闭客户端"""
        pass

    @abstractmethod
    async def generate(self, request: AIRequest) -> AIResponse:
        """生成响应

        Args:
            request: AI 请求

        Returns:
            AI 响应
        """
        pass

    async def generate_with_retry(self, request: AIRequest, max_retries: int = 3) -> AIResponse:
        """生成响应（带重试机制）

        Args:
            request: AI 请求
            max_retries: 最大重试次数

        Returns:
            AI 响应

        Raises:
            Exception: 所有重试都失败后抛出异常
        """
        try:
            from src.ai.token_tracker import get_token_tracker
        except ImportError:
            def get_token_tracker(*args, **kwargs):
                return None
        
        token_tracker = get_token_tracker()
        retries = 0
        last_error = None

        while retries <= max_retries:
            try:
                logger.info(f"AI API call attempt {retries + 1}/{max_retries + 1}")
                start_time = time.time()
                response = await self.generate(request)
                duration = time.time() - start_time
                
                # 记录token使用
                if response.usage and token_tracker:
                    token_tracker.track_usage(
                        provider=self.provider.value,
                        model=response.model,
                        prompt_tokens=response.usage.get("prompt_tokens", 0),
                        completion_tokens=response.usage.get("completion_tokens", 0),
                        total_tokens=response.usage.get("total_tokens", 0),
                        duration=duration,
                        success=True
                    )
                
                logger.info(f"AI API call successful in {duration:.1f}s")
                return response
            except Exception as e:
                error_msg = str(e)
                last_error = e
                logger.error(f"AI API call failed: {error_msg}")

                # 检查是否是速率限制错误
                if "rate limit" in error_msg.lower() or "429" in error_msg:
                    logger.warning("Rate limit detected, increasing backoff")
                    backoff_time = min(30, 5 * (retries + 1))  # 渐进式退避
                    await asyncio.sleep(backoff_time)
                elif "timeout" in error_msg.lower():
                    logger.warning("Timeout detected, retrying")
                    await asyncio.sleep(2)
                else:
                    # 其他错误，较短的退避
                    await asyncio.sleep(1)

                retries += 1

        # 所有重试都失败
        logger.error(f"AI API call failed after {max_retries + 1} attempts")
        raise last_error

    @abstractmethod
    def is_available(self) -> bool:
        """检查客户端是否可用"""
        pass

    @abstractmethod
    async def validate_api_access(self) -> Tuple[bool, str]:
        """验证 API 访问

        Returns:
            Tuple[bool, str]: (是否成功, 错误信息)
        """
        pass

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class AIModelManager:
    """AI 模型管理器

    管理多个 AI 客户端，提供统一的接口。
    """

    _instance: Optional["AIModelManager"] = None
    _clients: Dict[AIProvider, AIClient] = {}
    _initialized: bool = False

    def __new__(cls) -> "AIModelManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self._clients = {}
            self._initialized = True
            self._model_performance: Dict[AIProvider, Dict[str, Any]] = {}
            self._fallback_chain: List[AIProvider] = []

    async def initialize(self, config: Optional[Config] = None) -> None:
        """初始化管理器"""
        cfg = config or get_config()

        self._clients.clear()
        self._fallback_chain = []

        provider_map = {
            "anthropic": AIProvider.ANTHROPIC,
            "openai": AIProvider.OPENAI,
            "deepseek": AIProvider.DEEPSEEK,
            "aliyun": AIProvider.ALIYUN,
            "local": AIProvider.LOCAL,
        }

        provider = provider_map.get(cfg.ai.provider)
        if provider:
            await self._init_client(provider, cfg)
            self._fallback_chain = [provider]

            if cfg.ai.allow_fallback:
                for name, p in provider_map.items():
                    if p != provider:
                        try:
                            await self._init_client(p, cfg)
                            self._fallback_chain.append(p)
                        except Exception as e:
                            logger.warning(f"Failed to initialize fallback provider {name}: {e}")
                logger.info(f"回退机制已启用，fallback chain: {self._fallback_chain}")
            else:
                logger.info("回退机制已禁用，仅使用主provider")

        logger.info(f"Initialized model manager with fallback chain: {self._fallback_chain}")
        logger.info(f"Using provider: {cfg.ai.provider}")

    async def _init_client(self, provider: AIProvider, config: Config) -> None:
        """初始化客户端"""
        if provider in self._clients:
            return

        # 延迟导入以避免循环依赖
        if provider == AIProvider.ANTHROPIC:
            from src.ai.providers.anthropic import AnthropicClient

            client = AnthropicClient(config)
        elif provider == AIProvider.OPENAI:
            from src.ai.providers.openai import OpenAIClient

            client = OpenAIClient(config)
        elif provider == AIProvider.DEEPSEEK:
            from src.ai.providers.deepseek import DeepSeekClient

            client = DeepSeekClient(config)
        elif provider == AIProvider.ALIYUN:
            from src.ai.providers.aliyun import AliyunClient

            client = AliyunClient(config)
        else:
            return

        await client.initialize()
        self._clients[provider] = client

    async def close(self) -> None:
        """关闭所有客户端"""
        for client in self._clients.values():
            await client.close()
        self._clients.clear()

    def get_client(self, provider: AIProvider) -> Optional[AIClient]:
        """获取客户端

        Args:
            provider: 提供商

        Returns:
            客户端实例
        """
        return self._clients.get(provider)

    def get_default_client(self) -> Optional[AIClient]:
        """获取默认客户端"""
        cfg = get_config()
        provider_map = {
            "anthropic": AIProvider.ANTHROPIC,
            "openai": AIProvider.OPENAI,
            "deepseek": AIProvider.DEEPSEEK,
            "aliyun": AIProvider.ALIYUN,
            "local": AIProvider.LOCAL,
        }
        provider = provider_map.get(cfg.ai.provider)
        if provider:
            return self._clients.get(provider)
        return None

    async def generate(
        self, request: AIRequest, provider: Optional[AIProvider] = None
    ) -> AIResponse:
        """生成响应

        Args:
            request: AI 请求
            provider: 提供商，如果为 None 则使用默认提供商

        Returns:
            AI 响应
        """
        from src.ai.token_tracker import get_token_tracker
        
        token_tracker = get_token_tracker()
        
        if not token_tracker:
            raise RuntimeError("Token tracker not available")
        
        # 检查缓存
        cached_response = token_tracker.check_cache(
            prompt=request.prompt,
            system_prompt=request.system_prompt
        )
        if cached_response:
            logger.info("Using cached AI response")
            return cached_response
        
        # 尝试使用指定的提供商或默认提供商
        if provider is None:
            # 使用回退链
            for fallback_provider in self._fallback_chain:
                client = self.get_client(fallback_provider)
                if client and client.is_available():
                    try:
                        start_time = time.time()
                        response = await client.generate_with_retry(request)
                        duration = time.time() - start_time
                        
                        # 更新性能统计
                        self._update_performance(fallback_provider, duration, True)
                        
                        # 添加到缓存
                        token_tracker.add_to_cache(
                            prompt=request.prompt,
                            system_prompt=request.system_prompt,
                            result=response
                        )
                        
                        if fallback_provider != self._fallback_chain[0]:
                            logger.warning(f"Using fallback provider: {fallback_provider}")
                        
                        return response
                    except Exception as e:
                        logger.warning(f"Provider {fallback_provider} failed: {e}")
                        # 更新性能统计
                        self._update_performance(fallback_provider, 0, False)
                        # 继续尝试下一个回退提供商
                        continue
        else:
            # 使用指定的提供商
            client = self.get_client(provider)
            if client and client.is_available():
                try:
                    start_time = time.time()
                    response = await client.generate_with_retry(request)
                    duration = time.time() - start_time
                    
                    # 更新性能统计
                    self._update_performance(provider, duration, True)
                    
                    # 添加到缓存
                    token_tracker.add_to_cache(
                        prompt=request.prompt,
                        system_prompt=request.system_prompt,
                        result=response
                    )
                    
                    return response
                except Exception as e:
                    logger.warning(f"Provider {provider} failed: {e}")
                    # 更新性能统计
                    self._update_performance(provider, 0, False)

        raise RuntimeError("All AI providers failed")

    def list_available_providers(self) -> List[AIProvider]:
        """列出可用的提供商"""
        return [
            provider
            for provider, client in self._clients.items()
            if client.is_available()
        ]

    async def validate_all_providers(self) -> Dict[AIProvider, Tuple[bool, str]]:
        """验证所有提供商的 API 访问

        Returns:
            Dict[AIProvider, Tuple[bool, str]]: 每个提供商的验证结果
        """
        results = {}
        for provider, client in self._clients.items():
            try:
                success, error_msg = await client.validate_api_access()
                results[provider] = (success, error_msg)
            except Exception as e:
                results[provider] = (False, f"Validation failed: {str(e)}")
        return results

    async def validate_provider(self, provider: AIProvider) -> Tuple[bool, str]:
        """验证指定提供商的 API 访问

        Args:
            provider: 提供商

        Returns:
            Tuple[bool, str]: (是否成功, 错误信息)
        """
        client = self.get_client(provider)
        if client:
            return await client.validate_api_access()
        return False, "Client not initialized"

    async def validate_default_provider(self) -> Tuple[bool, str]:
        """验证默认提供商的 API 访问

        Returns:
            Tuple[bool, str]: (是否成功, 错误信息)
        """
        client = self.get_default_client()
        if client:
            return await client.validate_api_access()
        return False, "Default client not initialized"

    def _update_performance(self, provider: AIProvider, duration: float, success: bool) -> None:
        """更新模型性能统计

        Args:
            provider: 提供商
            duration: 执行时间（秒）
            success: 是否成功
        """
        if provider not in self._model_performance:
            self._model_performance[provider] = {
                "total_calls": 0,
                "successful_calls": 0,
                "total_duration": 0.0,
                "average_duration": 0.0,
                "success_rate": 0.0
            }

        stats = self._model_performance[provider]
        stats["total_calls"] += 1
        if success:
            stats["successful_calls"] += 1
            stats["total_duration"] += duration
            stats["average_duration"] = stats["total_duration"] / stats["successful_calls"]
        stats["success_rate"] = stats["successful_calls"] / stats["total_calls"]

    def get_performance_stats(self) -> Dict[AIProvider, Dict[str, Any]]:
        """获取模型性能统计

        Returns:
            Dict[AIProvider, Dict[str, Any]]: 每个提供商的性能统计
        """
        return self._model_performance

    def get_fallback_chain(self) -> List[AIProvider]:
        """获取回退链

        Returns:
            List[AIProvider]: 回退链列表
        """
        return self._fallback_chain

    def set_fallback_chain(self, chain: List[AIProvider]) -> None:
        """设置回退链

        Args:
            chain: 回退链列表
        """
        self._fallback_chain = chain
        logger.info(f"Set fallback chain: {chain}")


# 全局实例
_manager: Optional[AIModelManager] = None


async def get_model_manager(config: Optional[Config] = None) -> AIModelManager:
    """获取模型管理器实例

    Args:
        config: 配置对象

    Returns:
        模型管理器实例
    """
    global _manager
    if _manager is None:
        _manager = AIModelManager()
        await _manager.initialize(config)
    return _manager
