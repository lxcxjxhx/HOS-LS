"""Token消耗预估和费用计算模块

提供基于文件数量的Token消耗预估和API费用计算功能。
支持联网获取最新定价并本地缓存，每月自动更新。
"""

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any, List

from src.utils.logger import get_logger
from src.utils.cache_manager import get_cache_manager

logger = get_logger(__name__)

PRICING_CONFIG: Dict[str, Dict[str, float]] = {
    "deepseek": {
        "v4": {
            "input_price": 0.0015,
            "output_price": 0.002,
            "display_name": "DeepSeek V4"
        },
        "v3": {
            "input_price": 0.001,
            "output_price": 0.002,
            "display_name": "DeepSeek V3"
        }
    },
    "openai": {
        "gpt-4o": {
            "input_price": 0.0025,
            "output_price": 0.01,
            "display_name": "GPT-4o"
        },
        "gpt-4o-mini": {
            "input_price": 0.00015,
            "output_price": 0.0006,
            "display_name": "GPT-4o Mini"
        },
        "gpt-4-turbo": {
            "input_price": 0.01,
            "output_price": 0.03,
            "display_name": "GPT-4 Turbo"
        }
    },
    "anthropic": {
        "claude-3-5-sonnet": {
            "input_price": 0.003,
            "output_price": 0.015,
            "display_name": "Claude 3.5 Sonnet"
        },
        "claude-3-opus": {
            "input_price": 0.015,
            "output_price": 0.075,
            "display_name": "Claude 3 Opus"
        },
        "claude-3-haiku": {
            "input_price": 0.00025,
            "output_price": 0.00125,
            "display_name": "Claude 3 Haiku"
        }
    },
    "aliyun": {
        "qwen-plus": {
            "input_price": 0.0004,
            "output_price": 0.0012,
            "display_name": "Qwen Plus"
        },
        "qwen-max": {
            "input_price": 0.02,
            "output_price": 0.06,
            "display_name": "Qwen Max"
        }
    }
}

MODEL_ALIASES = {
    "deepseek-v4-pro": "deepseek/v4",
    "deepseek-v4": "deepseek/v4",
    "deepseek-v3": "deepseek/v3",
    "gpt-4o": "openai/gpt-4o",
    "gpt-4o-mini": "openai/gpt-4o-mini",
    "gpt-4-turbo": "openai/gpt-4-turbo",
    "claude-3-5-sonnet": "anthropic/claude-3-5-sonnet",
    "claude-3-opus": "anthropic/claude-3-opus",
    "claude-3-haiku": "anthropic/claude-3-haiku",
    "qwen-plus": "aliyun/qwen-plus",
    "qwen-max": "aliyun/qwen-max",
}

TOKEN_ESTIMATE_CONFIG = {
    "min_input_per_file": 5000,
    "max_input_per_file": 10000,
    "min_output_per_file": 2000,
    "max_output_per_file": 5000,
    "default_input_per_file": 7500,
    "default_output_per_file": 3500
}

CACHE_EXPIRY_DAYS = 30


@dataclass
class CostEstimate:
    """费用预估结果"""
    file_count: int
    provider: str
    model: str
    estimated_prompt_tokens: int
    estimated_completion_tokens: int
    estimated_total_tokens: int
    estimated_input_cost: float
    estimated_output_cost: float
    estimated_total_cost: float
    pricing_source: str = "default"


class PricingCache:
    """定价缓存管理器"""

    def __init__(self):
        cache_manager = get_cache_manager()
        self._cache_dir = cache_manager.get_path('pricing', '')
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file = self._cache_dir / 'api_pricing.json'
        self._last_update_file = self._cache_dir / 'pricing_last_update.txt'

    def is_cache_valid(self) -> bool:
        """检查缓存是否有效（未过期）"""
        if not self._cache_file.exists():
            return False

        if not self._last_update_file.exists():
            return False

        try:
            with open(self._last_update_file, 'r', encoding='utf-8') as f:
                last_update = datetime.fromisoformat(f.read().strip())
            return datetime.now() - last_update < timedelta(days=CACHE_EXPIRY_DAYS)
        except Exception:
            return False

    def save_pricing(self, pricing: Dict[str, Any]) -> None:
        """保存定价到缓存"""
        try:
            with open(self._cache_file, 'w', encoding='utf-8') as f:
                json.dump(pricing, f, ensure_ascii=False, indent=2)
            with open(self._last_update_file, 'w', encoding='utf-8') as f:
                f.write(datetime.now().isoformat())
            logger.info(f"定价已缓存到: {self._cache_file}")
        except Exception as e:
            logger.error(f"保存定价缓存失败: {e}")

    def load_pricing(self) -> Optional[Dict[str, Any]]:
        """从缓存加载定价"""
        if not self._cache_file.exists():
            return None
        try:
            with open(self._cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载定价缓存失败: {e}")
            return None

    def get_last_update_time(self) -> Optional[str]:
        """获取上次更新时间"""
        if not self._last_update_file.exists():
            return None
        try:
            with open(self._last_update_file, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except Exception:
            return None


class OnlinePricingFetcher:
    """联网获取定价信息"""

    def __init__(self):
        self._pricing_cache = PricingCache()

    def fetch_pricing(self, force_update: bool = False) -> Dict[str, Any]:
        """获取定价信息，优先从缓存加载，缓存过期则联网获取

        Args:
            force_update: 是否强制更新

        Returns:
            Dict: 定价配置字典
        """
        if not force_update and self._pricing_cache.is_cache_valid():
            cached = self._pricing_cache.load_pricing()
            if cached:
                logger.info("使用缓存的定价信息")
                return cached

        logger.info("正在联网获取最新定价信息...")

        try:
            pricing = self._fetch_from_ai()
            self._pricing_cache.save_pricing(pricing)
            return pricing
        except Exception as e:
            logger.error(f"联网获取定价失败: {e}")
            cached = self._pricing_cache.load_pricing()
            if cached:
                return cached
            return PRICING_CONFIG

    def _fetch_from_ai(self) -> Dict[str, Any]:
        """使用AI+联网搜索获取最新定价"""
        try:
            from src.ai.client import get_ai_client
            ai_client = get_ai_client()

            prompt = """请查询以下AI模型的最新API定价信息（2025年5月）：

1. DeepSeek V4 / V3 - 输入和输出价格（美元/千tokens）
2. OpenAI GPT-4o, GPT-4o Mini, GPT-4 Turbo - 输入和输出价格
3. Anthropic Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku - 输入和输出价格
4. 阿里云 Qwen Plus, Qwen Max - 输入和输出价格

请以JSON格式返回，格式如下：
{
  "deepseek": {
    "v4": {"input_price": 0.0015, "output_price": 0.002, "display_name": "DeepSeek V4"},
    "v3": {"input_price": 0.001, "output_price": 0.002, "display_name": "DeepSeek V3"}
  },
  "openai": {
    "gpt-4o": {"input_price": 0.0025, "output_price": 0.01, "display_name": "GPT-4o"},
    ...
  }
}

只返回JSON，不要其他文字。"""

            response = ai_client.generate(prompt, system_prompt="你是一个AI API定价查询助手。请只返回JSON格式的定价数据，不要有任何其他文字。")

            if response and response.content:
                content = response.content.strip()
                if content.startswith('```json'):
                    content = content[7:]
                if content.startswith('```'):
                    content = content[3:]
                if content.endswith('```'):
                    content = content[:-3]

                pricing = json.loads(content)
                logger.info("成功从AI获取最新定价信息")
                return pricing
        except Exception as e:
            logger.error(f"AI获取定价失败: {e}")

        return PRICING_CONFIG


class CostEstimator:
    """Token消耗预估和费用计算器"""

    def __init__(self):
        """初始化费用计算器"""
        self._pricing_cache = PricingCache()
        self._pricing_fetcher = OnlinePricingFetcher()
        self._pricing = self._load_pricing()
        self._token_config = TOKEN_ESTIMATE_CONFIG

    def _load_pricing(self) -> Dict[str, Any]:
        """加载定价配置"""
        return self._pricing_fetcher.fetch_pricing()

    def refresh_pricing(self, force: bool = False) -> None:
        """刷新定价信息

        Args:
            force: 是否强制刷新
        """
        self._pricing = self._pricing_fetcher.fetch_pricing(force_update=force)
        last_update = self._pricing_cache.get_last_update_time()
        logger.info(f"定价已更新，上次更新: {last_update or '从未更新'}")

    def get_pricing_source(self) -> str:
        """获取定价来源"""
        last_update = self._pricing_cache.get_last_update_time()
        if last_update:
            return f"在线获取 (缓存于 {last_update[:10]})"
        return "默认配置"

    def estimate_tokens(self, file_count: int, provider: str = "deepseek",
                       model: str = "v4") -> Dict[str, int]:
        """基于文件数量预估Token消耗

        Args:
            file_count: 文件数量
            provider: AI提供商 (deepseek/openai/anthropic/aliyun)
            model: 模型名称

        Returns:
            Dict[str, int]: 包含预估的prompt_tokens、completion_tokens和total_tokens
        """
        if file_count <= 0:
            logger.warning(f"无效的文件数量: {file_count}, 将使用0进行计算")
            return {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            }

        config = self._token_config
        prompt_tokens = file_count * config["default_input_per_file"]
        completion_tokens = file_count * config["default_output_per_file"]
        total_tokens = prompt_tokens + completion_tokens

        logger.info(f"预估 {file_count} 个文件的Token消耗: "
                   f"{prompt_tokens} prompt tokens, {completion_tokens} completion tokens, "
                   f"共 {total_tokens} tokens")

        return {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens
        }

    def calculate_cost(self, prompt_tokens: int, completion_tokens: int,
                      provider: str, model: str) -> float:
        """计算API调用费用

        Args:
            prompt_tokens: 提示词token数量
            completion_tokens: 完成token数量
            provider: AI提供商
            model: 模型名称

        Returns:
            float: 预估费用（美元）
        """
        provider_lower = provider.lower()
        model_lower = model.lower()

        alias_key = f"{provider_lower}-{model_lower}"
        if alias_key in MODEL_ALIASES:
            resolved = MODEL_ALIASES[alias_key]
            provider_lower, model_lower = resolved.split('/')

        if provider_lower not in self._pricing:
            logger.warning(f"未知的提供商: {provider}, 使用DeepSeek V4默认价格")
            provider_lower = "deepseek"
            model_lower = "v4"

        provider_pricing = self._pricing.get(provider_lower, {})
        model_pricing = None

        for key, config in provider_pricing.items():
            if model_lower == key.lower():
                model_pricing = config
                break

        if model_pricing is None:
            logger.warning(f"未找到模型 {model} 的定价信息, 使用默认配置")
            model_pricing = {
                "input_price": 0.001,
                "output_price": 0.002,
                "display_name": f"{provider} {model}"
            }

        input_cost = (prompt_tokens / 1000) * model_pricing["input_price"]
        output_cost = (completion_tokens / 1000) * model_pricing["output_price"]
        total_cost = input_cost + output_cost

        logger.info(f"费用计算: {prompt_tokens} prompt tokens + "
                   f"{completion_tokens} completion tokens @ {provider} {model} = "
                   f"${total_cost:.6f}")

        return round(total_cost, 6)

    def format_estimate(self, estimate_result: Dict[str, Any]) -> str:
        """格式化预估结果展示

        Args:
            estimate_result: estimate()返回的预估结果字典

        Returns:
            str: 格式化的预估结果字符串
        """
        if isinstance(estimate_result, dict):
            if "estimated_total_cost" in estimate_result:
                return self._format_full_estimate(estimate_result)
            elif "prompt_tokens" in estimate_result:
                return self._format_tokens_only(estimate_result)
            else:
                return str(estimate_result)
        return str(estimate_result)

    def _format_full_estimate(self, estimate: CostEstimate) -> str:
        """格式化完整预估结果"""
        lines = [
            "=" * 50,
            "           Token消耗与费用预估报告",
            "=" * 50,
            f"  文件数量:     {estimate.file_count}",
            f"  提供商:       {estimate.provider}",
            f"  模型:         {estimate.model}",
            "-" * 50,
            f"  预估输入Token:   {estimate.estimated_prompt_tokens:,}",
            f"  预估输出Token:   {estimate.estimated_completion_tokens:,}",
            f"  预估总Token:     {estimate.estimated_total_tokens:,}",
            "-" * 50,
            f"  预估输入费用:    ${estimate.estimated_input_cost:.6f}",
            f"  预估输出费用:    ${estimate.estimated_output_cost:.6f}",
            f"  预估总费用:      ${estimate.estimated_total_cost:.6f}",
            f"  定价来源:       {estimate.pricing_source}",
            "=" * 50
        ]
        return "\n".join(lines)

    def _format_tokens_only(self, tokens: Dict[str, int]) -> str:
        """格式化仅Token预估结果"""
        lines = [
            "=" * 40,
            "         Token消耗预估",
            "=" * 40,
            f"  预估输入Token:   {tokens['prompt_tokens']:,}",
            f"  预估输出Token:   {tokens['completion_tokens']:,}",
            f"  预估总Token:     {tokens['total_tokens']:,}",
            "=" * 40
        ]
        return "\n".join(lines)

    def estimate(self, file_count: int, provider: str = "deepseek",
                model: str = "v4") -> CostEstimate:
        """综合预估方法

        整合Token预估和费用计算，返回完整的预估结果。

        Args:
            file_count: 文件数量
            provider: AI提供商
            model: 模型名称

        Returns:
            CostEstimate: 完整的费用预估结果
        """
        tokens = self.estimate_tokens(file_count, provider, model)
        total_cost = self.calculate_cost(
            tokens["prompt_tokens"],
            tokens["completion_tokens"],
            provider,
            model
        )

        provider_lower = provider.lower()
        model_lower = model.lower()

        alias_key = f"{provider_lower}-{model_lower}"
        if alias_key in MODEL_ALIASES:
            resolved = MODEL_ALIASES[alias_key]
            provider_lower, model_lower = resolved.split('/')

        provider_pricing = self._pricing.get(provider_lower, {})
        model_pricing = provider_pricing.get(model_lower, {
            "input_price": 0.001,
            "output_price": 0.002
        })

        input_cost = (tokens["prompt_tokens"] / 1000) * model_pricing["input_price"]
        output_cost = (tokens["completion_tokens"] / 1000) * model_pricing["output_price"]

        estimate = CostEstimate(
            file_count=file_count,
            provider=provider,
            model=model,
            estimated_prompt_tokens=tokens["prompt_tokens"],
            estimated_completion_tokens=tokens["completion_tokens"],
            estimated_total_tokens=tokens["total_tokens"],
            estimated_input_cost=round(input_cost, 6),
            estimated_output_cost=round(output_cost, 6),
            estimated_total_cost=total_cost,
            pricing_source=self.get_pricing_source()
        )

        logger.info(f"完成预估: {file_count} 文件 @ {provider} {model} = ${total_cost:.6f}")
        return estimate

    def get_available_providers(self) -> Dict[str, list]:
        """获取所有可用的提供商和模型

        Returns:
            Dict[str, list]: 提供商及其模型的字典
        """
        result = {}
        for provider, models in self._pricing.items():
            result[provider] = list(models.keys())
        return result

    def get_model_pricing(self, provider: str, model: str) -> Optional[Dict[str, float]]:
        """获取指定模型的定价信息

        Args:
            provider: AI提供商
            model: 模型名称

        Returns:
            Optional[Dict[str, float]]: 定价信息，如果未找到则返回None
        """
        provider_lower = provider.lower()
        model_lower = model.lower()

        alias_key = f"{provider_lower}-{model_lower}"
        if alias_key in MODEL_ALIASES:
            resolved = MODEL_ALIASES[alias_key]
            provider_lower, model_lower = resolved.split('/')

        provider_pricing = self._pricing.get(provider_lower, {})
        for key, config in provider_pricing.items():
            if model_lower == key.lower():
                return config
        return None


_estimator: Optional[CostEstimator] = None


def get_cost_estimator() -> CostEstimator:
    """获取CostEstimator单例实例

    Returns:
        CostEstimator: 费用估算器实例
    """
    global _estimator
    if _estimator is None:
        _estimator = CostEstimator()
    return _estimator
