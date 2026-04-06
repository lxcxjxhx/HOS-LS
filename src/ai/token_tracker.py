"""Token使用跟踪模块

用于跟踪、记录和分析AI API的token消耗。
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

from src.core.config import get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class TokenTracker:
    """Token使用跟踪器"""

    def __init__(self):
        """初始化Token跟踪器"""
        self.config = get_config()
        self._token_usage: List[Dict[str, Any]] = []
        self._cache: Dict[str, Any] = {}
        self._cache_hits = 0
        self._cache_misses = 0
        self._total_tokens = 0
        self._total_calls = 0
        self._save_path = os.path.join(
            os.getcwd(),
            "token_usage.json"
        )
        self._load_usage_history()

    def track_usage(self, provider: str, model: str, prompt_tokens: int, 
                   completion_tokens: int, total_tokens: int, 
                   duration: float, success: bool = True) -> None:
        """跟踪token使用

        Args:
            provider: AI提供商
            model: 使用的模型
            prompt_tokens: 提示词token数
            completion_tokens: 完成token数
            total_tokens: 总token数
            duration: 执行时间（秒）
            success: 是否成功
        """
        usage_record = {
            "timestamp": datetime.now().isoformat(),
            "provider": provider,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "duration": duration,
            "success": success
        }
        
        self._token_usage.append(usage_record)
        self._total_tokens += total_tokens
        self._total_calls += 1
        
        logger.info(f"Token usage: {total_tokens} tokens ({prompt_tokens} prompt, {completion_tokens} completion) "
                   f"from {provider} {model} in {duration:.2f}s")
        
        # 定期保存
        if len(self._token_usage) % 10 == 0:
            self.save_usage_history()

    def get_cache_key(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """生成缓存键

        Args:
            prompt: 提示词
            system_prompt: 系统提示词

        Returns:
            str: 缓存键
        """
        import hashlib
        key = f"{system_prompt or ''}:{prompt}"
        return hashlib.md5(key.encode()).hexdigest()

    def check_cache(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[Any]:
        """检查缓存

        Args:
            prompt: 提示词
            system_prompt: 系统提示词

        Returns:
            Optional[Any]: 缓存的结果，如果没有则返回None
        """
        cache_key = self.get_cache_key(prompt, system_prompt)
        if cache_key in self._cache:
            self._cache_hits += 1
            logger.debug(f"Cache hit for prompt")
            return self._cache[cache_key]
        else:
            self._cache_misses += 1
            logger.debug(f"Cache miss for prompt")
            return None

    def add_to_cache(self, prompt: str, system_prompt: Optional[str] = None, 
                     result: Any = None) -> None:
        """添加到缓存

        Args:
            prompt: 提示词
            system_prompt: 系统提示词
            result: 结果
        """
        cache_key = self.get_cache_key(prompt, system_prompt)
        self._cache[cache_key] = result
        # 限制缓存大小
        if len(self._cache) > 1000:
            # 移除最旧的缓存项
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]

    def get_usage_stats(self) -> Dict[str, Any]:
        """获取使用统计

        Returns:
            Dict[str, Any]: 使用统计
        """
        if not self._token_usage:
            return {
                "total_calls": 0,
                "total_tokens": 0,
                "average_tokens_per_call": 0,
                "average_duration": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "cache_hit_rate": 0
            }
        
        total_duration = sum(record["duration"] for record in self._token_usage)
        cache_hit_rate = self._cache_hits / (self._cache_hits + self._cache_misses) * 100 if \
            (self._cache_hits + self._cache_misses) > 0 else 0
        
        return {
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
            "average_tokens_per_call": self._total_tokens / self._total_calls,
            "average_duration": total_duration / len(self._token_usage),
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_rate": cache_hit_rate
        }

    def get_provider_stats(self) -> Dict[str, Dict[str, Any]]:
        """获取提供商统计

        Returns:
            Dict[str, Dict[str, Any]]: 提供商统计
        """
        stats = {}
        for record in self._token_usage:
            provider = record["provider"]
            if provider not in stats:
                stats[provider] = {
                    "total_calls": 0,
                    "total_tokens": 0,
                    "total_duration": 0,
                    "success_count": 0
                }
            
            stats[provider]["total_calls"] += 1
            stats[provider]["total_tokens"] += record["total_tokens"]
            stats[provider]["total_duration"] += record["duration"]
            if record["success"]:
                stats[provider]["success_count"] += 1
        
        # 计算平均值
        for provider, data in stats.items():
            data["average_tokens_per_call"] = data["total_tokens"] / data["total_calls"]
            data["average_duration"] = data["total_duration"] / data["total_calls"]
            data["success_rate"] = data["success_count"] / data["total_calls"] * 100
        
        return stats

    def save_usage_history(self) -> None:
        """保存使用历史"""
        try:
            os.makedirs(os.path.dirname(self._save_path), exist_ok=True)
            with open(self._save_path, 'w', encoding='utf-8') as f:
                json.dump(self._token_usage, f, ensure_ascii=False, indent=2)
            logger.info(f"Saved token usage history to {self._save_path}")
        except Exception as e:
            logger.error(f"Failed to save token usage history: {e}")

    def _load_usage_history(self) -> None:
        """加载使用历史"""
        try:
            if os.path.exists(self._save_path):
                with open(self._save_path, 'r', encoding='utf-8') as f:
                    self._token_usage = json.load(f)
                # 计算历史统计
                self._total_calls = len(self._token_usage)
                self._total_tokens = sum(record["total_tokens"] for record in self._token_usage)
                logger.info(f"Loaded {len(self._token_usage)} token usage records")
        except Exception as e:
            logger.error(f"Failed to load token usage history: {e}")

    def generate_report(self) -> str:
        """生成使用报告

        Returns:
            str: 使用报告
        """
        stats = self.get_usage_stats()
        provider_stats = self.get_provider_stats()
        
        report = f"""# Token使用报告

## 总体统计
- 总API调用次数: {stats['total_calls']}
- 总Token消耗: {stats['total_tokens']}
- 平均每次调用Token消耗: {stats['average_tokens_per_call']:.2f}
- 平均响应时间: {stats['average_duration']:.2f}秒
- 缓存命中次数: {stats['cache_hits']}
- 缓存未命中次数: {stats['cache_misses']}
- 缓存命中率: {stats['cache_hit_rate']:.2f}%

## 提供商统计
"""
        
        for provider, data in provider_stats.items():
            report += f"\n### {provider}\n"
            report += f"- 调用次数: {data['total_calls']}\n"
            report += f"- Token消耗: {data['total_tokens']}\n"
            report += f"- 平均Token消耗: {data['average_tokens_per_call']:.2f}\n"
            report += f"- 平均响应时间: {data['average_duration']:.2f}秒\n"
            report += f"- 成功率: {data['success_rate']:.2f}%\n"
        
        return report


# 全局Token跟踪器实例
_token_tracker: Optional[TokenTracker] = None


def get_token_tracker() -> TokenTracker:
    """获取Token跟踪器实例

    Returns:
        TokenTracker: Token跟踪器实例
    """
    global _token_tracker
    if _token_tracker is None:
        _token_tracker = TokenTracker()
    return _token_tracker
