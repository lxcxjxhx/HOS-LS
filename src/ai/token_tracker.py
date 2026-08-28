"""
Token使用追踪模块
用于追踪所有AI API调用的token使用情况
"""

import hashlib
import json
import os
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

# 内容寻址响应缓存：diskcache 已列入 requirements.txt
try:
    from diskcache import Cache as _DiskCache

    _CACHE_DIR = os.path.join(
        os.environ.get("HOS_LS_CACHE_DIR", ".cache"), "hos-ls", "llm-cache"
    )
    _RESPONSE_CACHE: Optional[_DiskCache] = _DiskCache(_CACHE_DIR)
except Exception:  # pragma: no cover - 缓存不可用时降级为无缓存
    _RESPONSE_CACHE = None

_DEFAULT_CACHE_TTL = int(os.environ.get("HOS_LS_LLM_CACHE_TTL", "86400"))  # 24小时


class TokenUsageRecord:
    """Token使用记录"""

    def __init__(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        duration: float,
        success: bool,
        cached: bool = False,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        agent_name: Optional[str] = None,
        file_path: Optional[str] = None,
        **kwargs,
    ):
        self.provider = provider
        self.model = model
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = total_tokens
        self.duration = duration
        self.success = success
        self.cached = cached
        self.prompt = prompt
        self.response = response
        self.agent_name = agent_name
        self.file_path = file_path
        self.timestamp = datetime.now().isoformat()
        self.extra = kwargs


class TokenTracker:
    """Token使用追踪器（单例模式）"""

    _instance: Optional["TokenTracker"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._token_usage: List[TokenUsageRecord] = []
        self._total_usage: Dict[str, int] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
        self._request_count = 0
        self._success_count = 0
        self._failure_count = 0

    @classmethod
    def get_instance(cls) -> "TokenTracker":
        """获取单例实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def track_usage(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        duration: float,
        success: bool,
        cached: bool = False,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        agent_name: Optional[str] = None,
        file_path: Optional[str] = None,
        **kwargs,
    ) -> None:
        """记录一次token使用"""
        record = TokenUsageRecord(
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            duration=duration,
            success=success,
            cached=cached,
            prompt=prompt,
            response=response,
            agent_name=agent_name,
            file_path=file_path,
            **kwargs,
        )
        self._token_usage.append(record)

        self._total_usage["prompt_tokens"] += prompt_tokens
        self._total_usage["completion_tokens"] += completion_tokens
        self._total_usage["total_tokens"] += total_tokens

        self._request_count += 1
        if success:
            self._success_count += 1
        else:
            self._failure_count += 1

    def get_usage_stats(self) -> Dict[str, Any]:
        """获取使用统计"""
        return {
            "total_usage": self._total_usage.copy(),
            "request_count": self._request_count,
            "success_count": self._success_count,
            "failure_count": self._failure_count,
            "avg_prompt_tokens": (
                self._total_usage["prompt_tokens"] / self._request_count
                if self._request_count > 0
                else 0
            ),
            "avg_completion_tokens": (
                self._total_usage["completion_tokens"] / self._request_count
                if self._request_count > 0
                else 0
            ),
            "avg_total_tokens": (
                self._total_usage["total_tokens"] / self._request_count
                if self._request_count > 0
                else 0
            ),
        }

    def get_recent_usage(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取最近的token使用记录"""
        records = self._token_usage[-limit:]
        return [
            {
                "provider": r.provider,
                "model": r.model,
                "prompt_tokens": r.prompt_tokens,
                "completion_tokens": r.completion_tokens,
                "total_tokens": r.total_tokens,
                "duration": r.duration,
                "success": r.success,
                "timestamp": r.timestamp,
                "cached": r.cached,
                "prompt": r.prompt[:200] + "..." if r.prompt and len(r.prompt) > 200 else r.prompt,
                "response": (
                    r.response[:200] + "..." if r.response and len(r.response) > 200 else r.response
                ),
                "agent_name": r.agent_name,
                "file_path": str(r.file_path) if r.file_path else "",
            }
            for r in records
        ]

    def reset(self) -> None:
        """重置所有统计"""
        self._token_usage.clear()
        self._total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        self._request_count = 0
        self._success_count = 0
        self._failure_count = 0

    @staticmethod
    def _cache_key(
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """生成内容寻址缓存键（模型 + 提示词 + 采样参数）。"""
        payload = json.dumps(
            {
                "model": model or "",
                "system_prompt": system_prompt or "",
                "prompt": prompt,
                "temperature": temperature if temperature is not None else 0.0,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def check_cache(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> Optional[Any]:
        """检查响应缓存（内容寻址，同一 prompt 不重复付费）。

        命中时返回 AIResponse 对象，否则返回 None。
        """
        if _RESPONSE_CACHE is None or not prompt:
            return None
        try:
            key = self._cache_key(prompt, system_prompt, model, temperature)
            data = _RESPONSE_CACHE.get(key)
            if not data:
                return None
            from src.ai.models import AIProvider, AIResponse

            provider = data.get("provider", "")
            provider_enum = next(
                (p for p in AIProvider if p.value == provider),
                AIProvider.DEEPSEEK,
            )
            return AIResponse(
                content=data.get("content", ""),
                model=data.get("model", ""),
                provider=provider_enum,
                usage=data.get("usage", {}),
                metadata={"cached": True},
            )
        except Exception:
            return None

    def add_to_cache(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        result: Any = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> None:
        """添加到响应缓存。"""
        if _RESPONSE_CACHE is None or result is None or not prompt:
            return
        try:
            if hasattr(result, "to_dict"):
                data = result.to_dict()
            elif isinstance(result, dict):
                data = result
            else:
                return
            key = self._cache_key(prompt, system_prompt, model, temperature)
            _RESPONSE_CACHE.set(key, data, expire=_DEFAULT_CACHE_TTL)
        except Exception:
            pass

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取响应缓存统计信息。"""
        if _RESPONSE_CACHE is None:
            return {"enabled": False}
        try:
            stats = _RESPONSE_CACHE.stats(enable=True, reset=False)
            if isinstance(stats, tuple) and len(stats) == 2:
                hits, misses = stats
                stats = {"hits": hits, "misses": misses}
            return {
                "enabled": True,
                "cache_dir": _CACHE_DIR,
                "hits": int(stats.get("hits", 0)),
                "misses": int(stats.get("misses", 0)),
                "ttl_s": _DEFAULT_CACHE_TTL,
            }
        except Exception as e:
            return {"enabled": True, "error": str(e)}


_global_tracker: Optional[TokenTracker] = None


def get_token_tracker() -> TokenTracker:
    """获取全局token追踪器实例"""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = TokenTracker.get_instance()
    return _global_tracker
