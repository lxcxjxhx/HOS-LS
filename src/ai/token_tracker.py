"""
Token使用追踪模块
用于追踪所有AI API调用的token使用情况
"""
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any


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
        prompt: str = None,
        response: str = None,
        agent_name: str = None,
        file_path: str = None,
        **kwargs
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

    _instance: Optional['TokenTracker'] = None
    _lock = threading.Lock()

    def __init__(self):
        self._token_usage: List[TokenUsageRecord] = []
        self._total_usage: Dict[str, int] = {
            'prompt_tokens': 0,
            'completion_tokens': 0,
            'total_tokens': 0
        }
        self._request_count = 0
        self._success_count = 0
        self._failure_count = 0

    @classmethod
    def get_instance(cls) -> 'TokenTracker':
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
        prompt: str = None,
        response: str = None,
        agent_name: str = None,
        file_path: str = None,
        **kwargs
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
            **kwargs
        )
        self._token_usage.append(record)

        self._total_usage['prompt_tokens'] += prompt_tokens
        self._total_usage['completion_tokens'] += completion_tokens
        self._total_usage['total_tokens'] += total_tokens

        self._request_count += 1
        if success:
            self._success_count += 1
        else:
            self._failure_count += 1

    def get_usage_stats(self) -> Dict[str, Any]:
        """获取使用统计"""
        return {
            'total_usage': self._total_usage.copy(),
            'request_count': self._request_count,
            'success_count': self._success_count,
            'failure_count': self._failure_count,
            'avg_prompt_tokens': self._total_usage['prompt_tokens'] / self._request_count if self._request_count > 0 else 0,
            'avg_completion_tokens': self._total_usage['completion_tokens'] / self._request_count if self._request_count > 0 else 0,
            'avg_total_tokens': self._total_usage['total_tokens'] / self._request_count if self._request_count > 0 else 0,
        }

    def get_recent_usage(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取最近的token使用记录"""
        records = self._token_usage[-limit:]
        return [
            {
                'provider': r.provider,
                'model': r.model,
                'prompt_tokens': r.prompt_tokens,
                'completion_tokens': r.completion_tokens,
                'total_tokens': r.total_tokens,
                'duration': r.duration,
                'success': r.success,
                'timestamp': r.timestamp,
                'cached': r.cached,
                'prompt': r.prompt[:200] + '...' if r.prompt and len(r.prompt) > 200 else r.prompt,
                'response': r.response[:200] + '...' if r.response and len(r.response) > 200 else r.response,
                'agent_name': r.agent_name,
                'file_path': str(r.file_path) if r.file_path else ''
            }
            for r in records
        ]

    def reset(self) -> None:
        """重置所有统计"""
        self._token_usage.clear()
        self._total_usage = {
            'prompt_tokens': 0,
            'completion_tokens': 0,
            'total_tokens': 0
        }
        self._request_count = 0
        self._success_count = 0
        self._failure_count = 0


_global_tracker: Optional[TokenTracker] = None


def get_token_tracker() -> TokenTracker:
    """获取全局token追踪器实例"""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = TokenTracker.get_instance()
    return _global_tracker
