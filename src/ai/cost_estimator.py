"""运行前消费预估模块（Pre-run Cost Estimation）

在扫描开始前，根据目标文件数、历史 token 消耗均值与模型单价，估算本次
扫描的 token 消耗与费用，输出给用户确认，避免 AI 扫描账单失控。

主要功能：
    - 按 provider/model 的单价表（USD / 1K tokens）估算费用
    - 用 TokenTracker 历史统计校准「每文件平均 token」，
      无历史时回退到默认均值（2026-08-16 实测校准：70,807 token/文件，
      含 token 优化后实际消耗）
    - 支持 USD/CNY 双币种显示（人民币按 7.0 汇率估算）
    - get_cost_estimator() 工厂，供 scanner 的 try/except 钩子使用

⚠️ 费用口径说明（重要）：
    本模块按「缓存未命中（cache miss）」单价估算，是**费用上界（保守值）**。
    DeepSeek 等 provider 对缓存命中（相同前缀 prompt）按约 1/10 单价计费；
    HOS-LS 的 LLM 响应缓存（token_tracker 的 diskcache）与扫描内重复 prompt
    会命中缓存。2026-08-16 实测：RepoPairBench 50+10 样本双侧按理论单价
    估算 ¥25.4，实际账户扣费 ¥5.02（约 1/5）——实际花费通常显著低于本模块
    输出。因此本模块预估用于「预算上界」与「超额告警」，实际账单以余额
    变化为准。

Author: HOS-LS Team
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional

from src.utils.logger import get_logger

logger = get_logger("cost_estimator")

# ---------------------------------------------------------------------------
# 模型单价表（USD / 1K tokens）
# 来源：各 provider 官方定价；deepseek-v4-flash 取 flash 档（≈ deepseek-chat 档）
# 可在环境变量 HOS_LS_PRICING_JSON 覆盖（{"model": {"prompt": x, "completion": y}}）
# ---------------------------------------------------------------------------
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    # DeepSeek
    "deepseek-chat": {"prompt": 0.00027, "completion": 0.00110},
    "deepseek-reasoner": {"prompt": 0.00055, "completion": 0.00219},
    "deepseek-v4-flash": {"prompt": 0.00027, "completion": 0.00110},
    "deepseek-v4": {"prompt": 0.00055, "completion": 0.00219},
    "deepseek-coder": {"prompt": 0.00014, "completion": 0.00028},
    # OpenAI
    "gpt-4o": {"prompt": 0.00250, "completion": 0.01000},
    "gpt-4o-mini": {"prompt": 0.00015, "completion": 0.00060},
    "gpt-4.1": {"prompt": 0.00200, "completion": 0.00800},
    "o4-mini": {"prompt": 0.00110, "completion": 0.00440},
    # Anthropic
    "claude-3-opus": {"prompt": 0.01500, "completion": 0.07500},
    "claude-3-sonnet": {"prompt": 0.00300, "completion": 0.01500},
    "claude-3-haiku": {"prompt": 0.00025, "completion": 0.00125},
    "claude-sonnet-4": {"prompt": 0.00300, "completion": 0.01500},
    # Aliyun / Qwen
    "qwen3-coder-next": {"prompt": 0.00040, "completion": 0.00160},
    "qwen-max": {"prompt": 0.00240, "completion": 0.00960},
    "qwen-plus": {"prompt": 0.00040, "completion": 0.00120},
}

DEFAULT_PRICING: Dict[str, float] = {"prompt": 0.00040, "completion": 0.00160}

# 纯 AI 7-Agent 模式下的每文件 token 默认均值（2026-08-16 实测校准：
# RepoPairBench 10+50 样本双侧 4 轮实测 token Σ，均值 70,807 token/文件，
# 范围 66,111–75,191；含 token 优化（早停/压缩/分层）后的实际消耗）
DEFAULT_AVG_TOKENS_PER_FILE: int = 70807

# 默认每文件输入/输出 token 占比（估算用）
DEFAULT_PROMPT_RATIO: float = 0.80
DEFAULT_COMPLETION_RATIO: float = 0.20

# USD → CNY 汇率（估算展示用）
USD_TO_CNY: float = 7.0


def _load_pricing_override() -> Dict[str, Dict[str, float]]:
    """从环境变量 HOS_LS_PRICING_JSON 加载单价覆盖（便于不落配置文件调价）。"""
    import json

    raw = os.getenv("HOS_LS_PRICING_JSON")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if isinstance(v, dict)}
    except Exception as exc:  # pragma: no cover - 配置容错
        logger.warning("HOS_LS_PRICING_JSON 解析失败: %s", exc)
    return {}


_PRICING_OVERRIDE = _load_pricing_override()


def get_model_pricing(model: str) -> Dict[str, float]:
    """获取模型单价（USD/1K tokens）；未收录时用默认值。"""
    if model in _PRICING_OVERRIDE:
        return _PRICING_OVERRIDE[model]
    return MODEL_PRICING.get(model, DEFAULT_PRICING)


@dataclass
class CostEstimate:
    """一次扫描的成本预估结果。"""

    file_count: int = 0
    provider: str = "deepseek"
    model: str = "deepseek-v4-flash"
    avg_tokens_per_file: int = DEFAULT_AVG_TOKENS_PER_FILE
    estimated_total_tokens: int = 0
    estimated_prompt_tokens: int = 0
    estimated_completion_tokens: int = 0
    estimated_total_cost_usd: float = 0.0
    pricing_source: str = "默认单价表"
    using_history: bool = False

    @property
    def estimated_total_cost(self) -> float:
        """兼容 scanner 现有调用（字段名 estimated_total_cost）。"""
        return self.estimated_total_cost_usd

    @property
    def estimated_cost_cny(self) -> float:
        return self.estimated_total_cost_usd * USD_TO_CNY


class CostEstimator:
    """运行前成本预估器。"""

    def __init__(self) -> None:
        self._token_tracker = None
        try:
            from src.ai.token_tracker import get_token_tracker

            self._token_tracker = get_token_tracker()
        except Exception:  # pragma: no cover - 模块缺失时降级
            pass

    def _history_avg_tokens_per_file(self) -> Optional[float]:
        """用 TokenTracker 历史统计校准每文件 token 均值。"""
        if self._token_tracker is None:
            return None
        try:
            stats = self._token_tracker.get_usage_stats()
            avg = stats.get("avg_total_tokens") or 0
            if avg > 0:
                return float(avg)
        except Exception:  # pragma: no cover - 统计异常降级
            pass
        return None

    def estimate(
        self,
        file_count: int,
        provider: str = "deepseek",
        model: Optional[str] = None,
        avg_tokens_per_file: Optional[float] = None,
        prompt_ratio: float = DEFAULT_PROMPT_RATIO,
        completion_ratio: float = DEFAULT_COMPLETION_RATIO,
    ) -> CostEstimate:
        """估算 N 个文件的扫描 token 消耗与费用。

        Args:
            file_count: 待扫描文件数
            provider: provider 名称（deepseek/openai/anthropic/aliyun）
            model: 模型名，None 时按 provider 取默认
            avg_tokens_per_file: 每文件平均 token；None 时优先用历史均值，再回退默认
            prompt_ratio / completion_ratio: 输入/输出占比
        """
        model = model or _default_model_for(provider)
        pricing = get_model_pricing(model)

        using_history = False
        if avg_tokens_per_file is None:
            hist = self._history_avg_tokens_per_file()
            if hist is not None:
                avg_tokens_per_file = hist
                using_history = True
            else:
                avg_tokens_per_file = float(DEFAULT_AVG_TOKENS_PER_FILE)

        avg_tokens_per_file = max(1.0, float(avg_tokens_per_file))
        total_tokens = int(round(avg_tokens_per_file * max(0, file_count)))
        prompt_tokens = int(round(total_tokens * prompt_ratio))
        completion_tokens = int(round(total_tokens * completion_ratio))

        cost_usd = (
            prompt_tokens / 1000 * pricing["prompt"]
            + completion_tokens / 1000 * pricing["completion"]
        )

        pricing_source = (
            f"历史均值校准({avg_tokens_per_file:.0f} token/文件)"
            if using_history
            else f"默认均值({avg_tokens_per_file:.0f} token/文件)"
        )
        pricing_source += (
            f" + {model} 单价(prompt ${pricing['prompt']}/1K, completion ${pricing['completion']}/1K)"
            "（按缓存未命中价，为费用上界；缓存命中约 1/10）"
        )

        return CostEstimate(
            file_count=file_count,
            provider=provider,
            model=model,
            avg_tokens_per_file=int(round(avg_tokens_per_file)),
            estimated_total_tokens=total_tokens,
            estimated_prompt_tokens=prompt_tokens,
            estimated_completion_tokens=completion_tokens,
            estimated_total_cost_usd=round(cost_usd, 4),
            pricing_source=pricing_source,
            using_history=using_history,
        )


def _default_model_for(provider: str) -> str:
    """各 provider 的默认模型。"""
    return {
        "deepseek": "deepseek-v4-flash",
        "openai": "gpt-4o-mini",
        "anthropic": "claude-3-haiku",
        "aliyun": "qwen3-coder-next",
    }.get(provider, "deepseek-v4-flash")


_estimator: Optional[CostEstimator] = None


def get_cost_estimator() -> CostEstimator:
    """获取全局成本预估器单例（scanner try/except 钩子兼容）。"""
    global _estimator
    if _estimator is None:
        _estimator = CostEstimator()
    return _estimator
