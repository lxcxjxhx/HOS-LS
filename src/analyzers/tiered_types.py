"""Types for tiered analysis pipeline."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class TierDecision(Enum):
    """各层分析的决策结果"""

    # Tier 1 决策
    SKIP = "SKIP"  # 风险极低，跳过后续分析
    PROCEED_TO_TIER2 = "PROCEED_TO_TIER2"  # 存在可疑模式，需要AI分析
    FAST_CONFIRM = "FAST_CONFIRM"  # 高风险模式明确匹配，直接确认

    # Tier 2 决策
    REJECT = "REJECT"  # AI判定为误报或低风险
    PROCEED_TO_TIER3 = "PROCEED_TO_TIER3"  # 置信度不足，需要深度验证
    CONFIRM = "CONFIRM"  # AI高置信度确认漏洞

    # Tier 3 决策
    FINAL_REJECT = "FINAL_REJECT"  # 深度验证后排除
    FINAL_CONFIRM = "FINAL_CONFIRM"  # 深度验证后确认


@dataclass
class TierResult:
    """单层分析结果"""

    tier: int  # 1, 2, or 3
    decision: str  # TierDecision 的 value
    confidence: float  # 0.0 ~ 1.0 置信度
    findings: List[Dict[str, Any]]  # 发现的漏洞/问题列表
    elapsed_ms: float  # 本层耗时（毫秒）
    token_cost: int  # 本层消耗的 token 数


@dataclass
class TieredAnalysisResult:
    """完整的三层分析结果"""

    file_path: str
    final_decision: str  # 最终决策
    final_findings: List[Dict[str, Any]]  # 最终发现
    tier_results: List[TierResult]  # 各层分析结果
    total_elapsed_ms: float  # 总耗时（毫秒）
    total_tokens: int  # 总 token 消耗


# ============================================================================
# Tier 1: 快速筛查引擎
# ============================================================================
