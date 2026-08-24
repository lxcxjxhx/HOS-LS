"""评测框架

提供Pair-Correct指标计算、消融实验、基线对比等功能。
"""

from eval.metrics import (
    calculate_pair_correct,
    calculate_metrics,
    calculate_ablation_metrics,
    format_metrics_report,
    format_ablation_report,
)
from eval.ablation import (
    AblationRunner,
    AblationConfig,
    AblationResult,
)

__all__ = [
    "calculate_pair_correct",
    "calculate_metrics",
    "calculate_ablation_metrics",
    "format_metrics_report",
    "format_ablation_report",
    "AblationRunner",
    "AblationConfig",
    "AblationResult",
]
