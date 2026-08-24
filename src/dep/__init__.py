"""DEP (Differential & Evidence Proving) 模块

提供差分对比和反事实验证功能。
"""

from src.dep.differ import PathDiffer, SuspiciousPath
from src.dep.counterfactual import CounterfactualVerifier, VerificationResult

__all__ = [
    "PathDiffer",
    "SuspiciousPath",
    "CounterfactualVerifier",
    "VerificationResult",
]
