"""Stub AI evaluation module.

Provides graceful degradation when the real evaluation infrastructure
is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class EvaluationResult:
    """Minimal evaluation result placeholder."""
    score: float = 0.0
    metrics: Dict[str, float] = None
    details: str = ""
    passed: bool = False

    def __post_init__(self) -> None:
        if self.metrics is None:
            object.__setattr__(self, "metrics", {})


def get_evaluator(*args: Any, **kwargs: Any) -> None:
    """Return None — no evaluation engine available."""
    return None
