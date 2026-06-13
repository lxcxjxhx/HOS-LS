"""Stub DSPy optimization module.

Provides graceful degradation when DSPy infrastructure is unavailable.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


# Empty program registry — real implementations populate this.
_optimized_programs: Dict[str, "DSPyProgram"] = {}


class DSPyProgram:
    """Stub DSPy program that does nothing."""

    def __init__(self, name: str = "", *args: Any, **kwargs: Any) -> None:
        self.name = name

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Return None when invoked."""
        return None


def get_dspy_programs() -> Dict[str, DSPyProgram]:
    """Return the (empty) program registry."""
    return _optimized_programs
