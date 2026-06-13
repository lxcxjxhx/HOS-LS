"""Stub RAG graph integrator module.

Provides graceful degradation when the RAG-graph integration
infrastructure is unavailable.
"""

from __future__ import annotations

from typing import Any, Optional


class RAGGraphIntegrator:
    """Stub integrator that does nothing."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def integrate(self, *args: Any, **kwargs: Any) -> None:
        """No-op."""
        pass


def get_rag_graph_integrator(
    *args: Any,
    **kwargs: Any,
) -> Optional[RAGGraphIntegrator]:
    """Factory returning None — no integration engine available."""
    return None
