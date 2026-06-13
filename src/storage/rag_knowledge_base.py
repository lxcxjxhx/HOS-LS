"""Stub RAG knowledge base module.

Provides graceful degradation when the real RAG infrastructure is unavailable.
All methods return empty results or None without raising errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RAGDocument:
    """Minimal document representation for stub mode."""
    content: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class RAGKnowledgeBase:
    """Stub knowledge base that returns empty results."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def search(
        self,
        query: str,
        top_k: int = 5,
        **kwargs: Any,
    ) -> List[RAGDocument]:
        """Return empty search results."""
        return []

    def add_document(
        self,
        document: RAGDocument,
        **kwargs: Any,
    ) -> Optional[str]:
        """Accept the document but do nothing; return None."""
        return None

    def get_documents(
        self,
        **kwargs: Any,
    ) -> List[RAGDocument]:
        """Return an empty document list."""
        return []


def get_rag_knowledge_base(
    *args: Any,
    **kwargs: Any,
) -> Optional[RAGKnowledgeBase]:
    """Factory that returns None (no real infrastructure available)."""
    return None
