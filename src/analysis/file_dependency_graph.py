"""Stub file dependency graph module.

Provides graceful degradation when static analysis infrastructure
is unavailable. All methods return empty collections.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


class FileDependencyGraph:
    """Stub dependency graph that always reports no dependencies."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def build_graph(self, root_dir: str = "", **kwargs: Any) -> None:
        """No-op — no graph is built."""
        pass

    def get_dependencies(self, file_path: str) -> Set[str]:
        """Return an empty dependency set."""
        return set()

    def get_dependents(self, file_path: str) -> Set[str]:
        """Return an empty dependents set."""
        return set()

    def get_related_files(self, file_path: str, max_depth: int = 3, **kwargs: Any) -> List[str]:
        """Return an empty related files list."""
        return []


def get_file_dependency_graph(
    *args: Any,
    **kwargs: Any,
) -> FileDependencyGraph:
    """Factory returning an empty graph instance."""
    return FileDependencyGraph()
