"""核心扫描引擎模块

提供 HOS-LS 的核心扫描功能，包括配置管理、扫描引擎和主扫描器。
"""

from src.config.config import Config, ConfigManager
from src.core.engine import ScanEngine
from src.core.scanner import SecurityScanner
from src.core.registry import ModuleRegistry, DependencyInjector

__all__ = [
    "Config",
    "ConfigManager",
    "ScanEngine",
    "SecurityScanner",
    "ModuleRegistry",
    "DependencyInjector",
    "RAGGraphIntegrator",
    "get_rag_graph_integrator",
]


def __getattr__(name):
    """延迟导入 RAGGraphIntegrator"""
    if name in ("RAGGraphIntegrator", "get_rag_graph_integrator"):
        from src.ai.pure_ai.rag.graph_integrator import (
            RAGGraphIntegrator,
            get_rag_graph_integrator,
        )
        if name == "RAGGraphIntegrator":
            return RAGGraphIntegrator
        else:
            return get_rag_graph_integrator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
