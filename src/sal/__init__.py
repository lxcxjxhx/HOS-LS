"""SAL (Sink Anchoring & Localization) 模块

提供Sink注册表和路径探索功能，用于从Modified_Funcs出发找到到Sink的路径。
"""

from src.sal.sink_registry import SinkRegistry, SinkDefinition
from src.sal.path_explorer import SALExplorer, CandidatePath

__all__ = [
    "SinkRegistry",
    "SinkDefinition",
    "SALExplorer",
    "CandidatePath",
]
