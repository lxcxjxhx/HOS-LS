"""AI 实体提取模块

提供基于AI的命名实体识别和语义角色标注功能。
"""

from src.ai.entity.extractor import AIEntityExtractor, EntityExtractionResult, ExtractedEntity

__all__ = [
    "AIEntityExtractor",
    "EntityExtractionResult",
    "ExtractedEntity",
]
