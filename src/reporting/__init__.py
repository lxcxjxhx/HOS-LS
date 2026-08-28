"""报告生成模块

提供多格式报告生成功能。
"""

from src.reporting.category import (
    SPECIAL_SCAN_AREAS,
    CategorizedReportData,
    VulnerabilityCategory,
    VulnerabilityMetadata,
    classify_rule,
    get_special_scan_area,
    is_api_related,
)
from src.reporting.generator import ReportGenerator

__all__ = [
    "ReportGenerator",
    "VulnerabilityCategory",
    "VulnerabilityMetadata",
    "CategorizedReportData",
    "SPECIAL_SCAN_AREAS",
    "classify_rule",
    "get_special_scan_area",
    "is_api_related",
]
