"""报告生成模块

提供多格式报告生成功能。
"""

from src.reporting.generator import ReportGenerator
from src.reporting.category import (
    VulnerabilityCategory,
    VulnerabilityMetadata,
    CategorizedReportData,
    SPECIAL_SCAN_AREAS,
    classify_rule,
    get_special_scan_area,
    is_api_related,
)

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
