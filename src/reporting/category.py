"""漏洞分类定义模块

提供漏洞分类功能和元数据结构定义。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class VulnerabilityCategory(Enum):
    """漏洞分类枚举"""
    PORT_RELATED = "port_related"
    GENERAL_STATIC = "general_static"
    SPECIAL_SCAN = "special_scan"


SPECIAL_SCAN_AREAS = {
    "api_security": "API-*",
    "auth_security": "AUTH-*",
    "data_protection": "DATA-*",
    "config_security": "CFG-*",
}


def classify_rule(rule_id: str) -> VulnerabilityCategory:
    """根据规则ID分类漏洞

    Args:
        rule_id: 规则ID

    Returns:
        漏洞分类
    """
    if not rule_id:
        return VulnerabilityCategory.GENERAL_STATIC

    if rule_id.startswith("PORT-"):
        return VulnerabilityCategory.PORT_RELATED

    if rule_id.startswith(("API-", "AUTH-", "DATA-", "CFG-")):
        return VulnerabilityCategory.SPECIAL_SCAN

    return VulnerabilityCategory.GENERAL_STATIC


def get_special_scan_area(rule_id: str) -> str:
    """获取特殊扫描区域

    Args:
        rule_id: 规则ID

    Returns:
        特殊扫描区域名称，如果不属于特殊扫描区域则返回空字符串
    """
    if not rule_id:
        return ""

    if rule_id.startswith("API-"):
        return "api_security"
    if rule_id.startswith("AUTH-"):
        return "auth_security"
    if rule_id.startswith("DATA-"):
        return "data_protection"
    if rule_id.startswith("CFG-"):
        return "config_security"

    return ""


def is_api_related(rule_id: str) -> bool:
    """判断规则是否与API相关

    Args:
        rule_id: 规则ID

    Returns:
        是否与API相关
    """
    return rule_id.startswith("API-")


@dataclass
class VulnerabilityMetadata:
    """漏洞元数据"""
    category: VulnerabilityCategory = VulnerabilityCategory.GENERAL_STATIC
    sub_category: str = ""
    scan_type: str = ""
    related_port: str = ""
    related_file: str = ""
    special_scan_area: str = ""
    is_api_related: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "sub_category": self.sub_category,
            "scan_type": self.scan_type,
            "related_port": self.related_port,
            "related_file": self.related_file,
            "special_scan_area": self.special_scan_area,
            "is_api_related": self.is_api_related,
        }


@dataclass
class CategorizedReportData:
    """分类后的报告数据"""
    summary: Dict[str, Any] = field(default_factory=dict)
    port_related_findings: List[Any] = field(default_factory=list)
    general_static_findings: List[Any] = field(default_factory=list)
    special_scan_findings: Dict[str, List[Any]] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "port_related_findings": self.port_related_findings,
            "general_static_findings": self.general_static_findings,
            "special_scan_findings": self.special_scan_findings,
            "statistics": self.statistics,
        }

    def add_finding(self, finding: Any, rule_id: str) -> None:
        """添加发现到对应分类

        Args:
            finding: 发现对象
            rule_id: 规则ID
        """
        category = classify_rule(rule_id)

        if category == VulnerabilityCategory.PORT_RELATED:
            self.port_related_findings.append(finding)
        elif category == VulnerabilityCategory.SPECIAL_SCAN:
            area = get_special_scan_area(rule_id)
            if area not in self.special_scan_findings:
                self.special_scan_findings[area] = []
            self.special_scan_findings[area].append(finding)
        else:
            self.general_static_findings.append(finding)
