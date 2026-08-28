"""CVE 查询接口与实现

提供 Mock 和 NVD 集成的 CVE 查询功能。
"""

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

from src.analyzers.dependency_models import DependencyInfo, SupplyChainWarning, VersionRange, VulnerabilityInfo

logger = get_logger(__name__)


# =============================================================================
# CVE 查询接口（可插拔实现）
# =============================================================================


class CVECheckerInterface(ABC):
    """CVE 漏洞查询抽象接口

    定义漏洞查询的标准接口，允许接入不同的漏洞数据源
    （NVD、OSV、GHSA 等）。实现类可以对接网络 API 或本地数据库。
    """

    @abstractmethod
    def check_vulnerabilities(
        self, dependency: DependencyInfo
    ) -> List[VulnerabilityInfo]:
        """查询指定依赖的已知漏洞

        Args:
            dependency: 待查询的依赖信息

        Returns:
            匹配到的漏洞列表
        """

    @abstractmethod
    def is_available(self) -> bool:
        """检查漏洞查询服务是否可用

        Returns:
            服务是否可用
        """


class MockCVEChecker(CVECheckerInterface):
    """模拟 CVE 查询实现（离线/测试用）

    内置少量常见高危漏洞样本数据，用于在无网络环境下
    演示和测试漏洞匹配功能。生产环境应替换为真实数据源。
    """

    # 内置的已知高危漏洞样本（仅用于演示）
    _KNOWN_VULNS: Dict[str, List[Dict[str, Any]]] = {
        "log4j": [
            {
                "cve_id": "CVE-2021-44228",
                "affected_range": ">=2.0,<2.15.0",
                "severity": "critical",
                "cvss_score": 10.0,
                "summary": "Apache Log4j2 JNDI 远程代码执行漏洞（Log4Shell）",
                "fixed_version": "2.17.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            },
            {
                "cve_id": "CVE-2021-45046",
                "affected_range": ">=2.0,<2.17.0",
                "severity": "critical",
                "cvss_score": 9.0,
                "summary": "Apache Log4j2 Thread Context 远程代码执行漏洞",
                "fixed_version": "2.17.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"],
            },
        ],
        "requests": [
            {
                "cve_id": "CVE-2023-32681",
                "affected_range": ">=2.3.0,<2.31.0",
                "severity": "medium",
                "cvss_score": 6.1,
                "summary": "Requests 库非预期泄露代理认证凭据",
                "fixed_version": "2.31.0",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
            },
        ],
        "urllib3": [
            {
                "cve_id": "CVE-2023-43804",
                "affected_range": ">=2.0.0,<2.0.6",
                "severity": "high",
                "cvss_score": 8.1,
                "summary": "urllib3 Cookie 请求头泄露漏洞",
                "fixed_version": "2.0.6",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-43804"],
            },
            {
                "cve_id": "CVE-2023-45803",
                "affected_range": ">=2.0.0,<2.0.7",
                "severity": "medium",
                "cvss_score": 4.2,
                "summary": "urllib3 请求体在重定向时未正确剥离",
                "fixed_version": "2.0.7",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45803"],
            },
        ],
        "lodash": [
            {
                "cve_id": "CVE-2021-23337",
                "affected_range": ">=0,<4.17.21",
                "severity": "high",
                "cvss_score": 7.2,
                "summary": "Lodash 命令注入漏洞（通过 template 函数）",
                "fixed_version": "4.17.21",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
            },
        ],
        "fastjson": [
            {
                "cve_id": "CVE-2022-25845",
                "affected_range": ">=1.2.37,<1.2.83",
                "severity": "critical",
                "cvss_score": 9.8,
                "summary": "Fastjson autoType 远程代码执行漏洞",
                "fixed_version": "1.2.83",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-25845"],
            },
        ],
        "jackson-databind": [
            {
                "cve_id": "CVE-2020-36518",
                "affected_range": ">=2.0.0,<2.13.2.1",
                "severity": "high",
                "cvss_score": 7.5,
                "summary": "Jackson-databind 深度嵌套导致的拒绝服务漏洞",
                "fixed_version": "2.13.2.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-36518"],
            },
        ],
        "django": [
            {
                "cve_id": "CVE-2023-36053",
                "affected_range": ">=4.2,<4.2.3",
                "severity": "medium",
                "cvss_score": 5.3,
                "summary": "Django EmailValidator/URLValidator 正则表达式拒绝服务",
                "fixed_version": "4.2.3",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-36053"],
            },
        ],
        "express": [],
        "flask": [],
        "spring-boot": [],
    }

    def check_vulnerabilities(
        self, dependency: DependencyInfo
    ) -> List[VulnerabilityInfo]:
        """使用内置样本数据匹配漏洞

        Args:
            dependency: 待查询的依赖信息

        Returns:
            匹配到的漏洞列表
        """
        dep_name = dependency.name.lower()
        vulns_data = self._KNOWN_VULNS.get(dep_name, [])
        results: List[VulnerabilityInfo] = []

        for vuln in vulns_data:
            version_to_check = (
                dependency.resolved_version
                or (
                    dependency.version_range.exact_version
                    if dependency.version_range
                    else None
                )
            )

            if version_to_check:
                range_spec = vuln["affected_range"]
                vr = self._parse_range_spec(range_spec)
                if vr and not vr.matches(version_to_check):
                    continue

            results.append(
                VulnerabilityInfo(
                    cve_id=vuln["cve_id"],
                    dependency_name=dependency.name,
                    affected_version_range=vuln["affected_range"],
                    severity=vuln["severity"],
                    cvss_score=vuln["cvss_score"],
                    summary=vuln["summary"],
                    fixed_version=vuln.get("fixed_version"),
                    references=vuln.get("references", []),
                    source="mock",
                )
            )

        return results

    def is_available(self) -> bool:
        """模拟实现始终可用"""
        return True

    @staticmethod
    def _parse_range_spec(spec: str) -> Optional[VersionRange]:
        """解析范围规范字符串为 VersionRange 对象"""
        spec = spec.strip()
        if "," in spec:
            parts = [p.strip() for p in spec.split(",")]
            min_v = max_v = None
            for p in parts:
                if p.startswith(">="):
                    min_v = p[2:]
                elif p.startswith("<"):
                    max_v = p[1:]
                elif p.startswith(">"):
                    min_v = p[1:]
                elif p.startswith("<="):
                    max_v = p[2:]
            return VersionRange(
                raw_spec=spec,
                min_version=min_v,
                max_version=max_v,
            )
        return VersionRange(raw_spec=spec, exact_version=spec)


class NVDIntegratedCVEChecker(CVECheckerInterface):
    """基于 NVD 本地数据库的 CVE 查询实现

    集成项目已有的 NVD SQLite 数据库进行漏洞查询。
    当 NVD 数据库不可用时自动降级到 MockCVEChecker。
    """

    def __init__(self) -> None:
        self._nvd_adapter: Optional[Any] = None
        self._available = False
        self._fallback = MockCVEChecker()
        self._init_nvd_adapter()

    def _init_nvd_adapter(self) -> None:
        """尝试初始化 NVD 查询适配器"""
        try:
            from src.vuln_data.nvd_adapter import NVDAdapter
            from src.vuln_data.library_matcher import LibraryMatcher

            self._nvd_adapter = {"adapter": NVDAdapter, "matcher": LibraryMatcher}
            self._available = True
            logger.info("NVD 本地数据库连接成功，CVE 查询已就绪")
        except Exception as e:
            logger.debug(f"NVD 适配器初始化失败，将使用模拟数据: {e}")
            self._available = False

    def check_vulnerabilities(
        self, dependency: DependencyInfo
    ) -> List[VulnerabilityInfo]:
        """查询依赖漏洞，优先使用 NVD 数据库

        Args:
            dependency: 待查询的依赖信息

        Returns:
            匹配到的漏洞列表
        """
        if not self._available:
            return self._fallback.check_vulnerabilities(dependency)

        try:
            return self._query_nvd(dependency)
        except Exception as e:
            logger.warning(f"NVD 查询失败，降级到模拟数据: {e}")
            return self._fallback.check_vulnerabilities(dependency)

    def _query_nvd(self, dependency: DependencyInfo) -> List[VulnerabilityInfo]:
        """通过 NVD 适配器查询漏洞"""
        if not self._nvd_adapter:
            return []

        matcher = self._nvd_adapter["matcher"]()
        version = dependency.resolved_version or (
            dependency.version_range.exact_version if dependency.version_range else None
        )

        from src.vuln_data.library_matcher import LibraryInfo

        lib_info = LibraryInfo(
            name=dependency.name,
            version=version,
            source=dependency.source_file,
        )

        matches = matcher.match_library(lib_info)
        results: List[VulnerabilityInfo] = []
        for match in matches:
            results.append(
                VulnerabilityInfo(
                    cve_id=match.cve_id,
                    dependency_name=match.library_name,
                    affected_version_range=", ".join(match.affected_versions),
                    severity=match.severity,
                    cvss_score=self._severity_to_cvss(match.severity),
                    summary=match.description,
                    fixed_version=match.fix_version,
                    source="nvd",
                )
            )
        return results

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        """将严重等级映射为近似 CVSS 评分"""
        mapping = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
        }
        return mapping.get(severity.lower(), 5.0)

    def is_available(self) -> bool:
        """检查 NVD 数据库是否可用"""
        return self._available

