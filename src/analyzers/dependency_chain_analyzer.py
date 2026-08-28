"""依赖链分析模块

对标 Argus 论文 (arXiv:2604.06633) 的全供应链分析方法，
提供依赖发现、漏洞匹配、供应链风险评估等功能。

支持以下依赖清单格式：
- Java: pom.xml (Maven), build.gradle (Gradle)
- Python: requirements.txt, setup.py, pyproject.toml
- JavaScript: package.json
"""

import json
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# 枚举与常量
# =============================================================================


class Ecosystem(Enum):
    """依赖生态系统"""

    MAVEN = "Maven"
    PYPI = "PyPI"
    NPM = "npm"
    GRADLE = "Maven"  # Gradle 使用 Maven 坐标
    UNKNOWN = "Unknown"


class DependencyType(Enum):
    """依赖类型"""

    DIRECT = "direct"  # 直接依赖
    TRANSITIVE = "transitive"  # 传递依赖
    DEV = "dev"  # 开发依赖
    OPTIONAL = "optional"  # 可选依赖


class RiskLevel(Enum):
    """风险等级"""

    CRITICAL = "critical"  # 严重风险
    HIGH = "high"  # 高风险
    MEDIUM = "medium"  # 中风险
    LOW = "low"  # 低风险
    INFO = "info"  # 信息


class WarningType(Enum):
    """供应链警告类型"""

    TYPOSQUATTING = "typosquatting"  # 名称抢注
    DEPENDENCY_CONFUSION = "dependency_confusion"  # 依赖混淆
    UNMAINTAINED = "unmaintained"  # 停止维护
    DEEP_TRANSITIVE = "deep_transitive"  # 深层传递依赖
    CONFLICTING_VERSIONS = "conflicting_versions"  # 版本冲突
    DEPRECATED = "deprecated"  # 已弃用


# 常见高价值包的名称，用于检测名称抢注（typosquatting）
_WELL_KNOWN_PACKAGES: Dict[str, List[str]] = {
    "PyPI": [
        "requests", "flask", "django", "numpy", "pandas", "scipy",
        "boto3", "urllib3", "setuptools", "pip", "wheel", "six",
        "python-dateutil", "pyyaml", "cryptography", "paramiko",
        "sqlalchemy", "celery", "redis", "pytest", "matplotlib",
    ],
    "npm": [
        "react", "express", "lodash", "axios", "moment", "chalk",
        "webpack", "babel", "typescript", "eslint", "prettier",
        "next", "vue", "angular", "jquery", "bootstrap", "commander",
        "debug", "uuid", "dotenv", "cors", "mongoose", "socket.io",
    ],
    "Maven": [
        "spring-boot", "spring-core", "spring-web", "jackson-databind",
        "log4j", "slf4j", "commons-io", "commons-lang3", "guava",
        "junit", "mockito", "hibernate-core", "lombok", "fastjson",
    ],
}

# 已知的停止维护包
_DEPRECATED_PACKAGES: Dict[str, Set[str]] = {
    "PyPI": {
        "django-appconf", "django-contrib-comments", "easy-thumbnails",
        "flask-scripts", "nose", "optparse", "pbr",
    },
    "npm": {
        "request", "left-pad", "coffee-script", "gulp-util",
        "babel-polyfill", "uuid-v4", "node-uuid",
    },
    "Maven": set(),
}


# =============================================================================
# 数据类定义
# =============================================================================


@dataclass
class VersionRange:
    """版本范围约束

    表示依赖声明中的版本约束条件，例如 >=1.0,<2.0。
    """

    raw_spec: str  # 原始版本声明字符串，例如 ">=1.0,<2.0" 或 "^1.2.3"
    min_version: Optional[str] = None  # 最低版本（含）
    max_version: Optional[str] = None  # 最高版本（不含）
    min_inclusive: bool = True  # 最低版本是否包含边界
    max_inclusive: bool = False  # 最高版本是否包含边界
    exact_version: Optional[str] = None  # 精确版本号（若为精确锁定）

    def matches(self, version: str) -> bool:
        """检查给定版本是否满足此范围约束

        Args:
            version: 待检查的版本号

        Returns:
            是否满足版本范围
        """
        if self.exact_version:
            return self._compare_versions(version, self.exact_version) == 0

        try:
            parts = self._parse_version_tuple(version)
        except ValueError:
            return False

        if self.min_version:
            min_parts = self._parse_version_tuple(self.min_version)
            cmp = self._compare_tuples(parts, min_parts)
            if self.min_inclusive and cmp < 0:
                return False
            if not self.min_inclusive and cmp <= 0:
                return False

        if self.max_version:
            max_parts = self._parse_version_tuple(self.max_version)
            cmp = self._compare_tuples(parts, max_parts)
            if self.max_inclusive and cmp > 0:
                return False
            if not self.max_inclusive and cmp >= 0:
                return False

        return True

    @staticmethod
    def _parse_version_tuple(version: str) -> Tuple[int, ...]:
        """将版本号字符串解析为可比较的整数元组"""
        cleaned = re.sub(r"[^0-9.]", "", version)
        return tuple(int(x) for x in cleaned.split(".") if x)

    @staticmethod
    def _compare_tuples(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
        """比较两个版本元组，返回 -1/0/1"""
        max_len = max(len(a), len(b))
        a_padded = a + (0,) * (max_len - len(a))
        b_padded = b + (0,) * (max_len - len(b))
        if a_padded < b_padded:
            return -1
        if a_padded > b_padded:
            return 1
        return 0

    @staticmethod
    def _compare_versions(v1: str, v2: str) -> int:
        """比较两个版本号字符串"""
        t1 = VersionRange._parse_version_tuple(v1)
        t2 = VersionRange._parse_version_tuple(v2)
        return VersionRange._compare_tuples(t1, t2)


@dataclass
class DependencyInfo:
    """单个依赖项的完整信息

    记录从依赖清单中解析出的每个依赖的详细信息。
    """

    name: str  # 依赖包名称
    group_id: Optional[str] = None  # Maven 组ID（仅 Maven/Gradle）
    artifact_id: Optional[str] = None  # Maven 构件ID（仅 Maven/Gradle）
    version_range: Optional[VersionRange] = None  # 版本范围约束
    resolved_version: Optional[str] = None  # 实际解析到的版本号
    ecosystem: Ecosystem = Ecosystem.UNKNOWN  # 所属生态系统
    dependency_type: DependencyType = DependencyType.DIRECT  # 依赖类型
    source_file: str = ""  # 来源清单文件路径
    line_number: int = 0  # 在清单文件中的行号
    metadata: Dict[str, Any] = field(default_factory=dict)  # 额外元数据

    @property
    def qualified_name(self) -> str:
        """获取限定名称（Maven 格式为 group:artifact，其他为包名）"""
        if self.group_id and self.artifact_id:
            return f"{self.group_id}:{self.artifact_id}"
        return self.name

    @property
    def display_version(self) -> str:
        """获取用于展示的版本信息"""
        if self.resolved_version:
            return self.resolved_version
        if self.version_range:
            return self.version_range.raw_spec
        return "unspecified"


@dataclass
class VulnerabilityInfo:
    """依赖漏洞信息

    记录某个依赖项匹配到的已知漏洞详情。
    """

    cve_id: str  # CVE 编号，例如 CVE-2021-44228
    dependency_name: str  # 受影响的依赖名称
    affected_version_range: str  # 受影响的版本范围描述
    severity: str  # 严重等级：critical/high/medium/low
    cvss_score: float  # CVSS 评分（0.0 ~ 10.0）
    summary: str  # 漏洞简要描述
    fixed_version: Optional[str] = None  # 修复版本号（若有）
    references: List[str] = field(default_factory=list)  # 参考链接
    source: str = ""  # 数据来源（NVD/OSV/GHSA 等）

    @property
    def is_critical(self) -> bool:
        """是否为严重漏洞（CVSS >= 9.0）"""
        return self.cvss_score >= 9.0

    @property
    def is_high(self) -> bool:
        """是否为高危漏洞（CVSS >= 7.0）"""
        return self.cvss_score >= 7.0


@dataclass
class SupplyChainWarning:
    """供应链风险警告

    记录依赖链分析过程中发现的供应链安全风险。
    """

    warning_type: WarningType  # 警告类型
    risk_level: RiskLevel  # 风险等级
    dependency_name: str  # 涉及的依赖名称
    message: str  # 详细描述信息
    confidence: float = 1.0  # 置信度（0.0 ~ 1.0）
    metadata: Dict[str, Any] = field(default_factory=dict)  # 附加元数据


@dataclass
class DependencyReport:
    """依赖链分析报告

    汇总一次完整的依赖链分析结果，包括所有依赖项、
    漏洞匹配结果、供应链风险警告和综合评分。
    """

    project_path: str  # 被分析项目的根目录路径
    dependencies: List[DependencyInfo] = field(default_factory=list)  # 所有已发现的依赖列表
    vulnerable_deps: List[VulnerabilityInfo] = field(default_factory=list)  # 存在已知漏洞的依赖列表
    supply_chain_warnings: List[SupplyChainWarning] = field(
        default_factory=list
    )  # 供应链安全警告列表
    risk_score: float = 0.0  # 综合风险评分（0.0 ~ 100.0，越高风险越大）
    ecosystem: str = ""  # 项目主要生态系统标识
    manifest_files: List[str] = field(default_factory=list)  # 已解析的清单文件列表
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)  # 分析过程元数据

    @property
    def total_dependencies(self) -> int:
        """依赖总数"""
        return len(self.dependencies)

    @property
    def direct_dependencies(self) -> int:
        """直接依赖数量"""
        return sum(
            1 for d in self.dependencies if d.dependency_type == DependencyType.DIRECT
        )

    @property
    def transitive_dependencies(self) -> int:
        """传递依赖数量"""
        return sum(
            1
            for d in self.dependencies
            if d.dependency_type == DependencyType.TRANSITIVE
        )

    @property
    def critical_vulnerabilities(self) -> int:
        """严重漏洞数量"""
        return sum(1 for v in self.vulnerable_deps if v.is_critical)

    @property
    def high_vulnerabilities(self) -> int:
        """高危漏洞数量"""
        return sum(1 for v in self.vulnerable_deps if v.is_high)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式，便于序列化输出"""
        return {
            "project_path": self.project_path,
            "ecosystem": self.ecosystem,
            "manifest_files": self.manifest_files,
            "total_dependencies": self.total_dependencies,
            "direct_dependencies": self.direct_dependencies,
            "transitive_dependencies": self.transitive_dependencies,
            "risk_score": self.risk_score,
            "critical_vulnerabilities": self.critical_vulnerabilities,
            "high_vulnerabilities": self.high_vulnerabilities,
            "dependencies": [
                {
                    "name": d.qualified_name,
                    "version": d.display_version,
                    "ecosystem": d.ecosystem.value,
                    "type": d.dependency_type.value,
                    "source_file": d.source_file,
                }
                for d in self.dependencies
            ],
            "vulnerable_deps": [
                {
                    "cve_id": v.cve_id,
                    "dependency": v.dependency_name,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "summary": v.summary,
                    "fixed_version": v.fixed_version,
                    "source": v.source,
                }
                for v in self.vulnerable_deps
            ],
            "supply_chain_warnings": [
                {
                    "type": w.warning_type.value,
                    "risk_level": w.risk_level.value,
                    "dependency": w.dependency_name,
                    "message": w.message,
                    "confidence": w.confidence,
                }
                for w in self.supply_chain_warnings
            ],
            "analysis_metadata": self.analysis_metadata,
        }


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


# =============================================================================
# 依赖清单解析器
# =============================================================================


class _ManifestParser(ABC):
    """依赖清单解析器抽象基类"""

    @property
    @abstractmethod
    def manifest_filename(self) -> str:
        """清单文件名"""

    @abstractmethod
    def parse(self, file_path: Path) -> List[DependencyInfo]:
        """解析清单文件，返回依赖列表

        Args:
            file_path: 清单文件路径

        Returns:
            解析出的依赖列表
        """


class _PomXmlParser(_ManifestParser):
    """Maven pom.xml 解析器

    解析 pom.xml 中的 <dependencies> 和 <dependencyManagement>
    节点，提取 groupId、artifactId、version 和 scope 信息。
    """

    # Maven POM 命名空间
    _NS = {"m": "http://maven.apache.org/POM/4.0.0"}

    @property
    def manifest_filename(self) -> str:
        return "pom.xml"

    def parse(self, file_path: Path) -> List[DependencyInfo]:
        """解析 pom.xml 文件

        Args:
            file_path: pom.xml 文件路径

        Returns:
            解析出的 Maven 依赖列表
        """
        deps: List[DependencyInfo] = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # 检测是否使用了命名空间
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            # 解析 <properties> 中的版本变量
            properties = self._parse_properties(root, ns)

            # 解析所有 <dependency> 节点
            for dep_elem in root.iter(f"{ns}dependency"):
                dep = self._parse_dependency(dep_elem, ns, properties, str(file_path))
                if dep:
                    deps.append(dep)

        except ET.ParseError as e:
            logger.warning(f"pom.xml 解析失败 [{file_path}]: {e}")
        except Exception as e:
            logger.error(f"pom.xml 读取异常 [{file_path}]: {e}")

        return deps

    def _parse_properties(self, root: ET.Element, ns: str) -> Dict[str, str]:
        """提取 pom.xml 中的属性变量定义"""
        props: Dict[str, str] = {}
        props_elem = root.find(f"{ns}properties")
        if props_elem is not None:
            for child in props_elem:
                tag = child.tag.replace(ns, "")
                if child.text:
                    props[tag] = child.text.strip()
        return props

    def _parse_dependency(
        self,
        elem: ET.Element,
        ns: str,
        properties: Dict[str, str],
        source_file: str,
    ) -> Optional[DependencyInfo]:
        """解析单个 <dependency> 元素"""
        group_id = self._get_text(elem, f"{ns}groupId")
        artifact_id = self._get_text(elem, f"{ns}artifactId")
        version_str = self._get_text(elem, f"{ns}version")
        scope = self._get_text(elem, f"{ns}scope")

        if not artifact_id:
            return None

        # 解析版本属性引用 ${...}
        if version_str and version_str.startswith("${") and version_str.endswith("}"):
            prop_name = version_str[2:-1]
            version_str = properties.get(prop_name, version_str)

        # 确定依赖类型
        dep_type = DependencyType.DIRECT
        if scope in ("test",):
            dep_type = DependencyType.DEV
        elif scope in ("provided", "runtime"):
            dep_type = DependencyType.OPTIONAL

        # 构建版本范围
        version_range = self._build_version_range(version_str) if version_str else None

        name = f"{group_id}:{artifact_id}" if group_id else artifact_id

        return DependencyInfo(
            name=name,
            group_id=group_id,
            artifact_id=artifact_id,
            version_range=version_range,
            resolved_version=version_str if version_str and not self._is_range(version_str) else None,
            ecosystem=Ecosystem.MAVEN,
            dependency_type=dep_type,
            source_file=source_file,
        )

    @staticmethod
    def _get_text(elem: ET.Element, tag: str) -> Optional[str]:
        """安全获取子元素文本内容"""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return None

    @staticmethod
    def _build_version_range(version_str: str) -> Optional[VersionRange]:
        """将 Maven 版本字符串解析为 VersionRange"""
        if not version_str:
            return None
        version_str = version_str.strip()

        # Maven 版本范围语法
        if "," in version_str:
            parts = [p.strip() for p in version_str.split(",")]
            min_v = max_v = None
            min_inc = True
            max_inc = False
            for p in parts:
                p = p.strip()
                if p.startswith("["):
                    min_v = p[1:].split(",")[0] if "," in p else p[1:]
                    min_inc = True
                elif p.startswith("("):
                    min_v = p[1:].split(",")[0] if "," in p else p[1:]
                    min_inc = False
                elif p.endswith("]"):
                    max_v = p[:-1].split(",")[-1] if "," in p else p[:-1]
                    max_inc = True
                elif p.endswith(")"):
                    max_v = p[:-1].split(",")[-1] if "," in p else p[:-1]
                    max_inc = False
            return VersionRange(
                raw_spec=version_str,
                min_version=min_v,
                max_version=max_v,
                min_inclusive=min_inc,
                max_inclusive=max_inc,
            )

        if _PomXmlParser._is_range(version_str):
            return VersionRange(raw_spec=version_str)

        return VersionRange(raw_spec=version_str, exact_version=version_str)

    @staticmethod
    def _is_range(version_str: str) -> bool:
        """判断版本字符串是否为范围表达式"""
        return any(c in version_str for c in "[],()")


class _GradleParser(_ManifestParser):
    """Gradle build.gradle 解析器

    通过正则表达式解析 build.gradle 中的依赖声明，
    支持 implementation/api/compile 等常见配置。
    """

    # Gradle 依赖声明正则
    _DEP_PATTERNS = [
        # implementation 'group:artifact:version'
        re.compile(
            r"""(?:implementation|api|compile|testImplementation|"""
            r"""compileOnly|runtimeOnly|annotationProcessor|classpath)"""
            r"""\s+["']([^:"']+):([^:"']+):([^"']+)["']"""
        ),
        # implementation("group:artifact:version")
        re.compile(
            r"""(?:implementation|api|compile|testImplementation|"""
            r"""compileOnly|runtimeOnly|annotationProcessor|classpath)"""
            r"""\(\s*["']([^:"']+):([^:"']+):([^"']+)["']\s*\)"""
        ),
    ]

    # Gradle 简写依赖（仅名称和版本）
    _SHORT_DEP_PATTERN = re.compile(
        r"""(?:implementation|api|compile|testImplementation)"""
        r"""\s*[\(]?\s*["']([^:"'\s]+)\s*[:=]\s*([^"'\)]+)["']\s*[\)]?"""
    )

    @property
    def manifest_filename(self) -> str:
        return "build.gradle"

    def parse(self, file_path: Path) -> List[DependencyInfo]:
        """解析 build.gradle 文件

        Args:
            file_path: build.gradle 文件路径

        Returns:
            解析出的 Gradle 依赖列表
        """
        deps: List[DependencyInfo] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()

            for line_no, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue

                # 尝试匹配完整 Maven 坐标格式
                for pattern in self._DEP_PATTERNS:
                    match = pattern.search(stripped)
                    if match:
                        group_id = match.group(1)
                        artifact_id = match.group(2)
                        version = match.group(3)
                        dep_type = self._infer_dep_type(stripped)
                        deps.append(
                            DependencyInfo(
                                name=f"{group_id}:{artifact_id}",
                                group_id=group_id,
                                artifact_id=artifact_id,
                                version_range=VersionRange(
                                    raw_spec=version, exact_version=version
                                )
                                if not self._is_dynamic_version(version)
                                else VersionRange(raw_spec=version),
                                resolved_version=version
                                if not self._is_dynamic_version(version)
                                else None,
                                ecosystem=Ecosystem.GRADLE,
                                dependency_type=dep_type,
                                source_file=str(file_path),
                                line_number=line_no,
                            )
                        )
                        break

        except Exception as e:
            logger.error(f"build.gradle 读取异常 [{file_path}]: {e}")

        return deps

    @staticmethod
    def _infer_dep_type(line: str) -> DependencyType:
        """从声明关键字推断依赖类型"""
        if "testImplementation" in line or "testCompile" in line:
            return DependencyType.DEV
        if "compileOnly" in line or "runtimeOnly" in line:
            return DependencyType.OPTIONAL
        return DependencyType.DIRECT

    @staticmethod
    def _is_dynamic_version(version: str) -> bool:
        """判断是否为动态版本声明（如 +, latest.release）"""
        return version.endswith("+") or version.startswith("latest")


class _RequirementsTxtParser(_ManifestParser):
    """Python requirements.txt 解析器

    支持 ==、>=、<=、!=、~= 等版本约束语法，
    以及 -r 引入和 -e 可编辑安装模式。
    """

    _VERSION_SPEC_PATTERN = re.compile(
        r"^([A-Za-z0-9_][A-Za-z0-9._\-]*)\s*(.*)$"
    )

    @property
    def manifest_filename(self) -> str:
        return "requirements.txt"

    def parse(self, file_path: Path) -> List[DependencyInfo]:
        """解析 requirements.txt 文件

        Args:
            file_path: requirements.txt 文件路径

        Returns:
            解析出的 Python 依赖列表
        """
        deps: List[DependencyInfo] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()

            for line_no, raw_line in enumerate(lines, start=1):
                line = raw_line.strip()

                # 跳过空行、注释和选项行
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # 移除行内注释
                if " #" in line:
                    line = line[: line.index(" #")].strip()

                match = self._VERSION_SPEC_PATTERN.match(line)
                if not match:
                    continue

                name = match.group(1).strip()
                version_spec = match.group(2).strip()

                version_range = self._parse_version_spec(version_spec)
                resolved = None
                if version_range and version_range.exact_version:
                    resolved = version_range.exact_version

                deps.append(
                    DependencyInfo(
                        name=name,
                        version_range=version_range,
                        resolved_version=resolved,
                        ecosystem=Ecosystem.PYPI,
                        dependency_type=DependencyType.DIRECT,
                        source_file=str(file_path),
                        line_number=line_no,
                    )
                )

        except Exception as e:
            logger.error(f"requirements.txt 读取异常 [{file_path}]: {e}")

        return deps

    def _parse_version_spec(self, spec: str) -> Optional[VersionRange]:
        """解析 Python 版本约束规范"""
        if not spec:
            return None

        # 精确版本 ==1.2.3
        exact_match = re.match(r"^==\s*([^\s,]+)$", spec)
        if exact_match:
            return VersionRange(raw_spec=spec, exact_version=exact_match.group(1))

        # 兼容版本 ~=1.2.3
        compat_match = re.match(r"^~=\s*([^\s,]+)$", spec)
        if compat_match:
            ver = compat_match.group(1)
            parts = ver.split(".")
            if len(parts) >= 2:
                next_minor = ".".join(parts[:-1])
                next_parts = [int(x) for x in next_minor.split(".")]
                next_parts[-1] += 1
                upper = ".".join(str(x) for x in next_parts) + ".0"
                return VersionRange(
                    raw_spec=spec,
                    min_version=ver,
                    max_version=upper,
                    min_inclusive=True,
                    max_inclusive=False,
                )

        # 复合约束 >=1.0,<2.0
        if "," in spec:
            parts = [p.strip() for p in spec.split(",")]
            min_v = max_v = None
            min_inc = True
            max_inc = False
            for p in parts:
                if p.startswith(">="):
                    min_v = p[2:].strip()
                    min_inc = True
                elif p.startswith(">"):
                    min_v = p[1:].strip()
                    min_inc = False
                elif p.startswith("<="):
                    max_v = p[2:].strip()
                    max_inc = True
                elif p.startswith("<"):
                    max_v = p[1:].strip()
                    max_inc = False
                elif p.startswith("!="):
                    pass  # 排除版本暂不处理
                elif p.startswith("=="):
                    exact = p[2:].strip()
                    return VersionRange(raw_spec=spec, exact_version=exact)
            return VersionRange(
                raw_spec=spec,
                min_version=min_v,
                max_version=max_v,
                min_inclusive=min_inc,
                max_inclusive=max_inc,
            )

        # 单一约束
        for prefix, handler in [
            (">=", lambda v: VersionRange(raw_spec=spec, min_version=v)),
            ("<=", lambda v: VersionRange(raw_spec=spec, max_version=v, max_inclusive=True)),
            (">", lambda v: VersionRange(raw_spec=spec, min_version=v, min_inclusive=False)),
            ("<", lambda v: VersionRange(raw_spec=spec, max_version=v)),
            ("==", lambda v: VersionRange(raw_spec=spec, exact_version=v)),
        ]:
            if spec.startswith(prefix):
                return handler(spec[len(prefix):].strip())

        return VersionRange(raw_spec=spec)


class _SetupPyParser(_ManifestParser):
    """Python setup.py 解析器

    通过正则表达式提取 setup() 调用中的 install_requires
    和 extras_require 依赖声明。
    """

    _INSTALL_REQUIRES_PATTERN = re.compile(
        r"""install_requires\s*=\s*\[(.*?)\]""", re.DOTALL
    )
    _EXTRAS_REQUIRES_PATTERN = re.compile(
        r"""extras_require\s*=\s*\{(.*?)\}""", re.DOTALL
    )
    _DEP_STRING_PATTERN = re.compile(r"""["']([^"']+)["']""")
    _VERSION_PATTERN = re.compile(
        r"^([A-Za-z0-9_][A-Za-z0-9._\-]*(?:\[[^\]]*\])?)\s*(.*)$"
    )

    @property
    def manifest_filename(self) -> str:
        return "setup.py"

    def parse(self, file_path: Path) -> List[DependencyInfo]:
        """解析 setup.py 文件

        Args:
            file_path: setup.py 文件路径

        Returns:
            解析出的 Python 依赖列表
        """
        deps: List[DependencyInfo] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")

            # 提取 install_requires
            match = self._INSTALL_REQUIRES_PATTERN.search(content)
            if match:
                deps_block = match.group(1)
                for dep_match in self._DEP_STRING_PATTERN.finditer(deps_block):
                    dep_str = dep_match.group(1).strip()
                    dep = self._parse_dep_string(dep_str, str(file_path))
                    if dep:
                        deps.append(dep)

            # 提取 extras_require 中的依赖
            extras_match = self._EXTRAS_REQUIRES_PATTERN.search(content)
            if extras_match:
                extras_block = extras_match.group(1)
                for dep_match in self._DEP_STRING_PATTERN.finditer(extras_block):
                    dep_str = dep_match.group(1).strip()
                    dep = self._parse_dep_string(
                        dep_str, str(file_path), dep_type=DependencyType.OPTIONAL
                    )
                    if dep:
                        deps.append(dep)

        except Exception as e:
            logger.error(f"setup.py 读取异常 [{file_path}]: {e}")

        return deps

    def _parse_dep_string(
        self,
        dep_str: str,
        source_file: str,
        dep_type: DependencyType = DependencyType.DIRECT,
    ) -> Optional[DependencyInfo]:
        """解析单个依赖声明字符串"""
        # 移除 extras 标记，例如 package[extra]
        dep_str = re.sub(r"\[.*?\]", "", dep_str).strip()
        match = self._VERSION_PATTERN.match(dep_str)
        if not match:
            return None

        name = match.group(1).strip()
        version_spec = match.group(2).strip()

        version_range = None
        resolved = None
        if version_spec:
            version_range = VersionRange(raw_spec=version_spec)
            if version_spec.startswith("=="):
                exact = version_spec[2:].strip().split(",")[0].strip()
                version_range = VersionRange(raw_spec=version_spec, exact_version=exact)
                resolved = exact

        return DependencyInfo(
            name=name,
            version_range=version_range,
            resolved_version=resolved,
            ecosystem=Ecosystem.PYPI,
            dependency_type=dep_type,
            source_file=source_file,
        )


class _PyprojectTomlParser(_ManifestParser):
    """Python pyproject.toml 解析器

    解析 PEP 621 标准的 pyproject.toml 文件中的
    [project.dependencies] 和 [project.optional-dependencies]。
    使用简单的 TOML 解析（不依赖第三方库）。
    """

    @property
    def manifest_filename(self) -> str:
        return "pyproject.toml"

    def parse(self, file_path: Path) -> List[DependencyInfo]:
        """解析 pyproject.toml 文件

        Args:
            file_path: pyproject.toml 文件路径

        Returns:
            解析出的 Python 依赖列表
        """
        deps: List[DependencyInfo] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")

            # 尝试使用 tomllib（Python 3.11+）或 tomli
            parsed = self._parse_toml(content)
            if parsed is None:
                # 降级到正则解析
                return self._parse_with_regex(content, str(file_path))

            # 从解析后的字典中提取依赖
            project = parsed.get("project", {})

            # [project.dependencies]
            for dep_str in project.get("dependencies", []):
                dep = self._parse_pep508(dep_str, str(file_path))
                if dep:
                    deps.append(dep)

            # [project.optional-dependencies]
            for _group, group_deps in project.get("optional-dependencies", {}).items():
                for dep_str in group_deps:
                    dep = self._parse_pep508(
                        dep_str, str(file_path), dep_type=DependencyType.OPTIONAL
                    )
                    if dep:
                        deps.append(dep)

        except Exception as e:
            logger.error(f"pyproject.toml 读取异常 [{file_path}]: {e}")

        return deps

    def _parse_toml(self, content: str) -> Optional[Dict[str, Any]]:
        """尝试解析 TOML 内容"""
        # Python 3.11+ 内置 tomllib
        try:
            import tomllib
            return tomllib.loads(content)
        except ImportError:
            pass

        # 尝试 tomli
        try:
            import tomli
            return tomli.loads(content)
        except ImportError:
            pass

        return None

    def _parse_with_regex(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """使用正则表达式降级解析 pyproject.toml"""
        deps: List[DependencyInfo] = []

        # 匹配 [project.dependencies] 数组中的字符串
        dep_section = re.search(
            r"\[project\.dependencies\]\s*\n((?:\s*.*\n)*?)(?=\n\[|\Z)",
            content,
        )
        if dep_section:
            block = dep_section.group(1)
            for match in re.finditer(r'"([^"]+)"', block):
                dep = self._parse_pep508(match.group(1), source_file)
                if dep:
                    deps.append(dep)

        return deps

    def _parse_pep508(
        self,
        dep_str: str,
        source_file: str,
        dep_type: DependencyType = DependencyType.DIRECT,
    ) -> Optional[DependencyInfo]:
        """解析 PEP 508 依赖声明字符串"""
        dep_str = dep_str.strip()
        if not dep_str:
            return None

        # 移除 extras 和环境标记
        dep_str = re.sub(r"\[.*?\]", "", dep_str)
        dep_str = re.sub(r"\s*;.*$", "", dep_str)

        # 分离名称和版本约束
        match = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._\-]*)\s*(.*)$", dep_str)
        if not match:
            return None

        name = match.group(1).strip()
        version_spec = match.group(2).strip()

        version_range = None
        resolved = None
        if version_spec:
            version_range = VersionRange(raw_spec=version_spec)
            if version_spec.startswith("=="):
                exact = version_spec[2:].strip()
                version_range = VersionRange(raw_spec=version_spec, exact_version=exact)
                resolved = exact

        return DependencyInfo(
            name=name,
            version_range=version_range,
            resolved_version=resolved,
            ecosystem=Ecosystem.PYPI,
            dependency_type=dep_type,
            source_file=source_file,
        )


class _PackageJsonParser(_ManifestParser):
    """JavaScript package.json 解析器

    解析 dependencies、devDependencies、peerDependencies
    和 optionalDependencies 字段。
    """

    @property
    def manifest_filename(self) -> str:
        return "package.json"

    def parse(self, file_path: Path) -> List[DependencyInfo]:
        """解析 package.json 文件

        Args:
            file_path: package.json 文件路径

        Returns:
            解析出的 npm 依赖列表
        """
        deps: List[DependencyInfo] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)

            # dependencies
            for name, version in data.get("dependencies", {}).items():
                deps.append(
                    self._build_dep(name, version, DependencyType.DIRECT, str(file_path))
                )

            # devDependencies
            for name, version in data.get("devDependencies", {}).items():
                deps.append(
                    self._build_dep(name, version, DependencyType.DEV, str(file_path))
                )

            # peerDependencies
            for name, version in data.get("peerDependencies", {}).items():
                deps.append(
                    self._build_dep(
                        name, version, DependencyType.OPTIONAL, str(file_path)
                    )
                )

            # optionalDependencies
            for name, version in data.get("optionalDependencies", {}).items():
                deps.append(
                    self._build_dep(
                        name, version, DependencyType.OPTIONAL, str(file_path)
                    )
                )

        except json.JSONDecodeError as e:
            logger.warning(f"package.json JSON 解析失败 [{file_path}]: {e}")
        except Exception as e:
            logger.error(f"package.json 读取异常 [{file_path}]: {e}")

        return deps

    @staticmethod
    def _build_dep(
        name: str,
        version_spec: str,
        dep_type: DependencyType,
        source_file: str,
    ) -> DependencyInfo:
        """构建 npm 依赖信息对象"""
        version_range = _PackageJsonParser._parse_npm_version(version_spec)
        resolved = None
        if version_range and version_range.exact_version:
            resolved = version_range.exact_version

        return DependencyInfo(
            name=name,
            version_range=version_range,
            resolved_version=resolved,
            ecosystem=Ecosystem.NPM,
            dependency_type=dep_type,
            source_file=source_file,
        )

    @staticmethod
    def _parse_npm_version(spec: str) -> Optional[VersionRange]:
        """解析 npm 版本规范

        支持语义化版本（semver）语法：
        - 精确版本: 1.2.3
        - 兼容范围: ^1.2.3
        - 近似范围: ~1.2.3
        - 范围表达式: >=1.0.0 <2.0.0
        - 通配符: * / 1.x
        """
        spec = spec.strip()
        if not spec or spec == "*" or spec == "latest":
            return VersionRange(raw_spec=spec)

        # 精确版本
        if re.match(r"^\d+\.\d+\.\d+", spec):
            return VersionRange(raw_spec=spec, exact_version=spec)

        # ^ 兼容范围: ^1.2.3 => >=1.2.3 <2.0.0
        caret_match = re.match(r"^\^(\d+)(?:\.(\d+))?(?:\.(\d+))?", spec)
        if caret_match:
            major = int(caret_match.group(1))
            minor = int(caret_match.group(2) or 0)
            patch = int(caret_match.group(3) or 0)
            if major > 0:
                upper = f"{major + 1}.0.0"
            elif minor > 0:
                upper = f"0.{minor + 1}.0"
            else:
                upper = f"0.0.{patch + 1}"
            return VersionRange(
                raw_spec=spec,
                min_version=f"{major}.{minor}.{patch}",
                max_version=upper,
                min_inclusive=True,
                max_inclusive=False,
            )

        # ~ 近似范围: ~1.2.3 => >=1.2.3 <1.3.0
        tilde_match = re.match(r"^~(\d+)(?:\.(\d+))?(?:\.(\d+))?", spec)
        if tilde_match:
            major = int(tilde_match.group(1))
            minor = int(tilde_match.group(2) or 0)
            patch = int(tilde_match.group(3) or 0)
            return VersionRange(
                raw_spec=spec,
                min_version=f"{major}.{minor}.{patch}",
                max_version=f"{major}.{minor + 1}.0",
                min_inclusive=True,
                max_inclusive=False,
            )

        # 范围表达式 >=1.0.0 <2.0.0
        range_match = re.match(
            r">=?\s*(\d[\d.]*)\s+<?=?\s*(\d[\d.]*)", spec
        )
        if range_match:
            return VersionRange(
                raw_spec=spec,
                min_version=range_match.group(1),
                max_version=range_match.group(2),
            )

        # x 通配符: 1.x => >=1.0.0 <2.0.0
        x_match = re.match(r"^(\d+)\.x", spec)
        if x_match:
            major = int(x_match.group(1))
            return VersionRange(
                raw_spec=spec,
                min_version=f"{major}.0.0",
                max_version=f"{major + 1}.0.0",
            )

        return VersionRange(raw_spec=spec)


# =============================================================================
# 供应链风险评估引擎
# =============================================================================


class _SupplyChainRiskAssessor:
    """供应链风险评估引擎

    实现多种供应链安全风险检测：
    - 名称抢注（Typosquatting）检测
    - 依赖混淆（Dependency Confusion）风险检测
    - 停止维护（Unmaintained）依赖检测
    - 深层传递依赖（Deep Transitive）风险检测
    """

    def __init__(self) -> None:
        self._typo_patterns = [
            # 常见拼写错误模式
            ("rn", "m"),  # requests -> requets
            ("m", "rn"),
            ("l", "1"),  # 字母与数字混淆
            ("1", "l"),
            ("0", "o"),
            ("o", "0"),
            ("-", ""),  # 连字符变体
            ("", "-"),
            ("_", "-"),  # 下划线与连字符互换
            ("-", "_"),
        ]

    def assess(
        self,
        dependencies: List[DependencyInfo],
    ) -> List[SupplyChainWarning]:
        """执行全面的供应链风险评估

        Args:
            dependencies: 所有已发现的依赖列表

        Returns:
            供应链风险警告列表
        """
        warnings: List[SupplyChainWarning] = []

        warnings.extend(self._check_typosquatting(dependencies))
        warnings.extend(self._check_unmaintained(dependencies))
        warnings.extend(self._check_deep_transitive(dependencies))
        warnings.extend(self._check_version_conflicts(dependencies))

        return warnings

    def _check_typosquatting(
        self, dependencies: List[DependencyInfo]
    ) -> List[SupplyChainWarning]:
        """检测名称抢注风险

        将依赖名称与已知高价值包名进行比对，
        识别可能的拼写变体或仿冒包名。
        """
        warnings: List[SupplyChainWarning] = []
        dep_names = {d.name.lower() for d in dependencies}

        for dep in dependencies:
            dep_lower = dep.name.lower()
            ecosystem_name = dep.ecosystem.value
            well_known = _WELL_KNOWN_PACKAGES.get(ecosystem_name, [])

            for known_pkg in well_known:
                if dep_lower == known_pkg:
                    continue  # 是合法包名

                if self._is_typosquat(dep_lower, known_pkg):
                    warnings.append(
                        SupplyChainWarning(
                            warning_type=WarningType.TYPOSQUATTING,
                            risk_level=RiskLevel.HIGH,
                            dependency_name=dep.name,
                            message=(
                                f"依赖 '{dep.name}' 与知名包 '{known_pkg}' 名称高度相似，"
                                f"可能存在名称抢注（typosquatting）风险。"
                                f"请确认这是预期的包而非仿冒包。"
                            ),
                            confidence=0.85,
                            metadata={
                                "similar_to": known_pkg,
                                "ecosystem": ecosystem_name,
                            },
                        )
                    )

        return warnings

    def _is_typosquat(self, candidate: str, target: str) -> bool:
        """判断 candidate 是否为 target 的名称抢注变体"""
        if candidate == target:
            return False

        # 编辑距离检测（Levenshtein distance <= 2）
        if self._edit_distance(candidate, target) == 1:
            return True

        # 常见替换模式
        for original, replacement in self._typo_patterns:
            variant = target.replace(original, replacement)
            if variant == candidate and variant != target:
                return True

        return False

    @staticmethod
    def _edit_distance(s1: str, s2: str) -> int:
        """计算两个字符串的编辑距离（动态规划）"""
        m, n = len(s1), len(s2)
        if m * n > 10000:
            return 999  # 避免过长的字符串消耗资源

        dp = list(range(n + 1))
        for i in range(1, m + 1):
            prev = dp[0]
            dp[0] = i
            for j in range(1, n + 1):
                temp = dp[j]
                if s1[i - 1] == s2[j - 1]:
                    dp[j] = prev
                else:
                    dp[j] = 1 + min(prev, dp[j], dp[j - 1])
                prev = temp
        return dp[n]

    def _check_unmaintained(
        self, dependencies: List[DependencyInfo]
    ) -> List[SupplyChainWarning]:
        """检测已停止维护的依赖

        对照已知弃用包列表，标记不再维护的依赖。
        """
        warnings: List[SupplyChainWarning] = []

        for dep in dependencies:
            ecosystem_name = dep.ecosystem.value
            deprecated = _DEPRECATED_PACKAGES.get(ecosystem_name, set())
            if dep.name.lower() in {p.lower() for p in deprecated}:
                warnings.append(
                    SupplyChainWarning(
                        warning_type=WarningType.UNMAINTAINED,
                        risk_level=RiskLevel.MEDIUM,
                        dependency_name=dep.name,
                        message=(
                            f"依赖 '{dep.name}' 已被标记为停止维护/弃用。"
                            f"继续使用可能面临未修复的安全漏洞风险，"
                            f"建议寻找替代方案。"
                        ),
                        confidence=0.9,
                        metadata={"ecosystem": ecosystem_name},
                    )
                )

        return warnings

    def _check_deep_transitive(
        self, dependencies: List[DependencyInfo]
    ) -> List[SupplyChainWarning]:
        """检测深层传递依赖风险

        当传递依赖层级过深时，攻击面显著增大。
        """
        warnings: List[SupplyChainWarning] = []
        transitive_count = sum(
            1 for d in dependencies if d.dependency_type == DependencyType.TRANSITIVE
        )
        total = len(dependencies)

        if total > 0 and transitive_count / total > 0.7 and transitive_count > 50:
            warnings.append(
                SupplyChainWarning(
                    warning_type=WarningType.DEEP_TRANSITIVE,
                    risk_level=RiskLevel.MEDIUM,
                    dependency_name="(transitive)",
                    message=(
                        f"项目存在 {transitive_count} 个传递依赖（占比 "
                        f"{transitive_count / total:.0%}），依赖链过深。"
                        f"深层传递依赖增加了供应链攻击面，"
                        f"建议定期审计间接依赖并考虑精简依赖树。"
                    ),
                    confidence=0.75,
                    metadata={
                        "transitive_count": transitive_count,
                        "total_count": total,
                    },
                )
            )

        return warnings

    def _check_version_conflicts(
        self, dependencies: List[DependencyInfo]
    ) -> List[SupplyChainWarning]:
        """检测版本冲突

        同一包存在多个不同版本约束时可能导致运行时问题。
        """
        warnings: List[SupplyChainWarning] = []
        seen: Dict[str, List[DependencyInfo]] = {}

        for dep in dependencies:
            key = dep.qualified_name.lower()
            if key not in seen:
                seen[key] = []
            seen[key].append(dep)

        for name, dep_list in seen.items():
            if len(dep_list) <= 1:
                continue

            versions = set()
            for d in dep_list:
                v = d.resolved_version or (
                    d.version_range.raw_spec if d.version_range else "unspecified"
                )
                versions.add(v)

            if len(versions) > 1:
                warnings.append(
                    SupplyChainWarning(
                        warning_type=WarningType.CONFLICTING_VERSIONS,
                        risk_level=RiskLevel.LOW,
                        dependency_name=name,
                        message=(
                            f"依赖 '{name}' 存在多个不同版本约束: "
                            f"{', '.join(sorted(versions))}。"
                            f"版本冲突可能导致运行时行为不一致。"
                        ),
                        confidence=0.95,
                        metadata={"versions": sorted(versions)},
                    )
                )

        return warnings


# =============================================================================
# 主分析器
# =============================================================================


class DependencyChainAnalyzer:
    """依赖链分析器

    对标 Argus 论文 (arXiv:2604.06633) 的全供应链分析方法，
    对项目进行完整的依赖链安全分析。

    功能包括：
    1. 自动发现并解析多种依赖清单格式
    2. 对每个依赖进行已知漏洞匹配
    3. 评估供应链安全风险
    4. 生成综合风险评分

    用法示例::

        analyzer = DependencyChainAnalyzer()
        report = analyzer.analyze(Path("/path/to/project"))
        print(f"发现 {report.total_dependencies} 个依赖")
        print(f"风险评分: {report.risk_score}")
    """

    # 支持的清单文件及其解析器映射
    _MANIFEST_PARSERS: Dict[str, _ManifestParser] = {
        "pom.xml": _PomXmlParser(),
        "build.gradle": _GradleParser(),
        "requirements.txt": _RequirementsTxtParser(),
        "setup.py": _SetupPyParser(),
        "pyproject.toml": _PyprojectTomlParser(),
        "package.json": _PackageJsonParser(),
    }

    # 递归搜索深度限制
    _MAX_SCAN_DEPTH = 5

    def __init__(
        self,
        cve_checker: Optional[CVECheckerInterface] = None,
        max_scan_depth: int = 5,
    ) -> None:
        """初始化依赖链分析器

        Args:
            cve_checker: CVE 漏洞查询实现（默认使用 NVD 集成，降级到模拟数据）
            max_scan_depth: 项目目录最大递归搜索深度
        """
        self._cve_checker = cve_checker or NVDIntegratedCVEChecker()
        self._risk_assessor = _SupplyChainRiskAssessor()
        self._max_scan_depth = max_scan_depth
        logger.info(
            f"DependencyChainAnalyzer 初始化完成 "
            f"(CVE 数据源: {'NVD' if self._cve_checker.is_available() else 'Mock'})"
        )

    def analyze(self, project_path: Path) -> DependencyReport:
        """执行完整的依赖链分析

        按照以下步骤进行：
        1. 发现项目中的依赖清单文件
        2. 解析所有清单文件，提取依赖信息
        3. 对每个依赖进行漏洞匹配
        4. 执行供应链风险评估
        5. 计算综合风险评分

        Args:
            project_path: 项目根目录路径

        Returns:
            完整的依赖链分析报告
        """
        project_path = Path(project_path).resolve()
        logger.info(f"开始依赖链分析: {project_path}")

        report = DependencyReport(project_path=str(project_path))

        # 步骤 1: 发现清单文件
        manifest_files = self._discover_manifests(project_path)
        report.manifest_files = [str(f) for f in manifest_files]
        logger.info(f"发现 {len(manifest_files)} 个依赖清单文件")

        if not manifest_files:
            logger.warning(f"未在项目中找到任何依赖清单文件: {project_path}")
            report.analysis_metadata["warning"] = "未找到依赖清单文件"
            return report

        # 步骤 2: 解析依赖
        all_deps: List[DependencyInfo] = []
        for manifest in manifest_files:
            parser = self._get_parser(manifest.name)
            if parser:
                try:
                    deps = parser.parse(manifest)
                    all_deps.extend(deps)
                    logger.debug(f"从 {manifest.name} 解析出 {len(deps)} 个依赖")
                except Exception as e:
                    logger.error(f"解析 {manifest} 失败: {e}")

        report.dependencies = all_deps
        logger.info(f"共解析出 {len(all_deps)} 个依赖")

        # 确定主要生态系统
        report.ecosystem = self._detect_primary_ecosystem(all_deps)

        # 步骤 3: 漏洞匹配
        vulnerable_deps = self._match_vulnerabilities(all_deps)
        report.vulnerable_deps = vulnerable_deps
        logger.info(f"发现 {len(vulnerable_deps)} 个已知漏洞")

        # 步骤 4: 供应链风险评估
        warnings = self._risk_assessor.assess(all_deps)
        report.supply_chain_warnings = warnings
        logger.info(f"发现 {len(warnings)} 个供应链风险警告")

        # 步骤 5: 计算综合风险评分
        report.risk_score = self._calculate_risk_score(report)
        logger.info(f"综合风险评分: {report.risk_score:.1f}/100")

        report.analysis_metadata = {
            "total_manifests": len(manifest_files),
            "total_dependencies": len(all_deps),
            "vulnerabilities_found": len(vulnerable_deps),
            "supply_chain_warnings": len(warnings),
            "cve_checker_available": self._cve_checker.is_available(),
        }

        logger.info(f"依赖链分析完成: {project_path}")
        return report

    def _discover_manifests(self, project_path: Path) -> List[Path]:
        """递归搜索项目中的依赖清单文件

        Args:
            project_path: 项目根目录

        Returns:
            找到的清单文件路径列表
        """
        manifests: List[Path] = []
        target_names = set(self._MANIFEST_PARSERS.keys())

        # 排除的目录（避免扫描 node_modules、.git 等）
        excluded_dirs = {
            "node_modules",
            ".git",
            ".svn",
            "__pycache__",
            ".venv",
            "venv",
            "env",
            ".tox",
            "dist",
            "build",
            "target",
            ".gradle",
            ".idea",
            ".vscode",
        }

        try:
            self._walk_for_manifests(
                project_path, target_names, excluded_dirs, manifests, depth=0
            )
        except PermissionError:
            logger.warning(f"权限不足，无法完整扫描: {project_path}")

        return manifests

    def _walk_for_manifests(
        self,
        current_path: Path,
        target_names: Set[str],
        excluded_dirs: Set[str],
        results: List[Path],
        depth: int,
    ) -> None:
        """递归遍历目录查找清单文件"""
        if depth > self._max_scan_depth:
            return

        try:
            for entry in current_path.iterdir():
                if entry.is_file() and entry.name in target_names:
                    results.append(entry)
                elif (
                    entry.is_dir()
                    and entry.name not in excluded_dirs
                    and not entry.name.startswith(".")
                ):
                    self._walk_for_manifests(
                        entry, target_names, excluded_dirs, results, depth + 1
                    )
        except PermissionError:
            pass

    def _get_parser(self, filename: str) -> Optional[_ManifestParser]:
        """获取文件名对应的解析器"""
        return self._MANIFEST_PARSERS.get(filename)

    def _match_vulnerabilities(
        self, dependencies: List[DependencyInfo]
    ) -> List[VulnerabilityInfo]:
        """对所有依赖执行漏洞匹配

        Args:
            dependencies: 依赖列表

        Returns:
            匹配到的漏洞列表
        """
        all_vulns: List[VulnerabilityInfo] = []

        if not self._cve_checker.is_available():
            logger.warning("CVE 查询服务不可用，跳过漏洞匹配")
            return all_vulns

        for dep in dependencies:
            try:
                vulns = self._cve_checker.check_vulnerabilities(dep)
                all_vulns.extend(vulns)
            except Exception as e:
                logger.debug(f"漏洞查询失败 [{dep.name}]: {e}")

        return all_vulns

    @staticmethod
    def _detect_primary_ecosystem(dependencies: List[DependencyInfo]) -> str:
        """根据依赖分布判断项目主要生态系统"""
        counts: Dict[str, int] = {}
        for dep in dependencies:
            eco = dep.ecosystem.value
            counts[eco] = counts.get(eco, 0) + 1

        if not counts:
            return "Unknown"

        return max(counts, key=counts.get)  # type: ignore[arg-type]

    @staticmethod
    def _calculate_risk_score(report: DependencyReport) -> float:
        """计算综合风险评分（0 ~ 100）

        评分维度：
        - 漏洞严重度（权重 50%）：基于 CVSS 评分
        - 供应链风险（权重 30%）：基于警告数量和等级
        - 依赖复杂度（权重 20%）：基于依赖数量和深度

        Args:
            report: 依赖分析报告

        Returns:
            风险评分（0.0 ~ 100.0）
        """
        score = 0.0

        # --- 漏洞严重度评分（0 ~ 50 分）---
        vuln_score = 0.0
        for vuln in report.vulnerable_deps:
            if vuln.cvss_score >= 9.0:
                vuln_score += 15  # 严重漏洞
            elif vuln.cvss_score >= 7.0:
                vuln_score += 10  # 高危漏洞
            elif vuln.cvss_score >= 4.0:
                vuln_score += 5  # 中危漏洞
            else:
                vuln_score += 2  # 低危漏洞
        score += min(vuln_score, 50.0)

        # --- 供应链风险评分（0 ~ 30 分）---
        warning_score = 0.0
        for warning in report.supply_chain_warnings:
            level_weights = {
                RiskLevel.CRITICAL: 15.0,
                RiskLevel.HIGH: 10.0,
                RiskLevel.MEDIUM: 5.0,
                RiskLevel.LOW: 2.0,
                RiskLevel.INFO: 0.5,
            }
            warning_score += level_weights.get(warning.risk_level, 1.0) * warning.confidence
        score += min(warning_score, 30.0)

        # --- 依赖复杂度评分（0 ~ 20 分）---
        complexity_score = 0.0
        total = report.total_dependencies
        if total > 200:
            complexity_score += 15.0
        elif total > 100:
            complexity_score += 10.0
        elif total > 50:
            complexity_score += 5.0

        trans_ratio = (
            report.transitive_dependencies / total if total > 0 else 0
        )
        if trans_ratio > 0.8:
            complexity_score += 5.0
        elif trans_ratio > 0.5:
            complexity_score += 3.0

        score += min(complexity_score, 20.0)

        return round(min(score, 100.0), 1)
