"""依赖分析数据模型

定义依赖分析使用的枚举、常量和数据类。
"""

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)

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
