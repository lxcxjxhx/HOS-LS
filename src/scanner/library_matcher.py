"""库匹配器模块

识别代码中使用的库和版本，并基于已知的库漏洞数据库进行匹配。
优先使用NVD SQLite数据库，fallback到内置JSON数据库。
"""

import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)


@dataclass
class LibraryInfo:
    """库信息"""
    name: str
    version: Optional[str] = None
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LibraryVulnerability:
    """库漏洞信息"""
    cve_id: str
    library_name: str
    affected_versions: List[str]
    severity: str
    description: str
    fix_version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class LibraryMatcher:
    """库匹配器

    识别代码中使用的库和版本，并基于已知的库漏洞数据库进行匹配。
    优先使用NVD SQLite数据库进行精确匹配。
    """

    def __init__(self, config: Optional[Config] = None):
        """初始化库匹配器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._nvd_adapter = None
        self._nvd_available = False
        self._vulnerability_db = self._load_vulnerability_db()
        self._language_patterns = {
            'python': {
                'import': re.compile(r'^\s*import\s+([\w\.]+)'),
                'from_import': re.compile(r'^\s*from\s+([\w\.]+)\s+import'),
                'requirements': re.compile(r'^([\w\-\.]+)\s*==\s*([\d\.]+)'),
                'setup_py': re.compile(r'\'([\w\-\.]+)\',\s*version=\'([\d\.]+)\'')
            },
            'javascript': {
                'require': re.compile(r'require\(["\']([\w\-\.]+)["\']\)'),
                'import': re.compile(r'import.*from\s+["\']([\w\-\.]+)["\']'),
                'package_json': re.compile(r'"([\w\-\.]+)":\s*"([\d\.]+)"')
            },
            'java': {
                'import': re.compile(r'^\s*import\s+([\w\.]+);'),
                'maven': re.compile(r'<artifactId>([\w\-\.]+)</artifactId>.*<version>([\d\.]+)</version>', re.DOTALL),
                'gradle': re.compile(r'implementation\s+["\']([\w\:]+):([\w\-\.]+):([\d\.]+)["\']')
            }
        }
        self._init_nvd_connection()

    def _init_nvd_connection(self):
        """初始化NVD数据库连接"""
        try:
            from src.scanner.nvd_adapter import get_nvd_adapter
            self._nvd_adapter = get_nvd_adapter()
            self._nvd_available = self._nvd_adapter.is_available()
            if self._nvd_available:
                db_type = self._nvd_adapter.get_db_type()
                logger.info(f"NVD数据库连接成功 (类型: {db_type})")
            else:
                logger.info("NVD数据库不可用，使用内置漏洞数据库")
        except Exception as e:
            logger.debug(f"NVD适配器初始化失败: {e}")
            self._nvd_available = False

    def _load_vulnerability_db(self) -> Dict[str, List[LibraryVulnerability]]:
        """加载漏洞数据库

        Returns:
            漏洞数据库，按库名索引
        """
        vulnerability_db = {}
        
        # 加载内置漏洞数据库
        db_path = Path(__file__).parent / "vulnerability_db.json"
        if db_path.exists():
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data:
                    vuln = LibraryVulnerability(
                        cve_id=item.get("cve_id"),
                        library_name=item.get("library_name"),
                        affected_versions=item.get("affected_versions", []),
                        severity=item.get("severity"),
                        description=item.get("description"),
                        fix_version=item.get("fix_version"),
                        metadata=item.get("metadata", {})
                    )
                    if vuln.library_name not in vulnerability_db:
                        vulnerability_db[vuln.library_name] = []
                    vulnerability_db[vuln.library_name].append(vuln)
            except Exception as e:
                logger.error(f"加载漏洞数据库失败: {e}")
        
        return vulnerability_db

    def detect_libraries(self, code: str, language: str) -> List[LibraryInfo]:
        """检测代码中使用的库

        Args:
            code: 代码内容
            language: 编程语言

        Returns:
            检测到的库信息列表
        """
        libraries = []
        detected = set()

        patterns = self._language_patterns.get(language, {})
        
        for pattern_name, pattern in patterns.items():
            for match in pattern.finditer(code):
                if pattern_name in ['import', 'from_import', 'require']:
                    # 提取库名
                    library_name = match.group(1)
                    # 只取主库名（如 'requests' 而不是 'requests.exceptions'）
                    library_name = library_name.split('.')[0]
                    if library_name not in detected:
                        detected.add(library_name)
                        libraries.append(LibraryInfo(
                            name=library_name,
                            source=pattern_name
                        ))
                elif pattern_name in ['requirements', 'setup_py', 'package_json', 'maven', 'gradle']:
                    # 提取库名和版本
                    if pattern_name == 'gradle':
                        # Gradle 格式: group:name:version
                        group, name, version = match.groups()
                        library_name = f"{group}:{name}"
                    else:
                        if pattern_name == 'maven':
                            # Maven 格式: artifactId 和 version
                            name, version = match.groups()
                        else:
                            # 其他格式: name==version
                            name, version = match.groups()
                        library_name = name
                    
                    if library_name not in detected:
                        detected.add(library_name)
                        libraries.append(LibraryInfo(
                            name=library_name,
                            version=version,
                            source=pattern_name
                        ))
        
        return libraries

    def match_vulnerabilities(self, libraries: List[LibraryInfo]) -> List[LibraryVulnerability]:
        """匹配库漏洞

        Args:
            libraries: 库信息列表

        Returns:
            匹配到的漏洞列表
        """
        vulnerabilities = []

        if self._nvd_available and self._nvd_adapter:
            vulnerabilities.extend(self._match_via_nvd(libraries))
        else:
            vulnerabilities.extend(self._match_via_json(libraries))

        return vulnerabilities

    def _match_via_nvd(self, libraries: List[LibraryInfo]) -> List[LibraryVulnerability]:
        """通过NVD数据库匹配漏洞"""
        vulnerabilities = []

        for library in libraries:
            if not library.name:
                continue

            try:
                vendor = library.name.split('.')[0]
                product = library.name

                hits = self._nvd_adapter.scan_library(
                    vendor=vendor,
                    product=product,
                    version=library.version,
                    min_score=5.0,
                    limit=50
                )

                for hit in hits:
                    vuln = LibraryVulnerability(
                        cve_id=hit.cve_id,
                        library_name=library.name,
                        affected_versions=hit.affected_versions or [],
                        severity=self._map_severity(hit.severity),
                        description=hit.description,
                        fix_version=None,
                        metadata={
                            'cvss_score': hit.cvss_score,
                            'kev_exploited': hit.kev_exploited,
                            'exploit_count': hit.exploit_count,
                            'poc_stars': hit.poc_stars
                        }
                    )
                    vulnerabilities.append(vuln)

            except Exception as e:
                logger.debug(f"通过NVD匹配漏洞失败 {library.name}: {e}")

        return vulnerabilities

    def _match_via_json(self, libraries: List[LibraryInfo]) -> List[LibraryVulnerability]:
        """通过内置JSON数据库匹配漏洞"""
        vulnerabilities = []

        for library in libraries:
            if library.name in self._vulnerability_db:
                for vuln in self._vulnerability_db[library.name]:
                    if self._is_version_affected(library.version, vuln.affected_versions):
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _map_severity(self, severity: str) -> str:
        """映射NVD严重级别到标准级别"""
        if not severity:
            return 'MEDIUM'
        severity_upper = severity.upper()
        if severity_upper in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            return severity_upper
        if severity_upper.startswith('HIGH'):
            return 'HIGH'
        if severity_upper.startswith('MED'):
            return 'MEDIUM'
        if severity_upper.startswith('LOW'):
            return 'LOW'
        return 'MEDIUM'

    def _is_version_affected(self, version: Optional[str], affected_versions: List[str]) -> bool:
        """检查版本是否受影响

        Args:
            version: 库版本
            affected_versions: 受影响的版本列表

        Returns:
            是否受影响
        """
        if not version:
            return False

        for affected_version in affected_versions:
            if affected_version == version:
                return True
            # 处理版本范围，如 "< 1.0.0", ">= 2.0.0, < 2.1.0"
            if '<' in affected_version or '>' in affected_version:
                if self._check_version_range(version, affected_version):
                    return True
        
        return False

    def _check_version_range(self, version: str, version_range: str) -> bool:
        """检查版本是否在指定范围内

        Args:
            version: 库版本
            version_range: 版本范围

        Returns:
            是否在范围内
        """
        try:
            import packaging.version
            current_version = packaging.version.parse(version)
            
            # 处理逗号分隔的多个范围
            ranges = version_range.split(',')
            for range_str in ranges:
                range_str = range_str.strip()
                if range_str.startswith('<'):
                    if '<=' in range_str:
                        max_version = packaging.version.parse(range_str[2:].strip())
                        if current_version <= max_version:
                            return True
                    else:
                        max_version = packaging.version.parse(range_str[1:].strip())
                        if current_version < max_version:
                            return True
                elif range_str.startswith('>'):
                    if '>=' in range_str:
                        min_version = packaging.version.parse(range_str[2:].strip())
                        if current_version >= min_version:
                            return True
                    else:
                        min_version = packaging.version.parse(range_str[1:].strip())
                        if current_version > min_version:
                            return True
        except Exception:
            pass
        
        return False

    def get_vulnerability_by_cve(self, cve_id: str) -> Optional[LibraryVulnerability]:
        """根据CVE ID获取漏洞信息

        Args:
            cve_id: CVE ID

        Returns:
            漏洞信息
        """
        if self._nvd_available and self._nvd_adapter:
            try:
                detail = self._nvd_adapter.get_cve_details(cve_id)
                if detail:
                    return LibraryVulnerability(
                        cve_id=detail.get('cve_id', cve_id),
                        library_name='',
                        affected_versions=[],
                        severity=self._map_severity(detail.get('severity', '')),
                        description=detail.get('description', ''),
                        fix_version=None,
                        metadata={
                            'cvss_score': detail.get('cvss_score'),
                            'kev_exploited': detail.get('kev_exploited'),
                            'exploit_count': detail.get('exploit_count', 0),
                            'poc_count': detail.get('poc_count', 0)
                        }
                    )
            except Exception as e:
                logger.debug(f"通过NVD获取CVE详情失败: {e}")

        for vulnerabilities in self._vulnerability_db.values():
            for vuln in vulnerabilities:
                if vuln.cve_id == cve_id:
                    return vuln
        return None

    def get_nvd_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """获取CVE的NVD详细信息

        Args:
            cve_id: CVE ID

        Returns:
            NVD详细信息字典
        """
        if not self._nvd_available or not self._nvd_adapter:
            return None

        try:
            return self._nvd_adapter.get_cve_details(cve_id)
        except Exception as e:
            logger.debug(f"获取NVD详情失败: {e}")
            return None

    def update_vulnerability_db(self, vulnerabilities: List[LibraryVulnerability]) -> None:
        """更新漏洞数据库

        Args:
            vulnerabilities: 漏洞信息列表
        """
        for vuln in vulnerabilities:
            if vuln.library_name not in self._vulnerability_db:
                self._vulnerability_db[vuln.library_name] = []
            
            # 检查是否已存在
            exists = False
            for existing_vuln in self._vulnerability_db[vuln.library_name]:
                if existing_vuln.cve_id == vuln.cve_id:
                    exists = True
                    break
            
            if not exists:
                self._vulnerability_db[vuln.library_name].append(vuln)
        
        # 保存到文件
        self._save_vulnerability_db()

    def _save_vulnerability_db(self) -> None:
        """保存漏洞数据库到文件"""
        db_path = Path(__file__).parent / "vulnerability_db.json"
        try:
            data = []
            for library_name, vulnerabilities in self._vulnerability_db.items():
                for vuln in vulnerabilities:
                    data.append({
                        "cve_id": vuln.cve_id,
                        "library_name": vuln.library_name,
                        "affected_versions": vuln.affected_versions,
                        "severity": vuln.severity,
                        "description": vuln.description,
                        "fix_version": vuln.fix_version,
                        "metadata": vuln.metadata
                    })
            
            with open(db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存漏洞数据库失败: {e}")


# 全局库匹配器实例
_library_matcher: Optional[LibraryMatcher] = None


def get_library_matcher() -> LibraryMatcher:
    """获取全局库匹配器实例

    Returns:
        库匹配器实例
    """
    global _library_matcher
    if _library_matcher is None:
        _library_matcher = LibraryMatcher()
    return _library_matcher
