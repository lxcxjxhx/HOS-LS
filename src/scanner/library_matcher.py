"""库匹配器模块

识别代码中使用的库和版本，并基于已知的库漏洞数据库进行匹配。
优先使用NVD SQLite数据库进行匹配。
"""

import re
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)

NVD_DB_PATH = Path(r"c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\All Vulnerabilities\sql_data\nvd_vulnerability.db")


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

    识别代码中使用的库和版本，并基于NVD漏洞数据库进行匹配。
    """

    def __init__(self, config: Optional[Config] = None):
        """初始化库匹配器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._nvd_adapter = None
        self._nvd_available = False
        self._library_cve_cache: Dict[str, List[LibraryVulnerability]] = {}
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
            from src.scanner.nvd_adapter import NVDAdapter
            self._nvd_adapter = NVDAdapter()
            self._nvd_available = self._nvd_adapter.is_available()
            if self._nvd_available:
                db_type = self._nvd_adapter.get_db_type()
                logger.info(f"NVD数据库连接成功 (类型: {db_type})")
            else:
                logger.info("NVD数据库不可用")
        except Exception as e:
            logger.warning(f"NVD适配器初始化失败: {e}")
            self._nvd_available = False

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
            logger.warning("NVD数据库不可用，无法进行库漏洞匹配")

        return vulnerabilities

    def _match_via_nvd(
        self,
        libraries: Dict[str, List[str]],
        library_name: str = None,
        version: str = None
    ) -> List[Dict[str, Any]]:
        """通过NVD数据库匹配漏洞（带缓存优化）

        支持三种模式：
        1. 批量模式：libraries 为 Dict[str, List[str]]，返回 List[Dict[str, Any]]
        2. 单库模式：提供 library_name 和 version，直接查询 NVD DB CPE 表
        3. 联合查询：cpe JOIN cve JOIN cvss JOIN cwe

        Args:
            libraries: 库信息字典（批量模式）
            library_name: 单个库名称（单库模式）
            version: 库版本（单库模式）

        Returns:
            匹配到的漏洞列表，格式：
            [{'cve_id', 'cvss_score', 'cvss_severity', 'cwe_id', 'cwe_name', 'description', 'confidence'}]
        """
        if library_name:
            return self._query_single_library_nvd(library_name, version)

        vulnerabilities = []

        if not libraries:
            return vulnerabilities

        for lib_name, lib_versions in libraries.items():
            if not lib_name:
                continue

            try:
                if lib_name in self._library_cve_cache:
                    cached_results = self._library_cve_cache[lib_name]
                    vulnerabilities.extend(cached_results)
                    logger.debug(f"NVD缓存命中: {lib_name}")
                    continue

                results_for_lib = []
                for ver in (lib_versions or [None]):
                    direct_results = self._query_direct_nvd_db(lib_name, ver)
                    for dr in direct_results:
                        if ver and dr.get('cpe_version'):
                            cpe_ver = str(dr['cpe_version']).strip()
                            if cpe_ver and not self._is_cve_version_affected(ver, cpe_ver):
                                dr['confidence'] = 0.3
                                dr['version_mismatch'] = True
                                dr['version_mismatch_reason'] = f'Installed version {ver} not in affected range {cpe_ver}'
                                logger.debug(f"版本不匹配: {lib_name} {ver} vs CVE affected {cpe_ver}, 置信度降至0.3")
                        results_for_lib.append(dr)

                self._library_cve_cache[lib_name] = results_for_lib
                vulnerabilities.extend(results_for_lib)

            except Exception as e:
                logger.debug(f"通过NVD匹配漏洞失败 {lib_name}: {e}")
                self._library_cve_cache[lib_name] = []

        return vulnerabilities

    def _match_single_library_via_nvd(
        self,
        library_name: str,
        version: Optional[str] = None
    ) -> List[LibraryVulnerability]:
        """通过NVD数据库匹配单个库的漏洞

        Args:
            library_name: 库名称
            version: 库版本

        Returns:
            匹配到的漏洞列表
        """
        if not library_name:
            return []

        lib_str = str(library_name).strip()
        ver_str = str(version).strip() if version else None

        if lib_str in self._library_cve_cache:
            return self._library_cve_cache[lib_str]

        direct_results = self._query_direct_nvd_db(lib_str, ver_str)
        library_vulns = []

        for dr in direct_results:
            vuln = LibraryVulnerability(
                cve_id=dr['cve_id'],
                library_name=lib_str,
                affected_versions=[ver_str] if ver_str else [],
                severity=dr['cvss_severity'],
                description=dr['description'],
                fix_version=dr.get('fixed_version'),
                metadata={
                    'cvss_score': dr['cvss_score'],
                    'cwe_id': dr['cwe_id'],
                    'cwe_name': dr['cwe_name'],
                    'confidence': dr['confidence'],
                    'kev_exploited': False,
                    'exploit_count': 0,
                    'poc_stars': 0,
                    'cwe_ids': [],
                    'references': []
                }
            )
            library_vulns.append(vuln)

        if not direct_results and self._nvd_adapter:
            try:
                vendor = lib_str.split('.')[0]
                hits = self._nvd_adapter.scan_library(
                    vendor=vendor,
                    product=lib_str,
                    version=ver_str,
                    min_score=5.0,
                    limit=50
                )
                for hit in hits:
                    vuln = LibraryVulnerability(
                        cve_id=hit.cve_id,
                        library_name=lib_str,
                        affected_versions=hit.affected_versions or [],
                        severity=self._map_severity(hit.severity),
                        description=hit.description,
                        fix_version=hit.fix_version,
                        metadata={
                            'cvss_score': hit.cvss_score,
                            'kev_exploited': hit.kev_exploited,
                            'exploit_count': hit.exploit_count,
                            'poc_stars': hit.poc_stars,
                            'cwe_ids': hit.cwe_ids,
                            'references': hit.references
                        }
                    )
                    library_vulns.append(vuln)
            except Exception as e:
                logger.debug(f"Adapter fallback failed for {lib_str}: {e}")

        self._library_cve_cache[lib_str] = library_vulns
        return library_vulns

    def _query_single_library_nvd(
        self,
        library_name: str,
        version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """单库精确查询 NVD DB：cpe JOIN cve JOIN cvss JOIN cwe

        Args:
            library_name: 库名称
            version: 库版本

        Returns:
            漏洞列表 [{'cve_id', 'cvss_score', 'cvss_severity', 'cwe_id', 'cwe_name', 'description', 'confidence'}]
        """
        lib_str = str(library_name).strip().lower()
        ver_str = str(version).strip() if version else None

        cache_key = f"{lib_str}:{ver_str}" if ver_str else lib_str
        if cache_key in self._library_cve_cache:
            return self._library_cve_cache[cache_key]

        db_path_str = str(NVD_DB_PATH)
        if not Path(db_path_str).exists():
            logger.warning("NVD 数据库文件不存在: %s", db_path_str)
            return []

        conn = None
        try:
            conn = sqlite3.connect(db_path_str, timeout=30.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cpe_like = f"%{lib_str}%"

            if ver_str:
                cpe_query = """
                    SELECT DISTINCT cpe.cve_id
                    FROM cpe
                    WHERE LOWER(cpe.part22_cpe) LIKE ?
                      AND (cpe.version LIKE ? OR cpe.version = ?)
                    LIMIT 100
                """
                cursor.execute(cpe_query, [cpe_like, f"%{ver_str}%", ver_str])
            else:
                cpe_query = """
                    SELECT DISTINCT cpe.cve_id
                    FROM cpe
                    WHERE LOWER(cpe.part22_cpe) LIKE ?
                    LIMIT 100
                """
                cursor.execute(cpe_query, [cpe_like])

            cpe_rows = cursor.fetchall()
            if not cpe_rows:
                if ver_str:
                    logger.debug("无精确版本匹配 %s:%s，回退到仅包名查询", lib_str, ver_str)
                    return self._query_single_library_nvd(lib_str, None)

                logger.debug("无 CPE 匹配: %s", lib_str)
                cursor.close()
                conn.close()
                return []

            matched_cve_ids = list(set(row['cve_id'] for row in cpe_rows))
            cve_placeholders = ','.join(['?' for _ in matched_cve_ids])

            full_query = f"""
                SELECT DISTINCT
                    cve.cve_id,
                    cve.description,
                    cvss.cvss_score,
                    cvss.cvss_severity,
                    cwe.cwe_id,
                    cwe.name AS cwe_name
                FROM cve
                LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
                LEFT JOIN cve_cwe ON cve.cve_id = cve_cwe.cve_id
                LEFT JOIN cwe ON cve_cwe.cwe_id = cwe.cwe_id
                WHERE cve.cve_id IN ({cve_placeholders})
                ORDER BY cvss.cvss_score DESC
            """
            cursor.execute(full_query, matched_cve_ids)
            result_rows = cursor.fetchall()
            cursor.close()

            results = []
            seen_cves: Set[str] = set()
            for row in result_rows:
                cve_id = row['cve_id']
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                cvss_score = float(row['cvss_score']) if row['cvss_score'] is not None else 0.0
                severity_raw = row['cvss_severity'] or 'MEDIUM'
                severity_mapped = self._map_severity(str(severity_raw))
                confidence = min(1.0, max(0.3, cvss_score / 10.0))
                if ver_str:
                    confidence = min(1.0, confidence + 0.2)

                results.append({
                    'cve_id': cve_id,
                    'cvss_score': cvss_score,
                    'cvss_severity': severity_mapped,
                    'cwe_id': row['cwe_id'] or 'N/A',
                    'cwe_name': row['cwe_name'] or 'Unknown',
                    'description': row['description'] or '',
                    'confidence': round(confidence, 2)
                })

            logger.info("单库 NVD 查询: 找到 %d 个漏洞 '%s:%s'", len(results), lib_str, ver_str or '*')
            self._library_cve_cache[cache_key] = results
            return results

        except sqlite3.Error as e:
            logger.error("SQLite 错误查询单库 NVD: %s", e)
            return []
        except Exception as e:
            logger.error("意外错误查询单库 NVD: %s", e)
            return []
        finally:
            if conn:
                conn.close()

    def _map_severity(self, severity: str) -> str:
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

    def _is_nvd_db_available(self) -> bool:
        db_path_str = str(NVD_DB_PATH)
        return Path(db_path_str).exists() and Path(db_path_str).is_file()

    def _query_direct_nvd_db(
        self,
        library_name: str,
        version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        db_path_str = str(NVD_DB_PATH)
        if not Path(db_path_str).exists():
            logger.warning("NVD database file not found: %s", db_path_str)
            return []

        conn = None
        try:
            conn = sqlite3.connect(db_path_str, timeout=30.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cpe_search_terms = []
            lib_lower = library_name.lower()
            cpe_search_terms.append(f"%{lib_lower}%")
            parts = lib_lower.replace('-', ' ').replace('_', ' ').split()
            for part in parts:
                if len(part) > 2:
                    term = f"%{part}%"
                    if term not in cpe_search_terms:
                        cpe_search_terms.append(term)

            cpe_placeholders = ','.join(['?' for _ in cpe_search_terms])
            cpe_conditions = ' OR '.join([f'LOWER(cpe.part22_cpe) LIKE ?' for _ in cpe_search_terms])

            version_filter = ''
            version_params: List[str] = []
            if version:
                version_filter = ' AND (cpe.version LIKE ? OR cpe.version = ?)'
                version_params = [f'%{version}%', version]

            cpe_query = f"""
                SELECT DISTINCT cpe.cve_id, cpe.part22_cpe, cpe.version
                FROM cpe
                WHERE ({cpe_conditions})
                {version_filter}
                LIMIT 100
            """
            cursor.execute(cpe_query, cpe_search_terms + version_params)
            cpe_rows = cursor.fetchall()

            if not cpe_rows:
                logger.debug("No CPE match for library: %s version: %s", library_name, version)
                cursor.close()
                conn.close()
                return []

            matched_cve_ids = list(set(row['cve_id'] for row in cpe_rows))
            cve_placeholders = ','.join(['?' for _ in matched_cve_ids])

            full_query = f"""
                SELECT DISTINCT
                    cve.cve_id,
                    cve.description,
                    cvss.cvss_score,
                    cvss.cvss_severity,
                    cwe.cwe_id,
                    cwe.name AS cwe_name,
                    cpe.version AS cpe_version
                FROM cve
                LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
                LEFT JOIN cve_cwe ON cve.cve_id = cve_cwe.cve_id
                LEFT JOIN cwe ON cve_cwe.cwe_id = cwe.cwe_id
                LEFT JOIN cpe ON cve.cve_id = cpe.cve_id
                WHERE cve.cve_id IN ({cve_placeholders})
                ORDER BY cvss.cvss_score DESC
            """
            cursor.execute(full_query, matched_cve_ids)
            result_rows = cursor.fetchall()
            cursor.close()

            results: List[Dict[str, Any]] = []
            seen_cves: Set[str] = set()
            for row in result_rows:
                cve_id = row['cve_id']
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                cvss_score = float(row['cvss_score']) if row['cvss_score'] is not None else 0.0
                severity_raw = row['cvss_severity'] or 'MEDIUM'
                severity_mapped = self._map_severity(str(severity_raw))
                confidence = min(1.0, max(0.3, cvss_score / 10.0))
                if version:
                    cpe_ver = row['cpe_version'] or ''
                    if version in str(cpe_ver):
                        confidence = min(1.0, confidence + 0.2)

                results.append({
                    'cve_id': cve_id,
                    'cvss_score': cvss_score,
                    'cvss_severity': severity_mapped,
                    'cwe_id': row['cwe_id'] or 'N/A',
                    'cwe_name': row['cwe_name'] or 'Unknown',
                    'description': row['description'] or '',
                    'fixed_version': None,
                    'confidence': round(confidence, 2)
                })

            logger.info("Direct NVD DB query: found %d vulnerabilities for '%s'", len(results), library_name)
            return results

        except sqlite3.Error as e:
            logger.error("SQLite error querying NVD DB: %s", e)
            return []
        except Exception as e:
            logger.error("Unexpected error querying NVD DB: %s", e)
            return []
        finally:
            if conn:
                conn.close()

    def batch_match_vulnerabilities(
        self,
        package_list: List[tuple]
    ) -> Dict[tuple, List[Dict[str, Any]]]:
        """批量匹配库漏洞

        Args:
            package_list: (package_name, version) 元组列表

        Returns:
            字典映射 (package_name, version) -> 漏洞列表
        """
        if not package_list:
            return {}

        db_path_str = str(NVD_DB_PATH)
        if not Path(db_path_str).exists():
            logger.warning("NVD database file not found: %s", db_path_str)
            return {}

        package_list_cleaned = []
        for pkg in package_list:
            pkg_name_str = str(pkg[0]).strip().lower() if pkg[0] else None
            pkg_version_str = str(pkg[1]).strip() if len(pkg) > 1 and pkg[1] else None
            if pkg_name_str:
                package_list_cleaned.append((pkg_name_str, pkg_version_str))

        if not package_list_cleaned:
            return {}

        unique_packages = list(set(package_list_cleaned))

        cpe_matches = self._batch_query_cpe(unique_packages)

        if not cpe_matches:
            return {}

        all_cve_ids = set()
        for matches in cpe_matches.values():
            for match in matches:
                all_cve_ids.add(match['cve_id'])

        if not all_cve_ids:
            return {}

        cve_details = self._batch_query_vulnerabilities(list(all_cve_ids))

        result_map = self._match_batch_results(unique_packages, cpe_matches, cve_details)

        final_result = {}
        for pkg_name, pkg_version in package_list:
            pkg_name_str = str(pkg_name).strip().lower() if pkg_name else None
            pkg_version_str = str(pkg_version).strip() if pkg_version else None
            key = (pkg_name_str, pkg_version_str) if pkg_name_str else None
            if key and key in result_map:
                final_result[(pkg_name, pkg_version)] = result_map[key]
            elif pkg_name_str:
                fallback_key = (pkg_name_str, None)
                if fallback_key in result_map:
                    final_result[(pkg_name, pkg_version)] = result_map[fallback_key]
                else:
                    final_result[(pkg_name, pkg_version)] = []

        logger.info("批量 NVD 查询: %d 个包，找到 %d 个漏洞", len(package_list_cleaned), sum(len(v) for v in final_result.values()))

        return final_result

    def _batch_query_cpe(
        self,
        packages: List[tuple]
    ) -> Dict[tuple, List[Dict[str, Any]]]:
        """批量查询 CPE 表（使用 SQLite IN 子句优化）

        Args:
            packages: (package_name, version) 元组列表

        Returns:
            字典映射 (package_name, version) -> CPE 匹配结果
        """
        db_path_str = str(NVD_DB_PATH)
        if not Path(db_path_str).exists():
            return {}

        if not packages:
            return {}

        conn = None
        try:
            conn = sqlite3.connect(db_path_str, timeout=30.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            pkg_names = []
            name_to_packages = {}

            for pkg_name, pkg_version in packages:
                pkg_name_lower = pkg_name.lower()
                if pkg_name_lower not in name_to_packages:
                    name_to_packages[pkg_name_lower] = []
                    pkg_names.append(pkg_name_lower)
                name_to_packages[pkg_name_lower].append((pkg_name, pkg_version))

            unique_pkg_names = list(set(pkg_names))

            placeholders = ','.join(['?' for _ in unique_pkg_names])

            like_clauses = []
            params = []
            for pkg_name in unique_pkg_names:
                like_clauses.append('LOWER(cpe.part22_cpe) LIKE ?')
                params.append(f'%{pkg_name}%')
                parts = pkg_name.replace('-', ' ').replace('_', ' ').split()
                for part in parts:
                    if len(part) > 2:
                        like_clauses.append('LOWER(cpe.part22_cpe) LIKE ?')
                        params.append(f'%{part}%')

            combined_like = ' OR '.join(like_clauses)

            query = f"""
                SELECT cpe.cve_id, cpe.part22_cpe, cpe.version
                FROM cpe
                WHERE ({combined_like})
                LIMIT 500
            """

            cursor.execute(query, params)
            cpe_rows = cursor.fetchall()

            if not cpe_rows:
                return {}

            pkg_cpe_map = {}
            for pkg_name, pkg_version in packages:
                pkg_key = (pkg_name, pkg_version)
                pkg_cpe_map[pkg_key] = []

            for row in cpe_rows:
                cpe_part22 = str(row['part22_cpe']).lower() if row['part22_cpe'] else ''
                cpe_version = str(row['version']).strip() if row['version'] else None
                cve_id = row['cve_id']

                for pkg_name, pkg_version in packages:
                    pkg_key = (pkg_name, pkg_version)
                    lib_lower = pkg_name.lower()

                    is_match = False
                    if lib_lower in cpe_part22:
                        is_match = True
                    else:
                        parts = lib_lower.replace('-', ' ').replace('_', ' ').split()
                        if any(len(part) > 2 and part in cpe_part22 for part in parts):
                            is_match = True

                    if is_match:
                        if pkg_version:
                            if cpe_version and (pkg_version in cpe_version or cpe_version in pkg_version):
                                pkg_cpe_map[pkg_key].append({
                                    'cve_id': cve_id,
                                    'cpe_version': cpe_version
                                })
                        else:
                            pkg_cpe_map[pkg_key].append({
                                'cve_id': cve_id,
                                'cpe_version': cpe_version
                            })

            return pkg_cpe_map

        except sqlite3.Error as e:
            logger.error("SQLite error in batch CPE query: %s", e)
            return {}
        except Exception as e:
            logger.error("Unexpected error in batch CPE query: %s", e)
            return {}
        finally:
            if conn:
                conn.close()

    def _batch_query_vulnerabilities(
        self,
        cve_ids: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """批量查询 CVE 详细信息

        Args:
            cve_ids: CVE ID 列表

        Returns:
            字典映射 cve_id -> 漏洞详情
        """
        if not cve_ids:
            return {}

        db_path_str = str(NVD_DB_PATH)
        if not Path(db_path_str).exists():
            return {}

        conn = None
        try:
            conn = sqlite3.connect(db_path_str, timeout=30.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            placeholders = ','.join(['?' for _ in cve_ids])

            query = f"""
                SELECT DISTINCT
                    cve.cve_id,
                    cve.description,
                    cvss.cvss_score,
                    cvss.cvss_severity,
                    cwe.cwe_id,
                    cwe.name AS cwe_name
                FROM cve
                LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
                LEFT JOIN cve_cwe ON cve.cve_id = cve_cwe.cve_id
                LEFT JOIN cwe ON cve_cwe.cwe_id = cwe.cwe_id
                WHERE cve.cve_id IN ({placeholders})
            """

            cursor.execute(query, cve_ids)
            result_rows = cursor.fetchall()
            cursor.close()

            cve_details = {}
            for row in result_rows:
                cve_id = row['cve_id']
                cve_details[cve_id] = self._parse_nvd_result_row(row)

            return cve_details

        except sqlite3.Error as e:
            logger.error("SQLite error in batch CVE query: %s", e)
            return {}
        except Exception as e:
            logger.error("Unexpected error in batch CVE query: %s", e)
            return {}
        finally:
            if conn:
                conn.close()

    def _match_batch_results(
        self,
        packages: List[tuple],
        cpe_matches: Dict[tuple, List[Dict[str, Any]]],
        cve_details: Dict[str, Dict[str, Any]]
    ) -> Dict[tuple, List[Dict[str, Any]]]:
        """将批量查询结果映射回原始包

        Args:
            packages: 包列表
            cpe_matches: CPE 匹配结果
            cve_details: CVE 详细信息

        Returns:
            映射字典
        """
        result_map = {}

        for pkg_name, pkg_version in packages:
            pkg_key = (pkg_name, pkg_version)
            cpe_hits = cpe_matches.get(pkg_key, [])

            if not cpe_hits:
                result_map[pkg_key] = []
                continue

            seen_cves = set()
            vulns = []

            for hit in cpe_hits:
                cve_id = hit['cve_id']
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                if cve_id in cve_details:
                    vuln = cve_details[cve_id].copy()
                    cpe_ver = hit.get('cpe_version')
                    if pkg_version and cpe_ver:
                        confidence = vuln.get('confidence', 0.5)
                        if pkg_version in str(cpe_ver):
                            confidence = min(1.0, confidence + 0.2)
                        vuln['confidence'] = round(confidence, 2)
                    vulns.append(vuln)

            result_map[pkg_key] = vulns

        return result_map

    def match_library_vulnerabilities(
        self,
        library_name: str,
        version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if not library_name:
            logger.warning("match_library_vulnerabilities called with empty library_name")
            return []

        lib_name_str = str(library_name).strip()
        version_str = str(version).strip() if version else None

        if self._nvd_available and self._nvd_adapter:
            try:
                results = self._query_direct_nvd_db(lib_name_str, version_str)
                if results:
                    results.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
                    return results
            except Exception as e:
                logger.warning("NVD direct DB query failed for '%s': %s", lib_name_str, e)

        logger.warning("NVD database not available, returning empty list for library: %s", lib_name_str)
        return []

    def _build_cpe_search_terms(self, library_name: str) -> List[str]:
        lib_lower = str(library_name).lower()
        terms = [f"%{lib_lower}%"]
        parts = lib_lower.replace('-', ' ').replace('_', ' ').split()
        for part in parts:
            if len(part) > 2:
                term = f"%{part}%"
                if term not in terms:
                    terms.append(term)
        return terms

    def _parse_nvd_result_row(self, row: Any) -> Dict[str, Any]:
        cvss_score = float(row['cvss_score']) if row['cvss_score'] is not None else 0.0
        severity_raw = row['cvss_severity'] or 'MEDIUM'
        severity_mapped = self._map_severity(str(severity_raw))
        confidence = min(1.0, max(0.3, cvss_score / 10.0))
        return {
            'cve_id': row['cve_id'],
            'cvss_score': cvss_score,
            'cvss_severity': severity_mapped,
            'cwe_id': row.get('cwe_id') or 'N/A',
            'cwe_name': row.get('cwe_name') or 'Unknown',
            'description': row.get('description') or '',
            'fixed_version': None,
            'confidence': round(confidence, 2)
        }

    def _is_version_affected(self, version: Optional[str], affected_versions: List[str]) -> bool:
        """检查版本是否受影响

        Args:
            version: 库版本
            affected_versions: 受影响的版本列表

        Returns:
            是否受影响
        """
        if not version:
            return True  # 如果版本未知，假设可能受影响

        for affected_version in affected_versions:
            if affected_version == version:
                return True
            # 处理版本范围，如 "< 1.0.0", ">= 2.0.0, < 2.1.0"
            if '<' in affected_version or '>' in affected_version:
                if self._check_version_range(version, affected_version):
                    return True
        
        return False

    def _is_cve_version_affected(self, installed_version: str, affected_version: str) -> bool:
        """检查已安装版本是否在CVE受影响版本范围内

        Args:
            installed_version: 已安装的库版本
            affected_version: CVE受影响版本或范围

        Returns:
            是否在受影响范围内
        """
        installed_ver = str(installed_version).strip()
        affected_ver = str(affected_version).strip()

        if not installed_ver or not affected_ver:
            return True

        if affected_ver == installed_ver:
            return True

        try:
            import packaging.version
            current_version = packaging.version.parse(installed_ver)

            conditions = [c.strip() for c in affected_ver.split(',')]
            
            if '<=' in affected_ver:
                parts = affected_ver.split('<=')
                if len(parts) == 2:
                    max_ver = packaging.version.parse(parts[1].strip())
                    if current_version <= max_ver:
                        return True
            
            if '<' in affected_ver and '<=' not in affected_ver:
                parts = affected_ver.split('<')
                if len(parts) == 2:
                    max_ver = packaging.version.parse(parts[1].strip())
                    if current_version < max_ver:
                        return True
            
            if '>=' in affected_ver:
                parts = affected_ver.split('>=')
                if len(parts) == 2:
                    min_ver = packaging.version.parse(parts[1].strip())
                    if current_version >= min_ver:
                        return True
            
            if '>' in affected_ver and '>=' not in affected_ver:
                parts = affected_ver.split('>')
                if len(parts) == 2:
                    min_ver = packaging.version.parse(parts[1].strip())
                    if current_version > min_ver:
                        return True

            if affected_ver == '*' or affected_ver == '-':
                return True

            for condition in conditions:
                condition = condition.strip()
                if condition.startswith('<='):
                    max_ver = packaging.version.parse(condition[2:].strip())
                    if current_version <= max_ver:
                        return True
                elif condition.startswith('<'):
                    max_ver = packaging.version.parse(condition[1:].strip())
                    if current_version < max_ver:
                        return True
                elif condition.startswith('>='):
                    min_ver = packaging.version.parse(condition[2:].strip())
                    if current_version >= min_ver:
                        return True
                elif condition.startswith('>'):
                    min_ver = packaging.version.parse(condition[1:].strip())
                    if current_version > min_ver:
                        return True
                elif condition == installed_ver:
                    return True

        except Exception:
            pass

        return affected_ver in installed_ver or installed_ver in affected_ver

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
                            'poc_count': detail.get('poc_count', 0),
                            'cwe_ids': detail.get('cwe_ids'),
                            'references': detail.get('references')
                        }
                    )
            except Exception as e:
                logger.debug(f"通过NVD获取CVE详情失败: {e}")

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

    def get_exploits(self, cve_id: str) -> List[Dict[str, Any]]:
        """获取CVE的Exploit列表

        Args:
            cve_id: CVE ID

        Returns:
            Exploit列表
        """
        if not self._nvd_available or not self._nvd_adapter:
            return []

        try:
            return self._nvd_adapter.get_exploits(cve_id)
        except Exception as e:
            logger.debug(f"获取Exploit列表失败: {e}")
            return []

    def get_pocs(self, cve_id: str) -> List[Dict[str, Any]]:
        """获取CVE的PoC列表

        Args:
            cve_id: CVE ID

        Returns:
            PoC列表
        """
        if not self._nvd_available or not self._nvd_adapter:
            return []

        try:
            return self._nvd_adapter.get_pocs(cve_id)
        except Exception as e:
            logger.debug(f"获取PoC列表失败: {e}")
            return []

    def find_exploitable_vulnerabilities(
        self,
        min_score: float = 7.0,
        limit: int = 50
    ) -> List[LibraryVulnerability]:
        """查找可利用的漏洞

        Args:
            min_score: 最小CVSS分数
            limit: 返回数量限制

        Returns:
            可利用的漏洞列表
        """
        vulnerabilities = []

        if self._nvd_available and self._nvd_adapter:
            try:
                hits = self._nvd_adapter.find_exploitable(min_score=min_score, limit=limit)
                for hit in hits:
                    vuln = LibraryVulnerability(
                        cve_id=hit.cve_id,
                        library_name='',
                        affected_versions=hit.affected_versions or [],
                        severity=self._map_severity(hit.severity),
                        description=hit.description,
                        fix_version=hit.fix_version,
                        metadata={
                            'cvss_score': hit.cvss_score,
                            'kev_exploited': hit.kev_exploited,
                            'exploit_count': hit.exploit_count,
                            'poc_stars': hit.poc_stars
                        }
                    )
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug(f"查找可利用漏洞失败: {e}")

        return vulnerabilities


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
