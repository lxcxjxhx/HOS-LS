"""NVD数据库适配器

为扫描器提供NVD SQLite数据库查询接口
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from src.utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class NVDVulnerability:
    """NVD漏洞信息"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    kev_exploited: bool
    exploit_count: int
    poc_stars: int
    affected_versions: List[str]
    fix_version: Optional[str] = None
    references: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    published_date: Optional[str] = None

class NVDAdapter:
    """NVD数据库适配器"""

    def __init__(self):
        self._query_engine = None
        self._initialized = False
        self._db_type = None
        self._init_engine()

    def _init_engine(self):
        """初始化查询引擎"""
        try:
            from src.nvd.db.sqlite_connection import SQLiteConnection
            from src.nvd.query.sqlite_engine import SQLiteQueryEngine

            conn = SQLiteConnection.get_instance()
            if conn.table_exists('cve'):
                self._query_engine = SQLiteQueryEngine(conn)
                self._db_type = 'sqlite'
                self._initialized = True
                stats = conn.get_vulnerability_stats()
                logger.info(f"NVD SQLite查询引擎初始化成功: {stats}")
                return
        except Exception as e:
            logger.debug(f"SQLite引擎初始化失败: {e}")

        try:
            from src.nvd.db.connection import NVDConnection
            from src.nvd.query.engine import NVDQueryEngine

            conn = NVDConnection.get_instance()
            self._query_engine = NVDQueryEngine(conn)
            self._db_type = 'postgresql'
            self._initialized = True
            logger.info("NVD PostgreSQL查询引擎初始化成功")
        except Exception as e:
            logger.warning(f"NVD适配器初始化失败: {e}")
            self._initialized = False

    def is_available(self) -> bool:
        """检查NVD数据库是否可用"""
        return self._initialized and self._query_engine is not None

    def get_db_type(self) -> Optional[str]:
        """获取数据库类型"""
        return self._db_type

    def scan_library(
        self,
        vendor: str,
        product: str,
        version: Optional[str] = None,
        min_score: float = 0.0,
        limit: int = 50
    ) -> List[NVDVulnerability]:
        """扫描库漏洞"""
        if not self.is_available():
            return []

        try:
            hits = self._query_engine.scan_product(
                vendor=vendor,
                product=product,
                version=version,
                min_score=min_score,
                limit=limit
            )

            vulnerabilities = []
            for hit in hits:
                vuln = NVDVulnerability(
                    cve_id=hit.cve_id,
                    description=hit.description or '',
                    cvss_score=hit.cvss_score or 0.0,
                    severity=hit.cvss_severity or 'MEDIUM',
                    kev_exploited=bool(hit.kev_exploited) if hit.kev_exploited is not None else False,
                    exploit_count=hit.exploit_count or 0,
                    poc_stars=hit.max_poc_stars or 0,
                    affected_versions=[hit.affected_version] if hit.affected_version else [],
                    cwe_ids=hit.cwe_ids or [],
                    published_date=hit.published_date
                )
                vulnerabilities.append(vuln)

            return vulnerabilities
        except Exception as e:
            logger.debug(f"扫描库漏洞失败: {e}")
            return []

    def find_exploitable(
        self,
        min_score: float = 7.0,
        limit: int = 50
    ) -> List[NVDVulnerability]:
        """查找可利用的漏洞"""
        if not self.is_available():
            return []

        try:
            hits = self._query_engine.find_exploitable(
                min_score=min_score,
                limit=limit
            )

            vulnerabilities = []
            for hit in hits:
                vuln = NVDVulnerability(
                    cve_id=hit.cve_id,
                    description=hit.description or '',
                    cvss_score=hit.cvss_score or 0.0,
                    severity=hit.cvss_severity or 'MEDIUM',
                    kev_exploited=bool(hit.kev_exploited) if hit.kev_exploited is not None else False,
                    exploit_count=hit.exploit_count or 0,
                    poc_stars=hit.max_poc_stars or 0,
                    affected_versions=[],
                    cwe_ids=hit.cwe_ids or [],
                    published_date=hit.published_date
                )
                vulnerabilities.append(vuln)

            return vulnerabilities
        except Exception as e:
            logger.debug(f"查找可利用漏洞失败: {e}")
            return []

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """获取CVE详细信息"""
        if not self.is_available():
            return None

        try:
            detail = self._query_engine.get_cve_detail(cve_id)
            if detail:
                return {
                    'cve_id': detail.cve_id,
                    'description': detail.description,
                    'cvss_score': detail.cvss_score,
                    'severity': detail.cvss_severity,
                    'cvss_vector': detail.cvss_vector,
                    'kev_exploited': detail.kev_exploited,
                    'kev_description': getattr(detail, 'kev_description', None),
                    'exploit_count': detail.exploit_count,
                    'poc_count': detail.poc_count,
                    'cwe_ids': detail.cwe_ids,
                    'cwe_names': getattr(detail, 'cwe_names', []),
                    'published_date': getattr(detail, 'published_date', None),
                    'last_modified': getattr(detail, 'last_modified', None)
                }
        except Exception as e:
            logger.debug(f"获取CVE详情失败: {e}")

        return None

    def get_exploits(self, cve_id: str) -> List[Dict[str, Any]]:
        """获取CVE的Exploit列表"""
        if not self.is_available():
            return []

        try:
            return self._query_engine.get_exploits(cve_id)
        except Exception as e:
            logger.debug(f"获取Exploit列表失败: {e}")
            return []

    def get_pocs(self, cve_id: str) -> List[Dict[str, Any]]:
        """获取CVE的PoC列表"""
        if not self.is_available():
            return []

        try:
            return self._query_engine.get_pocs(cve_id)
        except Exception as e:
            logger.debug(f"获取PoC列表失败: {e}")
            return []

    def match_cwe(self, keywords: List[str], limit: int = 5) -> List[Dict[str, Any]]:
        """根据关键词匹配CWE

        Args:
            keywords: 关键词列表
            limit: 返回结果数量限制

        Returns:
            CWE匹配结果列表
        """
        if not self.is_available():
            return []

        if not keywords:
            return []

        try:
            return self._query_engine.match_cwe(keywords, limit)
        except Exception as e:
            logger.debug(f"CWE匹配失败: {e}")
            return []

    def get_cves_by_cwe(self, cwe_id: str, min_score: float = 0.0, limit: int = 50) -> List[NVDVulnerability]:
        """获取指定CWE相关的CVE

        Args:
            cwe_id: CWE ID
            min_score: 最低CVSS评分
            limit: 返回结果数量限制

        Returns:
            CVE漏洞列表
        """
        if not self.is_available():
            return []

        try:
            hits = self._query_engine.get_cves_by_cwe(cwe_id, min_score, limit)

            vulnerabilities = []
            for hit in hits:
                vuln = NVDVulnerability(
                    cve_id=hit.cve_id,
                    description=hit.description or '',
                    cvss_score=hit.cvss_score or 0.0,
                    severity=hit.cvss_severity or 'MEDIUM',
                    kev_exploited=bool(hit.kev_exploited) if hit.kev_exploited is not None else False,
                    exploit_count=hit.exploit_count or 0,
                    poc_stars=hit.max_poc_stars or 0,
                    affected_versions=[],
                    cwe_ids=hit.cwe_ids or [],
                    published_date=hit.published_date
                )
                vulnerabilities.append(vuln)

            return vulnerabilities
        except Exception as e:
            logger.debug(f"获取CWE相关的CVE失败: {e}")
            return []

_nvd_adapter: Optional[NVDAdapter] = None

def get_nvd_adapter() -> NVDAdapter:
    """获取全局NVD适配器实例"""
    global _nvd_adapter
    if _nvd_adapter is None:
        _nvd_adapter = NVDAdapter()
    return _nvd_adapter

def reset_nvd_adapter() -> None:
    """重置全局NVD适配器实例（用于测试）"""
    global _nvd_adapter
    _nvd_adapter = None
