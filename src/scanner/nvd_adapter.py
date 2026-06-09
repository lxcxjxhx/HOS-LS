"""NVD数据库适配器

为扫描器提供NVD SQLite数据库查询接口
修复版本：使用 NVDQueryAdapter 作为底层查询引擎
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
    """NVD数据库适配器

    使用 NVDQueryAdapter 作为底层查询引擎
    """

    def __init__(self):
        self._query_adapter = None
        self._initialized = False
        self._db_type = None
        self._init_engine()

    def _init_engine(self):
        """初始化查询引擎

        使用 NVDQueryAdapter 作为底层引擎
        """
        try:
            from src.nvd.nvd_query_adapter import NVDQueryAdapter

            self._query_adapter = NVDQueryAdapter()
            if self._query_adapter.is_available():
                self._db_type = 'sqlite'
                self._initialized = True
                stats = self._query_adapter.get_db_stats()
                logger.info(f"NVD查询引擎初始化成功: {stats}")
            else:
                logger.warning("NVD数据库不可用")
                self._initialized = False
        except Exception as e:
            logger.warning(f"NVD适配器初始化失败: {e}")
            self._initialized = False

    def is_available(self) -> bool:
        """检查NVD数据库是否可用"""
        return self._initialized and self._query_adapter is not None

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
        """扫描库漏洞

        使用 CWE 匹配来搜索相关漏洞
        """
        if not self.is_available():
            return []

        try:
            keywords = [product]
            if vendor:
                keywords.append(vendor)

            cwe_matches = self._query_adapter.match_cwe(keywords, limit=limit)

            vulnerabilities = []
            for match in cwe_matches:
                cwe_id = match.get('cwe_id', '')
                if cwe_id:
                    cve_results = self._query_adapter.search_vulnerabilities(
                        cwe_id=cwe_id,
                        limit=limit
                    )
                    for cve in cve_results:
                        cvss_score = cve.get('cvss_score', 0.0) or 0.0
                        if cvss_score >= min_score:
                            vuln = NVDVulnerability(
                                cve_id=cve.get('cve_id', ''),
                                description=cve.get('description', ''),
                                cvss_score=cvss_score,
                                severity=cve.get('severity', 'MEDIUM') or 'MEDIUM',
                                kev_exploited=False,
                                exploit_count=0,
                                poc_stars=0,
                                affected_versions=[version] if version else [],
                                cwe_ids=[cwe_id]
                            )
                            vulnerabilities.append(vuln)

            return vulnerabilities[:limit]
        except Exception as e:
            logger.debug(f"扫描库漏洞失败: {e}")
            return []

    def find_exploitable(
        self,
        min_score: float = 7.0,
        limit: int = 50
    ) -> List[NVDVulnerability]:
        """查找可利用的漏洞

        搜索高严重性的漏洞
        """
        if not self.is_available():
            return []

        try:
            cve_results = self._query_adapter.search_vulnerabilities(
                severity='HIGH',
                limit=limit
            )

            vulnerabilities = []
            for cve in cve_results:
                cvss_score = cve.get('cvss_score', 0.0) or 0.0
                if cvss_score >= min_score:
                    vuln = NVDVulnerability(
                        cve_id=cve.get('cve_id', ''),
                        description=cve.get('description', ''),
                        cvss_score=cvss_score,
                        severity=cve.get('severity', 'MEDIUM') or 'MEDIUM',
                        kev_exploited=False,
                        exploit_count=0,
                        poc_stars=0,
                        affected_versions=[],
                        cwe_ids=[]
                    )
                    vulnerabilities.append(vuln)

            return vulnerabilities[:limit]
        except Exception as e:
            logger.debug(f"查找可利用漏洞失败: {e}")
            return []

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """获取CVE详细信息"""
        if not self.is_available():
            return None

        try:
            cve_results = self._query_adapter.search_vulnerabilities(limit=100)
            for cve in cve_results:
                if cve.get('cve_id') == cve_id:
                    return {
                        'cve_id': cve.get('cve_id'),
                        'description': cve.get('description'),
                        'cvss_score': cve.get('cvss_score'),
                        'severity': cve.get('severity'),
                        'cvss_vector': None,
                        'kev_exploited': False,
                        'kev_description': None,
                        'exploit_count': 0,
                        'poc_count': 0,
                        'cwe_ids': [],
                        'cwe_names': [],
                        'published_date': None,
                        'last_modified': None
                    }
        except Exception as e:
            logger.debug(f"获取CVE详情失败: {e}")

        return None

    def get_exploits(self, cve_id: str) -> List[Dict[str, Any]]:
        """获取CVE的Exploit列表"""
        if not self.is_available():
            return []

        try:
            cwe_info = self._query_adapter.get_cwe_with_cves(cve_id, limit=10)
            if cwe_info and 'related_cves' in cwe_info:
                return cwe_info['related_cves']
        except Exception as e:
            logger.debug(f"获取Exploit列表失败: {e}")

        return []

    def get_pocs(self, cve_id: str) -> List[Dict[str, Any]]:
        """获取CVE的PoC列表"""
        if not self.is_available():
            return []

        try:
            cwe_info = self._query_adapter.get_cwe_with_cves(cve_id, limit=10)
            if cwe_info and 'related_cves' in cwe_info:
                return cwe_info['related_cves']
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
            return self._query_adapter.match_cwe(keywords, limit)
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
            cve_results = self._query_adapter.search_vulnerabilities(
                cwe_id=cwe_id,
                limit=limit
            )

            vulnerabilities = []
            for cve in cve_results:
                cvss_score = cve.get('cvss_score', 0.0) or 0.0
                if cvss_score >= min_score:
                    vuln = NVDVulnerability(
                        cve_id=cve.get('cve_id', ''),
                        description=cve.get('description', ''),
                        cvss_score=cvss_score,
                        severity=cve.get('severity', 'MEDIUM') or 'MEDIUM',
                        kev_exploited=False,
                        exploit_count=0,
                        poc_stars=0,
                        affected_versions=[],
                        cwe_ids=[cwe_id]
                    )
                    vulnerabilities.append(vuln)

            return vulnerabilities[:limit]
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
