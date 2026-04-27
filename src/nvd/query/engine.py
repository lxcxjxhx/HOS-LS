from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from ..db.connection import NVDConnection
from .templates import QueryTemplates

@dataclass
class CVEHit:
    """CVE命中结果"""
    cve_id: str
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    kev_exploited: Optional[bool]
    exploit_count: int
    max_poc_stars: int
    cwe_ids: List[str]
    description: str
    published_date: Optional[str]
    affected_version: Optional[str] = None

@dataclass
class CVEPoC:
    """CVE PoC信息"""
    cve_id: str
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    kev_exploited: Optional[bool]
    max_poc_stars: int
    repo_url: str
    stars: int
    language: Optional[str]
    description: str

@dataclass
class CVEDetail:
    """CVE详细信息"""
    cve_id: str
    description: str
    published_date: Optional[str]
    last_modified: Optional[str]
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    cvss_vector: Optional[str]
    kev_exploited: Optional[bool]
    kev_description: Optional[str]
    exploit_count: int
    poc_count: int
    cwe_ids: List[str]
    cwe_names: List[str]

class NVDQueryEngine:
    """NVD漏洞查询引擎"""
    
    def __init__(self, connection: Optional[NVDConnection] = None):
        self.conn = connection or NVDConnection.get_instance()
        self.templates = QueryTemplates()
    
    def scan_product(
        self,
        vendor: str,
        product: str,
        version: Optional[str] = None,
        min_score: float = 0.0,
        limit: int = 100
    ) -> List[CVEHit]:
        """扫描特定产品的漏洞"""
        params = {
            'vendor': vendor.lower(),
            'product': product.lower(),
            'min_score': min_score,
            'limit': limit
        }
        
        if version:
            params['version'] = version
            query = self.templates.SCAN_PRODUCT_VERSION
        else:
            query = self.templates.SCAN_PRODUCT
        
        results = self.conn.fetch_all(query, params)
        
        hits = []
        for row in results:
            hit = CVEHit(
                cve_id=row[0],
                cvss_score=row[1],
                cvss_severity=row[2],
                kev_exploited=row[3],
                exploit_count=row[4],
                max_poc_stars=row[5],
                cwe_ids=self._parse_array(row[6]) if row[6] else [],
                description=row[7] or '',
                published_date=str(row[8]) if row[8] else None,
                affected_version=row[9] if len(row) > 9 else None
            )
            hits.append(hit)
        
        return hits
    
    def find_exploitable(
        self,
        min_score: float = 7.0,
        limit: int = 100
    ) -> List[CVEHit]:
        """查找可利用的漏洞"""
        params = {
            'min_score': min_score,
            'limit': limit
        }
        
        results = self.conn.fetch_all(self.templates.FIND_EXPLOITABLE, params)
        
        hits = []
        for row in results:
            hit = CVEHit(
                cve_id=row[0],
                cvss_score=row[1],
                cvss_severity=row[2],
                kev_exploited=row[3],
                exploit_count=row[4],
                max_poc_stars=row[5],
                cwe_ids=self._parse_array(row[6]) if row[6] else [],
                description=row[7] or '',
                published_date=str(row[8]) if row[8] else None
            )
            hits.append(hit)
        
        return hits
    
    def find_poc_vulnerabilities(
        self,
        min_score: float = 7.0,
        min_stars: int = 10,
        limit: int = 100
    ) -> List[CVEPoC]:
        """查找有PoC的漏洞"""
        params = {
            'min_score': min_score,
            'min_stars': min_stars,
            'limit': limit
        }
        
        results = self.conn.fetch_all(self.templates.FIND_POC, params)
        
        pocs = []
        for row in results:
            poc = CVEPoC(
                cve_id=row[0],
                cvss_score=row[1],
                cvss_severity=row[2],
                kev_exploited=row[3],
                max_poc_stars=row[4],
                repo_url=row[5] or '',
                stars=row[6] or 0,
                language=row[7],
                description=row[8] or ''
            )
            pocs.append(poc)
        
        return pocs
    
    def get_cve_detail(self, cve_id: str) -> Optional[CVEDetail]:
        """获取CVE详细信息"""
        result = self.conn.fetch_one(self.templates.GET_CVE_DETAIL, {'cve_id': cve_id})
        
        if not result:
            return None
        
        return CVEDetail(
            cve_id=result[0],
            description=result[1] or '',
            published_date=str(result[2]) if result[2] else None,
            last_modified=str(result[3]) if result[3] else None,
            cvss_score=result[4],
            cvss_severity=result[5],
            cvss_vector=result[6],
            kev_exploited=result[7],
            kev_description=result[8],
            exploit_count=result[9] or 0,
            poc_count=result[10] or 0,
            cwe_ids=self._parse_array(result[11]) if result[11] else [],
            cwe_names=self._parse_array(result[12]) if result[12] else []
        )
    
    def get_exploits(self, cve_id: str) -> List[Dict[str, Any]]:
        """获取CVE的Exploit列表"""
        results = self.conn.fetch_all(self.templates.GET_EXPLOITS, {'cve_id': cve_id})
        
        exploits = []
        for row in results:
            exploits.append({
                'id': row[0],
                'source': row[1],
                'exploit_type': row[2],
                'platform': row[3],
                'port': row[4],
                'description': row[5],
                'file_path': row[6],
                'verified': row[7]
            })
        
        return exploits
    
    def get_pocs(self, cve_id: str) -> List[Dict[str, Any]]:
        """获取CVE的PoC列表"""
        results = self.conn.fetch_all(self.templates.GET_POCS, {'cve_id': cve_id})
        
        pocs = []
        for row in results:
            pocs.append({
                'id': row[0],
                'repo_url': row[1],
                'stars': row[2],
                'language': row[3],
                'description': row[4],
                'last_updated': str(row[5]) if row[5] else None
            })
        
        return pocs
    
    def _parse_array(self, array_str) -> List[str]:
        """解析PostgreSQL数组字符串"""
        if not array_str:
            return []
        if isinstance(array_str, list):
            return array_str
        if isinstance(array_str, str):
            return [x.strip() for x in array_str.strip('{}').split(',') if x.strip()]
        return []