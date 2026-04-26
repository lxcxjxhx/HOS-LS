from typing import Dict, List

class SQLiteQueryTemplates:
    """SQLite NVD查询SQL模板"""

    SCAN_PRODUCT = """
        SELECT DISTINCT
            cs.cve_id,
            cs.cvss_score,
            cs.cvss_severity,
            cs.kev_exploited,
            cs.exploit_count,
            cs.max_poc_stars,
            cs.cwe_ids,
            c.description,
            c.published_date
        FROM (
            SELECT
                cve.cve_id,
                cvss.score AS cvss_score,
                cvss.severity AS cvss_severity,
                kev.exploited AS kev_exploited,
                (SELECT COUNT(*) FROM exploit WHERE exploit.cve_id = cve.cve_id) AS exploit_count,
                (SELECT MAX(stars) FROM poc WHERE poc.cve_id = cve.cve_id) AS max_poc_stars,
                (SELECT group_concat(cwe_id) FROM cve_cwe WHERE cve_cwe.cve_id = cve.cve_id) AS cwe_ids
            FROM cve
            LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
            LEFT JOIN kev ON cve.cve_id = kev.cve_id
            WHERE cvss.score >= :min_score
        ) cs
        JOIN cve c ON cs.cve_id = c.cve_id
        JOIN cpe cp ON cs.cve_id = cp.cve_id
        WHERE cp.vendor = :vendor
          AND cp.product = :product
        ORDER BY
            cs.kev_exploited DESC,
            cs.cvss_score DESC
        LIMIT :limit
    """

    SCAN_PRODUCT_VERSION = """
        SELECT DISTINCT
            cs.cve_id,
            cs.cvss_score,
            cs.cvss_severity,
            cs.kev_exploited,
            cs.exploit_count,
            cs.max_poc_stars,
            cs.cwe_ids,
            c.description,
            c.published_date,
            cp.version as affected_version
        FROM (
            SELECT
                cve.cve_id,
                cvss.score AS cvss_score,
                cvss.severity AS cvss_severity,
                kev.exploited AS kev_exploited,
                (SELECT COUNT(*) FROM exploit WHERE exploit.cve_id = cve.cve_id) AS exploit_count,
                (SELECT MAX(stars) FROM poc WHERE poc.cve_id = cve.cve_id) AS max_poc_stars,
                (SELECT group_concat(cwe_id) FROM cve_cwe WHERE cve_cwe.cve_id = cve.cve_id) AS cwe_ids
            FROM cve
            LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
            LEFT JOIN kev ON cve.cve_id = kev.cve_id
            WHERE cvss.score >= :min_score
        ) cs
        JOIN cve c ON cs.cve_id = c.cve_id
        JOIN cpe cp ON cs.cve_id = cp.cve_id
        WHERE cp.vendor = :vendor
          AND cp.product = :product
          AND (
              (cp.version = :version)
              OR (cp.version_start IS NOT NULL AND cp.version_start <= :version
                  AND (cp.version_end IS NULL OR cp.version_end > :version))
              OR (cp.version_start IS NULL AND cp.version_end IS NOT NULL AND cp.version_end > :version)
          )
        ORDER BY
            cs.kev_exploited DESC,
            cs.cvss_score DESC
        LIMIT :limit
    """

    FIND_EXPLOITABLE = """
        SELECT
            cs.cve_id,
            cs.cvss_score,
            cs.cvss_severity,
            cs.kev_exploited,
            cs.exploit_count,
            cs.max_poc_stars,
            cs.cwe_ids,
            c.description,
            c.published_date
        FROM (
            SELECT
                cve.cve_id,
                cvss.score AS cvss_score,
                cvss.severity AS cvss_severity,
                kev.exploited AS kev_exploited,
                (SELECT COUNT(*) FROM exploit WHERE exploit.cve_id = cve.cve_id) AS exploit_count,
                (SELECT MAX(stars) FROM poc WHERE poc.cve_id = cve.cve_id) AS max_poc_stars,
                (SELECT group_concat(cwe_id) FROM cve_cwe WHERE cve_cwe.cve_id = cve.cve_id) AS cwe_ids
            FROM cve
            LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
            LEFT JOIN kev ON cve.cve_id = kev.cve_id
            WHERE cvss.score >= :min_score
        ) cs
        JOIN cve c ON cs.cve_id = c.cve_id
        WHERE cs.kev_exploited = 1 OR cs.exploit_count > 0
        ORDER BY
            cs.kev_exploited DESC,
            cs.exploit_count DESC,
            cs.cvss_score DESC
        LIMIT :limit
    """

    FIND_POC = """
        SELECT
            cs.cve_id,
            cs.cvss_score,
            cs.cvss_severity,
            cs.kev_exploited,
            cs.max_poc_stars,
            p.repo_url,
            p.stars,
            p.language,
            c.description
        FROM (
            SELECT
                cve.cve_id,
                cvss.score AS cvss_score,
                cvss.severity AS cvss_severity,
                kev.exploited AS kev_exploited,
                (SELECT MAX(stars) FROM poc WHERE poc.cve_id = cve.cve_id) AS max_poc_stars
            FROM cve
            LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
            LEFT JOIN kev ON cve.cve_id = kev.cve_id
            WHERE cvss.score >= :min_score
        ) cs
        JOIN cve c ON cs.cve_id = c.cve_id
        JOIN poc p ON cs.cve_id = p.cve_id
        WHERE p.stars >= :min_stars
        ORDER BY p.stars DESC
        LIMIT :limit
    """

    GET_CVE_DETAIL = """
        SELECT
            c.cve_id,
            c.description,
            c.published_date,
            c.last_modified,
            cvss.score,
            cvss.severity,
            cvss.vector,
            kev.exploited,
            kev.short_description,
            (SELECT COUNT(*) FROM exploit WHERE cve_id = c.cve_id) as exploit_count,
            (SELECT COUNT(*) FROM poc WHERE cve_id = c.cve_id) as poc_count,
            (SELECT group_concat(cwe_id) FROM cve_cwe WHERE cve_cwe.cve_id = c.cve_id) as cwe_ids,
            (SELECT group_concat(cwe.name) FROM cve_cwe JOIN cwe ON cve_cwe.cwe_id = cwe.cwe_id WHERE cve_cwe.cve_id = c.cve_id) as cwe_names
        FROM cve c
        LEFT JOIN cvss ON c.cve_id = cvss.cve_id
        LEFT JOIN kev ON c.cve_id = kev.cve_id
        WHERE c.cve_id = :cve_id
    """

    GET_EXPLOITS = """
        SELECT
            id,
            source,
            exploit_type,
            platform,
            port,
            description,
            file_path,
            verified
        FROM exploit
        WHERE cve_id = :cve_id
        ORDER BY verified DESC, id ASC
    """

    GET_POCS = """
        SELECT
            id,
            repo_url,
            stars,
            language,
            description,
            last_updated
        FROM poc
        WHERE cve_id = :cve_id
        ORDER BY stars DESC
    """

    MATCH_CWE = """
        SELECT
            cwe_id,
            cwe_name,
            cwe_description
        FROM cwe
        WHERE 1=1
        {conditions}
        ORDER BY cwe_id
        LIMIT :limit
    """

    GET_CVES_BY_CWE = """
        SELECT DISTINCT
            cs.cve_id,
            cs.cvss_score,
            cs.cvss_severity,
            cs.kev_exploited,
            cs.exploit_count,
            cs.max_poc_stars,
            cs.cwe_ids,
            c.description,
            c.published_date
        FROM (
            SELECT
                cve.cve_id,
                cvss.score AS cvss_score,
                cvss.severity AS cvss_severity,
                kev.exploited AS kev_exploited,
                (SELECT COUNT(*) FROM exploit WHERE exploit.cve_id = cve.cve_id) AS exploit_count,
                (SELECT MAX(stars) FROM poc WHERE poc.cve_id = cve.cve_id) AS max_poc_stars,
                (SELECT group_concat(cwe_id) FROM cve_cwe WHERE cve_cwe.cve_id = cve.cve_id) AS cwe_ids
            FROM cve
            LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
            LEFT JOIN kev ON cve.cve_id = kev.cve_id
            WHERE cvss.score >= :min_score
        ) cs
        JOIN cve c ON cs.cve_id = c.cve_id
        JOIN cve_cwe cc ON cs.cve_id = cc.cve_id
        WHERE cc.cwe_id = :cwe_id
        ORDER BY
            cs.kev_exploited DESC,
            cs.cvss_score DESC
        LIMIT :limit
    """

class SQLiteQueryEngine:
    """SQLite NVD漏洞查询引擎"""

    def __init__(self, connection):
        self.conn = connection
        self.templates = SQLiteQueryTemplates()

    def scan_product(
        self,
        vendor: str,
        product: str,
        version: str = None,
        min_score: float = 0.0,
        limit: int = 100
    ):
        from .engine import CVEHit

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
                kev_exploited=bool(row[3]) if row[3] is not None else None,
                exploit_count=row[4] or 0,
                max_poc_stars=row[5] or 0,
                cwe_ids=self._parse_concat(row[6]) if row[6] else [],
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
    ):
        from .engine import CVEHit

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
                kev_exploited=bool(row[3]) if row[3] is not None else None,
                exploit_count=row[4] or 0,
                max_poc_stars=row[5] or 0,
                cwe_ids=self._parse_concat(row[6]) if row[6] else [],
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
    ):
        from .engine import CVEPoC

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
                kev_exploited=bool(row[3]) if row[3] is not None else None,
                max_poc_stars=row[4] or 0,
                repo_url=row[5] or '',
                stars=row[6] or 0,
                language=row[7],
                description=row[8] or ''
            )
            pocs.append(poc)

        return pocs

    def get_cve_detail(self, cve_id: str):
        from .engine import CVEDetail

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
            kev_exploited=bool(result[7]) if result[7] is not None else None,
            kev_description=result[8],
            exploit_count=result[9] or 0,
            poc_count=result[10] or 0,
            cwe_ids=self._parse_concat(result[11]) if result[11] else [],
            cwe_names=self._parse_concat(result[12]) if result[12] else []
        )

    def get_exploits(self, cve_id: str):
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
                'verified': bool(row[7]) if row[7] is not None else False
            })

        return exploits

    def get_pocs(self, cve_id: str):
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

    def _parse_concat(self, concat_str):
        if not concat_str:
            return []
        if isinstance(concat_str, list):
            return concat_str
        if isinstance(concat_str, str):
            return [x.strip() for x in concat_str.split(',') if x.strip()]
        return []

    def match_cwe(self, keywords: List[str], limit: int = 10):
        """根据关键词匹配CWE

        Args:
            keywords: 关键词列表
            limit: 返回结果数量限制

        Returns:
            CWE匹配结果列表
        """
        if not keywords:
            return []

        conditions = []
        params = {'limit': limit}

        for i, keyword in enumerate(keywords):
            param_name = f'keyword_{i}'
            conditions.append(
                f"(cwe_name LIKE :{param_name} OR cwe_description LIKE :{param_name})"
            )
            params[param_name] = f'%{keyword}%'

        query = self.templates.MATCH_CWE.format(conditions=' AND '.join(conditions))
        results = self.conn.fetch_all(query, params)

        cwes = []
        for row in results:
            cwes.append({
                'cwe_id': row[0],
                'cwe_name': row[1],
                'cwe_description': row[2] or ''
            })

        return cwes

    def get_cves_by_cwe(self, cwe_id: str, min_score: float = 0.0, limit: int = 50):
        """获取指定CWE相关的CVE

        Args:
            cwe_id: CWE ID
            min_score: 最低CVSS评分
            limit: 返回结果数量限制

        Returns:
            CVE列表
        """
        from .engine import CVEHit

        params = {
            'cwe_id': cwe_id,
            'min_score': min_score,
            'limit': limit
        }

        results = self.conn.fetch_all(self.templates.GET_CVES_BY_CWE, params)

        hits = []
        for row in results:
            hit = CVEHit(
                cve_id=row[0],
                cvss_score=row[1],
                cvss_severity=row[2],
                kev_exploited=bool(row[3]) if row[3] is not None else None,
                exploit_count=row[4] or 0,
                max_poc_stars=row[5] or 0,
                cwe_ids=self._parse_concat(row[6]) if row[6] else [],
                description=row[7] or '',
                published_date=str(row[8]) if row[8] else None
            )
            hits.append(hit)

        return hits
