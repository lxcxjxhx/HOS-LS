from typing import Dict, List

class QueryTemplates:
    """NVD查询SQL模板"""
    
    SCAN_PRODUCT = """
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
        FROM cve_summary cs
        JOIN cve c ON cs.cve_id = c.cve_id
        JOIN cpe cp ON cs.cve_id = cp.cve_id
        WHERE cp.vendor = %(vendor)s
          AND cp.product = %(product)s
          AND cs.cvss_score >= %(min_score)s
        ORDER BY
            cs.kev_exploited DESC,
            cs.cvss_score DESC
        LIMIT %(limit)s
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
        FROM cve_summary cs
        JOIN cve c ON cs.cve_id = c.cve_id
        JOIN cpe cp ON cs.cve_id = cp.cve_id
        WHERE cp.vendor = %(vendor)s
          AND cp.product = %(product)s
          AND cs.cvss_score >= %(min_score)s
          AND (
              (cp.version = %(version)s)
              OR (cp.version_start IS NOT NULL AND cp.version_start <= %(version)s 
                  AND (cp.version_end IS NULL OR cp.version_end > %(version)s))
              OR (cp.version_start IS NULL AND cp.version_end IS NOT NULL AND cp.version_end > %(version)s)
              OR (cp.version_start IS NOT NULL AND cp.version_start_type = 'including' AND cp.version_start <= %(version)s
                  AND (cp.version_end IS NULL OR cp.version_end_type = 'excluding' AND cp.version_end > %(version)s
                       OR cp.version_end_type = 'including' AND cp.version_end >= %(version)s))
          )
        ORDER BY
            cs.kev_exploited DESC,
            cs.cvss_score DESC
        LIMIT %(limit)s
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
        FROM cve_summary cs
        JOIN cve c ON cs.cve_id = c.cve_id
        WHERE cs.cvss_score >= %(min_score)s
          AND (cs.kev_exploited = TRUE OR cs.exploit_count > 0)
        ORDER BY
            cs.kev_exploited DESC,
            cs.exploit_count DESC,
            cs.cvss_score DESC
        LIMIT %(limit)s
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
        FROM cve_summary cs
        JOIN cve c ON cs.cve_id = c.cve_id
        JOIN poc p ON cs.cve_id = p.cve_id
        WHERE cs.cvss_score >= %(min_score)s
          AND p.stars >= %(min_stars)s
        ORDER BY p.stars DESC
        LIMIT %(limit)s
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
            array_agg(DISTINCT cwe.cwe_id) FILTER (WHERE cwe.cwe_id IS NOT NULL) as cwe_ids,
            array_agg(DISTINCT cwe.name) FILTER (WHERE cwe.name IS NOT NULL) as cwe_names
        FROM cve c
        LEFT JOIN cvss ON c.cve_id = cvss.cve_id
        LEFT JOIN kev ON c.cve_id = kev.cve_id
        LEFT JOIN cve_cwe cc ON c.cve_id = cc.cve_id
        LEFT JOIN cwe ON cc.cwe_id = c.cwe_id
        WHERE c.cve_id = %(cve_id)s
        GROUP BY c.cve_id, c.description, c.published_date, c.last_modified,
                 cvss.score, cvss.severity, cvss.vector, kev.exploited, kev.short_description
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
        WHERE cve_id = %(cve_id)s
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
        WHERE cve_id = %(cve_id)s
        ORDER BY stars DESC
    """