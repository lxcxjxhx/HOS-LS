"""NVD 数据库查询适配器

实际查询 nvd_vulnerability.db 数据库进行 CWE 匹配和漏洞查询
优化版本：支持缓存和内存索引
"""

import os
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


class NVDQueryAdapter:
    """NVD 数据库查询适配器

    实际查询 nvd_vulnerability.db 数据库进行 CWE 匹配
    优化版本：缓存 + 内存索引 + CVSS 统计
    """

    def __init__(self, db_path: str = None, use_cache: bool = True):
        if db_path is None:
            db_path = self._find_default_db_path()

        self.db_path = db_path
        self._conn = None
        self._connected = False
        self._cwe_index: Optional[Dict[str, Dict[str, Any]]] = None
        self._index_built = False

        if use_cache:
            try:
                from src.nvd.query_cache import NVDQueryCache, get_global_cache
                self._cache = get_global_cache()
            except Exception:
                self._cache = None
        else:
            self._cache = None

        if db_path and os.path.exists(db_path):
            self._connect()
        else:
            logger.warning(f"NVD数据库文件不存在: {db_path}")

    def _find_default_db_path(self) -> Optional[str]:
        """查找默认的 NVD 数据库路径"""
        possible_paths = [
            Path(__file__).parent.parent.parent.parent / 'All Vulnerabilities' / 'sql_data' / 'nvd_vulnerability.db',
            Path('c:/1AAA_PROJECT/HOS/HOS-LS/HOS-LS/All Vulnerabilities/sql_data/nvd_vulnerability.db'),
            Path.cwd() / 'All Vulnerabilities' / 'sql_data' / 'nvd_vulnerability.db',
        ]

        for path in possible_paths:
            if path.exists():
                logger.info(f"找到NVD数据库: {path}")
                return str(path)

        return None

    def _connect(self) -> bool:
        """连接数据库"""
        try:
            import sqlite3
            self._conn = sqlite3.connect(self.db_path, timeout=30.0)
            self._conn.row_factory = sqlite3.Row
            self._connected = True
            logger.info(f"NVD数据库连接成功: {self.db_path}")
            return True
        except Exception as e:
            logger.error(f"NVD数据库连接失败: {e}")
            self._connected = False
            return False

    def _disconnect(self) -> None:
        """断开数据库连接"""
        if self._conn:
            self._conn.close()
            self._conn = None
            self._connected = False

    def _ensure_connected(self) -> bool:
        """确保已连接"""
        if not self._connected or self._conn is None:
            return self._connect()
        return True

    def is_available(self) -> bool:
        """检查数据库是否可用"""
        if not self._ensure_connected():
            return False

        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cwe LIMIT 1")
            cursor.close()
            return True
        except Exception:
            return False

    def _ensure_cwe_index(self) -> Dict[str, Dict[str, Any]]:
        """构建 CWE 内存索引

        一次性加载所有 CWE 到内存，加速后续查询
        """
        if self._cwe_index is not None:
            return self._cwe_index

        if not self._ensure_connected():
            return {}

        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT cwe_id, cwe_name, cwe_description
                FROM cwe
            """)
            rows = cursor.fetchall()
            cursor.close()

            self._cwe_index = {}
            for row in rows:
                self._cwe_index[row['cwe_id']] = {
                    'cwe_id': row['cwe_id'],
                    'cwe_name': row['cwe_name'],
                    'cwe_description': row['cwe_description'],
                    'name_lower': row['cwe_name'].lower(),
                    'desc_lower': row['cwe_description'].lower()
                }

            self._index_built = True
            logger.info(f"CWE内存索引构建完成，共 {len(self._cwe_index)} 条记录")
            return self._cwe_index

        except Exception as e:
            logger.error(f"CWE索引构建失败: {e}")
            return {}

    def _search_in_memory(self, keywords: List[str], limit: int = 5) -> List[Dict[str, Any]]:
        """在内存中搜索 CWE

        Args:
            keywords: 关键词列表
            limit: 返回数量限制

        Returns:
            匹配的 CWE 列表
        """
        cwe_index = self._ensure_cwe_index()
        if not cwe_index:
            return []

        scored = []
        for cwe_id, cwe_info in cwe_index.items():
            score = 0
            matched_kws = []

            name_lower = cwe_info['name_lower']
            desc_lower = cwe_info['desc_lower']

            for kw in keywords:
                kw_lower = kw.lower()

                if kw_lower in name_lower:
                    score += 3
                    matched_kws.append(kw)

                if kw_lower in desc_lower:
                    score += 1
                    if kw not in matched_kws:
                        matched_kws.append(kw)

            if score > 0:
                scored.append({
                    'cwe_id': cwe_id,
                    'cwe_name': cwe_info['cwe_name'],
                    'cwe_description': cwe_info['cwe_description'],
                    'confidence': min(1.0, score / 6.0),
                    'matched_keywords': matched_kws,
                    'score': score
                })

        scored.sort(key=lambda x: x['score'], reverse=True)
        return scored[:limit]

    def match_cwe(self, keywords: List[str], limit: int = 5) -> List[Dict[str, Any]]:
        """根据关键词匹配 NVD CWE

        优化版本：优先使用缓存，然后使用内存索引

        Args:
            keywords: 关键词列表
            limit: 返回数量限制

        Returns:
            匹配的 CWE 信息列表
        """
        if not keywords:
            return []

        cache_key = f"match:{','.join(sorted(keywords))}:{limit}"

        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        if self._ensure_connected() and self._cwe_index is not None:
            results = self._search_in_memory(keywords, limit)
        elif self._ensure_connected():
            results = self._search_with_index(keywords, limit)
        else:
            results = []

        if self._cache and results:
            self._cache.set(cache_key, results)

        return results

    def _search_with_index(self, keywords: List[str], limit: int = 5) -> List[Dict[str, Any]]:
        """使用索引搜索 CWE

        Args:
            keywords: 关键词列表
            limit: 返回数量限制

        Returns:
            匹配的 CWE 列表
        """
        cwe_index = self._ensure_cwe_index()
        if not cwe_index:
            return []

        return self._search_in_memory(keywords, limit)

    def get_cwe_by_id(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """根据 CWE ID 获取详细信息

        Args:
            cwe_id: CWE ID，如 'CWE-89'

        Returns:
            CWE 详细信息
        """
        if not self._ensure_connected():
            return None

        cache_key = f"cwe_by_id:{cwe_id}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            cwe_index = self._ensure_cwe_index()
            if cwe_id in cwe_index:
                result = {
                    'cwe_id': cwe_index[cwe_id]['cwe_id'],
                    'cwe_name': cwe_index[cwe_id]['cwe_name'],
                    'cwe_description': cwe_index[cwe_id]['cwe_description'],
                    'confidence': 1.0
                }
                if self._cache:
                    self._cache.set(cache_key, result)
                return result

            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT cwe_id, cwe_name, cwe_description
                FROM cwe
                WHERE cwe_id = ?
            """, (cwe_id,))

            row = cursor.fetchone()
            cursor.close()

            if row:
                result = {
                    'cwe_id': row['cwe_id'],
                    'cwe_name': row['cwe_name'],
                    'cwe_description': row['cwe_description'],
                    'confidence': 1.0
                }
                if self._cache:
                    self._cache.set(cache_key, result)
                return result

            return None

        except Exception as e:
            logger.error(f"CWE查询失败 (ID: {cwe_id}): {e}")
            return None

    def get_cwe_with_cvss_stats(self, cwe_id: str) -> Dict[str, Any]:
        """获取 CWE 的 CVSS 统计信息

        用于辅助判断漏洞严重性

        Args:
            cwe_id: CWE ID

        Returns:
            CVSS 统计信息
        """
        if not self._ensure_connected():
            return {}

        cache_key = f"cvss_stats:{cwe_id}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT
                    AVG(cvss.cvss_score) as avg_score,
                    MAX(cvss.cvss_score) as max_score,
                    MIN(cvss.cvss_score) as min_score,
                    COUNT(DISTINCT cvss.cvss_severity) as severity_count,
                    COUNT(DISTINCT cvss.cve_id) as cve_count
                FROM cve_cwe
                JOIN cvss ON cve_cwe.cve_id = cvss.cve_id
                WHERE cve_cwe.cwe_id = ?
            """, (cwe_id,))

            row = cursor.fetchone()
            cursor.close()

            result = {
                'cwe_id': cwe_id,
                'avg_cvss': float(row['avg_score']) if row['avg_score'] else 0.0,
                'max_cvss': float(row['max_score']) if row['max_score'] else 0.0,
                'min_cvss': float(row['min_score']) if row['min_score'] else 0.0,
                'severity_variants': row['severity_count'] or 0,
                'cve_count': row['cve_count'] or 0
            }

            if self._cache:
                self._cache.set(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"CVSS统计查询失败 (CWE: {cwe_id}): {e}")
            return {}

    def search_vulnerabilities(self, cwe_id: str = None, severity: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """搜索特定 CWE 的漏洞

        Args:
            cwe_id: CWE ID，如 'CWE-89'
            severity: 严重级别，如 'HIGH', 'CRITICAL'
            limit: 返回数量限制

        Returns:
            漏洞信息列表
        """
        if not self._ensure_connected():
            return []

        try:
            cursor = self._conn.cursor()

            query = """
                SELECT DISTINCT
                    cve.cve_id,
                    cve.description,
                    cvss.cvss_score,
                    cvss.cvss_severity
                FROM cve
                LEFT JOIN cvss ON cve.cve_id = cvss.cve_id
                LEFT JOIN cve_cwe ON cve.cve_id = cve_cwe.cve_id
                WHERE 1=1
            """
            params = []

            if cwe_id:
                query += " AND cve_cwe.cwe_id = ?"
                params.append(cwe_id)

            if severity:
                query += " AND cvss.cvss_severity = ?"
                params.append(severity.upper())

            query += f" ORDER BY cvss.cvss_score DESC LIMIT {limit}"

            cursor.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()

            results = []
            for row in rows:
                results.append({
                    'cve_id': row['cve_id'],
                    'description': row['description'],
                    'cvss_score': float(row['cvss_score']) if row['cvss_score'] else None,
                    'severity': row['cvss_severity']
                })

            return results

        except Exception as e:
            logger.error(f"漏洞搜索失败: {e}")
            return []

    def get_cwe_with_cves(self, cwe_id: str, limit: int = 10) -> Dict[str, Any]:
        """获取 CWE 及其相关的 CVE

        Args:
            cwe_id: CWE ID
            limit: 返回的 CVE 数量

        Returns:
            包含 CWE 信息和相关 CVE 列表的字典
        """
        cwe_info = self.get_cwe_by_id(cwe_id)
        if not cwe_info:
            return {}

        cves = self.search_vulnerabilities(cwe_id=cwe_id, limit=limit)
        cwe_info['related_cves'] = cves
        cwe_info['cve_count'] = len(cves)

        cvss_stats = self.get_cwe_with_cvss_stats(cwe_id)
        cwe_info['cvss_stats'] = cvss_stats

        return cwe_info

    def get_all_cwe_ids(self) -> List[str]:
        """获取所有 CWE ID 列表

        Returns:
            CWE ID 列表
        """
        if not self._ensure_connected():
            return []

        cache_key = "all_cwe_ids"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            cwe_index = self._ensure_cwe_index()
            if cwe_index:
                result = sorted(cwe_index.keys())
                if self._cache:
                    self._cache.set(cache_key, result)
                return result

            cursor = self._conn.cursor()
            cursor.execute("SELECT cwe_id FROM cwe ORDER BY cwe_id")
            rows = cursor.fetchall()
            cursor.close()
            result = [row['cwe_id'] for row in rows]

            if self._cache:
                self._cache.set(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"获取CWE列表失败: {e}")
            return []

    def get_db_stats(self) -> Dict[str, int]:
        """获取数据库统计信息

        Returns:
            各表的记录数统计
        """
        stats = {
            'connected': self._connected,
            'db_path': self.db_path,
            'index_built': self._index_built,
            'index_size': len(self._cwe_index) if self._cwe_index else 0
        }

        if not self._ensure_connected():
            return stats

        try:
            cursor = self._conn.cursor()
            tables = ['cve', 'cvss', 'cpe', 'cwe', 'cve_cwe', 'kev', 'exploit', 'poc']

            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    stats[table] = count
                except Exception:
                    stats[table] = 0

            cursor.close()
        except Exception as e:
            logger.error(f"获取数据库统计失败: {e}")

        return stats

    def clear_cache(self) -> None:
        """清空查询缓存"""
        if self._cache:
            self._cache.clear()

    def __del__(self):
        """析构时关闭连接"""
        self._disconnect()


def get_nvd_adapter(db_path: str = None, use_cache: bool = True) -> Optional[NVDQueryAdapter]:
    """获取 NVD 查询适配器实例

    Args:
        db_path: 数据库路径
        use_cache: 是否使用缓存

    Returns:
        NVDQueryAdapter 实例，如果数据库不可用则返回 None
    """
    adapter = NVDQueryAdapter(db_path, use_cache)
    if adapter.is_available():
        return adapter
    return None