"""NVD 数据库查询适配器

实际查询 nvd_vulnerability.db 数据库进行 CWE 匹配和漏洞查询
优化版本：支持缓存和内存索引
"""

import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


class NVDQueryAdapter:
    """NVD 数据库查询适配器

    实际查询 nvd_vulnerability.db 数据库进行 CWE 匹配
    优化版本：缓存 + 内存索引 + CVSS 统计
    """

    def __init__(self, db_path: Optional[str] = None, use_cache: bool = True):
        resolved_path: Optional[str] = db_path
        if resolved_path is None:
            resolved_path = self._find_default_db_path()

        self.db_path: Optional[str] = resolved_path
        self._conn: Optional[sqlite3.Connection] = None
        self._connected = False
        self._cwe_index: Optional[Dict[str, Dict[str, Any]]] = None
        self._index_built = False
        self._cache: Any = None

        if use_cache:
            try:
                from src.nvd.query_cache import get_global_cache

                self._cache = get_global_cache()
            except Exception:
                self._cache = None

        if self.db_path and os.path.exists(self.db_path):
            self._connect()
        else:
            logger.warning(f"NVD数据库文件不存在: {self.db_path}")

    def _find_default_db_path(self) -> Optional[str]:
        """查找默认的 NVD 数据库路径（使用增强的路径查找逻辑）"""
        try:
            from src.nvd.db.sqlite_connection import SQLiteConnection

            # 修复：使用公开的类方法 find_database_path() 而不是错误的实例方法
            found_path = SQLiteConnection.find_database_path()
            if found_path:
                logger.info(f"[NVDQueryAdapter] 使用增强路径查找找到数据库: {found_path}")
                return str(found_path)
        except Exception as e:
            logger.debug(f"[NVDQueryAdapter] SQLiteConnection路径查找失败: {e}")

        from src.core.config import get_config

        config = get_config()
        config_db_path = Path(config.nvd.database_path)

        possible_paths = [
            config_db_path,
            Path(__file__).parent.parent.parent.parent
            / "All Vulnerabilities"
            / "sql_data"
            / "nvd_vulnerability.db",
            Path.cwd() / "All Vulnerabilities" / "sql_data" / "nvd_vulnerability.db",
        ]

        for path in possible_paths:
            if path.exists() and path.is_file():
                try:
                    import sqlite3

                    test_conn = sqlite3.connect(str(path), timeout=1.0)
                    test_conn.execute("SELECT 1")
                    test_conn.close()
                    logger.info(f"找到NVD数据库: {path}")
                    return str(path)
                except Exception:
                    pass

        return None

    def _connect(self) -> bool:
        """连接数据库"""
        try:
            if self.db_path is None:
                return False
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
        if self._conn is not None:
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
        assert self._conn is not None

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
        assert self._conn is not None

        try:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT cwe_id, name, description
                FROM cwe
            """
            )
            rows = cursor.fetchall()
            cursor.close()

            self._cwe_index = {}
            for row in rows:
                self._cwe_index[row["cwe_id"]] = {
                    "cwe_id": row["cwe_id"],
                    "cwe_name": row["name"],
                    "cwe_description": row["description"],
                    "name_lower": row["name"].lower(),
                    "desc_lower": row["description"].lower(),
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

            name_lower = cwe_info["name_lower"]
            desc_lower = cwe_info["desc_lower"]

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
                scored.append(
                    {
                        "cwe_id": cwe_id,
                        "cwe_name": cwe_info["cwe_name"],
                        "cwe_description": cwe_info["cwe_description"],
                        "confidence": min(1.0, score / 6.0),
                        "matched_keywords": matched_kws,
                        "score": score,
                    }
                )

        scored.sort(key=lambda x: x["score"], reverse=True)
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
                return list(cached)

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
                return dict(cached)

        if not self._ensure_connected():
            return None
        assert self._conn is not None

        try:
            cwe_index = self._ensure_cwe_index()
            if cwe_id in cwe_index:
                result = {
                    "cwe_id": cwe_index[cwe_id]["cwe_id"],
                    "cwe_name": cwe_index[cwe_id]["cwe_name"],
                    "cwe_description": cwe_index[cwe_id]["cwe_description"],
                    "confidence": 1.0,
                }
                if self._cache:
                    self._cache.set(cache_key, result)
                return result

            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT cwe_id, name AS cwe_name, description AS cwe_description
                FROM cwe
                WHERE cwe_id = ?
            """,
                (cwe_id,),
            )

            row = cursor.fetchone()
            cursor.close()

            if row:
                result = {
                    "cwe_id": row["cwe_id"],
                    "cwe_name": row["cwe_name"],
                    "cwe_description": row["cwe_description"],
                    "confidence": 1.0,
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
                return dict(cached)

        assert self._conn is not None
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT
                    AVG(cvss.score) as avg_score,
                    MAX(cvss.score) as max_score,
                    MIN(cvss.score) as min_score,
                    COUNT(DISTINCT cvss.severity) as severity_count,
                    COUNT(DISTINCT cvss.cve_id) as cve_count
                FROM cve_cwe
                JOIN cvss ON cve_cwe.cve_id = cvss.cve_id
                WHERE cve_cwe.cwe_id = ?
            """,
                (cwe_id,),
            )

            row = cursor.fetchone()
            cursor.close()

            result = {
                "cwe_id": cwe_id,
                "avg_cvss": float(row["avg_score"]) if row["avg_score"] else 0.0,
                "max_cvss": float(row["max_score"]) if row["max_score"] else 0.0,
                "min_cvss": float(row["min_score"]) if row["min_score"] else 0.0,
                "severity_variants": row["severity_count"] or 0,
                "cve_count": row["cve_count"] or 0,
            }

            if self._cache:
                self._cache.set(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"CVSS统计查询失败 (CWE: {cwe_id}): {e}")
            return {}

    def search_vulnerabilities(
        self, cwe_id: Optional[str] = None, severity: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
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
        assert self._conn is not None

        try:
            cursor = self._conn.cursor()

            query = """
                SELECT DISTINCT
                    cve.cve_id,
                    cve.description,
                    cvss.score AS cvss_score,
                    cvss.severity AS cvss_severity
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
                query += " AND cvss.severity = ?"
                params.append(severity.upper())

            query += f" ORDER BY cvss.score DESC LIMIT {limit}"

            cursor.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()

            results = []
            for row in rows:
                results.append(
                    {
                        "cve_id": row["cve_id"],
                        "description": row["description"],
                        "cvss_score": float(row["cvss_score"]) if row["cvss_score"] else None,
                        "severity": row["cvss_severity"],
                    }
                )

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
        cwe_info["related_cves"] = cves
        cwe_info["cve_count"] = len(cves)

        cvss_stats = self.get_cwe_with_cvss_stats(cwe_id)
        cwe_info["cvss_stats"] = cvss_stats

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
                return list(cached)

        if not self._ensure_connected():
            return []
        assert self._conn is not None

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
            result = [row["cwe_id"] for row in rows]

            if self._cache:
                self._cache.set(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"获取CWE列表失败: {e}")
            return []

    def get_db_stats(self) -> Dict[str, Any]:
        """获取数据库统计信息

        Returns:
            各表的记录数统计
        """
        stats: Dict[str, Any] = {
            "connected": self._connected,
            "db_path": self.db_path,
            "index_built": self._index_built,
            "index_size": len(self._cwe_index) if self._cwe_index else 0,
        }

        if not self._ensure_connected():
            return stats
        assert self._conn is not None

        try:
            cursor = self._conn.cursor()
            tables = ["cve", "cvss", "cpe", "cwe", "cve_cwe", "kev", "exploit", "poc"]

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


def get_nvd_adapter(
    db_path: Optional[str] = None, use_cache: bool = True
) -> Optional[NVDQueryAdapter]:
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


# ---------------------------------------------------------------------------
# Deterministic semantic template retrieval (Requirement 11.8-11.9).
#
# The repository reads versioned Taint_Template rows beside the canonical
# catalog tables and ranks them with a versioned, deterministic combination of
# semantic weakness relevance, documented applicability, and available catalog
# evidence.  Every retrieval is provenance-linked to the append-only
# template_retrieval table.  Returned templates are non-confirmatory ranking
# input only: this API never emits a confirmation or controllability decision
# (Requirement 11.12-11.13).
# ---------------------------------------------------------------------------

TEMPLATE_RANKING_PROFILE = "template-ranking/v1"

# Versioned component weights used to combine the three ranking signals.
TEMPLATE_RANKING_WEIGHTS: Dict[str, float] = {
    "relevance": 0.5,
    "applicability": 0.3,
    "catalog_evidence": 0.2,
}

# Normalization scale for catalog evidence (counted CVE links for the query
# weakness): a CWE backed by this many catalog records reaches evidence 1.0.
CATALOG_EVIDENCE_SCALE = 100.0


@dataclass(frozen=True)
class RankedTemplate:
    """One ranked, provenance-linked Taint_Template row (non-confirmatory)."""

    template_id: str
    cwe_id: str
    role: str
    api_shape: str
    parameter_shape: Tuple[int, ...]
    applicability: Dict[str, Any]
    template_version: str
    final_score: float
    relevance: float
    applicability_score: float
    catalog_evidence: float


@dataclass(frozen=True)
class TemplateRetrievalResult:
    """Deterministic retrieval result with full scoring provenance."""

    cwe_id: str
    query_identity: str
    ranking_profile_version: str
    retrieval_id: str
    ranked: Tuple[RankedTemplate, ...] = field(default_factory=tuple)

    @property
    def template_ids(self) -> Tuple[str, ...]:
        return tuple(item.template_id for item in self.ranked)

    @property
    def scores(self) -> Tuple[float, ...]:
        return tuple(item.final_score for item in self.ranked)


def _tokenize(text: str) -> frozenset[str]:
    """Deterministic lowercase alphanumeric token set used by relevance."""
    return frozenset(re.findall(r"[a-z0-9]+", text.lower()))


def relevance_score(
    query_cwe_id: str,
    template_cwe_id: str,
    template_features: Tuple[str, ...],
    query_catalog_terms: frozenset[str],
) -> float:
    """Semantic weakness-to-template relevance in [0, 1].

    An exact weakness match scores 1.0.  Otherwise the score is the Jaccard
    overlap between the query weakness's catalog terms and the template's
    documented semantic features, which keeps the ranking evidence-driven and
    deterministic (no LLM or ad-hoc similarity).
    """
    if template_cwe_id == query_cwe_id:
        return 1.0
    template_terms = _tokenize(" ".join(template_features))
    if not template_terms or not query_catalog_terms:
        return 0.0
    overlap = len(template_terms & query_catalog_terms)
    return overlap / len(template_terms | query_catalog_terms)


def applicability_score(
    template_applicability: Dict[str, Any],
    query_applicability: Optional[Dict[str, Any]],
) -> float:
    """Documented applicability match in {0.0, 0.5, 1.0}.

    1.0 when every declared template condition is present and equal in the
    query applicability; 0.5 when a declared condition is unspecified by the
    query (neutral) or the template declares no conditions; 0.0 on an explicit
    conflict.
    """
    if not template_applicability:
        return 0.5
    if not query_applicability:
        return 0.5
    conflicts = any(
        key in query_applicability and query_applicability[key] != value
        for key, value in template_applicability.items()
    )
    if conflicts:
        return 0.0
    unspecified = any(
        key not in query_applicability
        for key in template_applicability
    )
    if unspecified:
        return 0.5
    return 1.0


def evidence_score(cve_count: int) -> float:
    """Available catalog evidence in [0, 1] normalized to a documented scale."""
    return min(1.0, cve_count / CATALOG_EVIDENCE_SCALE)


# One scored template before final ordering: (template_id, cwe_id, role,
# api_shape, parameter_shape, applicability, template_version, final_score,
# relevance, applicability_score, catalog_evidence).
ScoredTemplate = Tuple[
    str, str, str, str, Tuple[int, ...], Dict[str, Any], str, float, float, float, float
]


def rank_templates(templates: Sequence[ScoredTemplate]) -> List[RankedTemplate]:
    """Rank scored templates by final score desc, then template id (stable)."""
    ranked = [
        RankedTemplate(
            template_id=template_id,
            cwe_id=cwe_id,
            role=role,
            api_shape=api_shape,
            parameter_shape=parameter_shape,
            applicability=applicability,
            template_version=template_version,
            final_score=final_score,
            relevance=relevance,
            applicability_score=applicability_score_value,
            catalog_evidence=catalog_evidence,
        )
        for (
            template_id,
            cwe_id,
            role,
            api_shape,
            parameter_shape,
            applicability,
            template_version,
            final_score,
            relevance,
            applicability_score_value,
            catalog_evidence,
        ) in templates
    ]
    ranked.sort(key=lambda item: (-item.final_score, item.template_id))
    return ranked


class TaintTemplateRepository:
    """Provenance-linked, deterministic semantic template retrieval.

    Only in-scope templates (``scope_cwe_ids`` when provided) are considered.
    Ranking uses :data:`TEMPLATE_RANKING_PROFILE` with stable tie-breaking and
    records every query identity, input, template/catalog identity, component
    score, final score, and retrieval provenance.  Existing CVE/CWE queries and
    cache behavior of :class:`NVDQueryAdapter` are untouched.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        *,
        ranking_profile_version: str = TEMPLATE_RANKING_PROFILE,
        scope_cwe_ids: Optional[Tuple[str, ...]] = None,
        use_cache: bool = True,
    ) -> None:
        self.db_path = db_path
        self.ranking_profile_version = ranking_profile_version
        self.scope_cwe_ids = tuple(scope_cwe_ids) if scope_cwe_ids else None
        self._adapter = NVDQueryAdapter(db_path, use_cache=use_cache)
        self._retrieval_cache: Dict[str, TemplateRetrievalResult] = {}
        self._conn: Optional[sqlite3.Connection] = None
        if self._adapter._conn is not None:
            self._conn = self._adapter._conn

    def _ensure_available(self) -> bool:
        if self._conn is None and self.db_path:
            self._adapter._connect()
            self._conn = self._adapter._conn
        return self._conn is not None

    def clear_cache(self) -> None:
        """Clear the in-process retrieval cache (cache behavior is preserved)."""
        self._retrieval_cache.clear()

    def close(self) -> None:
        """Close the underlying adapter connection."""
        self._adapter._disconnect()
        self._conn = None

    def __del__(self) -> None:
        self.close()

    def query_identity(
        self,
        cwe_id: str,
        applicability: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> str:
        """Deterministic identity of one retrieval query (versioned inputs)."""
        payload = {
            "cwe_id": cwe_id,
            "applicability": applicability,
            "context": context,
            "ranking_profile_version": self.ranking_profile_version,
            "scope_cwe_ids": sorted(self.scope_cwe_ids) if self.scope_cwe_ids else None,
        }
        return "template-query:" + sha256(
            json_dumps(payload).encode("utf-8")
        ).hexdigest()

    def retrieve(
        self,
        cwe_id: str,
        *,
        applicability: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> TemplateRetrievalResult:
        """Retrieve in-scope templates ranked for the given weakness.

        The result is non-confirmatory ranking input; it exposes no
        confirmation or controllability surface.
        """
        identity = self.query_identity(cwe_id, applicability, context)
        if identity in self._retrieval_cache:
            return self._retrieval_cache[identity]
        if not self._ensure_available():
            return self._empty_result(cwe_id, identity)
        assert self._conn is not None

        try:
            query = (
                "SELECT template_id, cwe_id, role, api_shape, parameter_shape, "
                "applicability_json, semantic_features_json, template_version "
                "FROM taint_template"
            )
            params: List[Any] = []
            if self.scope_cwe_ids:
                query += " WHERE cwe_id IN (%s)" % ",".join(
                    "?" for _ in self.scope_cwe_ids
                )
                params = list(self.scope_cwe_ids)
            rows = self._conn.execute(query, params).fetchall()
        except sqlite3.Error as error:
            # A legacy catalog without the ECATSL tables simply has no templates.
            logger.warning(f"模板检索不可用: {error}")
            return self._empty_result(cwe_id, identity)

        catalog_terms: frozenset[str] = frozenset()
        cve_count = 0
        try:
            cwe_row = self._conn.execute(
                "SELECT name, description FROM cwe WHERE cwe_id = ?", (cwe_id,)
            ).fetchone()
            if cwe_row is not None:
                catalog_terms = _tokenize(
                    f"{cwe_row['name'] or ''} {cwe_row['description'] or ''}"
                )
            cve_count = self._conn.execute(
                "SELECT COUNT(DISTINCT cve_cwe.cve_id) FROM cve_cwe "
                "WHERE cve_cwe.cwe_id = ?",
                (cwe_id,),
            ).fetchone()[0] or 0
        except sqlite3.Error:
            catalog_terms = frozenset()
            cve_count = 0

        evidence = evidence_score(int(cve_count))
        weights = TEMPLATE_RANKING_WEIGHTS
        scored: List[ScoredTemplate] = []
        for row in rows:
            template_id = str(row["template_id"])
            template_cwe_id = str(row["cwe_id"])
            role = str(row["role"])
            api_shape = str(row["api_shape"])
            parameter_shape = json_loads(row["parameter_shape"])
            applicability_value = json_loads(row["applicability_json"])
            template_features = tuple(
                str(item)
                for item in json_loads(row["semantic_features_json"])
                if isinstance(item, (str, int, float))
            )
            template_version = str(row["template_version"])
            if parameter_shape is None or not isinstance(parameter_shape, (list, tuple)):
                parameter_shape = []
            relevance = relevance_score(
                cwe_id, template_cwe_id, template_features, catalog_terms
            )
            app_score = applicability_score(applicability_value, applicability)
            final_score = (
                weights["relevance"] * relevance
                + weights["applicability"] * app_score
                + weights["catalog_evidence"] * evidence
            )
            scored.append(
                (
                    template_id,
                    template_cwe_id,
                    role,
                    api_shape,
                    tuple(int(item) for item in parameter_shape),
                    applicability_value,
                    template_version,
                    final_score,
                    relevance,
                    app_score,
                    evidence,
                )
            )
        ranked = tuple(rank_templates(scored))
        result = TemplateRetrievalResult(
            cwe_id=cwe_id,
            query_identity=identity,
            ranking_profile_version=self.ranking_profile_version,
            retrieval_id=self._retrieval_id(identity, ranked),
            ranked=ranked,
        )
        self._persist_retrieval(result, applicability, context)
        self._retrieval_cache[identity] = result
        return result

    def _retrieval_id(
        self, query_identity: str, ranked: Tuple[RankedTemplate, ...]
    ) -> str:
        signature = "\0".join(
            f"{item.template_id}:{item.final_score!r}" for item in ranked
        )
        return "template-retrieval:" + sha256(
            (query_identity + "\n" + signature).encode("utf-8")
        ).hexdigest()

    def _empty_result(
        self, cwe_id: str, identity: str
    ) -> TemplateRetrievalResult:
        return TemplateRetrievalResult(
            cwe_id=cwe_id,
            query_identity=identity,
            ranking_profile_version=self.ranking_profile_version,
            retrieval_id=self._retrieval_id(identity, ()),
            ranked=(),
        )

    def _persist_retrieval(
        self,
        result: TemplateRetrievalResult,
        applicability: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> None:
        """Append the retrieval decision row when the schema is available."""
        if not self._ensure_available():
            return
        assert self._conn is not None
        try:
            has_table = self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'template_retrieval'"
            ).fetchone()
            if has_table is None:
                return
            self._conn.execute(
                """
                INSERT OR IGNORE INTO template_retrieval
                    (retrieval_id, cwe_id, query_identity,
                     ranking_profile_version, result_template_ids_json,
                     scores_json, provenance_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.retrieval_id,
                    result.cwe_id,
                    result.query_identity,
                    result.ranking_profile_version,
                    json_dumps(list(result.template_ids)),
                    json_dumps(list(result.scores)),
                    json_dumps(
                        {
                            "cwe_id": result.cwe_id,
                            "applicability": applicability,
                            "context": context,
                            "ranking_profile_version": result.ranking_profile_version,
                            "scope_cwe_ids": (
                                sorted(self.scope_cwe_ids)
                                if self.scope_cwe_ids
                                else None
                            ),
                            "retrieved_at": datetime.now(timezone.utc).isoformat(),
                        }
                    ),
                ),
            )
            self._conn.commit()
        except sqlite3.Error as error:
            logger.warning(f"模板检索记录持久化失败: {error}")


def json_dumps(value: Any) -> str:
    """Canonical JSON serialization used by template identities/provenance."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def json_loads(value: Any) -> Any:
    """Tolerant JSON decode for template shape columns."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except ValueError:
        return None
