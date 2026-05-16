"""混合检索查询层

实现结构化搜索和语义搜索的融合，提供更准确的CVE检索能力。
"""

from typing import Dict, List, Optional, Any

from src.utils.logger import get_logger
try:
    from src.storage.hybrid_store import HybridStore
except ImportError:
    from src.ai.pure_ai.rag.hybrid_store import HybridStore

logger = get_logger(__name__)


class HybridRetriever:
    """混合检索器"""

    def __init__(self, hybrid_store: HybridStore):
        """初始化混合检索器

        Args:
            hybrid_store: 混合存储实例
        """
        self.hybrid_store = hybrid_store

    def search(self, query: str, filters: Optional[Dict[str, Any]] = None, top_k: int = 10) -> List[Dict[str, Any]]:
        """执行混合搜索

        Args:
            query: 搜索查询
            filters: 过滤条件
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        try:
            # 执行混合搜索
            results = self.hybrid_store.hybrid_search(query, filters, top_k)
            return results
        except Exception as e:
            logger.error(f"混合搜索失败: {e}")
            return []

    def search_structured(self, filters: Dict[str, Any], limit: int = 100) -> List[Any]:
        """执行结构化搜索

        Args:
            filters: 过滤条件
            limit: 返回结果数量

        Returns:
            搜索结果列表
        """
        try:
            results = self.hybrid_store.search_cves(filters, limit)
            return results
        except Exception as e:
            logger.error(f"结构化搜索失败: {e}")
            return []

    def search_semantic(self, query: str, filters: Optional[Dict[str, Any]] = None, top_k: int = 10) -> List[Dict[str, Any]]:
        """执行语义搜索

        Args:
            query: 搜索查询
            filters: 过滤条件
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        try:
            results = self.hybrid_store.search_semantic(query, filters, top_k)
            return results
        except Exception as e:
            logger.error(f"语义搜索失败: {e}")
            return []

    def get_cve(self, cve_id: str) -> Optional[Any]:
        """获取单个CVE

        Args:
            cve_id: CVE ID

        Returns:
            CVE对象或None
        """
        try:
            return self.hybrid_store.get_cve(cve_id)
        except Exception as e:
            logger.error(f"获取CVE失败: {e}")
            return None

    def search_by_cwe(self, cwe: str, limit: int = 100) -> List[Any]:
        """按CWE搜索CVE

        Args:
            cwe: CWE ID
            limit: 返回结果数量

        Returns:
            CVE列表
        """
        filters = {'cwe': cwe}
        return self.search_structured(filters, limit)

    def search_by_severity(self, min_score: float, max_score: float, limit: int = 100) -> List[Any]:
        """按严重程度搜索CVE

        Args:
            min_score: 最小CVSS分数
            max_score: 最大CVSS分数
            limit: 返回结果数量

        Returns:
            CVE列表
        """
        filters = {'min_score': min_score, 'max_score': max_score}
        return self.search_structured(filters, limit)

    def search_by_date(self, start_date, end_date, limit: int = 100) -> List[Any]:
        """按日期搜索CVE

        Args:
            start_date: 开始日期
            end_date: 结束日期
            limit: 返回结果数量

        Returns:
            CVE列表
        """
        filters = {'start_date': start_date, 'end_date': end_date}
        return self.search_structured(filters, limit)

    def search_by_tags(self, tags: List[str], limit: int = 100) -> List[Any]:
        """按标签搜索CVE

        Args:
            tags: 标签列表
            limit: 返回结果数量

        Returns:
            CVE列表
        """
        filters = {'tags': tags}
        return self.search_structured(filters, limit)

    def search_attack_vectors(self, attack_vector: str, limit: int = 100) -> List[Any]:
        """按攻击向量搜索CVE

        Args:
            attack_vector: 攻击向量
            limit: 返回结果数量

        Returns:
            CVE列表
        """
        filters = {'tags': [attack_vector.lower()]}
        return self.search_structured(filters, limit)

    def get_statistics(self) -> Dict[str, Any]:
        """获取检索统计信息

        Returns:
            统计信息
        """
        try:
            return {
                'cve_count': self.hybrid_store.get_cve_count(),
                'vector_count': self.hybrid_store.get_vector_count()
            }
        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
            return {'cve_count': 0, 'vector_count': 0}


def create_hybrid_retriever(hybrid_store: HybridStore) -> HybridRetriever:
    """创建混合检索器

    Args:
        hybrid_store: 混合存储实例

    Returns:
        混合检索器实例
    """
    return HybridRetriever(hybrid_store)