"""排序器模块

对搜索结果进行排序，支持多种排序策略。
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import math

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScoredItem:
    """带分数的项"""
    item: Any
    score: float
    metadata: Dict[str, Any]


class RankingStrategy:
    """排序策略枚举"""
    SEMANTIC = "semantic"
    KEYWORD = "keyword"
    RECENCY = "recency"
    COMPLEXITY = "complexity"
    HYBRID = "hybrid"


class Ranker:
    """结果排序器

    支持多种排序策略，对搜索结果进行综合排序。
    """

    def __init__(self):
        """初始化排序器"""
        self._score_functions: Dict[str, Callable] = {
            'semantic': self._semantic_score,
            'keyword': self._keyword_score,
            'recency': self._recency_score,
            'complexity': self._complexity_score,
            'hybrid': self._hybrid_score,
        }

    def rank(
        self,
        items: List[Any],
        scores: List[float],
        strategy: str = 'hybrid',
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """对结果进行排序

        Args:
            items: 结果列表
            scores: 分数列表
            strategy: 排序策略
            metadata: 额外元数据

        Returns:
            排序后的结果列表
        """
        if not items:
            return []

        metadata = metadata or {}

        scored_items = []
        for i, item in enumerate(items):
            base_score = scores[i] if i < len(scores) else 0.0

            score_fn = self._score_functions.get(strategy, self._hybrid_score)
            final_score = score_fn(item, base_score, metadata)

            scored_items.append(ScoredItem(
                item=item,
                score=final_score,
                metadata={'base_score': base_score}
            ))

        scored_items.sort(key=lambda x: x.score, reverse=True)

        return [item.item for item in scored_items]

    def rank_with_scores(
        self,
        items: List[Any],
        scores: List[float],
        strategy: str = 'hybrid',
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[ScoredItem]:
        """对结果进行排序，返回带分数的结果

        Args:
            items: 结果列表
            scores: 分数列表
            strategy: 排序策略
            metadata: 额外元数据

        Returns:
            排序后的带分数结果列表
        """
        if not items:
            return []

        metadata = metadata or {}

        scored_items = []
        for i, item in enumerate(items):
            base_score = scores[i] if i < len(scores) else 0.0

            score_fn = self._score_functions.get(strategy, self._hybrid_score)
            final_score = score_fn(item, base_score, metadata)

            scored_items.append(ScoredItem(
                item=item,
                score=final_score,
                metadata={'base_score': base_score, **metadata}
            ))

        scored_items.sort(key=lambda x: x.score, reverse=True)

        return scored_items

    def rerank(
        self,
        items: List[Any],
        query: str,
        initial_scores: List[float],
        strategy: str = 'hybrid'
    ) -> List[Any]:
        """对结果进行重排序

        Args:
            items: 结果列表
            query: 查询字符串
            initial_scores: 初始分数列表
            strategy: 排序策略

        Returns:
            重排序后的结果列表
        """
        query_terms = set(query.lower().split())

        metadata = {
            'query_terms': query_terms,
            'query': query
        }

        return self.rank(items, initial_scores, strategy, metadata)

    def _semantic_score(
        self,
        item: Any,
        base_score: float,
        metadata: Dict[str, Any]
    ) -> float:
        """语义相似度分数

        Args:
            item: 结果项
            base_score: 基础分数
            metadata: 元数据

        Returns:
            最终分数
        """
        return base_score

    def _keyword_score(
        self,
        item: Any,
        base_score: float,
        metadata: Dict[str, Any]
    ) -> float:
        """关键词匹配分数

        Args:
            item: 结果项
            base_score: 基础分数
            metadata: 元数据

        Returns:
            最终分数
        """
        query_terms = metadata.get('query_terms', set())

        if not query_terms:
            return base_score

        item_text = ""
        if hasattr(item, 'content'):
            item_text = item.content.lower()
        elif hasattr(item, 'text'):
            item_text = item.text.lower()
        elif isinstance(item, str):
            item_text = item.lower()
        elif isinstance(item, dict):
            item_text = str(item).lower()

        matches = sum(1 for term in query_terms if term in item_text)
        keyword_boost = matches / max(len(query_terms), 1)

        return base_score * 0.7 + keyword_boost * 0.3

    def _recency_score(
        self,
        item: Any,
        base_score: float,
        metadata: Dict[str, Any]
    ) -> float:
        """时效性分数

        Args:
            item: 结果项
            base_score: 基础分数
            metadata: 元数据

        Returns:
            最终分数
        """
        return base_score

    def _complexity_score(
        self,
        item: Any,
        base_score: float,
        metadata: Dict[str, Any]
    ) -> float:
        """复杂度分数

        Args:
            item: 结果项
            base_score: 基础分数
            metadata: 元数据

        Returns:
            最终分数
        """
        return base_score

    def _hybrid_score(
        self,
        item: Any,
        base_score: float,
        metadata: Dict[str, Any]
    ) -> float:
        """混合分数（综合多种因素）

        Args:
            item: 结果项
            base_score: 基础分数
            metadata: 元数据

        Returns:
            最终分数
        """
        semantic = self._semantic_score(item, base_score, metadata)
        keyword = self._keyword_score(item, base_score, metadata)

        weighted = semantic * 0.6 + keyword * 0.4

        if hasattr(item, 'metadata'):
            item_meta = item.metadata if hasattr(item, 'metadata') else {}
            if isinstance(item, dict):
                item_meta = item.get('metadata', {})

            vuln_count = item_meta.get('vuln_count', 0)
            if vuln_count > 0:
                vuln_boost = min(0.2, vuln_count * 0.05)
                weighted += vuln_boost

            is_changed = item_meta.get('is_changed', False)
            if is_changed:
                weighted += 0.1

        return weighted

    def diversity_rerank(
        self,
        items: List[Any],
        scores: List[float],
        max_per_group: int = 3
    ) -> List[Any]:
        """多样性重排序

        确保同一分组的结果不超过一定数量，增加结果多样性。

        Args:
            items: 结果列表
            scores: 分数列表
            max_per_group: 每组最大数量

        Returns:
            重排序后的结果列表
        """
        if not items:
            return []

        groups: Dict[str, List[ScoredItem]] = {}

        for i, item in enumerate(items):
            score = scores[i] if i < len(scores) else 0.0

            group_key = self._get_group_key(item)

            if group_key not in groups:
                groups[group_key] = []

            if len(groups[group_key]) < max_per_group:
                groups[group_key].append(ScoredItem(
                    item=item,
                    score=score,
                    metadata={}
                ))

        all_items = []
        for group_items in groups.values():
            all_items.extend(group_items)

        all_items.sort(key=lambda x: x.score, reverse=True)

        return [item.item for item in all_items]

    def _get_group_key(self, item: Any) -> str:
        """获取分组键

        Args:
            item: 结果项

        Returns:
            分组键
        """
        if hasattr(item, 'file_path'):
            return item.file_path

        if isinstance(item, dict):
            if 'file_path' in item:
                return item['file_path']
            if 'metadata' in item and isinstance(item['metadata'], dict):
                return item['metadata'].get('file_path', 'default')

        if hasattr(item, 'metadata') and isinstance(item.metadata, dict):
            return item.metadata.get('file_path', 'default')

        return 'default'

    def top_k(
        self,
        items: List[Any],
        scores: List[float],
        k: int,
        strategy: str = 'hybrid'
    ) -> List[Any]:
        """获取 Top-K 结果

        Args:
            items: 结果列表
            scores: 分数列表
            k: 返回数量
            strategy: 排序策略

        Returns:
            Top-K 结果列表
        """
        ranked = self.rank(items, scores, strategy)
        return ranked[:k]
