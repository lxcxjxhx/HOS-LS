"""自适应检索器

实现根据查询复杂度和历史命中情况动态调整检索参数的功能，以提高检索效果。
"""

from typing import List, Dict, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AdaptiveRetriever:
    """自适应检索器

    根据查询复杂度和历史命中情况动态调整检索参数，以提高检索效果。
    """

    def __init__(self, hybrid_retriever, reranker, multi_hop_retriever):
        """初始化自适应检索器

        Args:
            hybrid_retriever: 混合检索器实例
            reranker: 重排序器实例
            multi_hop_retriever: 多跳检索器实例
        """
        self.hybrid_retriever = hybrid_retriever
        self.reranker = reranker
        self.multi_hop_retriever = multi_hop_retriever
        
        # 历史查询记录
        self.query_history = []
        
        # 默认参数
        self.default_params = {
            "simple": {"top_k": 5, "hops": 1},
            "medium": {"top_k": 10, "hops": 2},
            "complex": {"top_k": 20, "hops": 3}
        }

    def adaptive_search(self, query: str) -> List[Dict[str, Any]]:
        """自适应搜索

        Args:
            query: 查询文本

        Returns:
            搜索结果
        """
        # 分析查询复杂度
        complexity = self._analyze_query_complexity(query)
        logger.info(f"查询复杂度分析: {complexity}")
        
        # 根据复杂度获取初始参数
        params = self.default_params.get(complexity, self.default_params["medium"])
        top_k = params["top_k"]
        hops = params["hops"]
        
        # 执行多跳检索
        results = self.multi_hop_retriever.multi_hop_search(query, hops=hops, top_k=top_k)
        
        # 评估结果质量
        quality = self._evaluate_result_quality(results)
        logger.info(f"结果质量评估: {quality}")
        
        # 根据结果质量调整策略
        if quality < 0.5:
            logger.info("结果质量较低，扩大检索范围")
            # 扩大检索范围
            expanded_top_k = top_k * 2
            expanded_hops = min(hops + 1, 3)  # 最大跳数为3
            results = self.multi_hop_retriever.multi_hop_search(
                query, 
                hops=expanded_hops, 
                top_k=expanded_top_k
            )
        
        # 记录查询历史
        self._record_query_history(query, complexity, len(results), quality)
        
        return results

    def _analyze_query_complexity(self, query: str) -> str:
        """分析查询复杂度

        Args:
            query: 查询文本

        Returns:
            复杂度级别 (simple, medium, complex)
        """
        # 基于查询长度和关键词数量分析复杂度
        query_length = len(query)
        query_words = len(query.split())
        
        # 计算复杂度分数
        complexity_score = 0
        
        # 长度得分
        if query_length > 100:
            complexity_score += 3
        elif query_length > 50:
            complexity_score += 2
        else:
            complexity_score += 1
        
        # 关键词得分
        if query_words > 10:
            complexity_score += 3
        elif query_words > 5:
            complexity_score += 2
        else:
            complexity_score += 1
        
        # 特殊关键词得分
        complex_keywords = ["漏洞链", "攻击路径", "多步骤", "组合漏洞", "跨文件", "深度分析"]
        for keyword in complex_keywords:
            if keyword in query:
                complexity_score += 2
        
        # 确定复杂度级别
        if complexity_score >= 8:
            return "complex"
        elif complexity_score >= 5:
            return "medium"
        else:
            return "simple"

    def _evaluate_result_quality(self, results: List[Dict[str, Any]]) -> float:
        """评估结果质量

        Args:
            results: 检索结果

        Returns:
            质量分数 (0-1)
        """
        if not results:
            return 0.0
        
        # 计算质量分数
        quality_score = 0.0
        
        # 结果数量得分
        result_count = len(results)
        if result_count >= 5:
            quality_score += 0.3
        elif result_count >= 3:
            quality_score += 0.2
        else:
            quality_score += 0.1
        
        # 结果相关性得分（基于重排序得分）
        rerank_scores = [result.get("rerank_score", 0.0) for result in results]
        if rerank_scores:
            avg_score = sum(rerank_scores) / len(rerank_scores)
            # 归一化到 0-0.5
            quality_score += min(avg_score / 2.0, 0.5)
        
        # 结果多样性得分
        unique_ids = set()
        for result in results:
            unique_ids.add(result.get("document_id", ""))
        diversity_score = len(unique_ids) / len(results)
        quality_score += diversity_score * 0.2
        
        # 确保分数在 0-1 之间
        return min(quality_score, 1.0)

    def _record_query_history(self, query: str, complexity: str, result_count: int, quality: float) -> None:
        """记录查询历史

        Args:
            query: 查询文本
            complexity: 复杂度级别
            result_count: 结果数量
            quality: 质量分数
        """
        history_entry = {
            "query": query,
            "complexity": complexity,
            "result_count": result_count,
            "quality": quality,
            "timestamp": self._get_current_timestamp()
        }
        
        self.query_history.append(history_entry)
        
        # 只保留最近 100 条历史记录
        if len(self.query_history) > 100:
            self.query_history = self.query_history[-100:]

    def _get_current_timestamp(self) -> str:
        """获取当前时间戳

        Returns:
            时间戳字符串
        """
        from datetime import datetime
        return datetime.now().isoformat()

    def get_query_stats(self) -> Dict[str, Any]:
        """获取查询统计信息

        Returns:
            统计信息
        """
        if not self.query_history:
            return {
                "total_queries": 0,
                "avg_quality": 0.0,
                "complexity_distribution": {}
            }
        
        # 计算统计信息
        total_queries = len(self.query_history)
        avg_quality = sum(entry["quality"] for entry in self.query_history) / total_queries
        
        # 复杂度分布
        complexity_distribution = {"simple": 0, "medium": 0, "complex": 0}
        for entry in self.query_history:
            complexity = entry["complexity"]
            if complexity in complexity_distribution:
                complexity_distribution[complexity] += 1
        
        return {
            "total_queries": total_queries,
            "avg_quality": avg_quality,
            "complexity_distribution": complexity_distribution
        }

    def adjust_params(self, complexity: str, top_k: Optional[int] = None, hops: Optional[int] = None) -> None:
        """调整参数

        Args:
            complexity: 复杂度级别
            top_k: 新的 top_k 值
            hops: 新的 hops 值
        """
        if complexity in self.default_params:
            if top_k is not None:
                self.default_params[complexity]["top_k"] = top_k
            if hops is not None:
                self.default_params[complexity]["hops"] = hops
            logger.info(f"调整参数: {complexity} -> {self.default_params[complexity]}")

    def get_params(self, complexity: str) -> Dict[str, int]:
        """获取参数

        Args:
            complexity: 复杂度级别

        Returns:
            参数字典
        """
        return self.default_params.get(complexity, self.default_params["medium"])
