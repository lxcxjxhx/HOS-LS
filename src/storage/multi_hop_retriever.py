"""多跳检索器

实现多步检索和推理功能，让 RAG 具备推理能力，能够处理复杂的查询。
"""

from typing import List, Dict, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class MultiHopRetriever:
    """多跳检索器

    实现多步检索和推理，基于初始查询的结果生成新的查询，然后再次检索，以获取更全面的信息。
    """

    def __init__(self, hybrid_retriever, reranker):
        """初始化多跳检索器

        Args:
            hybrid_retriever: 混合检索器实例
            reranker: 重排序器实例
        """
        self.hybrid_retriever = hybrid_retriever
        self.reranker = reranker

    def multi_hop_search(self, query: str, hops: int = 2, top_k: int = 5) -> List[Dict[str, Any]]:
        """多跳搜索

        Args:
            query: 初始查询
            hops: 跳数
            top_k: 每跳返回结果数量

        Returns:
            多跳检索结果
        """
        if hops < 1:
            return []
        
        results = []
        current_query = query
        
        for hop in range(hops):
            logger.info(f"执行第 {hop+1} 跳检索，查询: {current_query}")
            
            # 当前跳的检索
            hop_results = self.hybrid_retriever.hybrid_search(current_query, top_k * 2)
            results.extend(hop_results)
            
            # 生成下一跳的查询
            if hop < hops - 1:
                next_query = self._generate_next_query(current_query, hop_results)
                if not next_query:
                    break
                current_query = next_query
        
        # 去重和排序
        unique_results = self._deduplicate_results(results)
        reranked_results = self.reranker.rerank(query, unique_results)
        
        return reranked_results[:top_k]

    def _generate_next_query(self, current_query: str, hop_results: List[Dict[str, Any]]) -> str:
        """生成下一跳的查询

        Args:
            current_query: 当前查询
            hop_results: 当前跳的检索结果

        Returns:
            下一跳的查询
        """
        if not hop_results:
            return ""
        
        # 提取关键信息
        key_terms = []
        for result in hop_results[:3]:  # 只使用前3个结果
            content = result.get("content", "")
            # 提取关键词
            terms = self._extract_key_terms(content)
            key_terms.extend(terms)
        
        # 去重
        key_terms = list(set(key_terms))[:5]  # 只保留前5个关键词
        
        if not key_terms:
            return ""
        
        # 生成下一跳查询
        next_query = f"{current_query} 关于 {', '.join(key_terms)}"
        logger.info(f"生成下一跳查询: {next_query}")
        
        return next_query

    def _extract_key_terms(self, text: str) -> List[str]:
        """提取关键词

        Args:
            text: 文本

        Returns:
            关键词列表
        """
        # 简单的关键词提取
        import re
        
        # 提取可能的关键词
        terms = []
        
        # 提取漏洞类型
        vulnerability_patterns = [
            r"RCE", r"SQL injection", r"XSS", r"CSRF", r"Command injection",
            r"Buffer overflow", r"Authentication bypass", r"Authorization bypass",
            r"Injection", r"Denial of service", r"Information disclosure",
            r"Privilege escalation", r"Path traversal", r"File inclusion"
        ]
        
        for pattern in vulnerability_patterns:
            if pattern in text:
                terms.append(pattern)
        
        # 提取函数名
        function_pattern = r"def\s+(\w+)\s*\("
        matches = re.findall(function_pattern, text)
        terms.extend(matches)
        
        # 提取类名
        class_pattern = r"class\s+(\w+)\s*\("
        matches = re.findall(class_pattern, text)
        terms.extend(matches)
        
        # 提取变量名
        variable_pattern = r"\b(\w+)\s*=\s*"
        matches = re.findall(variable_pattern, text)
        # 过滤掉常见的变量名
        common_vars = ["self", "def", "class", "import", "from", "if", "else", "for", "while", "try", "except"]
        terms.extend([var for var in matches if var not in common_vars])
        
        return terms[:10]  # 只返回前10个关键词

    def _deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """去重结果

        Args:
            results: 结果列表

        Returns:
            去重后的结果列表
        """
        seen = set()
        unique_results = []
        
        for result in results:
            doc_id = result.get("document_id", "")
            if doc_id not in seen:
                seen.add(doc_id)
                unique_results.append(result)
        
        return unique_results

    def get_hop_stats(self, query: str, hops: int = 2, top_k: int = 5) -> Dict[str, Any]:
        """获取多跳检索统计信息

        Args:
            query: 初始查询
            hops: 跳数
            top_k: 每跳返回结果数量

        Returns:
            统计信息
        """
        results = self.multi_hop_search(query, hops, top_k)
        
        stats = {
            "initial_query": query,
            "hops": hops,
            "top_k": top_k,
            "total_results": len(results),
            "result_ids": [result.get("document_id", "") for result in results]
        }
        
        return stats
