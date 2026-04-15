"""GraphRAG 适配器

将 GraphRAG 功能集成到现有的 RAG 系统中。
"""

from typing import Dict, List, Optional, Any

from src.graphrag.graph_builder import GraphBuilder
from src.graphrag.graph_store import GraphStore
from src.graphrag.graph_retriever import GraphRetriever
from src.analyzers.base import AnalysisContext
from src.learning.self_learning import Knowledge, KnowledgeType
from src.storage.rag_knowledge_base import RAGKnowledgeBase


class GraphRAGAdapter:
    """GraphRAG 适配器

    将 GraphRAG 功能集成到现有的 RAG 系统中。
    """

    def __init__(self, rag_knowledge_base: Optional[RAGKnowledgeBase] = None):
        """初始化 GraphRAG 适配器

        Args:
            rag_knowledge_base: 现有的 RAG 知识库实例
        """
        self._rag_knowledge_base = rag_knowledge_base or RAGKnowledgeBase()
        self._graph_builder = GraphBuilder()
        self._graph_store = GraphStore()
        self._graph_retriever = GraphRetriever()

    def build_graph_from_code(self, context: AnalysisContext) -> None:
        """从代码构建图谱

        Args:
            context: 分析上下文
        """
        # 构建图谱
        self._graph_builder.build_from_ast(context)
        self._graph_builder.build_from_taint(context)

        # 存储图谱
        nodes = self._graph_builder.get_nodes()
        edges = self._graph_builder.get_edges()
        self._graph_store.store_graph(nodes, edges)

    def build_graph_from_knowledge(self) -> None:
        """从知识库构建图谱"""
        # 获取所有知识
        knowledge_list = self._rag_knowledge_base.get_all_knowledge()
        
        # 构建图谱
        for knowledge in knowledge_list:
            # 创建分析上下文
            context = AnalysisContext(
                file_path=f"knowledge_{knowledge.id}.py",
                file_content=knowledge.content,
                language="python"
            )
            # 构建图谱
            self._graph_builder.build_from_ast(context)

        # 存储图谱
        nodes = self._graph_builder.get_nodes()
        edges = self._graph_builder.get_edges()
        self._graph_store.store_graph(nodes, edges)

    def hybrid_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """混合搜索

        Args:
            query: 查询文本
            top_k: 返回结果数量

        Returns:
            搜索结果
        """
        # 使用 GraphRAG 进行检索
        graph_results = self._graph_retriever.hybrid_retrieve(query, top_k)

        # 使用传统 RAG 进行检索
        rag_results = self._rag_knowledge_base.get_standardized_output(query, top_k)

        # 合并结果
        combined_results = []
        
        # 添加 GraphRAG 结果
        for result in graph_results:
            combined_results.append({
                "type": "graphrag",
                "content": result.get("content", ""),
                "score": result.get("score", 0.0),
                "source": "GraphRAG"
            })

        # 添加传统 RAG 结果
        for result in rag_results:
            combined_results.append({
                "type": "rag",
                "content": result.get("pattern", ""),
                "score": result.get("confidence", 0.0),
                "source": "RAG"
            })

        # 按分数排序
        combined_results.sort(key=lambda x: x.get("score", 0.0), reverse=True)

        return combined_results[:top_k]

    def find_attack_chains(self, sink_types: List[str] = None) -> List[Dict[str, Any]]:
        """查找攻击链

        Args:
            sink_types: 危险点类型列表

        Returns:
            攻击链列表
        """
        return self._graph_retriever.find_attack_chains(sink_types)

    def get_vulnerability_context(self, vulnerability_id: str) -> Dict[str, Any]:
        """获取漏洞上下文

        Args:
            vulnerability_id: 漏洞 ID

        Returns:
            漏洞上下文
        """
        return self._graph_retriever.get_vulnerability_context(vulnerability_id)

    def get_graph_statistics(self) -> Dict[str, Any]:
        """获取图谱统计信息

        Returns:
            统计信息
        """
        return self._graph_store.get_graph_statistics()

    def clear_graph(self) -> None:
        """清空图谱"""
        self._graph_store.clear_graph()
        self._graph_builder.clear()

    def close(self) -> None:
        """关闭连接"""
        self._graph_store.close()
        self._graph_retriever.close()


# 全局 GraphRAG 适配器实例
_graphrag_adapter: Optional[GraphRAGAdapter] = None


def get_graphrag_adapter(rag_knowledge_base: Optional[RAGKnowledgeBase] = None) -> GraphRAGAdapter:
    """获取全局 GraphRAG 适配器实例

    Args:
        rag_knowledge_base: 现有的 RAG 知识库实例

    Returns:
        GraphRAG 适配器实例
    """
    global _graphrag_adapter
    if _graphrag_adapter is None:
        _graphrag_adapter = GraphRAGAdapter(rag_knowledge_base)
    return _graphrag_adapter
