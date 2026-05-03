"""混合检索器

实现基于 Embedding、BM25 和规则匹配的混合检索，作为 Hybrid RAG 的核心组件。
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from src.utils.logger import get_logger
from src.storage.vector_store import VectorStore
from src.storage.bm25_index import BM25Index
from src.storage.rule_matcher import RuleMatcher

logger = get_logger(__name__)


class HybridRetriever:
    """混合检索器

    整合 Embedding、BM25 和规则匹配的结果，实现多路召回。
    """

    def __init__(self, storage_path: Path, vector_store: VectorStore):
        """初始化混合检索器

        Args:
            storage_path: 存储路径
            vector_store: 向量存储实例
        """
        self.storage_path = storage_path
        self.vector_store = vector_store
        
        # 初始化 BM25 索引
        self.bm25_index = BM25Index(storage_path)
        
        # 初始化规则匹配引擎
        self.rule_matcher = RuleMatcher()
        
        # 默认权重
        self.weights = {
            "embedding": 0.5,
            "bm25": 0.3,
            "rule": 0.2
        }

    def add_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """添加文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        # 添加到 BM25 索引
        self.bm25_index.add_document(document_id, content, metadata)
        
        # 注意：向量存储的添加由调用方负责

    def add_documents(self, documents: List[Dict[str, Any]]) -> None:
        """批量添加文档

        Args:
            documents: 文档列表，每个文档包含 document_id, content, metadata
        """
        # 批量添加到 BM25 索引
        bm25_documents = []
        for doc in documents:
            bm25_documents.append({
                "document_id": doc["document_id"],
                "content": doc["content"],
                "metadata": doc["metadata"]
            })
        self.bm25_index.add_documents(bm25_documents)
        
        # 注意：向量存储的添加由调用方负责

    def update_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """更新文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        # 更新 BM25 索引
        self.bm25_index.update_document(document_id, content, metadata)
        
        # 注意：向量存储的更新由调用方负责

    def delete_document(self, document_id: str) -> None:
        """删除文档

        Args:
            document_id: 文档ID
        """
        # 从 BM25 索引中删除
        self.bm25_index.delete_document(document_id)
        
        # 注意：向量存储的删除由调用方负责

    def hybrid_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """混合搜索

        Args:
            query: 查询文本
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        # 1. Embedding 搜索
        embedding_results = self.vector_store.search(query, top_k * 3)
        
        # 2. BM25 搜索
        bm25_results = self.bm25_index.search(query, top_k * 3)
        
        # 3. 规则匹配
        rule_results = []
        # 对所有文档进行规则匹配
        all_documents = self.vector_store.get_all_documents()
        for doc in all_documents:
            matches = self.rule_matcher.match_document(
                doc["document_id"],
                doc["content"],
                doc["metadata"]
            )
            if matches:
                # 计算规则匹配得分
                rule_score = sum(match["score"] for match in matches)
                rule_results.append({
                    "document_id": doc["document_id"],
                    "content": doc["content"],
                    "metadata": doc["metadata"],
                    "rule_score": rule_score,
                    "matches": matches
                })
        
        # 4. 融合结果
        combined_results = self._fuse_results(
            embedding_results,
            bm25_results,
            rule_results
        )
        
        # 5. 排序并返回结果
        sorted_results = sorted(
            combined_results,
            key=lambda x: x["score"],
            reverse=True
        )[:top_k]
        
        return sorted_results

    def _fuse_results(self, embedding_results: List[Dict[str, Any]],
                      bm25_results: List[Dict[str, Any]],
                      rule_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """融合结果

        Args:
            embedding_results: Embedding 搜索结果
            bm25_results: BM25 搜索结果
            rule_results: 规则匹配结果

        Returns:
            融合后的结果列表
        """
        # 构建文档ID到结果的映射
        doc_map = {}
        
        # 处理 Embedding 结果
        for result in embedding_results:
            doc_id = result["document_id"]
            if doc_id not in doc_map:
                doc_map[doc_id] = {
                    "document_id": doc_id,
                    "content": result["content"],
                    "metadata": result["metadata"],
                    "embedding_score": result.get("similarity", 0.0),
                    "bm25_score": 0.0,
                    "rule_score": 0.0
                }
            else:
                doc_map[doc_id]["embedding_score"] = result.get("similarity", 0.0)
        
        # 处理 BM25 结果
        for result in bm25_results:
            doc_id = result["document_id"]
            if doc_id not in doc_map:
                doc_map[doc_id] = {
                    "document_id": doc_id,
                    "content": result["content"],
                    "metadata": result["metadata"],
                    "embedding_score": 0.0,
                    "bm25_score": result.get("score", 0.0),
                    "rule_score": 0.0
                }
            else:
                doc_map[doc_id]["bm25_score"] = result.get("score", 0.0)
        
        # 处理规则匹配结果
        for result in rule_results:
            doc_id = result["document_id"]
            if doc_id not in doc_map:
                doc_map[doc_id] = {
                    "document_id": doc_id,
                    "content": result["content"],
                    "metadata": result["metadata"],
                    "embedding_score": 0.0,
                    "bm25_score": 0.0,
                    "rule_score": result.get("rule_score", 0.0)
                }
            else:
                doc_map[doc_id]["rule_score"] = result.get("rule_score", 0.0)
        
        # 计算综合得分
        fused_results = []
        for doc_id, doc_info in doc_map.items():
            # 归一化得分
            embedding_score = doc_info["embedding_score"]
            bm25_score = doc_info["bm25_score"]
            rule_score = doc_info["rule_score"]
            
            # 计算综合得分
            total_score = (
                self.weights["embedding"] * embedding_score +
                self.weights["bm25"] * (bm25_score / max(bm25_score, 1e-10)) +
                self.weights["rule"] * (rule_score / max(rule_score, 1e-10))
            )
            
            doc_info["score"] = total_score
            fused_results.append(doc_info)
        
        return fused_results

    def set_weights(self, weights: Dict[str, float]) -> None:
        """设置权重

        Args:
            weights: 权重字典，包含 embedding, bm25, rule
        """
        self.weights.update(weights)

    def get_weights(self) -> Dict[str, float]:
        """获取权重

        Returns:
            权重字典
        """
        return self.weights

    def clear(self) -> None:
        """清空索引"""
        self.bm25_index.clear()

    def __len__(self) -> int:
        """获取文档数量

        Returns:
            文档数量
        """
        return len(self.bm25_index)
