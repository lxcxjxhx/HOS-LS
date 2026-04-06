"""向量存储模块

实现基于本地文件的向量存储，支持文档的嵌入和相似度搜索。
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class VectorStore:
    """向量存储

    实现基于本地文件的向量存储，支持文档的嵌入和相似度搜索。
    """

    def __init__(self, storage_path: Path):
        """初始化向量存储

        Args:
            storage_path: 存储路径
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # 存储文件
        self.embeddings_path = self.storage_path / "embeddings.npy"
        self.documents_path = self.storage_path / "documents.json"
        
        # 内存存储
        self._embeddings: Optional[np.ndarray] = None
        self._documents: Dict[str, Dict] = {}
        self._document_ids: List[str] = []
        
        # 加载现有数据
        self.load()

    def add_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """添加文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        # 生成嵌入
        embedding = self._generate_embedding(content)
        
        # 添加到内存存储
        if document_id in self._documents:
            # 更新现有文档
            index = self._document_ids.index(document_id)
            self._embeddings[index] = embedding
        else:
            # 添加新文档
            self._document_ids.append(document_id)
            if self._embeddings is None:
                self._embeddings = np.array([embedding])
            else:
                self._embeddings = np.vstack([self._embeddings, embedding])
        
        # 更新文档信息
        self._documents[document_id] = {
            "content": content,
            "metadata": metadata,
            "embedding": embedding.tolist()
        }
        
        # 保存到文件
        self.save()

    def update_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """更新文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        self.add_document(document_id, content, metadata)

    def delete_document(self, document_id: str) -> None:
        """删除文档

        Args:
            document_id: 文档ID
        """
        if document_id in self._documents:
            # 移除文档
            index = self._document_ids.index(document_id)
            self._document_ids.pop(index)
            self._embeddings = np.delete(self._embeddings, index, axis=0)
            del self._documents[document_id]
            
            # 保存到文件
            self.save()

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """搜索文档

        Args:
            query: 查询文本
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        if self._embeddings is None or len(self._embeddings) == 0:
            return []
        
        # 生成查询嵌入
        query_embedding = self._generate_embedding(query)
        
        # 计算相似度
        similarities = self._calculate_similarity(query_embedding, self._embeddings)
        
        # 排序并返回结果
        sorted_indices = np.argsort(similarities)[::-1][:top_k]
        results = []
        
        for idx in sorted_indices:
            document_id = self._document_ids[idx]
            document = self._documents[document_id]
            results.append({
                "document_id": document_id,
                "content": document["content"],
                "metadata": document["metadata"],
                "similarity": float(similarities[idx])
            })
        
        return results

    def get_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        """获取文档

        Args:
            document_id: 文档ID

        Returns:
            文档信息
        """
        return self._documents.get(document_id)

    def get_all_documents(self) -> List[Dict[str, Any]]:
        """获取所有文档

        Returns:
            文档列表
        """
        return [{
            "document_id": doc_id,
            "content": doc["content"],
            "metadata": doc["metadata"]
        } for doc_id, doc in self._documents.items()]

    def clear(self) -> None:
        """清空向量存储"""
        self._embeddings = None
        self._documents.clear()
        self._document_ids.clear()
        self.save()

    def save(self) -> None:
        """保存向量存储"""
        # 保存嵌入
        if self._embeddings is not None:
            np.save(self.embeddings_path, self._embeddings)
        
        # 保存文档
        documents_data = {
            "document_ids": self._document_ids,
            "documents": self._documents
        }
        with open(self.documents_path, "w", encoding="utf-8") as f:
            json.dump(documents_data, f, indent=2, ensure_ascii=False)

    def load(self) -> None:
        """加载向量存储"""
        # 加载文档
        if self.documents_path.exists():
            try:
                with open(self.documents_path, "r", encoding="utf-8") as f:
                    documents_data = json.load(f)
                self._document_ids = documents_data.get("document_ids", [])
                self._documents = documents_data.get("documents", {})
            except Exception as e:
                logger.error(f"加载文档失败: {e}")
        
        # 加载嵌入
        if self.embeddings_path.exists():
            try:
                self._embeddings = np.load(self.embeddings_path)
            except Exception as e:
                logger.error(f"加载嵌入失败: {e}")

    def _generate_embedding(self, text: str) -> np.ndarray:
        """生成文本嵌入

        Args:
            text: 文本

        Returns:
            嵌入向量
        """
        # 使用简单的TF-IDF-like嵌入作为示例
        # 实际应用中应该使用更先进的嵌入模型
        words = text.lower().split()
        word_set = set(words)
        embedding = []
        
        # 使用前100个常见词作为特征
        common_words = [
            "the", "and", "of", "in", "a", "is", "that", "for", "on", "with",
            "as", "by", "at", "from", "to", "this", "are", "have", "be", "has",
            "it", "which", "or", "but", "an", "will", "not", "if", "can", "all",
            "were", "when", "there", "what", "so", "out", "up", "about", "into", "than",
            "then", "some", "like", "other", "how", "just", "more", "most", "time", "now",
            "no", "man", "one", "year", "people", "day", "way", "make", "help", "take",
            "see", "place", "work", "week", "system", "security", "vulnerability", "attack", "risk", "threat"
        ]
        
        for word in common_words:
            embedding.append(1.0 if word in word_set else 0.0)
        
        # 归一化
        embedding = np.array(embedding)
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        
        return embedding

    def _calculate_similarity(self, query_embedding: np.ndarray, embeddings: np.ndarray) -> np.ndarray:
        """计算相似度

        Args:
            query_embedding: 查询嵌入
            embeddings: 文档嵌入矩阵

        Returns:
            相似度数组
        """
        # 使用余弦相似度
        if len(embeddings) == 0:
            return np.array([])
        
        # 确保嵌入维度匹配
        if query_embedding.shape[0] != embeddings.shape[1]:
            return np.array([])
        
        # 计算余弦相似度
        dot_products = np.dot(embeddings, query_embedding)
        norms = np.linalg.norm(embeddings, axis=1)
        query_norm = np.linalg.norm(query_embedding)
        
        # 避免除零
        norms[norms == 0] = 1e-10
        query_norm = max(query_norm, 1e-10)
        
        similarities = dot_products / (norms * query_norm)
        return similarities

    def __len__(self) -> int:
        """获取文档数量

        Returns:
            文档数量
        """
        return len(self._document_ids)

    def __contains__(self, document_id: str) -> bool:
        """检查文档是否存在

        Args:
            document_id: 文档ID

        Returns:
            是否存在
        """
        return document_id in self._documents
