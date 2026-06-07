"""BM25 索引模块

实现基于 BM25 的关键词搜索，作为 Hybrid RAG 的一部分。
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


try:
    from rank_bm25 import BM25Okapi
except ImportError:
    logger.warning("rank-bm25 not installed, using fallback implementation")
    
    class BM25Okapi:
        """BM25 回退实现"""
        def __init__(self, corpus):
            self.corpus = corpus
            self.documents = []
            for doc in corpus:
                self.documents.append(doc.split())
        
        def get_scores(self, query):
            query_tokens = query.split()
            scores = []
            for doc in self.documents:
                score = 0
                for token in query_tokens:
                    if token in doc:
                        score += 1
                scores.append(score)
            return scores


class BM25Index:
    """BM25 索引

    实现基于 BM25 的关键词搜索，支持文档的添加、更新和搜索。
    """

    def __init__(self, storage_path: Optional[Path] = None):
        """初始化 BM25 索引

        Args:
            storage_path: 存储路径
        """
        self.storage_path = storage_path
        if storage_path:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            self.index_path = storage_path / "bm25_index.json"
        else:
            self.index_path = None
        
        # 内存存储
        self._documents: Dict[str, Dict] = {}
        self._document_ids: List[str] = []
        self._corpus: List[str] = []
        self._bm25 = None
        
        # 加载现有数据
        self.load()
        self._build_index()

    def add_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """添加文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        # 添加到内存存储
        if document_id in self._documents:
            # 更新现有文档
            index = self._document_ids.index(document_id)
            self._corpus[index] = content
        else:
            # 添加新文档
            self._document_ids.append(document_id)
            self._corpus.append(content)
        
        # 更新文档信息
        self._documents[document_id] = {
            "content": content,
            "metadata": metadata
        }
        
        # 重建索引
        self._build_index()
        
        # 保存到文件
        self.save()

    def add_documents(self, documents: List[Dict[str, Any]]) -> None:
        """批量添加文档

        Args:
            documents: 文档列表，每个文档包含 document_id, content, metadata
        """
        if not documents:
            return
        
        # 添加文档
        for doc in documents:
            document_id = doc["document_id"]
            content = doc["content"]
            metadata = doc["metadata"]
            
            if document_id in self._documents:
                # 更新现有文档
                index = self._document_ids.index(document_id)
                self._corpus[index] = content
            else:
                # 添加新文档
                self._document_ids.append(document_id)
                self._corpus.append(content)
            
            # 更新文档信息
            self._documents[document_id] = {
                "content": content,
                "metadata": metadata
            }
        
        # 重建索引
        self._build_index()
        
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
            self._corpus.pop(index)
            del self._documents[document_id]
            
            # 重建索引
            self._build_index()
            
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
        if not self._bm25 or not self._corpus:
            return []
        
        # 计算得分
        scores = self._bm25.get_scores(query.split())
        
        # 排序并返回结果
        sorted_indices = sorted(
            range(len(scores)),
            key=lambda i: scores[i],
            reverse=True
        )[:top_k]
        
        results = []
        for idx in sorted_indices:
            if scores[idx] > 0:
                document_id = self._document_ids[idx]
                document = self._documents[document_id]
                results.append({
                    "document_id": document_id,
                    "content": document["content"],
                    "metadata": document["metadata"],
                    "score": float(scores[idx])
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
        """清空索引"""
        self._documents.clear()
        self._document_ids.clear()
        self._corpus.clear()
        self._bm25 = None
        self.save()

    def save(self) -> None:
        """保存索引"""
        if not self.index_path:
            return
        
        try:
            data = {
                "document_ids": self._document_ids,
                "corpus": self._corpus,
                "documents": self._documents
            }
            with open(self.index_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存 BM25 索引失败: {e}")

    def load(self) -> None:
        """加载索引"""
        if not self.index_path or not self.index_path.exists():
            return
        
        try:
            with open(self.index_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._document_ids = data.get("document_ids", [])
            self._corpus = data.get("corpus", [])
            self._documents = data.get("documents", {})
        except Exception as e:
            logger.error(f"加载 BM25 索引失败: {e}")

    def _build_index(self) -> None:
        """构建 BM25 索引"""
        if not self._corpus:
            self._bm25 = None
            return
        
        try:
            # 分词
            tokenized_corpus = [doc.split() for doc in self._corpus]
            self._bm25 = BM25Okapi(tokenized_corpus)
        except Exception as e:
            logger.error(f"构建 BM25 索引失败: {e}")
            self._bm25 = None

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
