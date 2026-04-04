"""向量存储管理器模块

使用 ChromaDB 进行向量存储和检索，支持代码语义搜索和相似性分析。
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import chromadb
    from chromadb.config import Settings

    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


@dataclass
class CodeSnippet:
    """代码片段"""

    id: str
    code: str
    language: str
    file_path: str
    line_start: int
    line_end: int
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "code": self.code,
            "language": self.language,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "function_name": self.function_name,
            "class_name": self.class_name,
            "metadata": self.metadata,
        }


@dataclass
class SearchResult:
    """搜索结果"""

    id: str
    code: str
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "code": self.code,
            "score": self.score,
            "metadata": self.metadata,
        }


@dataclass
class VectorStoreConfig:
    """向量存储配置"""

    persist_directory: Optional[str] = None
    collection_name: str = "code_embeddings"
    embedding_dimension: int = 384
    distance_metric: str = "cosine"
    batch_size: int = 100
    max_results: int = 10


class VectorStore:
    """向量存储管理器

    使用 ChromaDB 进行向量存储和检索。
    """

    def __init__(
        self,
        config: Optional[VectorStoreConfig] = None,
        embedder: Optional[Any] = None,
    ):
        """初始化向量存储管理器

        Args:
            config: 向量存储配置
            embedder: 代码嵌入生成器
        """
        self.config = config or VectorStoreConfig()
        self.embedder = embedder

        self._client: Optional[Any] = None
        self._collection: Optional[Any] = None
        self._initialized = False

        if CHROMADB_AVAILABLE:
            self._initialize_chroma()

    def _initialize_chroma(self) -> None:
        """初始化 ChromaDB"""
        if not CHROMADB_AVAILABLE:
            return

        try:
            if self.config.persist_directory:
                settings = Settings(
                    persist_directory=self.config.persist_directory,
                    anonymized_telemetry=False,
                )
                self._client = chromadb.Client(settings)
            else:
                self._client = chromadb.Client()

            self._collection = self._client.get_or_create_collection(
                name=self.config.collection_name,
                metadata={"hnsw:space": self.config.distance_metric},
            )

            self._initialized = True
        except Exception:
            self._initialized = False

    def store_embeddings(
        self,
        code_snippets: List[CodeSnippet],
        embeddings: Optional[List[List[float]]] = None,
    ) -> int:
        """存储代码嵌入

        Args:
            code_snippets: 代码片段列表
            embeddings: 预计算的嵌入向量列表

        Returns:
            存储的嵌入数量
        """
        if not self._initialized or not self._collection:
            return 0

        if not code_snippets:
            return 0

        ids: List[str] = []
        documents: List[str] = []
        metadatas: List[Dict[str, Any]] = []
        embeddings_list: Optional[List[List[float]]] = embeddings

        for snippet in code_snippets:
            ids.append(snippet.id)
            documents.append(snippet.code)
            metadatas.append({
                "language": snippet.language,
                "file_path": snippet.file_path,
                "line_start": snippet.line_start,
                "line_end": snippet.line_end,
                "function_name": snippet.function_name or "",
                "class_name": snippet.class_name or "",
            })

        if embeddings_list is None and self.embedder:
            embeddings_list = self.embedder.embed_batch(documents)

        try:
            if embeddings_list:
                self._collection.add(
                    ids=ids,
                    documents=documents,
                    metadatas=metadatas,
                    embeddings=embeddings_list,
                )
            else:
                self._collection.add(
                    ids=ids,
                    documents=documents,
                    metadatas=metadatas,
                )

            return len(ids)
        except Exception:
            return 0

    def search_similar(
        self,
        query: str,
        n_results: Optional[int] = None,
        where: Optional[Dict[str, Any]] = None,
        query_embedding: Optional[List[float]] = None,
    ) -> List[SearchResult]:
        """搜索相似代码

        Args:
            query: 查询文本
            n_results: 返回结果数量
            where: 元数据过滤条件
            query_embedding: 查询嵌入向量

        Returns:
            搜索结果列表
        """
        if not self._initialized or not self._collection:
            return []

        n = n_results or self.config.max_results

        try:
            if query_embedding:
                results = self._collection.query(
                    query_embeddings=[query_embedding],
                    n_results=n,
                    where=where,
                )
            else:
                results = self._collection.query(
                    query_texts=[query],
                    n_results=n,
                    where=where,
                )

            search_results: List[SearchResult] = []

            if results and results.get("ids"):
                ids = results["ids"][0] if results["ids"] else []
                documents = results.get("documents", [[]])[0]
                distances = results.get("distances", [[]])[0]
                metadatas = results.get("metadatas", [[]])[0]

                for i, id_ in enumerate(ids):
                    score = 1.0 - distances[i] if distances else 0.0
                    metadata = metadatas[i] if metadatas else {}

                    search_results.append(
                        SearchResult(
                            id=id_,
                            code=documents[i] if documents else "",
                            score=score,
                            metadata=metadata,
                        )
                    )

            return search_results

        except Exception:
            return []

    def search_by_embedding(
        self,
        embedding: List[float],
        n_results: Optional[int] = None,
        where: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        """通过嵌入向量搜索

        Args:
            embedding: 嵌入向量
            n_results: 返回结果数量
            where: 元数据过滤条件

        Returns:
            搜索结果列表
        """
        return self.search_similar(
            query="",
            n_results=n_results,
            where=where,
            query_embedding=embedding,
        )

    def delete_embeddings(self, ids: List[str]) -> bool:
        """删除嵌入

        Args:
            ids: 要删除的嵌入ID列表

        Returns:
            是否成功
        """
        if not self._initialized or not self._collection:
            return False

        try:
            self._collection.delete(ids=ids)
            return True
        except Exception:
            return False

    def delete_by_metadata(self, where: Dict[str, Any]) -> bool:
        """通过元数据删除嵌入

        Args:
            where: 元数据过滤条件

        Returns:
            是否成功
        """
        if not self._initialized or not self._collection:
            return False

        try:
            self._collection.delete(where=where)
            return True
        except Exception:
            return False

    def get_embedding(self, id: str) -> Optional[Dict[str, Any]]:
        """获取嵌入

        Args:
            id: 嵌入ID

        Returns:
            嵌入信息
        """
        if not self._initialized or not self._collection:
            return None

        try:
            results = self._collection.get(ids=[id])

            if results and results.get("ids"):
                return {
                    "id": results["ids"][0],
                    "document": results["documents"][0] if results.get("documents") else "",
                    "metadata": results["metadatas"][0] if results.get("metadatas") else {},
                    "embedding": results["embeddings"][0] if results.get("embeddings") else None,
                }

            return None
        except Exception:
            return None

    def count(self) -> int:
        """获取嵌入数量

        Returns:
            嵌入数量
        """
        if not self._initialized or not self._collection:
            return 0

        try:
            return self._collection.count()
        except Exception:
            return 0

    def clear(self) -> bool:
        """清空所有嵌入

        Returns:
            是否成功
        """
        if not self._initialized or not self._collection:
            return False

        try:
            self._client.delete_collection(self.config.collection_name)
            self._collection = self._client.get_or_create_collection(
                name=self.config.collection_name,
                metadata={"hnsw:space": self.config.distance_metric},
            )
            return True
        except Exception:
            return False

    def update_embedding(
        self,
        id: str,
        code: str,
        metadata: Optional[Dict[str, Any]] = None,
        embedding: Optional[List[float]] = None,
    ) -> bool:
        """更新嵌入

        Args:
            id: 嵌入ID
            code: 代码内容
            metadata: 元数据
            embedding: 嵌入向量

        Returns:
            是否成功
        """
        if not self._initialized or not self._collection:
            return False

        try:
            embeddings_list = [embedding] if embedding else None

            if embeddings_list is None and self.embedder:
                embeddings_list = [self.embedder.embed_code(code)]

            self._collection.update(
                ids=[id],
                documents=[code],
                metadatas=[metadata] if metadata else None,
                embeddings=embeddings_list,
            )

            return True
        except Exception:
            return False

    def batch_search(
        self,
        queries: List[str],
        n_results: Optional[int] = None,
    ) -> List[List[SearchResult]]:
        """批量搜索

        Args:
            queries: 查询文本列表
            n_results: 每个查询返回的结果数量

        Returns:
            搜索结果列表的列表
        """
        if not self._initialized or not self._collection:
            return [[] for _ in queries]

        n = n_results or self.config.max_results

        try:
            results = self._collection.query(
                query_texts=queries,
                n_results=n,
            )

            all_results: List[List[SearchResult]] = []

            if results and results.get("ids"):
                for i, ids in enumerate(results["ids"]):
                    query_results: List[SearchResult] = []
                    documents = results.get("documents", [[]])[i]
                    distances = results.get("distances", [[]])[i]
                    metadatas = results.get("metadatas", [[]])[i]

                    for j, id_ in enumerate(ids):
                        score = 1.0 - distances[j] if distances else 0.0
                        metadata = metadatas[j] if metadatas else {}

                        query_results.append(
                            SearchResult(
                                id=id_,
                                code=documents[j] if documents else "",
                                score=score,
                                metadata=metadata,
                            )
                        )

                    all_results.append(query_results)

            return all_results

        except Exception:
            return [[] for _ in queries]

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息字典
        """
        if not self._initialized:
            return {
                "initialized": False,
                "count": 0,
                "collection_name": self.config.collection_name,
            }

        return {
            "initialized": True,
            "count": self.count(),
            "collection_name": self.config.collection_name,
            "embedding_dimension": self.config.embedding_dimension,
            "distance_metric": self.config.distance_metric,
        }

    def is_available(self) -> bool:
        """检查是否可用

        Returns:
            是否可用
        """
        return self._initialized and CHROMADB_AVAILABLE


class InMemoryVectorStore:
    """内存向量存储

    不依赖 ChromaDB 的简单内存向量存储实现。
    """

    def __init__(
        self,
        config: Optional[VectorStoreConfig] = None,
        embedder: Optional[Any] = None,
    ):
        """初始化内存向量存储

        Args:
            config: 向量存储配置
            embedder: 代码嵌入生成器
        """
        self.config = config or VectorStoreConfig()
        self.embedder = embedder

        self._store: Dict[str, Dict[str, Any]] = {}
        self._embeddings: Dict[str, List[float]] = {}

    def store_embeddings(
        self,
        code_snippets: List[CodeSnippet],
        embeddings: Optional[List[List[float]]] = None,
    ) -> int:
        """存储代码嵌入

        Args:
            code_snippets: 代码片段列表
            embeddings: 预计算的嵌入向量列表

        Returns:
            存储的嵌入数量
        """
        if not code_snippets:
            return 0

        embeddings_list = embeddings

        if embeddings_list is None and self.embedder:
            codes = [s.code for s in code_snippets]
            embeddings_list = self.embedder.embed_batch(codes)

        count = 0
        for i, snippet in enumerate(code_snippets):
            self._store[snippet.id] = {
                "code": snippet.code,
                "metadata": {
                    "language": snippet.language,
                    "file_path": snippet.file_path,
                    "line_start": snippet.line_start,
                    "line_end": snippet.line_end,
                    "function_name": snippet.function_name,
                    "class_name": snippet.class_name,
                },
            }

            if embeddings_list and i < len(embeddings_list):
                self._embeddings[snippet.id] = embeddings_list[i]

            count += 1

        return count

    def search_similar(
        self,
        query: str,
        n_results: Optional[int] = None,
        where: Optional[Dict[str, Any]] = None,
        query_embedding: Optional[List[float]] = None,
    ) -> List[SearchResult]:
        """搜索相似代码

        Args:
            query: 查询文本
            n_results: 返回结果数量
            where: 元数据过滤条件
            query_embedding: 查询嵌入向量

        Returns:
            搜索结果列表
        """
        n = n_results or self.config.max_results

        if not self._store:
            return []

        query_emb = query_embedding
        if query_emb is None and self.embedder:
            query_emb = self.embedder.embed_code(query)

        results: List[SearchResult] = []

        for id_, data in self._store.items():
            metadata = data["metadata"]

            if where:
                match = all(
                    metadata.get(k) == v or (isinstance(v, list) and metadata.get(k) in v)
                    for k, v in where.items()
                )
                if not match:
                    continue

            score = 0.0

            if query_emb and id_ in self._embeddings:
                score = self._cosine_similarity(query_emb, self._embeddings[id_])
            else:
                query_lower = query.lower()
                code_lower = data["code"].lower()
                if query_lower in code_lower:
                    score = 0.5 + 0.5 * (code_lower.count(query_lower) / max(len(code_lower), 1))

            results.append(
                SearchResult(
                    id=id_,
                    code=data["code"],
                    score=score,
                    metadata=metadata,
                )
            )

        results.sort(key=lambda x: x.score, reverse=True)

        return results[:n]

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        """计算余弦相似度

        Args:
            a: 向量a
            b: 向量b

        Returns:
            余弦相似度
        """
        if not NUMPY_AVAILABLE:
            if len(a) != len(b):
                return 0.0

            dot_product = sum(x * y for x, y in zip(a, b))
            norm_a = sum(x * x for x in a) ** 0.5
            norm_b = sum(x * x for x in b) ** 0.5

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return dot_product / (norm_a * norm_b)

        a_arr = np.array(a)
        b_arr = np.array(b)

        dot_product = np.dot(a_arr, b_arr)
        norm_a = np.linalg.norm(a_arr)
        norm_b = np.linalg.norm(b_arr)

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return float(dot_product / (norm_a * norm_b))

    def delete_embeddings(self, ids: List[str]) -> bool:
        """删除嵌入

        Args:
            ids: 要删除的嵌入ID列表

        Returns:
            是否成功
        """
        for id_ in ids:
            self._store.pop(id_, None)
            self._embeddings.pop(id_, None)

        return True

    def count(self) -> int:
        """获取嵌入数量

        Returns:
            嵌入数量
        """
        return len(self._store)

    def clear(self) -> bool:
        """清空所有嵌入

        Returns:
            是否成功
        """
        self._store.clear()
        self._embeddings.clear()
        return True

    def is_available(self) -> bool:
        """检查是否可用

        Returns:
            是否可用
        """
        return True


def create_vector_store(
    config: Optional[VectorStoreConfig] = None,
    embedder: Optional[Any] = None,
    prefer_memory: bool = False,
) -> Union[VectorStore, InMemoryVectorStore]:
    """创建向量存储

    Args:
        config: 向量存储配置
        embedder: 代码嵌入生成器
        prefer_memory: 是否优先使用内存存储

    Returns:
        向量存储实例
    """
    if prefer_memory or not CHROMADB_AVAILABLE:
        return InMemoryVectorStore(config, embedder)

    return VectorStore(config, embedder)
