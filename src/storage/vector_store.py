"""向量存储模块

实现基于本地文件的向量存储，支持文档的嵌入和相似度搜索。
"""

import json
import numpy as np
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.utils.logger import get_logger
from src.storage.code_embedder import CodeEmbedder, EmbedConfig

logger = get_logger(__name__)


class VectorStore:
    """向量存储

    实现基于本地文件的向量存储，支持文档的嵌入和相似度搜索。
    """

    def __init__(self, storage_path: Path, model_name: Optional[str] = None):
        """初始化向量存储

        Args:
            storage_path: 存储路径
            model_name: 嵌入模型名称
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # 存储文件
        self.embeddings_path = self.storage_path / "embeddings.npy"
        self.documents_path = self.storage_path / "documents.json"
        self.embedding_cache_path = self.storage_path / "embedding_cache.json"
        
        # 内存存储
        self._embeddings: Optional[np.ndarray] = None
        self._documents: Dict[str, Dict] = {}
        self._document_ids: List[str] = []
        self._embedding_cache: Dict[str, List[float]] = {}  # 文本哈希到embedding的缓存
        
        # 初始化 CodeEmbedder
        config = EmbedConfig()
        if model_name:
            config.model_name = model_name
        self.embedder = CodeEmbedder(config)
        
        # 加载现有数据
        self.load()
        self._load_embedding_cache()

    def add_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """添加文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        # 生成嵌入
        embedding = self._generate_embedding(content)
        
        # 检查嵌入维度是否一致
        if self._embeddings is not None:
            existing_dim = self._embeddings.shape[1]
            new_dim = len(embedding)
            if existing_dim != new_dim:
                logger.warning(f"嵌入维度不匹配: 现有维度 {existing_dim}, 新维度 {new_dim}")
                logger.warning("清空现有嵌入数据以使用新维度")
                # 清空现有数据
                self._embeddings = None
                self._document_ids = []
                self._documents.clear()
        
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
    
    def add_documents(self, documents: List[Dict[str, Any]], build_index: bool = True) -> None:
        """批量添加文档

        Args:
            documents: 文档列表，每个文档包含 document_id, content, metadata
            build_index: 是否立即构建索引并保存
        """
        if not documents:
            return
        
        # 批量处理文档
        new_embeddings = []
        contents = []
        doc_info = []
        
        for doc in documents:
            document_id = doc["document_id"]
            content = doc["content"]
            metadata = doc["metadata"]
            
            contents.append(content)
            doc_info.append((document_id, content, metadata))
            
        # 使用批量嵌入
        if self.embedder.is_available() and contents:
            try:
                # 使用 CodeEmbedder 的批量嵌入功能
                batch_embeddings = self.embedder.embed_batch(contents)
                new_embeddings = [np.array(embedding) for embedding in batch_embeddings]
            except Exception as e:
                logger.error(f"批量嵌入失败: {e}")
                # 降级到单个嵌入
                new_embeddings = [self._generate_embedding(content) for content in contents]
        else:
            # 单个生成嵌入
            new_embeddings = [self._generate_embedding(content) for content in contents]
        
        # 检查嵌入维度是否一致
        if new_embeddings:
            embedding_dim = len(new_embeddings[0])
            
            # 检查现有嵌入维度是否匹配
            if self._embeddings is not None:
                existing_dim = self._embeddings.shape[1]
                if existing_dim != embedding_dim:
                    logger.warning(f"嵌入维度不匹配: 现有维度 {existing_dim}, 新维度 {embedding_dim}")
                    logger.warning("清空现有嵌入数据以使用新维度")
                    # 清空现有数据
                    self._embeddings = None
                    self._document_ids = []
                    self._documents.clear()
        
        # 更新文档信息
        for i, (document_id, content, metadata) in enumerate(doc_info):
            embedding = new_embeddings[i]
            self._documents[document_id] = {
                "content": content,
                "metadata": metadata,
                "embedding": embedding.tolist()
            }
            
            # 添加到文档ID列表（如果不存在）
            if document_id not in self._document_ids:
                self._document_ids.append(document_id)
        
        # 批量更新嵌入
        if self._embeddings is None:
            self._embeddings = np.array(new_embeddings)
        else:
            # 只添加新的嵌入，避免重复
            self._embeddings = np.vstack([self._embeddings, new_embeddings])
        
        # 条件性保存
        if build_index:
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

    def save(self, incremental: bool = False) -> None:
        """保存向量存储

        Args:
            incremental: 是否增量保存
        """
        # 保存嵌入
        if self._embeddings is not None:
            # 增量保存时，只保存新的嵌入
            if incremental and self.embeddings_path.exists():
                # 加载现有嵌入
                try:
                    existing_embeddings = np.load(self.embeddings_path)
                    # 只保存新增的嵌入
                    if len(self._embeddings) > len(existing_embeddings):
                        new_embeddings = self._embeddings[len(existing_embeddings):]
                        # 追加到现有文件
                        # 注意：numpy 不支持直接追加，这里使用临时文件
                        temp_path = self.embeddings_path.with_suffix(".tmp")
                        np.save(temp_path, new_embeddings)
                        # 合并文件
                        combined_embeddings = np.vstack([existing_embeddings, new_embeddings])
                        np.save(self.embeddings_path, combined_embeddings)
                        temp_path.unlink()
                except Exception as e:
                    logger.error(f"增量保存嵌入失败: {e}")
                    # 失败时回退到完整保存
                    np.save(self.embeddings_path, self._embeddings)
            else:
                np.save(self.embeddings_path, self._embeddings)
        
        # 保存文档
        if incremental and self.documents_path.exists():
            # 加载现有文档
            try:
                with open(self.documents_path, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
                # 更新文档数据
                existing_data["document_ids"] = self._document_ids
                existing_data["documents"].update(self._documents)
                # 保存更新后的数据
                with open(self.documents_path, "w", encoding="utf-8") as f:
                    json.dump(existing_data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"增量保存文档失败: {e}")
                # 失败时回退到完整保存
                documents_data = {
                    "document_ids": self._document_ids,
                    "documents": self._documents
                }
                with open(self.documents_path, "w", encoding="utf-8") as f:
                    json.dump(documents_data, f, indent=2, ensure_ascii=False)
        else:
            documents_data = {
                "document_ids": self._document_ids,
                "documents": self._documents
            }
            with open(self.documents_path, "w", encoding="utf-8") as f:
                json.dump(documents_data, f, indent=2, ensure_ascii=False)
        
        # 保存embedding缓存
        self._save_embedding_cache()

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

    def _load_embedding_cache(self):
        """加载embedding缓存"""
        try:
            if self.embedding_cache_path.exists():
                with open(self.embedding_cache_path, 'r', encoding='utf-8') as f:
                    self._embedding_cache = json.load(f)
                logger.info(f"加载了 {len(self._embedding_cache)} 个embedding缓存")
        except Exception as e:
            logger.error(f"加载embedding缓存失败: {e}")
            self._embedding_cache = {}

    def _save_embedding_cache(self):
        """保存embedding缓存"""
        try:
            with open(self.embedding_cache_path, 'w', encoding='utf-8') as f:
                json.dump(self._embedding_cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存embedding缓存失败: {e}")

    def _get_text_hash(self, text: str) -> str:
        """计算文本哈希

        Args:
            text: 文本

        Returns:
            文本哈希
        """
        return hashlib.sha256(text.encode()).hexdigest()

    def _generate_embedding(self, text: str) -> np.ndarray:
        """生成文本嵌入

        Args:
            text: 文本

        Returns:
            嵌入向量
        """
        # 计算文本哈希
        text_hash = self._get_text_hash(text)
        
        # 检查缓存
        if text_hash in self._embedding_cache:
            return np.array(self._embedding_cache[text_hash])
        
        # 使用 CodeEmbedder 生成嵌入
        if self.embedder.is_available():
            embedding = self.embedder.embed_code(text)
            embedding = np.array(embedding)
        else:
            # 降级方案：使用简单的哈希嵌入，生成512维向量
            hash_value = text_hash
            embedding = []
            
            # 生成512维向量，与模型一致
            for i in range(0, 512):
                if i < len(hash_value):
                    embedding.append(int(hash_value[i % len(hash_value)], 16) / 15.0)
                else:
                    embedding.append(0.0)
            
            embedding = np.array(embedding)
            norm = np.linalg.norm(embedding)
            if norm > 0:
                embedding = embedding / norm
        
        # 缓存结果
        self._embedding_cache[text_hash] = embedding.tolist()
        
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
