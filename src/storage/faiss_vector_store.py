"""FAISS 向量存储模块

实现基于 FAISS 的向量存储，支持 GPU 加速的相似度搜索。
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.storage.code_embedder import CodeEmbedder, EmbedConfig
from src.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import faiss
    FAISS_AVAILABLE = True
    
    # 检查是否支持 GPU
    try:
        import faiss
        res = faiss.StandardGpuResources()
        GPU_AVAILABLE = True
    except Exception:
        GPU_AVAILABLE = False
except ImportError:
    FAISS_AVAILABLE = False
    GPU_AVAILABLE = False


class FAISSVectorStore:
    """FAISS 向量存储

    实现基于 FAISS 的向量存储，支持 GPU 加速的相似度搜索。
    """

    def __init__(self, storage_path: Path, embed_config: Optional[EmbedConfig] = None):
        """初始化 FAISS 向量存储

        Args:
            storage_path: 存储路径
            embed_config: 嵌入配置
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # 存储文件
        self.index_path = self.storage_path / "faiss_index.bin"
        self.documents_path = self.storage_path / "documents.json"
        
        # 内存存储
        self._index = None
        self._documents: Dict[str, Dict] = {}
        self._document_ids: List[str] = []
        self._embedder = CodeEmbedder(embed_config or EmbedConfig())
        self._embedding_dim = self._embedder.get_embedding_dimension()
        
        # 加载现有数据
        self.load()

    def add_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """添加文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        if not FAISS_AVAILABLE:
            logger.warning("FAISS not available, skipping document addition")
            return
        
        # 生成嵌入
        embedding = self._embedder.embed_code(content)
        embedding_np = np.array(embedding, dtype=np.float32)
        
        # 添加到内存存储
        if document_id in self._documents:
            # 更新现有文档
            index = self._document_ids.index(document_id)
            # FAISS 不支持直接更新，需要重建索引
            self._rebuild_index()
        else:
            # 添加新文档
            self._document_ids.append(document_id)
            if self._index is None:
                # 创建索引
                self._create_index()
            # 添加到索引
            self._index.add(np.array([embedding_np]))
        
        # 更新文档信息
        self._documents[document_id] = {
            "content": content,
            "metadata": metadata,
            "embedding": embedding
        }
        
        # 保存到文件
        self.save()
    
    def add_documents(self, documents: List[Dict[str, Any]], build_index: bool = True) -> None:
        """批量添加文档

        Args:
            documents: 文档列表，每个文档包含 document_id, content, metadata
            build_index: 是否立即构建索引并保存
        """
        if not FAISS_AVAILABLE or not documents:
            return
        
        # 批量处理文档
        new_embeddings = []
        new_document_ids = []
        
        for doc in documents:
            document_id = doc["document_id"]
            content = doc["content"]
            metadata = doc["metadata"]
            
            # 生成嵌入
            embedding = self._embedder.embed_code(content)
            new_embeddings.append(embedding)
            new_document_ids.append(document_id)
            
            # 更新文档信息
            self._documents[document_id] = {
                "content": content,
                "metadata": metadata,
                "embedding": embedding
            }
            
            # 添加到文档ID列表（如果不存在）
            if document_id not in self._document_ids:
                self._document_ids.append(document_id)
        
        # 批量更新索引
        if new_embeddings:
            if self._index is None:
                self._create_index()
            embeddings_np = np.array(new_embeddings, dtype=np.float32)
            self._index.add(embeddings_np)
        
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
        if not FAISS_AVAILABLE or document_id not in self._documents:
            return
        
        # 移除文档
        index = self._document_ids.index(document_id)
        self._document_ids.pop(index)
        del self._documents[document_id]
        
        # 重建索引
        self._rebuild_index()
        
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
        if not FAISS_AVAILABLE or self._index is None:
            return []
        
        # 生成查询嵌入
        query_embedding = self._embedder.embed_code(query)
        query_embedding_np = np.array([query_embedding], dtype=np.float32)
        
        # 搜索
        distances, indices = self._index.search(query_embedding_np, top_k)
        
        # 处理结果
        results = []
        for i, idx in enumerate(indices[0]):
            if idx < len(self._document_ids):
                document_id = self._document_ids[idx]
                document = self._documents[document_id]
                results.append({
                    "document_id": document_id,
                    "content": document["content"],
                    "metadata": document["metadata"],
                    "similarity": float(1 - distances[0][i])  # 转换为相似度
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
        self._index = None
        self._documents.clear()
        self._document_ids.clear()
        self.save()

    def save(self) -> None:
        """保存向量存储"""
        if not FAISS_AVAILABLE:
            return
        
        # 保存索引
        if self._index is not None:
            try:
                # 如果是 GPU 索引，先转换为 CPU 索引
                if GPU_AVAILABLE and hasattr(self._index, "index"):
                    cpu_index = faiss.index_gpu_to_cpu(self._index)
                    faiss.write_index(cpu_index, str(self.index_path))
                else:
                    faiss.write_index(self._index, str(self.index_path))
            except Exception as e:
                logger.error(f"保存索引失败: {e}")
        
        # 保存文档
        documents_data = {
            "document_ids": self._document_ids,
            "documents": self._documents
        }
        with open(self.documents_path, "w", encoding="utf-8") as f:
            json.dump(documents_data, f, indent=2, ensure_ascii=False)

    def load(self) -> None:
        """加载向量存储"""
        if not FAISS_AVAILABLE:
            return
        
        # 加载文档
        if self.documents_path.exists():
            try:
                with open(self.documents_path, "r", encoding="utf-8") as f:
                    documents_data = json.load(f)
                self._document_ids = documents_data.get("document_ids", [])
                self._documents = documents_data.get("documents", {})
            except Exception as e:
                logger.error(f"加载文档失败: {e}")
        
        # 加载索引
        if self.index_path.exists():
            try:
                cpu_index = faiss.read_index(str(self.index_path))
                # 如果支持 GPU，转换为 GPU 索引
                if GPU_AVAILABLE:
                    res = faiss.StandardGpuResources()
                    self._index = faiss.index_cpu_to_gpu(res, 0, cpu_index)
                    logger.info("✅ FAISS GPU index loaded")
                else:
                    self._index = cpu_index
                    logger.info("✅ FAISS CPU index loaded")
            except Exception as e:
                logger.error(f"加载索引失败: {e}")
                # 重建索引
                self._rebuild_index()

    def _create_index(self) -> None:
        """创建 FAISS 索引"""
        if not FAISS_AVAILABLE:
            return
        
        # 创建 HNSW 索引，适合相似度搜索
        index = faiss.IndexHNSWFlat(self._embedding_dim, 32)
        index.hnsw.efConstruction = 40
        index.hnsw.efSearch = 16
        
        # 如果支持 GPU，转换为 GPU 索引
        if GPU_AVAILABLE:
            try:
                res = faiss.StandardGpuResources()
                self._index = faiss.index_cpu_to_gpu(res, 0, index)
                logger.info("✅ FAISS GPU index created")
            except Exception as e:
                logger.warning(f"创建 GPU 索引失败，使用 CPU 索引: {e}")
                self._index = index
        else:
            self._index = index
            logger.info("✅ FAISS CPU index created")

    def _rebuild_index(self) -> None:
        """重建索引"""
        if not FAISS_AVAILABLE:
            return
        
        # 创建新索引
        self._create_index()
        
        # 添加所有文档的嵌入
        if self._documents:
            embeddings = []
            for doc_id in self._document_ids:
                doc = self._documents.get(doc_id)
                if doc and "embedding" in doc:
                    embeddings.append(doc["embedding"])
            
            if embeddings:
                embeddings_np = np.array(embeddings, dtype=np.float32)
                self._index.add(embeddings_np)
                logger.info(f"✅ Index rebuilt with {len(embeddings)} documents")

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
