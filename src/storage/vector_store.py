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

    def __init__(self, storage_path: Path, model_name: Optional[str] = None, custom_model_path: Optional[str] = None):
        """初始化向量存储

        Args:
            storage_path: 存储路径
            model_name: 嵌入模型名称
            custom_model_path: 自定义模型路径
        """
        # 检查是否为纯AI模式
        from src.core.config import get_config
        core_config = get_config()
        self.pure_ai = hasattr(core_config, 'pure_ai') and core_config.pure_ai
        
        if self.pure_ai:
            # 纯AI模式下，跳过所有存储初始化
            self.storage_path = storage_path
            # 初始化空的内存存储
            self._embeddings: Optional[np.ndarray] = None
            self._documents: Dict[str, Dict] = {}
            self._document_ids: List[str] = []
            self._embedding_cache: Dict[str, List[float]] = {}
            self._access_stats: Dict[str, Dict] = {}
            # 初始化一个简单的嵌入器
            from src.storage.code_embedder import create_embedder, EmbedConfig
            config = EmbedConfig()
            config.pure_ai = True
            self.embedder = create_embedder(config, custom_model_path=custom_model_path)
            return
        
        # 非纯AI模式下正常初始化
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # 存储文件
        self.embeddings_path = self.storage_path / "embeddings.npy"
        self.documents_path = self.storage_path / "documents.json"
        self.embedding_cache_path = self.storage_path / "embedding_cache.json"
        
        # 冷热分层相关
        self.hot_storage_path = self.storage_path / "hot"
        self.cold_storage_path = self.storage_path / "cold"
        self.hot_storage_path.mkdir(exist_ok=True)
        self.cold_storage_path.mkdir(exist_ok=True)
        
        # 内存存储
        self._embeddings: Optional[np.ndarray] = None
        self._documents: Dict[str, Dict] = {}
        self._document_ids: List[str] = []
        self._embedding_cache: Dict[str, List[float]] = {}  # 文本哈希到embedding的缓存
        
        # 访问频率监控
        self._access_stats: Dict[str, Dict] = {}  # 文档ID到访问统计的映射
        
        # 初始化 CodeEmbedder（使用单例模式）
        from src.storage.code_embedder import create_embedder, EmbedConfig
        config = EmbedConfig()
        if model_name:
            config.model_name = model_name
        self.embedder = create_embedder(config, custom_model_path=custom_model_path)
        
        # 加载现有数据
        self.load()
        self._load_embedding_cache()
        self._load_access_stats()

    def add_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """添加文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        # 生成嵌入
        embedding = self._generate_embedding(content)
        
        # 确保所有嵌入维度一致为256维
        target_dim = 256
        embedding = self._ensure_embedding_dimension(embedding, target_dim)
        
        # 检查现有嵌入维度
        if self._embeddings is not None:
            existing_dim = self._embeddings.shape[1]
            if existing_dim != target_dim:
                # 转换现有嵌入到目标维度
                logger.info(f"转换现有嵌入维度从 {existing_dim} 到 {target_dim}")
                new_embeddings = []
                for i in range(len(self._embeddings)):
                    new_embedding = self._ensure_embedding_dimension(self._embeddings[i], target_dim)
                    new_embeddings.append(new_embedding)
                self._embeddings = np.array(new_embeddings)
                
                # 更新文档中的嵌入
                for doc_id in self._documents:
                    doc_embedding = np.array(self._documents[doc_id]["embedding"])
                    new_doc_embedding = self._ensure_embedding_dimension(doc_embedding, target_dim)
                    self._documents[doc_id]["embedding"] = new_doc_embedding.tolist()
        
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
        
        # 分批处理文档
        BATCH_SIZE = 32
        total_docs = len(documents)
        
        for i in range(0, total_docs, BATCH_SIZE):
            batch = documents[i:i + BATCH_SIZE]
            logger.info(f"处理文档批次 {i//BATCH_SIZE + 1}/{(total_docs + BATCH_SIZE - 1)//BATCH_SIZE}")
            
            # 批量处理文档
            new_embeddings = []
            contents = []
            doc_info = []
            
            for doc in batch:
                document_id = doc["document_id"]
                content = doc["content"]
                metadata = doc["metadata"]
                
                contents.append(content)
                doc_info.append((document_id, content, metadata))
                
            # 使用批量嵌入
            if self.embedder.is_available() and contents:
                try:
                    # 使用 CodeEmbedder 的批量嵌入功能
                    batch_embeddings = self.embedder.embed_batch(contents, batch_size=BATCH_SIZE)
                    new_embeddings = [np.array(embedding) for embedding in batch_embeddings]
                except Exception as e:
                    logger.error(f"批量嵌入失败: {e}")
                    # 降级到单个嵌入
                    new_embeddings = [self._generate_embedding(content) for content in contents]
            else:
                # 单个生成嵌入
                new_embeddings = [self._generate_embedding(content) for content in contents]
            
            # 确保所有嵌入维度一致为256维
            target_dim = 256
            new_embeddings = [self._ensure_embedding_dimension(embedding, target_dim) for embedding in new_embeddings]
            
            # 检查现有嵌入维度
            if self._embeddings is not None:
                existing_dim = self._embeddings.shape[1]
                if existing_dim != target_dim:
                    # 转换现有嵌入到目标维度
                    logger.info(f"转换现有嵌入维度从 {existing_dim} 到 {target_dim}")
                    converted_embeddings = []
                    for i in range(len(self._embeddings)):
                        converted_embedding = self._ensure_embedding_dimension(self._embeddings[i], target_dim)
                        converted_embeddings.append(converted_embedding)
                    self._embeddings = np.array(converted_embeddings)
                    
                    # 更新文档中的嵌入
                    for doc_id in self._documents:
                        doc_embedding = np.array(self._documents[doc_id]["embedding"])
                        converted_doc_embedding = self._ensure_embedding_dimension(doc_embedding, target_dim)
                        self._documents[doc_id]["embedding"] = converted_doc_embedding.tolist()
            
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
            
            # 清理内存
            del new_embeddings
            del contents
            del doc_info
            import gc
            gc.collect()
        
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
            
            # 更新访问统计信息
            self._update_access_stats(document_id)
            
            results.append({
                "document_id": document_id,
                "content": document["content"],
                "metadata": document["metadata"],
                "similarity": float(similarities[idx])
            })
        
        # 检查是否需要进行冷热分层
        self._check_hot_cold_demotion()
        
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
        if self.pure_ai:
            # 纯AI模式下，跳过保存操作
            return
        
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
        if self.pure_ai:
            # 纯AI模式下，跳过加载操作
            return
        
        # 加载文档
        if hasattr(self, 'documents_path') and self.documents_path.exists():
            try:
                with open(self.documents_path, "r", encoding="utf-8") as f:
                    documents_data = json.load(f)
                self._document_ids = documents_data.get("document_ids", [])
                self._documents = documents_data.get("documents", {})
            except Exception as e:
                logger.error(f"加载文档失败: {e}")
        
        # 加载嵌入
        if hasattr(self, 'embeddings_path') and self.embeddings_path.exists():
            try:
                self._embeddings = np.load(self.embeddings_path)
            except Exception as e:
                logger.error(f"加载嵌入失败: {e}")

    def _load_embedding_cache(self):
        """加载embedding缓存"""
        if self.pure_ai:
            # 纯AI模式下，跳过加载操作
            return
        
        try:
            if hasattr(self, 'embedding_cache_path') and self.embedding_cache_path.exists():
                with open(self.embedding_cache_path, 'r', encoding='utf-8') as f:
                    self._embedding_cache = json.load(f)
                logger.info(f"加载了 {len(self._embedding_cache)} 个embedding缓存")
        except Exception as e:
            logger.error(f"加载embedding缓存失败: {e}")
            self._embedding_cache = {}

    def _save_embedding_cache(self):
        """保存embedding缓存"""
        if self.pure_ai:
            # 纯AI模式下，跳过保存操作
            return
        
        try:
            if hasattr(self, 'embedding_cache_path'):
                with open(self.embedding_cache_path, 'w', encoding='utf-8') as f:
                    json.dump(self._embedding_cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存embedding缓存失败: {e}")

    def _load_access_stats(self):
        """加载访问统计信息"""
        if self.pure_ai:
            # 纯AI模式下，跳过加载操作
            return
        
        access_stats_path = self.storage_path / "access_stats.json"
        try:
            if access_stats_path.exists():
                with open(access_stats_path, 'r', encoding='utf-8') as f:
                    self._access_stats = json.load(f)
                logger.info(f"加载了 {len(self._access_stats)} 条访问统计信息")
        except Exception as e:
            logger.error(f"加载访问统计信息失败: {e}")
            self._access_stats = {}

    def _save_access_stats(self):
        """保存访问统计信息"""
        if self.pure_ai:
            # 纯AI模式下，跳过保存操作
            return
        
        access_stats_path = self.storage_path / "access_stats.json"
        try:
            with open(access_stats_path, 'w', encoding='utf-8') as f:
                json.dump(self._access_stats, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存访问统计信息失败: {e}")

    def _update_access_stats(self, document_id: str):
        """更新文档的访问统计信息

        Args:
            document_id: 文档ID
        """
        import time
        current_time = time.time()
        
        if document_id not in self._access_stats:
            self._access_stats[document_id] = {
                'access_count': 0,
                'last_access': current_time,
                'first_access': current_time
            }
        
        stats = self._access_stats[document_id]
        stats['access_count'] += 1
        stats['last_access'] = current_time
        
        # 定期保存访问统计信息
        if len(self._access_stats) % 100 == 0:
            self._save_access_stats()

    def _check_hot_cold_demotion(self):
        """检查并执行冷热分层"""
        import time
        current_time = time.time()
        
        # 定期执行，避免频繁检查
        if hasattr(self, '_last_check_time') and current_time - self._last_check_time < 3600:  # 1小时检查一次
            return
        
        self._last_check_time = current_time
        
        # 定义热点和冷点的阈值
        HOT_ACCESS_COUNT = 5  # 热点访问次数阈值
        COLD_DAYS = 30  # 冷点天数阈值
        
        # 检查每个文档
        for document_id, stats in self._access_stats.items():
            access_count = stats.get('access_count', 0)
            last_access = stats.get('last_access', 0)
            days_since_last_access = (current_time - last_access) / (24 * 3600)
            
            # 检查是否需要从热存储移动到冷存储
            if access_count < HOT_ACCESS_COUNT and days_since_last_access > COLD_DAYS:
                self._move_to_cold_storage(document_id)
            # 检查是否需要从冷存储移动到热存储
            elif access_count >= HOT_ACCESS_COUNT and days_since_last_access < COLD_DAYS:
                self._move_to_hot_storage(document_id)

    def _move_to_cold_storage(self, document_id: str):
        """将文档移动到冷存储

        Args:
            document_id: 文档ID
        """
        try:
            # 这里只是标记，实际的存储移动需要根据具体实现
            # 例如，可以将文档从内存缓存中移除，只保留在磁盘上
            logger.info(f"将文档 {document_id} 移动到冷存储")
            # 实际的移动操作
        except Exception as e:
            logger.error(f"将文档移动到冷存储失败: {e}")

    def _move_to_hot_storage(self, document_id: str):
        """将文档移动到热存储

        Args:
            document_id: 文档ID
        """
        try:
            # 这里只是标记，实际的存储移动需要根据具体实现
            # 例如，可以将文档加载到内存缓存中
            logger.info(f"将文档 {document_id} 移动到热存储")
            # 实际的移动操作
        except Exception as e:
            logger.error(f"将文档移动到热存储失败: {e}")

    def _get_text_hash(self, text: str) -> str:
        """计算文本哈希

        Args:
            text: 文本

        Returns:
            文本哈希
        """
        return hashlib.sha256(text.encode()).hexdigest()

    def is_valid(self, vec):
        """检查向量是否有效（无NaN和inf值）

        Args:
            vec: 向量

        Returns:
            是否有效
        """
        return not (np.isnan(vec).any() or np.isinf(vec).any())

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
            embedding = np.array(self._embedding_cache[text_hash])
            if self.is_valid(embedding):
                return embedding
            else:
                # 缓存中的向量无效，删除并重新生成
                del self._embedding_cache[text_hash]
        
        # 使用 CodeEmbedder 生成嵌入
        if self.embedder.is_available():
            try:
                embedding = self.embedder.embed_code(text)
                embedding = np.array(embedding)
                
                # 确保嵌入维度为256维
                embedding = self._ensure_embedding_dimension(embedding, 256)
                
                # 检查并处理NaN值
                if not self.is_valid(embedding):
                    logger.warning("检测到NaN或inf值，丢弃嵌入...")
                    # 生成一个默认的有效向量
                    embedding = np.zeros(256)
                    embedding[0] = 1.0  # 确保向量非零
            except Exception as e:
                logger.error(f"生成嵌入失败: {e}")
                # 生成一个默认的有效向量
                embedding = np.zeros(256)
                embedding[0] = 1.0
        else:
            # 降级方案：使用简单的哈希嵌入，生成256维向量
            hash_value = text_hash
            embedding = []
            
            # 生成256维向量，与模型一致
            for i in range(0, 256):
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
    
    def _ensure_embedding_dimension(self, embedding: np.ndarray, target_dim: int) -> np.ndarray:
        """确保嵌入维度为目标维度

        Args:
            embedding: 原始嵌入向量
            target_dim: 目标维度

        Returns:
            调整后的嵌入向量
        """
        current_dim = len(embedding)
        if current_dim == target_dim:
            return embedding
        elif current_dim > target_dim:
            # 截断到目标维度
            return embedding[:target_dim]
        else:
            # 填充到目标维度
            padding = np.zeros(target_dim - current_dim)
            return np.concatenate([embedding, padding])

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
