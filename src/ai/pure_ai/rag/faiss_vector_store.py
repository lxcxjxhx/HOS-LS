"""FAISS 向量存储模块

实现基于 FAISS 的向量存储，支持 GPU 加速的相似度搜索和 LlamaIndex 混合检索。
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from src.ai.pure_ai.rag.code_embedder import CodeEmbedder, EmbedConfig
from src.utils.logger import get_logger

try:
    from llama_index.core import VectorStoreIndex, Document
    from llama_index.core.storage.index_store import SimpleIndexStore
    from llama_index.core.storage.docstore import SimpleDocumentStore
    from llama_index.core.graph_stores import SimpleGraphStore
    from llama_index.graph_stores.neo4j import Neo4jGraphStore
    LLAMA_INDEX_AVAILABLE = True
except ImportError:
    LLAMA_INDEX_AVAILABLE = False

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

    def __init__(self, storage_path: Path, embed_config: Optional[EmbedConfig] = None, neo4j_config: Optional[Dict] = None):
        """初始化 FAISS 向量存储

        Args:
            storage_path: 存储路径
            embed_config: 嵌入配置
            neo4j_config: Neo4j 配置，用于 LlamaIndex Property Graph Index
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # 存储文件
        self.index_path = self.storage_path / "faiss_index.bin"
        self.documents_path = self.storage_path / "documents.json"
        self.llama_index_path = self.storage_path / "llama_index"
        
        # 内存存储
        self._index = None
        self._documents: Dict[str, Dict] = {}
        self._document_ids: List[str] = []
        self._embedder = CodeEmbedder(embed_config or EmbedConfig())
        self._embedding_dim = self._embedder.get_embedding_dimension()
        self._neo4j_config = neo4j_config
        self._llama_index = None
        self._graph_store = None
        
        # 加载现有数据
        self.load()
        
        # 初始化 LlamaIndex
        if LLAMA_INDEX_AVAILABLE:
            self._initialize_llama_index()

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
        
        # 更新 LlamaIndex
        if LLAMA_INDEX_AVAILABLE and self._llama_index:
            try:
                # 创建 LlamaIndex Document
                doc = Document(
                    text=content,
                    id_=document_id,
                    metadata=metadata
                )
                # 添加到 LlamaIndex
                self._llama_index.insert(doc)
                # 保存 LlamaIndex
                self._llama_index.storage_context.persist(persist_dir=str(self.llama_index_path))
            except Exception as e:
                logger.error(f"Failed to update LlamaIndex: {e}")
        
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
        llama_documents = []
        
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
            
            # 创建 LlamaIndex Document
            if LLAMA_INDEX_AVAILABLE and self._llama_index:
                llama_doc = Document(
                    text=content,
                    id_=document_id,
                    metadata=metadata
                )
                llama_documents.append(llama_doc)
        
        # 批量更新索引
        if new_embeddings:
            if self._index is None:
                self._create_index()
            embeddings_np = np.array(new_embeddings, dtype=np.float32)
            self._index.add(embeddings_np)
        
        # 批量更新 LlamaIndex
        if LLAMA_INDEX_AVAILABLE and self._llama_index and llama_documents:
            try:
                for doc in llama_documents:
                    self._llama_index.insert(doc)
                # 保存 LlamaIndex
                self._llama_index.storage_context.persist(persist_dir=str(self.llama_index_path))
            except Exception as e:
                logger.error(f"Failed to update LlamaIndex: {e}")
        
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

    def hybrid_search(self, query: str, top_k: int = 10, filter_metadata: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """混合检索（FAISS + LlamaIndex）

        Args:
            query: 查询文本
            top_k: 返回结果数量
            filter_metadata: 元数据过滤条件

        Returns:
            搜索结果列表
        """
        # 1. 使用 FAISS 进行向量搜索
        faiss_results = self.search(query, top_k)
        
        # 2. 使用 LlamaIndex 进行混合检索（如果可用）
        llama_results = []
        if LLAMA_INDEX_AVAILABLE and self._llama_index:
            try:
                # 构建查询引擎
                query_engine = self._llama_index.as_query_engine(
                    similarity_top_k=top_k,
                    vector_store_query_mode="hybrid"
                )
                # 执行查询
                response = query_engine.query(query)
                # 处理结果
                for node in response.source_nodes:
                    llama_results.append({
                        "document_id": node.node.id,
                        "content": node.node.text,
                        "metadata": node.node.metadata or {},
                        "similarity": node.score
                    })
            except Exception as e:
                logger.error(f"LlamaIndex search failed: {e}")
        
        # 3. 合并结果（去重并排序）
        combined_results = {}
        
        # 添加 FAISS 结果
        for result in faiss_results:
            combined_results[result["document_id"]] = result
        
        # 添加 LlamaIndex 结果（如果相似度更高）
        for result in llama_results:
            doc_id = result["document_id"]
            if doc_id not in combined_results or result["similarity"] > combined_results[doc_id]["similarity"]:
                combined_results[doc_id] = result
        
        # 4. 应用元数据过滤
        if filter_metadata:
            filtered_results = []
            for result in combined_results.values():
                match = True
                for key, value in filter_metadata.items():
                    if key not in result["metadata"] or result["metadata"][key] != value:
                        match = False
                        break
                if match:
                    filtered_results.append(result)
            combined_results = {r["document_id"]: r for r in filtered_results}
        
        # 5. 按相似度排序并返回前 top_k 个结果
        sorted_results = sorted(
            combined_results.values(),
            key=lambda x: x["similarity"],
            reverse=True
        )
        
        return sorted_results[:top_k]

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

    def _initialize_llama_index(self) -> None:
        """初始化 LlamaIndex"""
        try:
            # 创建存储目录
            self.llama_index_path.mkdir(parents=True, exist_ok=True)
            
            # 初始化文档存储
            docstore = SimpleDocumentStore.from_persist_dir(str(self.llama_index_path))
            
            # 初始化索引存储
            index_store = SimpleIndexStore.from_persist_dir(str(self.llama_index_path))
            
            # 初始化图存储
            if self._neo4j_config:
                # 使用 Neo4j 图存储
                self._graph_store = Neo4jGraphStore(
                    url=self._neo4j_config.get("uri", "bolt://localhost:7687"),
                    username=self._neo4j_config.get("username", "neo4j"),
                    password=self._neo4j_config.get("password", "password")
                )
            else:
                # 使用简单图存储
                self._graph_store = SimpleGraphStore.from_persist_dir(str(self.llama_index_path))
            
            # 从存储加载索引
            try:
                self._llama_index = VectorStoreIndex.from_persist_dir(
                    persist_dir=str(self.llama_index_path),
                    docstore=docstore,
                    index_store=index_store,
                    graph_store=self._graph_store
                )
                logger.info("✅ LlamaIndex loaded from storage")
            except Exception:
                # 如果没有现有索引，创建新的
                self._llama_index = VectorStoreIndex(
                    documents=[],
                    docstore=docstore,
                    index_store=index_store,
                    graph_store=self._graph_store
                )
                logger.info("✅ New LlamaIndex created")
        except Exception as e:
            logger.error(f"LlamaIndex initialization failed: {e}")
            self._llama_index = None

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

    def index_file_function_chunks(
        self,
        file_path: str,
        content: str,
        language: str,
        function_patterns: Optional[Dict[str, List]] = None
    ) -> int:
        """将文件索引为函数级 chunks

        Args:
            file_path: 文件路径
            content: 文件内容
            language: 编程语言
            function_patterns: 函数模式定义

        Returns:
            索引的 chunk 数量
        """
        import hashlib
        import re

        if function_patterns is None:
            function_patterns = {
                'python': [
                    (r'^def\s+(\w+)\s*\(', 'function'),
                    (r'^async\s+def\s+(\w+)\s*\(', 'async_function'),
                    (r'^class\s+(\w+)\s*[\(:]', 'class'),
                ],
                'javascript': [
                    (r'^function\s+(\w+)\s*\(', 'function'),
                    (r'^const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>', 'arrow_function'),
                    (r'^class\s+(\w+)', 'class'),
                ],
                'java': [
                    (r'^(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:void|int|String|Object|\w+)\s+(\w+)\s*\(', 'method'),
                    (r'^class\s+(\w+)', 'class'),
                ],
                'go': [
                    (r'^func\s+(\w+)\s*\(', 'function'),
                    (r'^func\s+\((\w+)\s+\*?\w+\)\s+(\w+)\s*\(', 'method'),
                    (r'^type\s+(\w+)\s+struct', 'struct'),
                ],
            }

        lines = content.split('\n')
        patterns = function_patterns.get(language, [])

        function_boundaries = []
        for i, line in enumerate(lines):
            for pattern, func_type in patterns:
                match = re.match(pattern, line.strip())
                if match:
                    func_name = match.group(1) if match.groups() else 'anonymous'
                    function_boundaries.append({
                        'line': i + 1,
                        'name': func_name,
                        'type': func_type,
                        'content': ''
                    })
                    break

        if not function_boundaries:
            chunk_id = hashlib.md5(f"{file_path}:0".encode()).hexdigest()[:16]
            self.add_document(
                document_id=chunk_id,
                content=content,
                metadata={
                    'file_path': file_path,
                    'language': language,
                    'chunk_type': 'module',
                    'function_name': '<module>',
                    'line_start': 1,
                    'line_end': len(lines)
                }
            )
            return 1

        chunks = []
        for idx, boundary in enumerate(function_boundaries):
            start_line = boundary['line']

            if idx + 1 < len(function_boundaries):
                end_line = function_boundaries[idx + 1]['line'] - 1
            else:
                end_line = len(lines)

            func_lines = lines[start_line - 1:end_line]
            func_content = '\n'.join(func_lines)

            boundary['content'] = func_content
            boundary['line_start'] = start_line
            boundary['line_end'] = end_line

            chunk_id = hashlib.md5(f"{file_path}:{start_line}".encode()).hexdigest()[:16]

            chunks.append({
                'document_id': chunk_id,
                'content': func_content,
                'metadata': {
                    'file_path': file_path,
                    'language': language,
                    'chunk_type': boundary['type'],
                    'function_name': boundary['name'],
                    'line_start': start_line,
                    'line_end': end_line
                }
            })

        self.add_documents(chunks, build_index=True)
        return len(chunks)

    def get_file_chunks(self, file_path: str) -> List[Dict[str, Any]]:
        """获取文件的所有 chunks

        Args:
            file_path: 文件路径

        Returns:
            chunk 列表
        """
        results = []
        for doc_id, doc in self._documents.items():
            metadata = doc.get('metadata', {})
            if metadata.get('file_path') == file_path:
                results.append({
                    'document_id': doc_id,
                    'content': doc['content'],
                    'metadata': metadata
                })

        results.sort(key=lambda x: x['metadata'].get('line_start', 0))
        return results

    def incremental_update(
        self,
        file_path: str,
        new_content: str,
        language: str
    ) -> Tuple[int, int]:
        """增量更新文件索引

        Args:
            file_path: 文件路径
            new_content: 新的文件内容
            language: 编程语言

        Returns:
            (删除的 chunk 数, 新增的 chunk 数)
        """
        existing_chunks = self.get_file_chunks(file_path)

        for chunk in existing_chunks:
            self.delete_document(chunk['document_id'])

        new_chunk_count = self.index_file_function_chunks(
            file_path, new_content, language
        )

        return len(existing_chunks), new_chunk_count

    def search_in_file(
        self,
        file_path: str,
        query: str,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """在特定文件内搜索

        Args:
            file_path: 文件路径
            query: 搜索查询
            top_k: 返回数量

        Returns:
            搜索结果列表
        """
        file_chunks = self.get_file_chunks(file_path)

        if not file_chunks:
            return []

        query_embedding = self._embedder.embed_code(query)
        query_np = np.array([query_embedding], dtype=np.float32)

        chunk_embeddings = []
        chunk_ids = []
        for chunk in file_chunks:
            if 'embedding' in self._documents.get(chunk['document_id'], {}):
                emb = self._documents[chunk['document_id']]['embedding']
                chunk_embeddings.append(emb)
                chunk_ids.append(chunk['document_id'])

        if not chunk_embeddings:
            return file_chunks[:top_k]

        embeddings_np = np.array(chunk_embeddings, dtype=np.float32)

        if self._index is None:
            self._create_index()

        self._index.add(embeddings_np)

        distances, indices = self._index.search(query_np, min(top_k, len(chunk_ids)))

        results = []
        for i, idx in enumerate(indices[0]):
            if idx < len(chunk_ids):
                chunk_id = chunk_ids[idx]
                chunk = file_chunks[[c['document_id'] for c in file_chunks].index(chunk_id)]
                results.append({
                    **chunk,
                    'similarity': float(1 - distances[0][i])
                })

        return results
