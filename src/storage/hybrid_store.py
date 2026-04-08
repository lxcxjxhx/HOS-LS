"""混合存储模块

集成PostgreSQL存储和向量存储，为NVD数据提供统一的存储接口。
"""

from typing import Dict, List, Optional, Any
from pathlib import Path
import re

from src.utils.logger import get_logger
from src.integration.nvd_processor import CVEStructuredData, CVEChunk
from src.storage.postgres_storage import PostgresStorage
from src.storage.vector_store import VectorStore
from src.ai.semantic_engine import SemanticEngine

# 导入BM25
from rank_bm25 import BM25Okapi
import numpy as np

logger = get_logger(__name__)


class HybridStore:
    """混合存储"""

    def __init__(self, postgres_config: Dict[str, Any], vector_config: Dict[str, Any]):
        """初始化混合存储

        Args:
            postgres_config: PostgreSQL配置
            vector_config: 向量存储配置
        """
        self.postgres_config = postgres_config
        self.vector_config = vector_config
        
        # 初始化PostgreSQL存储
        self.postgres = PostgresStorage(postgres_config)
        self.postgres.connect()
        
        # 初始化向量存储
        vector_path = Path(vector_config.get('path', './rag_knowledge_base/vector_store'))
        model_name = vector_config.get('model_name', 'BAAI/bge-small-en-v1.5')
        self.vector_store = VectorStore(vector_path, model_name=model_name)
        
        # 初始化BM25
        self.bm25 = None
        self.bm25_documents = []
        self.bm25_cve_ids = []
        self.bm25_contents = []
        self.bm25_index_built = False
        
        # 初始化语义引擎（用于rerank）
        self.semantic_engine = SemanticEngine()

    def close(self):
        """关闭存储连接"""
        if self.postgres:
            self.postgres.close()
        # 向量存储不需要显式关闭

    def store_cve(self, structured_data: CVEStructuredData, chunks: List[CVEChunk]) -> bool:
        """存储CVE数据

        Args:
            structured_data: CVE结构化数据
            chunks: CVE数据块列表

        Returns:
            是否存储成功
        """
        try:
            # 存储结构化数据到PostgreSQL
            postgres_success = self.postgres.store_cve(structured_data)
            if not postgres_success:
                logger.error(f"存储结构化数据失败: {structured_data.cve_id}")
                return False

            # 存储数据块到向量库
            for chunk in chunks:
                # 使用chunk_id作为文档ID
                document_id = chunk.chunk_id
                
                # 添加到向量存储
                self.vector_store.add_document(
                    document_id=document_id,
                    content=chunk.content,
                    metadata={
                        "cve_id": structured_data.cve_id,
                        "chunk_type": chunk.chunk_type,
                        "chunk_id": chunk.chunk_id,
                        **chunk.metadata
                    }
                )

            return True
        except Exception as e:
            logger.error(f"存储CVE失败: {e}")
            return False

    def store_cves_batch(self, cve_data_list: List[tuple[CVEStructuredData, List[CVEChunk]]]) -> int:
        """批量存储CVE数据

        Args:
            cve_data_list: CVE数据列表，每个元素是(结构化数据, 数据块列表)

        Returns:
            成功存储的数量
        """
        success_count = 0
        
        try:
            if not cve_data_list:
                return 0
            
            # 批量存储结构化数据
            structured_data_list = [data[0] for data in cve_data_list]
            postgres_success = self.postgres.store_cves_batch(structured_data_list)
            
            # 批量存储向量数据（分批处理）
            BATCH_SIZE = 500
            documents = []
            
            for i, (structured_data, chunks) in enumerate(cve_data_list):
                for chunk in chunks:
                    # 使用chunk_id作为文档ID
                    document_id = chunk.chunk_id
                    documents.append({
                        "document_id": document_id,
                        "content": chunk.content,
                        "metadata": {
                            "cve_id": structured_data.cve_id,
                            "chunk_type": chunk.chunk_type,
                            "chunk_id": chunk.chunk_id,
                            **chunk.metadata
                        }
                    })
                
                # 达到批量大小或处理完所有数据时，执行存储
                if len(documents) >= BATCH_SIZE or i == len(cve_data_list) - 1:
                    if documents:
                        logger.info(f"批量存储 {len(documents)} 个向量数据")
                        self.vector_store.add_documents(documents, build_index=False)
                        # 清理内存
                        del documents
                        documents = []
                        import gc
                        gc.collect()
            
            # 构建向量索引
            self.vector_store.save()
            
            success_count = postgres_success
        except Exception as e:
            logger.error(f"批量存储CVE失败: {e}")
        
        return success_count

    def get_cve(self, cve_id: str) -> Optional[CVEStructuredData]:
        """获取CVE数据

        Args:
            cve_id: CVE ID

        Returns:
            CVE结构化数据或None
        """
        return self.postgres.get_cve(cve_id)

    def search_cves(self, filters: Dict[str, Any], limit: int = 100) -> List[CVEStructuredData]:
        """搜索CVE

        Args:
            filters: 搜索过滤器
            limit: 返回结果数量限制

        Returns:
            CVE结构化数据列表
        """
        return self.postgres.search_cves(filters, limit)

    def search_semantic(self, query: str, filters: Optional[Dict[str, Any]] = None, top_k: int = 10) -> List[Dict[str, Any]]:
        """语义搜索

        Args:
            query: 搜索查询
            filters: 过滤条件
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        # 执行向量搜索
        results = self.vector_store.search(query, top_k=top_k)
        
        # 应用过滤条件
        if filters:
            filtered_results = []
            for result in results:
                metadata = result.get('metadata', {})
                match = True
                
                # 过滤CVE ID
                if 'cve_id' in filters:
                    cve_id_filter = filters['cve_id']
                    cve_id = metadata.get('cve_id', '')
                    if not cve_id.startswith(cve_id_filter):
                        match = False
                
                # 过滤chunk类型
                if 'chunk_type' in filters:
                    chunk_type = metadata.get('chunk_type', '')
                    if chunk_type != filters['chunk_type']:
                        match = False
                
                if match:
                    filtered_results.append(result)
            
            results = filtered_results[:top_k]
        
        return results

    async def hybrid_search(self, query: str, filters: Optional[Dict[str, Any]] = None, top_k: int = 5) -> List[Dict[str, Any]]:
        """混合搜索

        Args:
            query: 搜索查询
            filters: 过滤条件
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        # 1. 语义搜索
        semantic_results = self.search_semantic(query, filters, top_k=top_k * 3)
        
        # 2. BM25搜索
        bm25_results = self.search_bm25(query, top_k=top_k * 3)
        
        # 3. 融合结果
        # 创建CVE ID到结果的映射
        cve_results = {}
        cve_chunks = {}
        
        # 添加语义结果
        for result in semantic_results:
            cve_id = result.get('metadata', {}).get('cve_id')
            if cve_id:
                if cve_id not in cve_results:
                    # 获取完整CVE信息
                    cve = self.postgres.get_cve(cve_id)
                    if cve:
                        cve_results[cve_id] = {
                            'type': 'semantic',
                            'cve': cve,
                            'score': result.get('similarity', 0.0),
                            'chunks': []
                        }
                        cve_chunks[cve_id] = []
                if cve_id in cve_chunks:
                    cve_chunks[cve_id].append({
                        'content': result.get('content'),
                        'chunk_type': result.get('metadata', {}).get('chunk_type'),
                        'score': result.get('similarity', 0.0)
                    })
        
        # 添加BM25结果
        for result in bm25_results:
            cve_id = result.get('cve_id')
            if cve_id:
                if cve_id not in cve_results:
                    # 获取完整CVE信息
                    cve = self.postgres.get_cve(cve_id)
                    if cve:
                        cve_results[cve_id] = {
                            'type': 'bm25',
                            'cve': cve,
                            'score': result.get('score', 0.0),
                            'chunks': []
                        }
                        cve_chunks[cve_id] = []
                if cve_id in cve_chunks:
                    cve_chunks[cve_id].append({
                        'content': result.get('content'),
                        'chunk_type': 'bm25',
                        'score': result.get('score', 0.0)
                    })
        
        # 对每个CVE的chunks进行排序并拼接Top-K
        for cve_id, chunks in cve_chunks.items():
            if cve_id in cve_results:
                # 按得分排序
                sorted_chunks = sorted(chunks, key=lambda x: x['score'], reverse=True)[:3]  # 每个CVE取前3个chunks
                # 拼接chunks
                combined_content = '\n\n'.join([chunk['content'] for chunk in sorted_chunks])
                cve_results[cve_id]['chunks'] = sorted_chunks
                cve_results[cve_id]['combined_content'] = combined_content
                # 计算综合得分
                if len(chunks) > 0:
                    avg_score = sum(chunk['score'] for chunk in chunks) / len(chunks)
                    cve_results[cve_id]['score'] = avg_score
        
        # 按得分排序
        sorted_results = sorted(
            cve_results.values(),
            key=lambda x: x['score'],
            reverse=True
        )[:top_k]
        
        # 4. Rerank结果
        import asyncio
        reranked_results = await self.semantic_engine.rerank_results(query, sorted_results)
        
        return reranked_results

    def delete_cve(self, cve_id: str) -> bool:
        """删除CVE

        Args:
            cve_id: CVE ID

        Returns:
            是否删除成功
        """
        try:
            # 删除结构化数据
            postgres_success = self.postgres.delete_cve(cve_id)
            
            # 删除向量数据
            # 删除所有相关的文档
            # 注意：这里需要根据实际的向量存储实现来删除
            # 目前的VectorStore没有批量删除功能，需要逐个删除
            # 这里暂时跳过，因为当前的VectorStore实现不支持按条件删除
            
            return postgres_success
        except Exception as e:
            logger.error(f"删除CVE失败: {e}")
            return False

    def get_cve_count(self) -> int:
        """获取CVE数量

        Returns:
            CVE数量
        """
        return self.postgres.get_cve_count()

    def get_vector_count(self) -> int:
        """获取向量数量

        Returns:
            向量数量
        """
        return len(self.vector_store)

    def vacuum(self):
        """执行存储清理"""
        try:
            # 清理PostgreSQL
            self.postgres.vacuum()
            
            # 向量存储清理（如果需要）
            # 目前的VectorStore没有清理方法
        except Exception as e:
            logger.error(f"清理存储失败: {e}")

    def generate_embeddings(self, texts: List[str], batch_size: int = 128) -> List[List[float]]:
        """生成文本嵌入

        Args:
            texts: 文本列表
            batch_size: 批处理大小

        Returns:
            嵌入向量列表
        """
        try:
            # 使用CodeEmbedder生成嵌入
            return self.vector_store.embedder.embed_batch(texts, batch_size=batch_size)
        except Exception as e:
            logger.error(f"生成嵌入失败: {e}")
            return []

    def build_bm25_index(self):
        """构建BM25索引

        Returns:
            bool: 是否构建成功
        """
        try:
            # 收集所有文档
            self.bm25_documents = []
            self.bm25_cve_ids = []
            self.bm25_contents = []
            
            # 从向量存储中获取所有文档
            all_documents = self.vector_store.get_all_documents()
            
            logger.info(f"开始构建BM25索引，共 {len(all_documents)} 个文档...")
            
            # 简单分词函数
            def tokenize(text):
                # 简单的分词实现
                text = re.sub(r'[^a-zA-Z0-9\s]', '', text.lower())
                return text.split()
            
            # 收集文档数据
            for doc in all_documents:
                content = doc.get('content', '')
                metadata = doc.get('metadata', {})
                cve_id = metadata.get('cve_id', '')
                
                if content and cve_id:
                    tokens = tokenize(content)
                    if tokens:
                        self.bm25_documents.append(tokens)
                        self.bm25_cve_ids.append(cve_id)
                        self.bm25_contents.append(content)
            
            # 构建BM25索引
            if self.bm25_documents:
                self.bm25 = BM25Okapi(self.bm25_documents)
                logger.info(f"BM25索引构建完成，包含 {len(self.bm25_documents)} 个文档")
            else:
                logger.warning("没有文档可用于构建BM25索引")
            
            # 标记索引已构建
            self.bm25_index_built = True
            return True
        except Exception as e:
            logger.error(f"构建BM25索引失败: {e}")
            return False

    def search_bm25(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """BM25搜索

        Args:
            query: 搜索查询
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        try:
            if not self.bm25_index_built:
                self.build_bm25_index()
            
            # 简单分词
            def tokenize(text):
                text = re.sub(r'[^a-zA-Z0-9\s]', '', text.lower())
                return text.split()
            
            # 搜索
            query_tokens = tokenize(query)
            if not query_tokens or not self.bm25:
                return []
            
            # 执行BM25搜索
            scores = self.bm25.get_scores(query_tokens)
            sorted_indices = np.argsort(scores)[::-1][:top_k]
            
            results = []
            for idx in sorted_indices:
                if scores[idx] > 0:
                    results.append({
                        'cve_id': self.bm25_cve_ids[idx],
                        'content': self.bm25_contents[idx],
                        'score': float(scores[idx])
                    })
            
            return results
        except Exception as e:
            logger.error(f"BM25搜索失败: {e}")
            return []

    def update_bm25_index(self, cve_id: str, content: str):
        """更新BM25索引

        Args:
            cve_id: CVE ID
            content: 文档内容
        """
        try:
            # 简单分词
            def tokenize(text):
                text = re.sub(r'[^a-zA-Z0-9\s]', '', text.lower())
                return text.split()
            
            # 添加到文档列表
            self.bm25_documents.append(tokenize(content))
            self.bm25_cve_ids.append(cve_id)
            
            # 重新构建索引
            self.bm25 = BM25Okapi(self.bm25_documents)
            self.bm25_index_built = True
        except Exception as e:
            logger.error(f"更新BM25索引失败: {e}")