"""混合存储模块

集成PostgreSQL存储和向量存储，为NVD数据提供统一的存储接口。
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from src.utils.logger import get_logger
from src.integration.nvd_processor import CVEStructuredData, CVEChunk
from src.storage.postgres_storage import PostgresStorage
from src.storage.vector_store import VectorStore

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
        vector_path = Path(vector_config.get('path', './vector_store'))
        model_name = vector_config.get('model_name', 'google/embeddinggemma-300M')
        self.vector_store = VectorStore(vector_path, model_name=model_name)

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
                # 生成文档ID
                document_id = f"{structured_data.cve_id}_{chunk.chunk_type}"
                
                # 添加到向量存储
                self.vector_store.add_document(
                    document_id=document_id,
                    content=chunk.content,
                    metadata={
                        "cve_id": structured_data.cve_id,
                        "chunk_type": chunk.chunk_type,
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
            # 批量存储结构化数据
            structured_data_list = [data[0] for data in cve_data_list]
            postgres_success = self.postgres.store_cves_batch(structured_data_list)
            
            # 批量存储向量数据
            documents = []
            for structured_data, chunks in cve_data_list:
                for chunk in chunks:
                    document_id = f"{structured_data.cve_id}_{chunk.chunk_type}"
                    documents.append({
                        "document_id": document_id,
                        "content": chunk.content,
                        "metadata": {
                            "cve_id": structured_data.cve_id,
                            "chunk_type": chunk.chunk_type,
                            **chunk.metadata
                        }
                    })
            
            if documents:
                self.vector_store.add_documents(documents, build_index=False)
            
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

    def hybrid_search(self, query: str, filters: Optional[Dict[str, Any]] = None, top_k: int = 10) -> List[Dict[str, Any]]:
        """混合搜索

        Args:
            query: 搜索查询
            filters: 过滤条件
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        # 1. 结构化搜索
        structured_results = self.postgres.search_cves(filters or {}, limit=top_k * 2)
        
        # 2. 语义搜索
        semantic_results = self.search_semantic(query, filters, top_k=top_k * 2)
        
        # 3. 融合结果
        # 创建CVE ID到结果的映射
        cve_results = {}
        
        # 添加结构化结果
        for cve in structured_results:
            cve_results[cve.cve_id] = {
                'type': 'structured',
                'cve': cve,
                'score': 1.0  # 结构化匹配得分
            }
        
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
                            'chunk_type': result.get('metadata', {}).get('chunk_type'),
                            'content': result.get('content')
                        }
                else:
                    # 融合得分
                    cve_results[cve_id]['score'] = max(
                        cve_results[cve_id]['score'],
                        result.get('similarity', 0.0)
                    )
        
        # 按得分排序
        sorted_results = sorted(
            cve_results.values(),
            key=lambda x: x['score'],
            reverse=True
        )[:top_k]
        
        return sorted_results

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