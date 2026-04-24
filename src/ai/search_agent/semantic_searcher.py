"""语义搜索器模块

基于向量嵌入的语义搜索，实现类似 Cursor 的代码检索能力。
"""

import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import hashlib

from src.storage.faiss_vector_store import FAISSVectorStore
from src.storage.code_embedder import CodeEmbedder, EmbedConfig
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SemanticSearchResult:
    """语义搜索结果"""

    def __init__(self, chunk_id: str, content: str, metadata: Dict[str, Any], similarity: float):
        self.chunk_id = chunk_id
        self.content = content
        self.metadata = metadata
        self.similarity = similarity
        self.file_path = metadata.get('file_path', '')
        self.line_start = metadata.get('line_start', 0)
        self.line_end = metadata.get('line_end', 0)
        self.function_name = metadata.get('function_name', '')

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chunk_id': self.chunk_id,
            'content': self.content,
            'metadata': self.metadata,
            'similarity': self.similarity,
            'file_path': self.file_path,
            'line_start': self.line_start,
            'line_end': self.line_end,
            'function_name': self.function_name
        }


class SemanticSearcher:
    """语义搜索器

    基于 FAISS 向量存储的语义搜索，支持函数级 chunk 检索。
    """

    def __init__(self, storage_path: Optional[Path] = None, embed_config: Optional[EmbedConfig] = None):
        """初始化语义搜索器

        Args:
            storage_path: 存储路径，如果为 None 则使用临时存储
            embed_config: 嵌入配置
        """
        self.embedder = CodeEmbedder(embed_config or EmbedConfig())

        if storage_path:
            self.vector_store = FAISSVectorStore(storage_path, embed_config)
        else:
            self.vector_store = None

        self._chunk_cache: Dict[str, List[SemanticSearchResult]] = {}
        self._embedding_cache: Dict[str, List[float]] = {}

    def _generate_chunk_id(self, file_path: str, chunk_index: int) -> str:
        """生成 chunk ID

        Args:
            file_path: 文件路径
            chunk_index: chunk 索引

        Returns:
            chunk ID
        """
        content = f"{file_path}:{chunk_index}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    async def search(
        self,
        query: str,
        top_k: int = 5,
        file_filter: Optional[List[str]] = None,
        language_filter: Optional[str] = None
    ) -> List[SemanticSearchResult]:
        """搜索相关代码块

        Args:
            query: 搜索查询
            top_k: 返回结果数量
            file_filter: 文件路径过滤列表
            language_filter: 语言过滤

        Returns:
            搜索结果列表
        """
        cache_key = f"{query}:{top_k}:{file_filter}:{language_filter}"
        if cache_key in self._chunk_cache:
            return self._chunk_cache[cache_key]

        if not self.vector_store:
            return []

        results = self.vector_store.search(query, top_k)

        semantic_results = []
        for result in results:
            metadata = result.get('metadata', {})

            if file_filter and metadata.get('file_path') not in file_filter:
                continue

            if language_filter and metadata.get('language') != language_filter:
                continue

            semantic_results.append(SemanticSearchResult(
                chunk_id=result['document_id'],
                content=result['content'],
                metadata=metadata,
                similarity=result.get('similarity', 0.0)
            ))

        self._chunk_cache[cache_key] = semantic_results
        return semantic_results

    def index_file(
        self,
        file_path: str,
        content: str,
        language: str,
        chunks: List[Dict[str, Any]]
    ) -> int:
        """索引文件 chunk

        Args:
            file_path: 文件路径
            content: 文件完整内容
            language: 编程语言
            chunks: chunk 列表，每个包含 {content, line_start, line_end, function_name}

        Returns:
            索引的 chunk 数量
        """
        if not self.vector_store:
            return 0

        documents = []
        for i, chunk in enumerate(chunks):
            chunk_id = self._generate_chunk_id(file_path, i)

            metadata = {
                'file_path': file_path,
                'language': language,
                'line_start': chunk.get('line_start', 0),
                'line_end': chunk.get('line_end', 0),
                'function_name': chunk.get('function_name', ''),
                'chunk_index': i
            }

            documents.append({
                'document_id': chunk_id,
                'content': chunk.get('content', ''),
                'metadata': metadata
            })

        if documents:
            self.vector_store.add_documents(documents, build_index=True)

        return len(documents)

    async def search_files_by_keyword(
        self,
        keyword: str,
        files: List[str],
        top_k: int = 10
    ) -> List[Tuple[str, float]]:
        """基于关键词搜索文件

        Args:
            keyword: 关键词
            files: 文件列表
            top_k: 返回结果数量

        Returns:
            (文件路径, 相关度分数) 列表
        """
        scores: Dict[str, float] = {}

        keyword_lower = keyword.lower()

        for file_path in files:
            try:
                path_lower = file_path.lower()
                score = 0.0

                if keyword_lower in path_lower:
                    score += 1.0

                filename = Path(file_path).name.lower()
                if keyword_lower in filename:
                    score += 0.5

                dir_parts = Path(file_path).parts
                for part in dir_parts:
                    if keyword_lower in part:
                        score += 0.3
                        break

                if score > 0:
                    scores[file_path] = score

            except Exception as e:
                logger.debug(f"关键词匹配失败 {file_path}: {e}")
                continue

        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return sorted_scores[:top_k]

    def clear_cache(self) -> None:
        """清空缓存"""
        self._chunk_cache.clear()
        self._embedding_cache.clear()

    def get_index_stats(self) -> Dict[str, Any]:
        """获取索引统计信息

        Returns:
            统计信息字典
        """
        if not self.vector_store:
            return {'total_chunks': 0, 'indexed_files': 0}

        return {
            'total_chunks': len(self.vector_store),
            'indexed_files': len(set(
                d['metadata'].get('file_path', '')
                for d in self.vector_store.get_all_documents()
            ))
        }
