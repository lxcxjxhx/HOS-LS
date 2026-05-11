"""向量存储统一接口模块

提供统一的向量存储接口，支持多种实现（numpy/FAISS）。
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from pathlib import Path

from src.ai.pure_ai.rag.code_embedder import EmbedConfig


class VectorStoreBase(ABC):
    """向量存储基类接口

    定义所有向量存储实现必须遵循的接口。
    """

    @abstractmethod
    def add_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """添加文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        pass

    @abstractmethod
    def add_documents(self, documents: List[Dict[str, Any]], build_index: bool = True) -> None:
        """批量添加文档

        Args:
            documents: 文档列表，每个文档包含 document_id, content, metadata
            build_index: 是否立即构建索引并保存
        """
        pass

    @abstractmethod
    def update_document(self, document_id: str, content: str, metadata: Dict[str, Any]) -> None:
        """更新文档

        Args:
            document_id: 文档ID
            content: 文档内容
            metadata: 文档元数据
        """
        pass

    @abstractmethod
    def delete_document(self, document_id: str) -> None:
        """删除文档

        Args:
            document_id: 文档ID
        """
        pass

    @abstractmethod
    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """搜索文档

        Args:
            query: 查询文本
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        pass

    @abstractmethod
    def get_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        """获取文档

        Args:
            document_id: 文档ID

        Returns:
            文档信息
        """
        pass

    @abstractmethod
    def get_all_documents(self) -> List[Dict[str, Any]]:
        """获取所有文档

        Returns:
            文档列表
        """
        pass

    @abstractmethod
    def clear(self) -> None:
        """清空向量存储"""
        pass

    @abstractmethod
    def save(self) -> None:
        """保存向量存储"""
        pass

    @abstractmethod
    def load(self) -> None:
        """加载向量存储"""
        pass

    @abstractmethod
    def __len__(self) -> int:
        """获取文档数量"""
        pass

    @abstractmethod
    def __contains__(self, document_id: str) -> bool:
        """检查文档是否存在

        Args:
            document_id: 文档ID

        Returns:
            是否存在
        """
        pass


class VectorStoreFactory:
    """向量存储工厂类

    根据配置创建合适的向量存储实现。
    """

    _IMPLEMENTATIONS = {
        'numpy': 'src.storage.vector_store.VectorStore',
        'faiss': 'src.storage.faiss_vector_store.FAISSVectorStore',
    }

    _instance_cache: Dict[str, VectorStoreBase] = {}

    @classmethod
    def create(
        cls,
        implementation: str = 'numpy',
        storage_path: Optional[Path] = None,
        model_name: Optional[str] = None,
        custom_model_path: Optional[str] = None,
        embed_config: Optional[EmbedConfig] = None,
        neo4j_config: Optional[Dict] = None
    ) -> VectorStoreBase:
        """创建向量存储实例

        Args:
            implementation: 实现类型 ('numpy' 或 'faiss')
            storage_path: 存储路径
            model_name: 嵌入模型名称（用于 numpy 实现）
            custom_model_path: 自定义模型路径
            embed_config: 嵌入配置（用于 FAISS 实现）
            neo4j_config: Neo4j 配置（用于 FAISS 实现）

        Returns:
            向量存储实例

        Raises:
            ValueError: 不支持的实现类型
        """
        if implementation not in cls._IMPLEMENTATIONS:
            raise ValueError(
                f"Unsupported implementation: {implementation}. "
                f"Available: {list(cls._IMPLEMENTATIONS.keys())}"
            )

        cache_key = f"{implementation}:{storage_path}"
        if cache_key in cls._instance_cache:
            return cls._instance_cache[cache_key]

        if implementation == 'numpy':
            from src.ai.pure_ai.rag.vector_store import VectorStore
            instance = VectorStore(
                storage_path=storage_path,
                model_name=model_name,
                custom_model_path=custom_model_path
            )
        elif implementation == 'faiss':
            from src.ai.pure_ai.rag.faiss_vector_store import FAISSVectorStore
            instance = FAISSVectorStore(
                storage_path=storage_path,
                embed_config=embed_config,
                neo4j_config=neo4j_config
            )

        cls._instance_cache[cache_key] = instance
        return instance

    @classmethod
    def create_auto(
        cls,
        storage_path: Path,
        prefer_faiss: bool = True,
        **kwargs
    ) -> VectorStoreBase:
        """自动选择最佳实现

        Args:
            storage_path: 存储路径
            prefer_faiss: 是否优先使用 FAISS
            **kwargs: 传递给具体实现的参数

        Returns:
            向量存储实例
        """
        if prefer_faiss:
            try:
                import faiss
                return cls.create('faiss', storage_path=storage_path, **kwargs)
            except ImportError:
                pass

        return cls.create('numpy', storage_path=storage_path, **kwargs)

    @classmethod
    def register_implementation(cls, name: str, class_path: str) -> None:
        """注册新的实现类型

        Args:
            name: 实现名称
            class_path: 类的完整路径
        """
        cls._IMPLEMENTATIONS[name] = class_path

    @classmethod
    def clear_cache(cls) -> None:
        """清除实例缓存"""
        cls._instance_cache.clear()

    @classmethod
    def list_implementations(cls) -> List[str]:
        """列出所有可用的实现

        Returns:
            实现名称列表
        """
        return list(cls._IMPLEMENTATIONS.keys())


def get_vector_store(
    storage_path: Path,
    use_faiss: bool = True,
    **kwargs
) -> VectorStoreBase:
    """获取向量存储实例的便捷函数

    Args:
        storage_path: 存储路径
        use_faiss: 是否使用 FAISS 实现
        **kwargs: 传递给工厂的其他参数

    Returns:
        向量存储实例
    """
    return VectorStoreFactory.create_auto(
        storage_path=storage_path,
        prefer_faiss=use_faiss,
        **kwargs
    )