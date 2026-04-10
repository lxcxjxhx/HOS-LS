"""混合检索器测试"""

import pytest
import tempfile
import shutil
from pathlib import Path
from src.storage.vector_store import VectorStore
from src.storage.hybrid_retriever import HybridRetriever


class TestHybridRetriever:
    """混合检索器测试"""

    def setup_method(self):
        """设置测试环境"""
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / "test_hybrid_retriever"
        # 初始化向量存储
        self.vector_store = VectorStore(self.storage_path / "vector_store")
        # 初始化混合检索器
        self.hybrid_retriever = HybridRetriever(self.storage_path, self.vector_store)

    def teardown_method(self):
        """清理测试环境"""
        # 清理临时目录
        shutil.rmtree(self.temp_dir)

    def test_add_document(self):
        """测试添加文档"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.hybrid_retriever.add_document(document_id, content, metadata)
        # 同时添加到向量存储
        self.vector_store.add_document(document_id, content, metadata)

    def test_add_documents(self):
        """测试批量添加文档"""
        # 批量添加文档
        documents = [
            {
                "document_id": "test_doc_1",
                "content": "测试文档1内容",
                "metadata": {"type": "test", "source": "test_source_1"}
            },
            {
                "document_id": "test_doc_2",
                "content": "测试文档2内容",
                "metadata": {"type": "test", "source": "test_source_2"}
            }
        ]
        self.hybrid_retriever.add_documents(documents)
        # 同时添加到向量存储
        self.vector_store.add_documents(documents)

    def test_update_document(self):
        """测试更新文档"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.hybrid_retriever.add_document(document_id, content, metadata)
        self.vector_store.add_document(document_id, content, metadata)

        # 更新文档
        updated_content = "更新后的测试文档内容"
        updated_metadata = {"type": "test", "source": "updated_source"}
        self.hybrid_retriever.update_document(document_id, updated_content, updated_metadata)
        self.vector_store.update_document(document_id, updated_content, updated_metadata)

    def test_delete_document(self):
        """测试删除文档"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.hybrid_retriever.add_document(document_id, content, metadata)
        self.vector_store.add_document(document_id, content, metadata)

        # 删除文档
        self.hybrid_retriever.delete_document(document_id)
        self.vector_store.delete_document(document_id)

    def test_hybrid_search(self):
        """测试混合搜索"""
        # 添加文档
        documents = [
            {
                "document_id": "test_doc_1",
                "content": "SQL注入漏洞是一种常见的Web应用安全漏洞",
                "metadata": {"type": "vulnerability", "source": "test_source"}
            },
            {
                "document_id": "test_doc_2",
                "content": "XSS攻击是一种注入攻击",
                "metadata": {"type": "attack", "source": "test_source"}
            }
        ]
        self.hybrid_retriever.add_documents(documents)
        self.vector_store.add_documents(documents)

        # 测试混合搜索
        query = "SQL注入"
        results = self.hybrid_retriever.hybrid_search(query, top_k=2)
        assert len(results) > 0

    def test_set_weights(self):
        """测试设置权重"""
        # 设置新权重
        new_weights = {
            "embedding": 0.6,
            "bm25": 0.2,
            "rule": 0.2
        }
        self.hybrid_retriever.set_weights(new_weights)

        # 验证权重是否设置成功
        weights = self.hybrid_retriever.get_weights()
        assert weights["embedding"] == 0.6
        assert weights["bm25"] == 0.2
        assert weights["rule"] == 0.2

    def test_clear(self):
        """测试清空索引"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.hybrid_retriever.add_document(document_id, content, metadata)

        # 清空索引
        self.hybrid_retriever.clear()

    def test_length(self):
        """测试获取文档数量"""
        # 添加文档
        documents = [
            {
                "document_id": "test_doc_1",
                "content": "测试文档1内容",
                "metadata": {"type": "test", "source": "test_source_1"}
            },
            {
                "document_id": "test_doc_2",
                "content": "测试文档2内容",
                "metadata": {"type": "test", "source": "test_source_2"}
            }
        ]
        self.hybrid_retriever.add_documents(documents)

        # 验证文档数量
        assert len(self.hybrid_retriever) == len(documents)
