"""向量存储测试"""

import pytest
import tempfile
import shutil
from pathlib import Path
from src.storage.vector_store import VectorStore


class TestVectorStore:
    """向量存储测试"""

    def setup_method(self):
        """设置测试环境"""
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / "test_vector_store"
        # 初始化向量存储
        self.vector_store = VectorStore(self.storage_path)

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
        self.vector_store.add_document(document_id, content, metadata)

        # 验证文档是否添加成功
        document = self.vector_store.get_document(document_id)
        assert document is not None
        assert document["content"] == content
        assert document["metadata"] == metadata

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
        self.vector_store.add_documents(documents)

        # 验证文档是否添加成功
        all_documents = self.vector_store.get_all_documents()
        assert len(all_documents) == len(documents)

    def test_update_document(self):
        """测试更新文档"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.vector_store.add_document(document_id, content, metadata)

        # 更新文档
        updated_content = "更新后的测试文档内容"
        updated_metadata = {"type": "test", "source": "updated_source"}
        self.vector_store.update_document(document_id, updated_content, updated_metadata)

        # 验证更新是否成功
        updated_document = self.vector_store.get_document(document_id)
        assert updated_document["content"] == updated_content
        assert updated_document["metadata"] == updated_metadata

    def test_delete_document(self):
        """测试删除文档"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.vector_store.add_document(document_id, content, metadata)

        # 删除文档
        self.vector_store.delete_document(document_id)

        # 验证删除是否成功
        deleted_document = self.vector_store.get_document(document_id)
        assert deleted_document is None

    def test_search(self):
        """测试搜索文档"""
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
        self.vector_store.add_documents(documents)

        # 测试搜索
        query = "SQL注入"
        results = self.vector_store.search(query, top_k=2)
        assert len(results) > 0

    def test_save_load(self):
        """测试保存和加载"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.vector_store.add_document(document_id, content, metadata)

        # 保存向量存储
        self.vector_store.save()

        # 创建新的向量存储实例并加载
        new_vector_store = VectorStore(self.storage_path)
        loaded_document = new_vector_store.get_document(document_id)
        assert loaded_document is not None
        assert loaded_document["content"] == content

    def test_clear(self):
        """测试清空向量存储"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.vector_store.add_document(document_id, content, metadata)

        # 清空向量存储
        self.vector_store.clear()

        # 验证清空是否成功
        all_documents = self.vector_store.get_all_documents()
        assert len(all_documents) == 0

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
        self.vector_store.add_documents(documents)

        # 验证文档数量
        assert len(self.vector_store) == len(documents)

    def test_contains(self):
        """测试检查文档是否存在"""
        # 添加文档
        document_id = "test_doc_1"
        content = "测试文档内容"
        metadata = {"type": "test", "source": "test_source"}
        self.vector_store.add_document(document_id, content, metadata)

        # 验证文档是否存在
        assert document_id in self.vector_store
        assert "non_existent_doc" not in self.vector_store
