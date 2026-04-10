"""RAG知识库测试"""

import pytest
import tempfile
import shutil
from pathlib import Path
from src.storage.rag_knowledge_base import RAGKnowledgeBase
from tests.rag.test_data import get_test_knowledge, get_test_patterns, get_test_query


class TestRAGKnowledgeBase:
    """RAG知识库测试"""

    def setup_method(self):
        """设置测试环境"""
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        self.base_path = Path(self.temp_dir) / "test_rag_kb"
        # 初始化RAG知识库
        self.kb = RAGKnowledgeBase(base_path=self.base_path)

    def teardown_method(self):
        """清理测试环境"""
        # 清理临时目录
        shutil.rmtree(self.temp_dir)

    def test_add_knowledge(self):
        """测试添加知识"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            knowledge_id = self.kb.add_knowledge(knowledge)
            assert knowledge_id == knowledge.id

        # 验证知识是否添加成功
        all_knowledge = self.kb.get_all_knowledge()
        assert len(all_knowledge) == len(knowledge_list)

    def test_add_pattern(self):
        """测试添加模式"""
        pattern_list = get_test_patterns()
        for pattern in pattern_list:
            pattern_id = self.kb.add_pattern(pattern)
            assert pattern_id == pattern.id

        # 验证模式是否添加成功
        all_patterns = self.kb.get_all_patterns()
        assert len(all_patterns) == len(pattern_list)

    def test_get_knowledge(self):
        """测试获取知识"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 测试获取单个知识
        knowledge = self.kb.get_knowledge(knowledge_list[0].id)
        assert knowledge is not None
        assert knowledge.id == knowledge_list[0].id

    def test_get_pattern(self):
        """测试获取模式"""
        pattern_list = get_test_patterns()
        for pattern in pattern_list:
            self.kb.add_pattern(pattern)

        # 测试获取单个模式
        pattern = self.kb.get_pattern(pattern_list[0].id)
        assert pattern is not None
        assert pattern.id == pattern_list[0].id

    def test_search_knowledge(self):
        """测试搜索知识"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 测试搜索
        query = get_test_query()
        results = self.kb.search_knowledge(query, top_k=3)
        assert len(results) > 0

    def test_update_knowledge(self):
        """测试更新知识"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 测试更新知识
        updated_content = "更新后的内容：SQL注入漏洞的详细描述"
        success = self.kb.update_knowledge(knowledge_list[0].id, content=updated_content)
        assert success

        # 验证更新是否成功
        updated_knowledge = self.kb.get_knowledge(knowledge_list[0].id)
        assert updated_knowledge.content == updated_content

    def test_delete_knowledge(self):
        """测试删除知识"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 测试删除知识
        success = self.kb.delete_knowledge(knowledge_list[0].id)
        assert success

        # 验证删除是否成功
        deleted_knowledge = self.kb.get_knowledge(knowledge_list[0].id)
        assert deleted_knowledge is None

    def test_save_load(self):
        """测试保存和加载"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 保存知识库
        self.kb.save()

        # 创建新的知识库实例并加载
        new_kb = RAGKnowledgeBase(base_path=self.base_path)
        loaded_knowledge = new_kb.get_all_knowledge()
        assert len(loaded_knowledge) == len(knowledge_list)

    def test_build_knowledge_graph(self):
        """测试构建知识图谱"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 构建知识图谱
        self.kb.build_knowledge_graph()

        # 验证知识图谱是否构建成功
        nodes = self.kb.get_graph_nodes()
        edges = self.kb.get_graph_edges()
        assert len(nodes) > 0

    def test_consolidate_knowledge(self):
        """测试整理知识库"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 整理知识库
        self.kb.consolidate_knowledge()

        # 验证整理是否成功
        consolidated_knowledge = self.kb.get_all_knowledge()
        assert len(consolidated_knowledge) > 0

    def test_get_standardized_output(self):
        """测试获取标准化输出"""
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 测试获取标准化输出
        query = get_test_query()
        output = self.kb.get_standardized_output(query, top_k=3)
        assert len(output) > 0
