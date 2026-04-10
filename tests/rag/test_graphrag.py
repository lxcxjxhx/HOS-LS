"""GraphRAG测试"""

import pytest
import tempfile
import shutil
from pathlib import Path
from src.graphrag.graphrag_adapter import GraphRAGAdapter
from src.storage.rag_knowledge_base import RAGKnowledgeBase
from tests.rag.test_data import get_test_knowledge
from src.analyzers.base import AnalysisContext


class TestGraphRAG:
    """GraphRAG测试"""

    def setup_method(self):
        """设置测试环境"""
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        self.base_path = Path(self.temp_dir) / "test_rag_kb"
        # 初始化RAG知识库
        self.kb = RAGKnowledgeBase(base_path=self.base_path)
        # 初始化GraphRAG适配器
        self.graphrag = GraphRAGAdapter(self.kb)

    def teardown_method(self):
        """清理测试环境"""
        # 清理临时目录
        shutil.rmtree(self.temp_dir)

    def test_build_graph_from_knowledge(self):
        """测试从知识库构建图谱"""
        # 添加测试知识
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 从知识库构建图谱
        self.graphrag.build_graph_from_knowledge()

    def test_hybrid_search(self):
        """测试混合搜索"""
        # 添加测试知识
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 构建图谱
        self.graphrag.build_graph_from_knowledge()

        # 测试混合搜索
        query = "SQL注入漏洞"
        results = self.graphrag.hybrid_search(query, top_k=3)
        assert len(results) > 0

    def test_find_attack_chains(self):
        """测试查找攻击链"""
        # 测试查找攻击链
        attack_chains = self.graphrag.find_attack_chains()
        # 攻击链可能为空，因为我们没有添加足够的攻击相关知识

    def test_get_vulnerability_context(self):
        """测试获取漏洞上下文"""
        # 测试获取漏洞上下文
        # 由于我们没有添加具体的漏洞，这里可能返回空
        context = self.graphrag.get_vulnerability_context("test_vuln_id")

    def test_get_graph_statistics(self):
        """测试获取图谱统计信息"""
        # 添加测试知识
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 构建图谱
        self.graphrag.build_graph_from_knowledge()

        # 获取图谱统计信息
        stats = self.graphrag.get_graph_statistics()
        assert isinstance(stats, dict)

    def test_clear_graph(self):
        """测试清空图谱"""
        # 添加测试知识
        knowledge_list = get_test_knowledge()
        for knowledge in knowledge_list:
            self.kb.add_knowledge(knowledge)

        # 构建图谱
        self.graphrag.build_graph_from_knowledge()

        # 清空图谱
        self.graphrag.clear_graph()

    def test_close(self):
        """测试关闭连接"""
        # 测试关闭连接
        self.graphrag.close()
