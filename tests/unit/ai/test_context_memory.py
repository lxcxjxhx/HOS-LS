"""上下文记忆管理器测试"""

import pytest
import time
from src.ai.pure_ai.context_memory import (
    ContextMemoryManager,
    Entity,
    ConversationTurn
)


class TestContextMemoryManager:
    """ContextMemoryManager 测试类"""

    @pytest.fixture
    def memory_manager(self):
        """创建上下文记忆管理器实例"""
        return ContextMemoryManager(
            config={"max_entities": 20, "max_history": 10}
        )

    def test_extract_entities(self, memory_manager):
        """测试提取实体"""
        text = """
        Please analyze the file src/main.py and check the function authenticate_user.
        Also look at the class UserValidator in models.py.
        The variable config needs to be checked.
        """

        entities = memory_manager.extract_entities(text)

        file_entities = [e for e in entities if e.type == "file"]
        assert len(file_entities) >= 1
        assert any("src/main.py" in e.name or "src" in e.name for e in file_entities)

        function_entities = [e for e in entities if e.type == "function"]
        assert any("authenticate_user" in e.name for e in function_entities)

        class_entities = [e for e in entities if e.type == "class"]
        assert any("UserValidator" in e.name for e in class_entities)

    def test_resolve_pronouns(self, memory_manager):
        """测试代词解析"""
        memory_manager.extract_entities("Please check the file config.py")

        resolved = memory_manager.resolve_pronouns("Analyze this file for vulnerabilities")

        assert "[file:" in resolved or "config.py" in resolved

    def test_track_intent(self, memory_manager):
        """测试意图跟踪"""
        entities = [
            Entity("file", "test.py", "test.py", time.time(), time.time(), 1)
        ]

        scan_intent = memory_manager.track_intent("scan the codebase", entities)
        assert scan_intent == "scan"

        analyze_intent = memory_manager.track_intent("analyze the security issues", entities)
        assert analyze_intent == "analyze"

        modify_intent = memory_manager.track_intent("modify the function", entities)
        assert modify_intent == "modify"

    def test_add_to_history(self, memory_manager):
        """测试添加历史记录"""
        entities = [
            Entity("file", "test.py", "test.py", time.time(), time.time(), 1)
        ]

        memory_manager.add_to_history(
            user_input="scan the file",
            entities=entities,
            intent="scan",
            response_summary="Scan completed"
        )

        history = memory_manager.get_conversation_history()
        assert len(history) == 1
        assert history[0].user_input == "scan the file"
        assert history[0].intent == "scan"
        assert history[0].response_summary == "Scan completed"

    def test_get_recent_entities(self, memory_manager):
        """测试获取最近实体"""
        text = """
        check src/main.py
        also analyze src/utils.py
        look at function process_data
        """

        memory_manager.extract_entities(text)

        recent = memory_manager.get_recent_entities(limit=5)
        assert len(recent) <= 5
        assert all(isinstance(e, Entity) for e in recent)

    def test_lru_eviction(self, memory_manager):
        """测试 LRU 驱逐机制"""
        limited_manager = ContextMemoryManager(config={"max_entities": 3})

        limited_manager.extract_entities("analyze file1.py")
        time.sleep(0.01)
        limited_manager.extract_entities("check file2.py")
        time.sleep(0.01)
        limited_manager.extract_entities("review file3.py")
        time.sleep(0.01)

        assert len(limited_manager._entities) <= 3

        limited_manager.extract_entities("scan file4.py")

        assert len(limited_manager._entities) <= 3

        entity_names = [e.name for e in limited_manager._entities.values()]
        assert "file4.py" in entity_names or "file3.py" in entity_names
        assert "file1.py" not in entity_names or "file2.py" in entity_names
