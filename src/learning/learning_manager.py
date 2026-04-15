"""学习管理器模块

协调AI驱动的自学习系统，管理学习过程和知识库更新。
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

from src.learning.ai_learning import AIDrivenLearning, AILearningResult
from src.learning.self_learning import ScanResult, Feedback
from src.storage.rag_knowledge_base import get_rag_knowledge_base
from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)


@dataclass
class LearningStats:
    """学习统计信息"""
    total_scans: int = 0
    total_findings: int = 0
    total_feedbacks: int = 0
    total_patterns: int = 0
    total_knowledge: int = 0
    total_improvements: int = 0
    last_learning_time: Optional[datetime] = None


class LearningManager:
    """学习管理器

    协调AI驱动的自学习系统，管理学习过程和知识库更新。
    """

    _instance: Optional["LearningManager"] = None

    def __new__(cls) -> "LearningManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """初始化学习管理器"""
        if not hasattr(self, "_initialized"):
            self._initialized = True
            self.config = get_config()
            self._ai_learning = AIDrivenLearning(self.config)
            self._rag_knowledge_base = get_rag_knowledge_base()
            self._stats = LearningStats()
            self._knowledge_base_path = Path("./rag_knowledge_base")
            self._load_stats()

    async def learn_from_scan(self, scan_result: ScanResult) -> AILearningResult:
        """从单次扫描结果中学习

        Args:
            scan_result: 扫描结果

        Returns:
            AI学习结果
        """
        try:
            result = await self._ai_learning.learn_from_scan_results([scan_result])
            self._update_stats(scan_result, result)
            
            # 更新到RAG知识库
            for pattern in result.patterns:
                # 注意：RAG知识库可能不支持直接添加pattern，需要转换为knowledge
                from src.learning.self_learning import Knowledge, KnowledgeType
                knowledge = Knowledge(
                    id=pattern.id,
                    knowledge_type=KnowledgeType.PATTERN,
                    content=pattern.pattern_value,
                    source="pattern_learning",
                    confidence=pattern.confidence,
                    tags=[pattern.pattern_type],
                    metadata={
                        "pattern_type": pattern.pattern_type,
                        "occurrence_count": pattern.occurrence_count,
                        "true_positive_count": pattern.true_positive_count,
                        "false_positive_count": pattern.false_positive_count
                    }
                )
                self._rag_knowledge_base.add_knowledge(knowledge)
            for knowledge in result.knowledge:
                self._rag_knowledge_base.add_knowledge(knowledge)
            
            # 注意：RAG知识库可能不需要显式构建知识图谱
            
            self._save_knowledge_base()
            self._save_stats()
            return result
        except Exception as e:
            logger.error(f"从扫描结果学习失败: {e}")
            raise

    async def learn_from_multiple_scans(self, scan_results: List[ScanResult]) -> AILearningResult:
        """从多个扫描结果中学习

        Args:
            scan_results: 扫描结果列表

        Returns:
            AI学习结果
        """
        try:
            result = await self._ai_learning.learn_from_scan_results(scan_results)
            for scan_result in scan_results:
                self._update_stats(scan_result, result)
            
            # 更新到RAG知识库
            for pattern in result.patterns:
                # 注意：RAG知识库可能不支持直接添加pattern，需要转换为knowledge
                from src.learning.self_learning import Knowledge, KnowledgeType
                knowledge = Knowledge(
                    id=pattern.id,
                    knowledge_type=KnowledgeType.PATTERN,
                    content=pattern.pattern_value,
                    source="pattern_learning",
                    confidence=pattern.confidence,
                    tags=[pattern.pattern_type],
                    metadata={
                        "pattern_type": pattern.pattern_type,
                        "occurrence_count": pattern.occurrence_count,
                        "true_positive_count": pattern.true_positive_count,
                        "false_positive_count": pattern.false_positive_count
                    }
                )
                self._rag_knowledge_base.add_knowledge(knowledge)
            for knowledge in result.knowledge:
                self._rag_knowledge_base.add_knowledge(knowledge)
            
            # 注意：RAG知识库可能不需要显式构建知识图谱
            
            self._save_knowledge_base()
            self._save_stats()
            return result
        except Exception as e:
            logger.error(f"从多个扫描结果学习失败: {e}")
            raise

    async def learn_from_feedback(self, feedback: Feedback) -> AILearningResult:
        """从用户反馈中学习

        Args:
            feedback: 用户反馈

        Returns:
            AI学习结果
        """
        try:
            result = await self._ai_learning.learn_from_feedback(feedback)
            self._stats.total_feedbacks += 1
            self._stats.total_improvements += len(result.improvement_suggestions)
            
            # 更新到RAG知识库
            for pattern in result.patterns:
                # 注意：RAG知识库可能不支持直接添加pattern，需要转换为knowledge
                from src.learning.self_learning import Knowledge, KnowledgeType
                knowledge = Knowledge(
                    id=pattern.id,
                    knowledge_type=KnowledgeType.PATTERN,
                    content=pattern.pattern_value,
                    source="pattern_learning",
                    confidence=pattern.confidence,
                    tags=[pattern.pattern_type],
                    metadata={
                        "pattern_type": pattern.pattern_type,
                        "occurrence_count": pattern.occurrence_count,
                        "true_positive_count": pattern.true_positive_count,
                        "false_positive_count": pattern.false_positive_count
                    }
                )
                self._rag_knowledge_base.add_knowledge(knowledge)
            for knowledge in result.knowledge:
                self._rag_knowledge_base.add_knowledge(knowledge)
            
            # 注意：RAG知识库可能不需要显式构建知识图谱
            
            self._save_knowledge_base()
            self._save_stats()
            return result
        except Exception as e:
            logger.error(f"从反馈学习失败: {e}")
            raise

    def get_stats(self) -> LearningStats:
        """获取学习统计信息

        Returns:
            学习统计信息
        """
        return self._stats

    def get_patterns(self) -> List[Dict]:
        """获取所有模式

        Returns:
            模式列表
        """
        patterns = self._ai_learning.get_self_learning().get_all_patterns()
        return [p.to_dict() for p in patterns]

    def get_knowledge(self) -> List[Dict]:
        """获取所有知识

        Returns:
            知识列表
        """
        knowledge = self._ai_learning.get_self_learning().get_all_knowledge()
        return [k.to_dict() for k in knowledge]

    def get_improvement_suggestions(self) -> List[Dict]:
        """获取改进建议

        Returns:
            改进建议列表
        """
        return self._ai_learning.get_self_learning().suggest_rule_improvements()

    def get_knowledge_graph(self) -> Dict[str, List]:
        """获取知识图谱

        Returns:
            知识图谱（节点和边）
        """
        # 注意：RAG知识库可能不提供知识图谱功能
        # 这里返回一个空的知识图谱结构
        return {
            "nodes": [],
            "edges": []
        }

    def search_knowledge(self, query: str) -> List[Dict]:
        """搜索知识

        Args:
            query: 搜索查询

        Returns:
            知识列表
        """
        knowledge_list = self._rag_knowledge_base.search_knowledge(query)
        return [k.to_dict() for k in knowledge_list]

    def get_knowledge_by_type(self, knowledge_type: str) -> List[Dict]:
        """按类型获取知识

        Args:
            knowledge_type: 知识类型

        Returns:
            知识列表
        """
        from src.learning.self_learning import KnowledgeType
        knowledge_list = self._rag_knowledge_base.get_knowledge_by_type(knowledge_type)
        return [k.to_dict() for k in knowledge_list]

    def get_knowledge_by_tag(self, tag: str) -> List[Dict]:
        """按标签获取知识

        Args:
            tag: 标签

        Returns:
            知识列表
        """
        knowledge_list = self._rag_knowledge_base.get_knowledge_by_tag(tag)
        return [k.to_dict() for k in knowledge_list]

    def save_knowledge_base(self, path: Optional[Union[str, Path]] = None) -> None:
        """保存知识库

        Args:
            path: 保存路径
        """
        try:
            self._ai_learning.save_knowledge_base(path)
            logger.info(f"知识库已保存")
        except Exception as e:
            logger.error(f"保存知识库失败: {e}")

    def load_knowledge_base(self, path: Optional[Union[str, Path]] = None) -> None:
        """加载知识库

        Args:
            path: 加载路径
        """
        try:
            self._ai_learning.load_knowledge_base(path)
            logger.info(f"知识库已加载")
            self._update_stats_from_knowledge()
        except Exception as e:
            logger.error(f"加载知识库失败: {e}")

    def _update_stats(self, scan_result: ScanResult, learning_result: AILearningResult):
        """更新统计信息

        Args:
            scan_result: 扫描结果
            learning_result: 学习结果
        """
        self._stats.total_scans += 1
        self._stats.total_findings += len(scan_result.findings)
        self._stats.total_patterns += len(learning_result.patterns)
        self._stats.total_knowledge += len(learning_result.knowledge)
        self._stats.total_improvements += len(learning_result.improvement_suggestions)
        self._stats.last_learning_time = datetime.now()

    def _update_stats_from_knowledge(self):
        """从知识库更新统计信息"""
        patterns = self._ai_learning.get_self_learning().get_all_patterns()
        knowledge = self._ai_learning.get_self_learning().get_all_knowledge()
        self._stats.total_patterns = len(patterns)
        self._stats.total_knowledge = len(knowledge)

    def _save_knowledge_base(self):
        """保存知识库"""
        self._ai_learning.save_knowledge_base(self._knowledge_base_path)

    def _save_stats(self):
        """保存统计信息"""
        stats_path = self._knowledge_base_path / "learning_stats.json"
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        
        import json
        stats_data = {
            "total_scans": self._stats.total_scans,
            "total_findings": self._stats.total_findings,
            "total_feedbacks": self._stats.total_feedbacks,
            "total_patterns": self._stats.total_patterns,
            "total_knowledge": self._stats.total_knowledge,
            "total_improvements": self._stats.total_improvements,
            "last_learning_time": self._stats.last_learning_time.isoformat() if self._stats.last_learning_time else None
        }
        
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(stats_data, f, indent=2, ensure_ascii=False)

    def _load_stats(self):
        """加载统计信息"""
        stats_path = self._knowledge_base_path / "learning_stats.json"
        if stats_path.exists():
            import json
            try:
                with open(stats_path, "r", encoding="utf-8") as f:
                    stats_data = json.load(f)
                
                self._stats.total_scans = stats_data.get("total_scans", 0)
                self._stats.total_findings = stats_data.get("total_findings", 0)
                self._stats.total_feedbacks = stats_data.get("total_feedbacks", 0)
                self._stats.total_patterns = stats_data.get("total_patterns", 0)
                self._stats.total_knowledge = stats_data.get("total_knowledge", 0)
                self._stats.total_improvements = stats_data.get("total_improvements", 0)
                
                last_time = stats_data.get("last_learning_time")
                if last_time:
                    self._stats.last_learning_time = datetime.fromisoformat(last_time)
            except Exception as e:
                logger.error(f"加载统计信息失败: {e}")

    def reset(self):
        """重置学习管理器"""
        self._stats = LearningStats()
        self._ai_learning = AIDrivenLearning(self.config)
        self._save_stats()


# 全局学习管理器实例
_learning_manager: Optional[LearningManager] = None


def get_learning_manager() -> LearningManager:
    """获取全局学习管理器实例

    Returns:
        学习管理器实例
    """
    global _learning_manager
    if _learning_manager is None:
        _learning_manager = LearningManager()
    return _learning_manager
