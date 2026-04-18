"""知识库管理器

管理多个知识库，每个知识库对应一个领域（漏洞类、代码类、规则类）。
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from src.utils.logger import get_logger
from src.storage.rag_knowledge_base import RAGKnowledgeBase, get_rag_knowledge_base
from src.learning.self_learning import Knowledge, KnowledgeType

logger = get_logger(__name__)


class KnowledgeBaseManager:
    """知识库管理器"""

    def __init__(self, base_path: Path):
        """初始化知识库管理器

        Args:
            base_path: 知识库基础路径
        """
        self.base_path = base_path
        self.knowledge_bases: Dict[str, RAGKnowledgeBase] = {}
        self.domain_map = {
            KnowledgeType.VULNERABILITY_DOMAIN.value: "vulnerability",
            KnowledgeType.CODE_DOMAIN.value: "code",
            KnowledgeType.RULE_DOMAIN.value: "rule"
        }
        
        # 初始化各个领域的知识库
        self._init_knowledge_bases()

    def _init_knowledge_bases(self):
        """初始化各个领域的知识库"""
        for domain_type, domain_name in self.domain_map.items():
            try:
                # 为每个领域创建独立的知识库目录
                domain_path = self.base_path / domain_name
                domain_path.mkdir(exist_ok=True, parents=True)
                
                # 初始化知识库
                kb = RAGKnowledgeBase(domain_path)
                self.knowledge_bases[domain_type] = kb
                logger.info(f"成功初始化 {domain_name} 领域知识库")
            except Exception as e:
                logger.error(f"初始化 {domain_name} 领域知识库失败: {e}")

    def get_knowledge_base(self, domain_type: str) -> Optional[RAGKnowledgeBase]:
        """获取指定领域的知识库

        Args:
            domain_type: 领域类型

        Returns:
            知识库实例或None
        """
        return self.knowledge_bases.get(domain_type)

    def add_knowledge(self, knowledge: Knowledge) -> bool:
        """添加知识到相应的领域知识库

        Args:
            knowledge: 知识对象

        Returns:
            是否添加成功
        """
        try:
            # 确定知识所属的领域
            domain_type = self._determine_domain(knowledge)
            kb = self.get_knowledge_base(domain_type)
            
            if kb:
                return kb.add_knowledge(knowledge)
            else:
                logger.error(f"无法找到领域 {domain_type} 对应的知识库")
                return False
        except Exception as e:
            logger.error(f"添加知识失败: {e}")
            return False

    def add_knowledge_batch(self, knowledge_list: List[Knowledge]) -> int:
        """批量添加知识到相应的领域知识库

        Args:
            knowledge_list: 知识对象列表

        Returns:
            添加成功的数量
        """
        success_count = 0
        
        # 按领域分组
        domain_groups = {}
        for knowledge in knowledge_list:
            domain_type = self._determine_domain(knowledge)
            if domain_type not in domain_groups:
                domain_groups[domain_type] = []
            domain_groups[domain_type].append(knowledge)
        
        # 批量添加到各个领域
        for domain_type, group in domain_groups.items():
            kb = self.get_knowledge_base(domain_type)
            if kb:
                try:
                    count = kb.add_knowledge_batch(group)
                    success_count += count
                except Exception as e:
                    logger.error(f"批量添加知识到 {domain_type} 领域失败: {e}")
        
        return success_count

    def search(self, query: str, domain_types: Optional[List[str]] = None, top_k: int = 10) -> List[Dict[str, Any]]:
        """搜索知识

        Args:
            query: 搜索查询
            domain_types: 领域类型列表，None表示搜索所有领域
            top_k: 返回结果数量

        Returns:
            搜索结果列表
        """
        results = []
        
        # 确定要搜索的领域
        if domain_types:
            search_domains = domain_types
        else:
            search_domains = list(self.knowledge_bases.keys())
        
        # 在每个领域中搜索
        for domain_type in search_domains:
            kb = self.get_knowledge_base(domain_type)
            if kb:
                try:
                    domain_results = kb.search(query, top_k=top_k)
                    # 添加领域信息，将Knowledge对象转换为字典
                    for result in domain_results:
                        # 将Knowledge对象转换为字典
                        result_dict = result.to_dict() if hasattr(result, 'to_dict') else {}
                        result_dict['domain'] = domain_type
                        results.append(result_dict)
                except Exception as e:
                    logger.error(f"在 {domain_type} 领域搜索失败: {e}")
        
        # 按相似度排序
        results.sort(key=lambda x: x.get('similarity', 0.0), reverse=True)
        return results[:top_k]

    def _determine_domain(self, knowledge: Knowledge) -> str:
        """确定知识所属的领域

        Args:
            knowledge: 知识对象

        Returns:
            领域类型
        """
        # 根据知识类型确定领域
        knowledge_type = knowledge.knowledge_type.value
        
        if knowledge_type == KnowledgeType.VULNERABILITY.value:
            return KnowledgeType.VULNERABILITY_DOMAIN.value
        elif knowledge_type == KnowledgeType.PATTERN.value:
            return KnowledgeType.CODE_DOMAIN.value
        elif knowledge_type == KnowledgeType.RULE.value:
            return KnowledgeType.RULE_DOMAIN.value
        else:
            # 默认领域
            return KnowledgeType.VULNERABILITY_DOMAIN.value

    def close(self):
        """关闭所有知识库"""
        for domain_type, kb in self.knowledge_bases.items():
            try:
                kb.save()
                logger.info(f"成功保存 {domain_type} 领域知识库")
            except Exception as e:
                logger.error(f"保存 {domain_type} 领域知识库失败: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息
        """
        stats = {}
        for domain_type, kb in self.knowledge_bases.items():
            try:
                stats[domain_type] = {
                    'knowledge_count': len(kb._knowledge),
                    'vector_count': len(kb.vector_store)
                }
            except Exception as e:
                logger.error(f"获取 {domain_type} 领域统计信息失败: {e}")
                stats[domain_type] = {'knowledge_count': 0, 'vector_count': 0}
        return stats


def get_knowledge_base_manager(base_path: Optional[Path] = None) -> KnowledgeBaseManager:
    """获取知识库管理器

    Args:
        base_path: 知识库基础路径

    Returns:
        知识库管理器实例
    """
    if not base_path:
        from src.core.config import get_config
        config = get_config()
        base_path = Path(config.get('rag', {}).get('knowledge_base_path', './rag_knowledge_base'))
    
    return KnowledgeBaseManager(base_path)