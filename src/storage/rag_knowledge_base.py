"""RAG知识库管理模块

实现基于向量存储的RAG知识库，替代传统的knowledge_base，支持语义检索和知识图谱。
"""

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Union, Any

from src.learning.self_learning import Knowledge, KnowledgeType, Pattern
from src.utils.logger import get_logger
from src.core.config import Config, get_config
from src.storage.vector_store import VectorStore

logger = get_logger(__name__)


def validate_json_file(file_path: Path) -> tuple[bool, str | None, Exception | None]:
    """验证JSON文件
    
    Args:
        file_path: JSON文件路径
        
    Returns:
        (是否有效, 错误信息, 异常对象)
    """
    if not file_path.exists():
        return False, "文件不存在", None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # 尝试加载
        data = json.loads(content)
        return True, None, None
    except json.JSONDecodeError as e:
        return False, f"JSON语法错误: {e}", e
    except Exception as e:
        return False, f"文件读取错误: {e}", e


def find_latest_valid_backup(history_path: Path) -> Path | None:
    """查找最近的有效备份
    
    Args:
        history_path: 历史备份目录
        
    Returns:
        最近的有效备份路径，或None
    """
    if not history_path.exists():
        return None
    
    # 获取所有备份目录，按时间倒序
    backup_dirs = sorted(
        [d for d in history_path.iterdir() if d.is_dir()],
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )
    
    for backup_dir in backup_dirs:
        # 检查备份是否有效
        knowledge_valid, _, _ = validate_json_file(backup_dir / "knowledge.json")
        if knowledge_valid:
            return backup_dir
    
    return None


def restore_from_backup(backup_dir: Path, target_dir: Path) -> bool:
    """从备份恢复
    
    Args:
        backup_dir: 备份目录
        target_dir: 目标目录
        
    Returns:
        是否恢复成功
    """
    try:
        # 复制备份文件到目标目录
        for file_name in ["knowledge.json", "patterns.json", "knowledge_graph.json"]:
            src_file = backup_dir / file_name
            if src_file.exists():
                shutil.copy(src_file, target_dir / file_name)
        
        # 复制向量存储
        src_vector = backup_dir / "vector_store"
        if src_vector.exists():
            target_vector = target_dir / "vector_store"
            if target_vector.exists():
                shutil.rmtree(target_vector)
            shutil.copytree(src_vector, target_vector)
        
        logger.info(f"从备份恢复成功: {backup_dir}")
        return True
    except Exception as e:
        logger.error(f"从备份恢复失败: {e}")
        import traceback
        traceback.print_exc()
        return False


@dataclass
class RAGKnowledgeBase:
    """RAG知识库管理系统"""

    def __init__(self, config: Optional[Config] = None, base_path: Optional[Union[str, Path]] = None, model_name: Optional[str] = None):
        """初始化RAG知识库

        Args:
            config: 配置对象
            base_path: 知识库基础路径
            model_name: 嵌入模型名称
        """
        self.config = config or get_config()
        self.base_path = Path(base_path or "./rag_knowledge_base")
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # 知识库文件路径
        self.knowledge_path = self.base_path / "knowledge.json"
        self.patterns_path = self.base_path / "patterns.json"
        self.graph_path = self.base_path / "knowledge_graph.json"
        
        # 版本控制和历史记录
        self.version_path = self.base_path / "version.json"
        self.history_path = self.base_path / "history"
        self.history_path.mkdir(parents=True, exist_ok=True)
        
        # 向量存储
        self.vector_store = VectorStore(self.base_path / "vector_store", model_name=model_name)
        
        # 内存存储
        self._knowledge: Dict[str, Knowledge] = {}
        self._patterns: Dict[str, Pattern] = {}
        self._graph_nodes: Dict[str, Dict] = {}
        self._graph_edges: Dict[str, Dict] = {}
        
        # 索引
        self._type_index: Dict[str, List[str]] = {}
        self._tag_index: Dict[str, List[str]] = {}
        
        # 版本信息
        self.version = 1
        self.history = []
        self.usage_count = 0  # 使用次数计数器
        
        # 内存管理
        self.memory_limit = 2 * 1024 * 1024 * 1024  # 默认内存限制：2GB
        self._memory_usage = 0
        
        # 加载现有数据
        self.load()
        self.load_version_info()
    
    def _reset_knowledge_base(self) -> None:
        """重置知识库到初始状态"""
        logger.warning("重置知识库到初始状态...")
        
        # 清空内存存储
        self._knowledge.clear()
        self._patterns.clear()
        self._graph_nodes.clear()
        self._graph_edges.clear()
        self._type_index.clear()
        self._tag_index.clear()
        
        # 重置版本信息
        self.version = 1
        self.history = []
        self.usage_count = 0
        
        # 清空向量存储
        self.vector_store.clear()
        
        # 删除损坏的文件
        for file_path in [self.knowledge_path, self.patterns_path, self.graph_path]:
            if file_path.exists():
                try:
                    file_path.unlink()
                    logger.info(f"已删除损坏的文件: {file_path}")
                except Exception as e:
                    logger.warning(f"删除文件失败: {file_path} - {e}")
        
        logger.warning("知识库已重置到初始状态")
        
    def _get_memory_usage(self) -> int:
        """获取当前内存使用情况

        Returns:
            当前内存使用量（字节）
        """
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            return 0
    
    def _check_memory_limit(self) -> bool:
        """检查内存使用是否超过限制

        Returns:
            是否超过内存限制
        """
        current_memory = self._get_memory_usage()
        return current_memory < self.memory_limit

    def add_knowledge(self, knowledge: Knowledge) -> str:
        """添加知识

        Args:
            knowledge: 知识对象

        Returns:
            知识ID
        """
        self.record_usage()
        self._knowledge[knowledge.id] = knowledge
        self._update_indexes(knowledge)
        self._add_to_graph(knowledge)
        
        # 添加到向量存储
        self.vector_store.add_document(
            document_id=knowledge.id,
            content=knowledge.content,
            metadata={
                "type": knowledge.knowledge_type.value,
                "source": knowledge.source,
                "tags": knowledge.tags
            }
        )
        
        self.save()
        return knowledge.id
    
    def add_knowledge_batch(self, knowledge_list: List[Knowledge], auto_save: bool = True, build_index: bool = True) -> int:
        """批量添加知识

        Args:
            knowledge_list: 知识对象列表
            auto_save: 是否自动保存
            build_index: 是否立即构建索引

        Returns:
            添加的知识数量
        """
        if not knowledge_list:
            return 0
        
        self.record_usage()
        
        # 检查内存限制
        if not self._check_memory_limit():
            logger.warning("内存使用接近限制，将分批处理")
            # 分批处理 - 使用小 batch 大小以避免 OOM
            import torch
            inject_batch_size = 8  # 关键！使用小 batch 大小以避免 OOM
            total_added = 0
            total_batches = (len(knowledge_list) + inject_batch_size - 1) // inject_batch_size
            
            for i in range(0, len(knowledge_list), inject_batch_size):
                batch = knowledge_list[i:i+inject_batch_size]
                batch_num = i // inject_batch_size + 1
                
                try:
                    # 批量添加到内存存储
                    for knowledge in batch:
                        self._knowledge[knowledge.id] = knowledge
                        self._update_indexes(knowledge)
                        self._add_to_graph(knowledge)
                    
                    # 批量添加到向量存储
                    documents = []
                    for knowledge in batch:
                        documents.append({
                            "document_id": knowledge.id,
                            "content": knowledge.content,
                            "metadata": {
                                "type": knowledge.knowledge_type.value,
                                "source": knowledge.source,
                                "tags": knowledge.tags
                            }
                        })
                    
                    # 批量添加文档到向量存储
                    self.vector_store.add_documents(documents, build_index=build_index)
                    total_added += len(batch)
                    logger.info(f"✅ 成功注入批次 {batch_num}/{total_batches}：{len(batch)} 条")
                except Exception as e:
                    logger.error(f"❌ 批次 {batch_num} 失败: {e}，跳过或重试")
                    continue
                
                # 每批注入后强制清理内存
                import gc
                gc.collect()
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                    logger.info("已清理 GPU 内存")
            
            # 条件性保存
            if auto_save:
                self.save()
            return total_added
        else:
            # 即使内存充足，也使用小 batch 大小以避免 OOM
            import torch
            inject_batch_size = 8  # 关键！使用小 batch 大小以避免 OOM
            total_added = 0
            total_batches = (len(knowledge_list) + inject_batch_size - 1) // inject_batch_size
            
            for i in range(0, len(knowledge_list), inject_batch_size):
                batch = knowledge_list[i:i+inject_batch_size]
                batch_num = i // inject_batch_size + 1
                
                try:
                    # 批量添加到内存存储
                    for knowledge in batch:
                        self._knowledge[knowledge.id] = knowledge
                        self._update_indexes(knowledge)
                        self._add_to_graph(knowledge)
                    
                    # 批量添加到向量存储
                    documents = []
                    for knowledge in batch:
                        documents.append({
                            "document_id": knowledge.id,
                            "content": knowledge.content,
                            "metadata": {
                                "type": knowledge.knowledge_type.value,
                                "source": knowledge.source,
                                "tags": knowledge.tags
                            }
                        })
                    
                    # 批量添加文档到向量存储
                    self.vector_store.add_documents(documents, build_index=build_index)
                    total_added += len(batch)
                    logger.info(f"✅ 成功注入批次 {batch_num}/{total_batches}：{len(batch)} 条")
                except Exception as e:
                    logger.error(f"❌ 批次 {batch_num} 失败: {e}，跳过或重试")
                    continue
                
                # 每批注入后强制清理内存
                import gc
                gc.collect()
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                    logger.info("已清理 GPU 内存")
            
            # 条件性保存
            if auto_save:
                self.save()
            return total_added

    def add_pattern(self, pattern: Pattern) -> str:
        """添加模式

        Args:
            pattern: 模式对象

        Returns:
            模式ID
        """
        self.record_usage()
        self._patterns[pattern.id] = pattern
        self._add_to_graph(pattern)
        
        # 添加到向量存储
        self.vector_store.add_document(
            document_id=pattern.id,
            content=pattern.description,
            metadata={
                "type": "pattern",
                "pattern_type": pattern.pattern_type
            }
        )
        
        self.save()
        return pattern.id

    def get_knowledge(self, knowledge_id: str) -> Optional[Knowledge]:
        """获取知识

        Args:
            knowledge_id: 知识ID

        Returns:
            知识对象
        """
        self.record_usage()
        return self._knowledge.get(knowledge_id)

    def get_pattern(self, pattern_id: str) -> Optional[Pattern]:
        """获取模式

        Args:
            pattern_id: 模式ID

        Returns:
            模式对象
        """
        self.record_usage()
        return self._patterns.get(pattern_id)

    def get_knowledge_by_type(self, knowledge_type: Union[str, KnowledgeType]) -> List[Knowledge]:
        """按类型获取知识

        Args:
            knowledge_type: 知识类型

        Returns:
            知识列表
        """
        type_str = knowledge_type.value if isinstance(knowledge_type, KnowledgeType) else knowledge_type
        ids = self._type_index.get(type_str, [])
        return [self._knowledge.get(id) for id in ids if self._knowledge.get(id)]

    def get_knowledge_by_tag(self, tag: str) -> List[Knowledge]:
        """按标签获取知识

        Args:
            tag: 标签

        Returns:
            知识列表
        """
        ids = self._tag_index.get(tag, [])
        return [self._knowledge.get(id) for id in ids if self._knowledge.get(id)]

    def search_knowledge(self, query: str, top_k: int = 5) -> List[Knowledge]:
        """搜索知识

        Args:
            query: 搜索查询
            top_k: 返回结果数量

        Returns:
            知识列表
        """
        self.record_usage()
        
        # 使用向量存储进行语义搜索
        results = self.vector_store.search(
            query=query,
            top_k=top_k
        )
        
        # 转换为知识对象
        knowledge_results = []
        for result in results:
            knowledge_id = result["document_id"]
            if knowledge_id in self._knowledge:
                knowledge_results.append(self._knowledge[knowledge_id])
            elif knowledge_id in self._patterns:
                # 也可以返回模式
                pass
        
        return knowledge_results

    def search(self, query: str, top_k: int = 5) -> List[Knowledge]:
        """搜索知识（与search_knowledge方法相同）

        Args:
            query: 搜索查询
            top_k: 返回结果数量

        Returns:
            知识列表
        """
        return self.search_knowledge(query, top_k)

    def get_standardized_output(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """获取标准化的输出格式

        Args:
            query: 搜索查询
            top_k: 返回结果数量

        Returns:
            标准化的输出列表
        """
        self.record_usage()
        
        # 使用向量存储进行语义搜索
        results = self.vector_store.search(
            query=query,
            top_k=top_k
        )
        
        # 转换为标准化输出
        output = []
        for result in results:
            knowledge_id = result["document_id"]
            if knowledge_id in self._knowledge:
                knowledge = self._knowledge[knowledge_id]
                output.append({
                    "type": "pattern",
                    "pattern": knowledge.content[:100] + "..." if len(knowledge.content) > 100 else knowledge.content,
                    "risk": knowledge.tags[0] if knowledge.tags else "Unknown",
                    "constraints": [],
                    "evidence": [f"RAG: {knowledge.content[:200]}..." if len(knowledge.content) > 200 else knowledge.content],
                    "source_agent": "RAG-Agent",
                    "confidence": knowledge.confidence,
                    "metadata": {
                        "knowledge_type": knowledge.knowledge_type.value,
                        "source": knowledge.source,
                        "tags": knowledge.tags
                    }
                })
            elif knowledge_id in self._patterns:
                pattern = self._patterns[knowledge_id]
                output.append({
                    "type": "pattern",
                    "pattern": pattern.pattern_value,
                    "risk": pattern.pattern_type,
                    "constraints": [],
                    "evidence": [f"RAG: {pattern.description}"],
                    "source_agent": "RAG-Agent",
                    "confidence": pattern.confidence,
                    "metadata": {
                        "pattern_type": pattern.pattern_type,
                        "occurrence_count": pattern.occurrence_count
                    }
                })
        
        return output

    def update_knowledge(self, knowledge_id: str, **kwargs) -> bool:
        """更新知识

        Args:
            knowledge_id: 知识ID
            **kwargs: 更新的字段

        Returns:
            是否更新成功
        """
        knowledge = self._knowledge.get(knowledge_id)
        if not knowledge:
            return False
        
        # 更新字段
        for key, value in kwargs.items():
            if hasattr(knowledge, key):
                setattr(knowledge, key, value)
        
        knowledge.updated_at = datetime.now()
        self._update_indexes(knowledge)
        
        # 更新向量存储
        self.vector_store.update_document(
            document_id=knowledge_id,
            content=knowledge.content,
            metadata={
                "type": knowledge.knowledge_type.value,
                "source": knowledge.source,
                "tags": knowledge.tags
            }
        )
        
        self.save()
        return True

    def update_pattern(self, pattern_id: str, **kwargs) -> bool:
        """更新模式

        Args:
            pattern_id: 模式ID
            **kwargs: 更新的字段

        Returns:
            是否更新成功
        """
        pattern = self._patterns.get(pattern_id)
        if not pattern:
            return False
        
        # 更新字段
        for key, value in kwargs.items():
            if hasattr(pattern, key):
                setattr(pattern, key, value)
        
        pattern.updated_at = datetime.now()
        
        # 更新向量存储
        self.vector_store.update_document(
            document_id=pattern_id,
            content=pattern.description,
            metadata={
                "type": "pattern",
                "pattern_type": pattern.pattern_type
            }
        )
        
        self.save()
        return True

    def delete_knowledge(self, knowledge_id: str) -> bool:
        """删除知识

        Args:
            knowledge_id: 知识ID

        Returns:
            是否删除成功
        """
        if knowledge_id in self._knowledge:
            del self._knowledge[knowledge_id]
            self._remove_from_indexes(knowledge_id)
            self._remove_from_graph(knowledge_id)
            
            # 从向量存储中删除
            self.vector_store.delete_document(knowledge_id)
            
            self.save()
            return True
        return False

    def delete_pattern(self, pattern_id: str) -> bool:
        """删除模式

        Args:
            pattern_id: 模式ID

        Returns:
            是否删除成功
        """
        if pattern_id in self._patterns:
            del self._patterns[pattern_id]
            self._remove_from_graph(pattern_id)
            
            # 从向量存储中删除
            self.vector_store.delete_document(pattern_id)
            
            self.save()
            return True
        return False

    def get_all_knowledge(self) -> List[Knowledge]:
        """获取所有知识

        Returns:
            知识列表
        """
        return list(self._knowledge.values())

    def get_all_patterns(self) -> List[Pattern]:
        """获取所有模式

        Returns:
            模式列表
        """
        return list(self._patterns.values())

    def get_graph_nodes(self) -> List[Dict]:
        """获取知识图谱节点

        Returns:
            节点列表
        """
        return list(self._graph_nodes.values())

    def get_graph_edges(self) -> List[Dict]:
        """获取知识图谱边

        Returns:
            边列表
        """
        return list(self._graph_edges.values())

    def build_knowledge_graph(self) -> None:
        """构建知识图谱"""
        # 清空现有图谱
        self._graph_nodes.clear()
        self._graph_edges.clear()
        
        # 添加知识节点
        for knowledge in self._knowledge.values():
            self._add_to_graph(knowledge)
        
        # 添加模式节点
        for pattern in self._patterns.values():
            self._add_to_graph(pattern)
        
        # 建立关联
        self._build_relationships()
        
        self.save()

    def save(self, create_backup: bool = True, build_index: bool = True) -> None:
        """保存知识库

        Args:
            create_backup: 是否创建备份
            build_index: 是否构建索引
        """
        import psutil
        process = psutil.Process()
        start_memory = process.memory_info().rss / 1024 / 1024
        
        # 条件性创建备份
        backup_path = None
        if create_backup:
            backup_path = self.create_backup()
        
        # 保存知识
        knowledge_data = [k.to_dict() for k in self._knowledge.values()]
        with open(self.knowledge_path, "w", encoding="utf-8") as f:
            json.dump(knowledge_data, f, indent=2, ensure_ascii=False)
        
        # 保存模式
        pattern_data = [p.to_dict() for p in self._patterns.values()]
        with open(self.patterns_path, "w", encoding="utf-8") as f:
            json.dump(pattern_data, f, indent=2, ensure_ascii=False)
        
        # 保存知识图谱
        graph_data = {
            "nodes": list(self._graph_nodes.values()),
            "edges": list(self._graph_edges.values())
        }
        with open(self.graph_path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
        
        # 条件性构建向量索引
        if build_index:
            self.vector_store.save()
        
        # 更新版本号
        self.version += 1
        
        # 记录保存操作
        self.record_history(
            "save",
            {
                "backup_path": backup_path,
                "knowledge_count": len(self._knowledge),
                "pattern_count": len(self._patterns),
                "graph_nodes_count": len(self._graph_nodes),
                "graph_edges_count": len(self._graph_edges),
                "created_backup": create_backup,
                "built_index": build_index
            }
        )
        
        end_memory = process.memory_info().rss / 1024 / 1024
        logger.info(f"保存完成，内存使用: {end_memory:.2f} MB (变化: {end_memory - start_memory:.2f} MB)")

    def load(self) -> None:
        """加载知识库"""
        logger.info("开始加载知识库...")
        
        # 先进行数据完整性检查
        files_to_check = [
            (self.knowledge_path, "knowledge.json"),
            (self.patterns_path, "patterns.json"),
            (self.graph_path, "knowledge_graph.json"),
        ]
        
        damaged_files = []
        for file_path, file_name in files_to_check:
            if file_path.exists():
                is_valid, error_msg, _ = validate_json_file(file_path)
                if not is_valid:
                    damaged_files.append((file_name, error_msg))
                    logger.error(f"发现损坏的文件: {file_name} - {error_msg}")
        
        # 如果有损坏文件，尝试从备份恢复
        if damaged_files:
            logger.warning("发现损坏的文件，尝试从备份恢复...")
            latest_backup = find_latest_valid_backup(self.history_path)
            if latest_backup:
                logger.info(f"找到有效备份: {latest_backup}")
                # 询问是否恢复（这里我们自动恢复）
                if restore_from_backup(latest_backup, self.base_path):
                    logger.info("从备份恢复成功，重新加载知识库")
                else:
                    logger.error("从备份恢复失败，将重置知识库")
                    # 重置知识库
                    self._reset_knowledge_base()
            else:
                logger.error("没有找到有效备份，将重置知识库")
                self._reset_knowledge_base()
        else:
            logger.info("所有文件完整性检查通过")
        
        # 加载知识
        if self.knowledge_path.exists():
            try:
                with open(self.knowledge_path, "r", encoding="utf-8") as f:
                    knowledge_data = json.load(f)
                for data in knowledge_data:
                    knowledge = Knowledge(
                        id=data["id"],
                        knowledge_type=KnowledgeType(data["knowledge_type"]),
                        content=data["content"],
                        source=data["source"],
                        confidence=data["confidence"],
                        tags=data.get("tags", []),
                        metadata=data.get("metadata", {})
                    )
                    self._knowledge[knowledge.id] = knowledge
                    self._update_indexes(knowledge)
                    
                    # 添加到向量存储
                    self.vector_store.add_document(
                        document_id=knowledge.id,
                        content=knowledge.content,
                        metadata={
                            "type": knowledge.knowledge_type.value,
                            "source": knowledge.source,
                            "tags": knowledge.tags
                        }
                    )
                logger.info(f"成功加载 {len(knowledge_data)} 条知识")
            except Exception as e:
                logger.error(f"加载知识失败: {e}")
                import traceback
                traceback.print_exc()
        
        # 加载模式
        if self.patterns_path.exists():
            try:
                with open(self.patterns_path, "r", encoding="utf-8") as f:
                    pattern_data = json.load(f)
                for data in pattern_data:
                    pattern = Pattern(
                        id=data["id"],
                        pattern_type=data["pattern_type"],
                        pattern_value=data["pattern_value"],
                        description=data["description"],
                        confidence=data["confidence"],
                        occurrence_count=data.get("occurrence_count", 0),
                        true_positive_count=data.get("true_positive_count", 0),
                        false_positive_count=data.get("false_positive_count", 0),
                        metadata=data.get("metadata", {})
                    )
                    self._patterns[pattern.id] = pattern
                    
                    # 添加到向量存储
                    self.vector_store.add_document(
                        document_id=pattern.id,
                        content=pattern.description,
                        metadata={
                            "type": "pattern",
                            "pattern_type": pattern.pattern_type
                        }
                    )
            except Exception as e:
                logger.error(f"加载模式失败: {e}")
        
        # 加载知识图谱
        if self.graph_path.exists():
            try:
                with open(self.graph_path, "r", encoding="utf-8") as f:
                    graph_data = json.load(f)
                
                # 加载节点
                for node_data in graph_data.get("nodes", []):
                    self._graph_nodes[node_data["id"]] = node_data
                
                # 加载边
                for edge_data in graph_data.get("edges", []):
                    self._graph_edges[edge_data["id"]] = edge_data
            except Exception as e:
                logger.error(f"加载知识图谱失败: {e}")

    def load_version_info(self) -> None:
        """加载版本信息"""
        if self.version_path.exists():
            try:
                with open(self.version_path, "r", encoding="utf-8") as f:
                    version_data = json.load(f)
                self.version = version_data.get("version", 1)
                self.history = version_data.get("history", [])
                self.usage_count = version_data.get("usage_count", 0)
            except Exception as e:
                logger.error(f"加载版本信息失败: {e}")

    def save_version_info(self) -> None:
        """保存版本信息"""
        version_data = {
            "version": self.version,
            "history": self.history,
            "usage_count": self.usage_count,
            "last_updated": datetime.now().isoformat()
        }
        with open(self.version_path, "w", encoding="utf-8") as f:
            json.dump(version_data, f, indent=2, ensure_ascii=False)

    def create_backup(self) -> str:
        """创建知识库备份

        Returns:
            备份文件路径
        """
        backup_dir = self.history_path / f"v{self.version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # 备份知识库文件
        if self.knowledge_path.exists():
            shutil.copy(self.knowledge_path, backup_dir / "knowledge.json")
        if self.patterns_path.exists():
            shutil.copy(self.patterns_path, backup_dir / "patterns.json")
        if self.graph_path.exists():
            shutil.copy(self.graph_path, backup_dir / "knowledge_graph.json")
        
        # 备份向量存储
        vector_backup = backup_dir / "vector_store"
        vector_backup.mkdir(parents=True, exist_ok=True)
        if (self.base_path / "vector_store").exists():
            for file in (self.base_path / "vector_store").iterdir():
                if file.is_file():
                    shutil.copy(file, vector_backup / file.name)
        
        return str(backup_dir)

    def record_history(self, action: str, details: Dict[str, Any]) -> None:
        """记录历史操作

        Args:
            action: 操作类型
            details: 操作详情
        """
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "version": self.version,
            "action": action,
            "details": details
        }
        self.history.append(history_entry)
        # 只保留最近100条历史记录
        if len(self.history) > 100:
            self.history = self.history[-100:]
        self.save_version_info()

    def auto_record_learning(self, learning_results: List[Dict[str, Any]]) -> None:
        """自动记录学习结果

        Args:
            learning_results: 学习结果列表
        """
        for result in learning_results:
            # 创建知识对象
            knowledge = Knowledge(
                id=hashlib.sha256(f"{result.get('content', '')}_{datetime.now().isoformat()}".encode()).hexdigest()[:16],
                knowledge_type=KnowledgeType(result.get('knowledge_type', 'ai_learning')),
                content=result.get('content', ''),
                source=result.get('source', 'auto_learning'),
                confidence=result.get('confidence', 0.8),
                tags=result.get('tags', []),
                metadata=result.get('metadata', {})
            )
            
            # 添加到知识库
            self.add_knowledge(knowledge)
            
            # 记录历史
            self.record_history(
                "auto_learning",
                {
                    "knowledge_id": knowledge.id,
                    "knowledge_type": knowledge.knowledge_type.value,
                    "source": knowledge.source
                }
            )

    def get_history(self) -> List[Dict[str, Any]]:
        """获取历史记录

        Returns:
            历史记录列表
        """
        return self.history

    def record_usage(self) -> None:
        """记录知识库使用次数
        
        每次使用知识库时调用此方法，当使用次数达到5的倍数时，自动进行整理。
        """
        self.usage_count += 1
        
        # 检查是否需要整理
        if self.usage_count % 5 == 0:
            logger.info(f"使用次数达到 {self.usage_count}，触发知识库整理")
            self.consolidate_knowledge()
            self.clean_history()
        
        self.save_version_info()

    def consolidate_knowledge(self) -> None:
        """整理知识库，合并同类知识
        
        自动识别和合并同类知识，优化知识库结构，提高查询效率。
        """
        logger.info(f"开始整理知识库，当前知识数量: {len(self._knowledge)}")
        
        # 按类型分组知识
        knowledge_by_type = {}
        for knowledge in self._knowledge.values():
            type_str = knowledge.knowledge_type.value
            if type_str not in knowledge_by_type:
                knowledge_by_type[type_str] = []
            knowledge_by_type[type_str].append(knowledge)
        
        # 合并同类知识
        consolidated_knowledge = {}
        for type_str, knowledge_list in knowledge_by_type.items():
            # 对每个类型的知识进行相似度分析和合并
            merged = self._merge_similar_knowledge(knowledge_list)
            for knowledge in merged:
                consolidated_knowledge[knowledge.id] = knowledge
        
        # 更新知识库
        self._knowledge = consolidated_knowledge
        
        # 重新构建索引和知识图谱
        self._type_index.clear()
        self._tag_index.clear()
        for knowledge in self._knowledge.values():
            self._update_indexes(knowledge)
        
        # 重新构建知识图谱
        self.build_knowledge_graph()
        
        # 重新构建向量存储
        self.vector_store.clear()
        for knowledge in self._knowledge.values():
            self.vector_store.add_document(
                document_id=knowledge.id,
                content=knowledge.content,
                metadata={
                    "type": knowledge.knowledge_type.value,
                    "source": knowledge.source,
                    "tags": knowledge.tags
                }
            )
        for pattern in self._patterns.values():
            self.vector_store.add_document(
                document_id=pattern.id,
                content=pattern.description,
                metadata={
                    "type": "pattern",
                    "pattern_type": pattern.pattern_type
                }
            )
        
        # 保存整理结果
        self.save()
        
        logger.info(f"知识库整理完成，整理后知识数量: {len(self._knowledge)}")
        
        # 记录整理操作
        self.record_history(
            "consolidate",
            {
                "original_count": len(self._knowledge) + len(merged) if 'merged' in locals() else len(self._knowledge),
                "consolidated_count": len(self._knowledge),
                "types": list(knowledge_by_type.keys())
            }
        )

    def clean_history(self) -> None:
        """清理历史记录
        
        删除所有历史备份文件，只保留当前版本的知识库。
        """
        logger.info("开始清理历史记录")
        import time
        
        # 删除所有历史备份目录
        if self.history_path.exists():
            for backup_dir in self.history_path.iterdir():
                if backup_dir.is_dir():
                    # 尝试删除，带有重试机制
                    max_retries = 3
                    retry_delay = 1  # 秒
                    
                    for attempt in range(max_retries):
                        try:
                            shutil.rmtree(backup_dir)
                            logger.info(f"删除历史备份: {backup_dir}")
                            break
                        except PermissionError as e:
                            if attempt < max_retries - 1:
                                logger.warning(f"删除历史备份被拒绝，尝试 {attempt + 1}/{max_retries}，等待 {retry_delay} 秒: {backup_dir}")
                                time.sleep(retry_delay)
                            else:
                                logger.error(f"删除历史备份失败（已达最大重试次数）: {backup_dir}, 错误: {e}")
                        except Exception as e:
                            logger.error(f"删除历史备份失败: {backup_dir}, 错误: {e}")
                            break
        
        # 清空历史记录
        self.history = []
        self.save_version_info()
        
        logger.info("历史记录清理完成")

    def rollback(self, version: int) -> bool:
        """回滚到指定版本

        Args:
            version: 版本号

        Returns:
            是否回滚成功
        """
        # 查找指定版本的备份
        backup_dirs = sorted(self.history_path.iterdir(), reverse=True)
        target_backup = None
        
        for backup_dir in backup_dirs:
            backup_version = int(backup_dir.name.split('_')[0][1:])
            if backup_version <= version:
                target_backup = backup_dir
                break
        
        if not target_backup:
            logger.error(f"找不到版本 {version} 的备份")
            return False
        
        try:
            # 备份当前版本
            self.create_backup()
            
            # 恢复指定版本
            backup_knowledge = target_backup / "knowledge.json"
            backup_patterns = target_backup / "patterns.json"
            backup_graph = target_backup / "knowledge_graph.json"
            backup_vector = target_backup / "vector_store"
            
            if backup_knowledge.exists():
                shutil.copy(backup_knowledge, self.knowledge_path)
            if backup_patterns.exists():
                shutil.copy(backup_patterns, self.patterns_path)
            if backup_graph.exists():
                shutil.copy(backup_graph, self.graph_path)
            if backup_vector.exists():
                vector_store_path = self.base_path / "vector_store"
                if vector_store_path.exists():
                    shutil.rmtree(vector_store_path)
                shutil.copytree(backup_vector, vector_store_path)
            
            # 重新加载数据
            self._knowledge.clear()
            self._patterns.clear()
            self._graph_nodes.clear()
            self._graph_edges.clear()
            self._type_index.clear()
            self._tag_index.clear()
            self.vector_store.clear()
            
            self.load()
            self.version = version
            
            # 记录回滚操作
            self.record_history(
                "rollback",
                {
                    "from_version": self.version,
                    "to_version": version,
                    "backup_path": str(target_backup)
                }
            )
            
            return True
        except Exception as e:
            logger.error(f"回滚失败: {e}")
            return False

    def _update_indexes(self, knowledge: Knowledge) -> None:
        """更新索引"""
        # 类型索引
        type_str = knowledge.knowledge_type.value
        if type_str not in self._type_index:
            self._type_index[type_str] = []
        if knowledge.id not in self._type_index[type_str]:
            self._type_index[type_str].append(knowledge.id)
        
        # 标签索引
        for tag in knowledge.tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = []
            if knowledge.id not in self._tag_index[tag]:
                self._tag_index[tag].append(knowledge.id)

    def _remove_from_indexes(self, knowledge_id: str) -> None:
        """从索引中移除"""
        # 从类型索引中移除
        for type_str, ids in list(self._type_index.items()):
            if knowledge_id in ids:
                ids.remove(knowledge_id)
                if not ids:
                    del self._type_index[type_str]
        
        # 从标签索引中移除
        for tag, ids in list(self._tag_index.items()):
            if knowledge_id in ids:
                ids.remove(knowledge_id)
                if not ids:
                    del self._tag_index[tag]

    def _add_to_graph(self, item: Union[Knowledge, Pattern]) -> None:
        """添加到知识图谱"""
        if isinstance(item, Knowledge):
            node_id = item.id
            node_type = "knowledge"
            content = item.content
            metadata = {
                "type": item.knowledge_type.value,
                "source": item.source,
                "confidence": item.confidence,
                "tags": item.tags,
                "created_at": item.created_at.isoformat() if hasattr(item, 'created_at') else datetime.now().isoformat(),
                "updated_at": item.updated_at.isoformat() if hasattr(item, 'updated_at') else datetime.now().isoformat()
            }
        else:  # Pattern
            node_id = item.id
            node_type = "pattern"
            content = item.description
            metadata = {
                "pattern_type": item.pattern_type,
                "pattern_value": item.pattern_value,
                "confidence": item.confidence,
                "occurrence_count": item.occurrence_count,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
        
        # 创建或更新节点
        self._graph_nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "content": content,
            "metadata": metadata
        }

    def _remove_from_graph(self, item_id: str) -> None:
        """从知识图谱中移除"""
        # 移除节点
        if item_id in self._graph_nodes:
            del self._graph_nodes[item_id]
        
        # 移除相关边
        edges_to_remove = []
        for edge_id, edge in self._graph_edges.items():
            if edge["source"] == item_id or edge["target"] == item_id:
                edges_to_remove.append(edge_id)
        
        for edge_id in edges_to_remove:
            del self._graph_edges[edge_id]

    def _build_relationships(self) -> None:
        """构建知识图谱关系"""
        # 知识之间的关系
        for knowledge1 in self._knowledge.values():
            for knowledge2 in self._knowledge.values():
                if knowledge1.id != knowledge2.id:
                    # 检查内容相似度
                    similarity = self._calculate_similarity(knowledge1.content, knowledge2.content)
                    if similarity > 0.5:
                        edge_id = hashlib.sha256(f"{knowledge1.id}_{knowledge2.id}_related".encode()).hexdigest()[:16]
                        if edge_id not in self._graph_edges:
                            self._graph_edges[edge_id] = {
                                "id": edge_id,
                                "source": knowledge1.id,
                                "target": knowledge2.id,
                                "relationship": "related_to",
                                "weight": similarity,
                                "created_at": datetime.now().isoformat()
                            }
        
        # 知识与模式之间的关系
        for knowledge in self._knowledge.values():
            for pattern in self._patterns.values():
                # 检查模式是否在知识内容中
                if pattern.pattern_value in knowledge.content:
                    edge_id = hashlib.sha256(f"{knowledge.id}_{pattern.id}_contains".encode()).hexdigest()[:16]
                    if edge_id not in self._graph_edges:
                        self._graph_edges[edge_id] = {
                            "id": edge_id,
                            "source": knowledge.id,
                            "target": pattern.id,
                            "relationship": "contains_pattern",
                            "weight": 0.8,
                            "created_at": datetime.now().isoformat()
                        }

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """计算文本相似度

        Args:
            text1: 文本1
            text2: 文本2

        Returns:
            相似度（0-1）
        """
        import re
        from collections import Counter
        
        # 分词
        def tokenize(text):
            return Counter(re.findall(r'\w+', text.lower()))
        
        tokens1 = tokenize(text1)
        tokens2 = tokenize(text2)
        
        # 计算交集
        intersection = set(tokens1.keys()) & set(tokens2.keys())
        if not intersection:
            return 0.0
        
        # 计算Jaccard相似度
        union = set(tokens1.keys()) | set(tokens2.keys())
        return len(intersection) / len(union)

    def _merge_similar_knowledge(self, knowledge_list: List[Knowledge]) -> List[Knowledge]:
        """合并相似的知识

        Args:
            knowledge_list: 知识列表

        Returns:
            合并后的知识列表
        """
        if len(knowledge_list) <= 1:
            return knowledge_list
        
        merged = []
        processed = set()
        
        for i, knowledge1 in enumerate(knowledge_list):
            if i in processed:
                continue
            
            # 查找相似的知识
            similar = [knowledge1]
            for j, knowledge2 in enumerate(knowledge_list):
                if i == j or j in processed:
                    continue
                
                # 计算相似度
                similarity = self._calculate_similarity(
                    knowledge1.content, 
                    knowledge2.content
                )
                
                # 如果相似度高于阈值，则认为是同类知识
                if similarity > 0.6:
                    similar.append(knowledge2)
                    processed.add(j)
            
            # 合并相似的知识
            if len(similar) > 1:
                merged_knowledge = self._merge_knowledge_items(similar)
                merged.append(merged_knowledge)
            else:
                merged.append(knowledge1)
            
            processed.add(i)
        
        return merged

    def _merge_knowledge_items(self, knowledge_items: List[Knowledge]) -> Knowledge:
        """合并多个知识项

        Args:
            knowledge_items: 知识项列表

        Returns:
            合并后的知识项
        """
        # 计算合并后的内容
        contents = [k.content for k in knowledge_items]
        merged_content = " ".join(contents)
        
        # 合并标签
        tags = set()
        for k in knowledge_items:
            tags.update(k.tags)
        
        # 计算平均置信度
        confidence = sum(k.confidence for k in knowledge_items) / len(knowledge_items)
        
        # 合并元数据
        metadata = {}
        for k in knowledge_items:
            metadata.update(k.metadata)
        
        # 创建新的知识项
        merged_id = hashlib.sha256(
            f"merged_{'_'.join(k.id for k in knowledge_items)}".encode()
        ).hexdigest()[:16]
        
        return Knowledge(
            id=merged_id,
            knowledge_type=knowledge_items[0].knowledge_type,
            content=merged_content,
            source="merged_learning",
            confidence=confidence,
            tags=list(tags),
            metadata=metadata
        )


# 全局RAG知识库实例
_rag_knowledge_base: Optional[RAGKnowledgeBase] = None


def get_rag_knowledge_base(model_name: Optional[str] = None) -> RAGKnowledgeBase:
    """获取全局RAG知识库实例

    Args:
        model_name: 嵌入模型名称

    Returns:
        RAG知识库实例
    """
    global _rag_knowledge_base
    if _rag_knowledge_base is None:
        _rag_knowledge_base = RAGKnowledgeBase(model_name=model_name)
    return _rag_knowledge_base
