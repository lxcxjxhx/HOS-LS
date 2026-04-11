"""上下文记忆系统（Context Memory System）

提供多轮对话的智能记忆能力：
- 实体记忆：自动提取并记住文件路径、函数名、变量名等
- 意图链追踪：记录多轮对话的话题转换
- 指代消解：解决"它"、"这个"等代词引用
- 长期记忆：跨会话持久化重要信息

目标效果：
- 多轮对话连贯性评分: 3.0/5 → 4.5+/5
- 口语化理解准确率提升: +25%
"""

import re
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class EntityType(Enum):
    """实体类型"""
    FILE_PATH = "file_path"
    FUNCTION = "function"
    VARIABLE = "variable"
    CONCEPT = "concept"
    MODULE = "module"
    ERROR_TYPE = "error_type"
    USER_MENTION = "user_mention"


@dataclass
class ExtractedEntity:
    """提取到的实体"""
    type: EntityType
    value: str
    alias: str = ""  # 别名或描述
    confidence: float = 1.0  # 置信度 (0-1)
    context: str = ""  # 出现时的上下文


@dataclass
class MemoryEntity:
    """记忆实体
    
    长期存储的实体信息，支持跨轮次引用。
    
    Attributes:
        entity_type: 实体类型
        value: 实体值
        aliases: 别名列表
        confidence: 置信度
        first_seen_at: 首次出现时间
        last_referenced_at: 最后引用时间
        reference_count: 引用次数
        context_snippet: 出现时的上下文片段
        associated_metadata: 关联元数据
    """
    entity_type: str = ""
    value: str = ""
    aliases: List[str] = field(default_factory=list)
    confidence: float = 1.0
    first_seen_at: datetime = field(default_factory=datetime.now)
    last_referenced_at: datetime = field(default_factory=datetime.now)
    reference_count: int = 0
    context_snippet: str = ""
    associated_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'entity_type': self.entity_type,
            'value': self.value,
            'aliases': self.aliases,
            'confidence': self.confidence,
            'first_seen_at': self.first_seen_at.isoformat(),
            'last_referenced_at': self.last_referenced_at.isoformat(),
            'reference_count': self.reference_count,
            'context_snippet': self.context_snippet,
            'associated_metadata': self.associated_metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MemoryEntity':
        return cls(
            entity_type=data.get('entity_type', ''),
            value=data.get('value', ''),
            aliases=data.get('aliases', []),
            confidence=data.get('confidence', 1.0),
            first_seen_at=datetime.fromisoformat(data['first_seen_at']) if data.get('first_seen_at') else datetime.now(),
            last_referenced_at=datetime.fromisoformat(data['last_referenced_at']) if data.get('last_referenced_at') else datetime.now(),
            reference_count=data.get('reference_count', 0),
            context_snippet=data.get('context_snippet', ''),
            associated_metadata=data.get('associated_metadata', {})
        )


@dataclass
class IntentChainNode:
    """意图链节点"""
    intent_type: str = ""
    intent_text: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    entities_extracted: List[str] = field(default_factory=list)
    success: bool = False
    result_summary: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'intent_type': self.intent_type,
            'intent_text': self.intent_text,
            'timestamp': self.timestamp.isoformat(),
            'entities_extracted': self.entities_extracted,
            'success': self.success,
            'result_summary': self.result_summary
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IntentChainNode':
        return cls(
            intent_type=data.get('intent_type', ''),
            intent_text=data.get('intent_text', ''),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else datetime.now(),
            entities_extracted=data.get('entities_extracted', []),
            success=data.get('success', False),
            result_summary=data.get('result_summary', '')
        )


class ConversationMemory:
    """增强版对话记忆系统
    
    管理多轮对话中的实体、意图和上下文。
    
    使用示例:
        memory = ConversationMemory()
        
        # 提取并记忆实体
        memory.extract_and_memorize("扫描 src/auth/login.py", parsed_intent)
        
        # 指代消解
        resolved = memory.resolve_references("修复它")
        # → "修复 src/auth/login.py"
        
        # 记录意图
        memory.track_intent(intent, user_input, True, result_summary)
        
        # 获取上下文用于AI Prompt
        context = memory.get_context_for_prompt()
    """
    
    # 实体提取规则
    ENTITY_EXTRACTION_RULES = {
        EntityType.FILE_PATH: [
            r'["\']?([\w\-./\\]+?\.(?:py|js|ts|jsx|tsx|java|go|rs|c|cpp|h|hpp|cs|rb|php))["\']?',
            r'(?:文件|file)[:\s]+([\w\-./\\]+\.(?:py|js|ts|java))',
            r'@(?:file|func):(\S+)',
            r'[A-Za-z]:\\(?:[\w\-\\]+\.(?:py|js|ts))',
            r'/(?:[\w/]+\.(?:py|js|ts))',
        ],
        EntityType.FUNCTION: [
            r'(?:函数|方法|function|method|def)\s+(\w+)\s*\(?',
            r'(\w+)\s*\(\s*.*\)\s*(?:{|->)',
            r'(?:调用|call|invoke)\s+(\w+)',
        ],
        EntityType.VARIABLE: [
            r'(?:变量|variable)\s+(\w+)',
            r'(?:参数|parameter|param)\s+(\w+)',
        ],
        EntityType.CONCEPT: [
            r'(?:漏洞|vulnerability|CVE-\d+-\d+)',
            r'(?:攻击|attack|exploit)\s*(?:向量|vector|chain)?',
            r'(?:注入|injection)\s*(?:SQL|XSS|CMD)?',
            r'(?:认证|auth|authentication|登录|login)',
            r'(?:授权|authorization|权限|permission)',
        ],
        EntityType.MODULE: [
            r'(?:模块|module|包|package)\s+(\w+)',
            r'(?:库|library|框架|framework)\s+(\w+)',
        ]
    }
    
    # 代词映射表
    PRONOUN_MAP = {
        '它': lambda self: self.active_entities[0] if self.active_entities else None,
        '这个': lambda self: self.active_entities[0] if self.active_entities else None,
        '那个': lambda self: self.active_entities[-1] if self.active_entities else None,
        '刚才那个': lambda self: self._get_last_mentioned_entity(),
        '之前提到的': lambda self: self._get_last_mentioned_entity(),
        '前者': lambda self: self.active_entities[-2] if len(self.active_entities) > 1 else None,
        '后者': lambda self: self.active_entities[-1] if self.active_entities else None,
    }
    
    def __init__(self, max_entities: int = 200, max_intent_chain: int = 20):
        """
        Args:
            max_entities: 最大实体数量
            max_intent_chain: 最大意图链长度
        """
        self.entities: Dict[str, MemoryEntity] = {}  # key = normalized_value
        self.intent_chain: List[IntentChainNode] = []
        self.active_entities: List[str] = []  # 最近使用的实体key列表
        
        self.total_interactions: int = 0
        self.entity_hit_count: int = 0
        
        self._max_entities = max_entities
        self._max_intent_chain = max_intent_chain
    
    def extract_and_memorize(self, user_input: str, parsed_intent=None):
        """从用户输入中提取并记忆实体
        
        Args:
            user_input: 用户输入文本
            parsed_intent: 解析后的意图对象（可选）
        """
        extracted = self._extract_all_entities(user_input)
        
        for entity in extracted:
            normalized_key = self._normalize_key(entity.value)
            
            if normalized_key in self.entities:
                # 更新已有实体
                existing = self.entities[normalized_key]
                existing.last_referenced_at = datetime.now()
                existing.reference_count += 1
                
                if entity.alias and entity.alias not in existing.aliases:
                    existing.aliases.append(entity.alias)
                
                # 更新置信度（取最大值）
                existing.confidence = max(existing.confidence, entity.confidence)
            else:
                # 新实体
                if len(self.entities) >= self._max_entities:
                    # 淘汰最久未使用的实体
                    self._evict_oldest_entity()
                
                self.entities[normalized_key] = MemoryEntity(
                    entity_type=entity.type.value,
                    value=entity.value,
                    aliases=[entity.alias] if entity.alias else [],
                    confidence=entity.confidence,
                    first_seen_at=datetime.now(),
                    last_referenced_at=datetime.now(),
                    context_snippet=user_input[:200]
                )
        
        # 更新活跃实体列表（最近使用的10个）
        self._update_active_entities()
    
    def resolve_references(self, text: str) -> str:
        """解析文本中的指代词
        
        Args:
            text: 包含代词的文本
            
        Returns:
            替换后的文本
        """
        resolved_text = text
        
        for pronoun, resolver in self.PRONOUN_MAP.items():
            if pronoun in resolved_text:
                entity_value = resolver(self)
                
                if entity_value:
                    # 获取实体的完整值
                    entity = self.entities.get(entity_value)
                    display_value = entity.value if entity else entity_value
                    
                    resolved_text = resolved_text.replace(pronoun, display_value, 1)  # 只替换第一个匹配
                    self.entity_hit_count += 1
        
        return resolved_text
    
    def track_intent(self, intent, user_input: str, success: bool, result_summary: str = ""):
        """记录意图到意图链
        
        Args:
            intent: 意图对象
            user_input: 用户输入
            success: 是否成功执行
            result_summary: 结果摘要
        """
        intent_type_str = intent.type.value if hasattr(intent, 'type') else str(intent or 'unknown')
        
        # 安全处理可能为None的输入
        safe_input = (user_input or '')[:200]
        safe_summary = (result_summary or '')[:100]
        
        node = IntentChainNode(
            intent_type=intent_type_str,
            intent_text=safe_input,
            timestamp=datetime.now(),
            entities_extracted=list(self.active_entities[:5]),
            success=success,
            result_summary=safe_summary
        )
        
        self.intent_chain.append(node)
        
        # 限制链长度
        if len(self.intent_chain) > self._max_intent_chain:
            self.intent_chain.pop(0)
        
        self.total_interactions += 1
    
    def get_context_for_prompt(self) -> str:
        """生成用于AI Prompt的上下文字符串"""
        parts = ["\n=== 🧠 上下文记忆 ==="]
        
        # 最近意图（最近3个）
        recent_intents = self.intent_chain[-3:]
        if recent_intents:
            parts.append("\n**最近的操作:**")
            for node in reversed(recent_intents):
                status = "✅" if node.success else "❌"
                parts.append(f"  {status} [{node.intent_type}] {node.intent_text[:60]}")
        
        # 活跃实体（最近5个）
        active_ents = [self.entities[key] for key in self.active_entities[:5] if key in self.entities]
        if active_ents:
            parts.append("\n**正在讨论的对象:**")
            for ent in active_ents:
                aliases_str = f" (别名: {', '.join(ent.aliases[:2])})" if ent.aliases else ""
                parts.append(f"  • [{ent.entity_type}] {ent.value}{aliases_str} (提及{ent.reference_count}次)")
        
        # 统计信息
        parts.append(f"\n**记忆统计:** {len(self.entities)}个实体, {self.total_interactions}次交互")
        
        return "\n".join(parts)
    
    def save_to_disk(self, filepath: str):
        """持久化记忆到磁盘"""
        data = {
            'entities': {k: v.to_dict() for k, v in self.entities.items()},
            'intent_chain': [n.to_dict() for n in self.intent_chain],
            'total_interactions': self.total_interactions,
            'saved_at': datetime.now().isoformat()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    
    @classmethod
    def load_from_disk(cls, filepath: str) -> 'ConversationMemory':
        """从磁盘加载记忆"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        memory = cls.__new__(cls)
        memory.entities = {
            k: MemoryEntity.from_dict(v) 
            for k, v in data.get('entities', {}).items()
        }
        memory.intent_chain = [
            IntentChainNode.from_dict(n) 
            for n in data.get('intent_chain', [])
        ]
        memory.total_interactions = data.get('total_interactions', 0)
        
        # 重建活跃实体列表
        memory._update_active_entities()
        
        return memory
    
    def clear(self):
        """清空所有记忆"""
        self.entities.clear()
        self.intent_chain.clear()
        self.active_entities.clear()
        self.total_interactions = 0
        self.entity_hit_count = 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_refs = sum(e.reference_count for e in self.entities.values())
        hit_rate = (self.entity_hit_count / max(self.total_interactions, 1)) * 100
        
        return {
            'total_entities': len(self.entities),
            'total_intents': len(self.intent_chain),
            'total_interactions': self.total_interactions,
            'entity_references': total_refs,
            'pronoun_resolution_hits': self.entity_hit_count,
            'pronoun_resolution_rate': f"{hit_rate:.1f}%"
        }
    
    # ========== 私有方法 ==========
    
    def _extract_all_entities(self, text: str) -> List[ExtractedEntity]:
        """从文本中提取所有实体"""
        entities = []
        
        for entity_type, patterns in self.ENTITY_EXTRACTION_RULES.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            value = match[0]
                        else:
                            value = match
                        
                        if value and len(value) > 1:  # 过滤太短的匹配
                            entities.append(ExtractedEntity(
                                type=entity_type,
                                value=value,
                                confidence=0.9 if any(
                                    p.startswith(r'(?:文件|函数|变量)') 
                                    for p in patterns
                                ) else 0.7,
                                context=text[:100]
                            ))
                except Exception:
                    continue
        
        return entities
    
    def _normalize_key(self, value: str) -> str:
        """标准化实体键（用于去重）"""
        return value.lower().replace('\\', '/').strip()
    
    def _update_active_entities(self):
        """更新活跃实体列表（按最后引用时间排序）"""
        if not self.entities:
            self.active_entities = []
            return
        
        sorted_entities = sorted(
            self.entities.items(),
            key=lambda x: x[1].last_referenced_at,
            reverse=True
        )
        
        self.active_entities = [key for key, _ in sorted_entities[:10]]
    
    def _evict_oldest_entity(self):
        """淘汰最久未使用的实体"""
        if not self.entities:
            return
        
        oldest_key = min(
            self.entities.keys(),
            key=lambda k: self.entities[k].last_referenced_at
        )
        
        del self.entities[oldest_key]
    
    def _get_last_mentioned_entity(self) -> Optional[str]:
        """获取最后提到的实体"""
        if not self.active_entities:
            return None
        
        # 从意图链中查找最后一个有明确实体的意图
        for node in reversed(self.intent_chain):
            if node.entities_extracted:
                # 返回最后一个在活跃列表中的实体
                for entity_key in reversed(node.entities_extracted):
                    if entity_key in self.entities:
                        return entity_key
        
        return self.active_entities[-1] if self.active_entities else None


# ========== 全局单例 ==========
_global_memory: Optional[ConversationMemory] = None


def get_conversation_memory() -> ConversationMemory:
    """获取全局ConversationMemory实例（单例模式）"""
    global _global_memory
    
    if _global_memory is None:
        _global_memory = ConversationMemory()
    
    return _global_memory


# ========== 测试代码 ==========
if __name__ == "__main__":
    print("=== 🧪 上下文记忆系统测试 ===\n")
    
    memory = ConversationMemory()
    
    # 测试1: 实体提取与记忆
    print("📝 测试1: 实体提取与记忆")
    inputs = [
        "扫描 src/auth/login.py 文件",
        "查看 authenticate_user 函数",
        "分析 SQL注入 漏洞",
        "检查 config 变量"
    ]
    
    for user_input in inputs:
        memory.extract_and_memorize(user_input)
        print(f"   输入: {user_input}")
    
    print(f"\n   已记忆 {len(memory.entities)} 个实体:")
    for key, ent in list(memory.entities.items())[:5]:
        print(f"   • [{ent.entity_type}] {ent.value} (提及{ent.reference_count}次)")
    print()
    
    # 测试2: 指代消解
    print("🔗 测试2: 指代消解")
    test_cases = [
        ("修复它", "修复 src/auth/login.py"),
        ("查看这个函数", "查看 authenticate_user"),
        ("分析那个漏洞", "分析 SQL注入"),
    ]
    
    for original, expected_contains in test_cases:
        resolved = memory.resolve_references(original)
        status = "✅" if expected_contains.split()[-1] in resolved else "❌"
        print(f"   {status} '{original}' → '{resolved}'")
    print()
    
    # 测试3: 意图链追踪
    print("📊 测试3: 意图链追踪")
    
    class MockIntent:
        type = type('IntentType', (object,), {'value': 'scan'})()
    
    for i, user_input in enumerate(inputs):
        memory.track_intent(MockIntent(), user_input, True, f"完成{i+1}")
    
    context = memory.get_context_for_prompt()
    print(context)
    print()
    
    # 测试4: 统计信息
    print("📈 测试4: 统计信息")
    stats = memory.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    print()
    
    print("✅ 所有测试完成！")
