"""增强版会话管理器（Enhanced Conversation Manager）

在原有ConversationManager基础上，集成：
- 上下文记忆系统（实体提取、指代消解、意图链追踪）
- 智能输入预处理
- 增强的上下文摘要生成

提供更智能的多轮对话体验。
"""

from typing import Dict, Any, Optional, List
from pathlib import Path
import os
import json
from datetime import datetime

from src.core.config import Config
from src.core.conversation_manager import (
    ConversationManager,
    Message,
    ConversationHistory,
    PlanState,
    ProjectContext
)
from src.core.context_memory import (
    ConversationMemory,
    MemoryEntity,
    EntityType,
    get_conversation_memory
)


@dataclass
class ProcessedInput:
    """处理后的用户输入"""
    original: str                    # 原始输入
    resolved: str                     # 指代消解后的输入
    intent: Any                      # 解析后的意图
    extracted_entities: List[str]     # 提取到的实体列表
    entities_info: List[Dict]        # 实体详细信息
    was_modified: bool               # 是否被修改过（指代消解）


class EnhancedConversationManager(ConversationManager):
    """增强版会话管理器
    
    在原有功能基础上，新增：
    - 上下文记忆系统
    - 智能指代消解
    - 实体自动提取与记忆
    - 增强的AI Prompt上下文生成
    
    使用示例:
        manager = EnhancedConversationManager(config)
        
        # 处理用户输入（自动提取实体和指代消解）
        processed = manager.process_user_input("扫描它")
        # processed.resolved → "扫描 src/auth/login.py"
        
        # 记录执行结果（自动更新意图链）
        manager.record_execution_result(result)
        
        # 获取增强版上下文（包含记忆信息）
        context = manager.get_enhanced_context_summary()
    """
    
    def __init__(self, config: Config, session_name: str = None):
        """初始化增强版会话管理器
        
        Args:
            config: 配置对象
            session_name: 会话名称
        """
        super().__init__(config, session_name)
        
        # 初始化上下文记忆系统
        self.memory = ConversationMemory()
        
        # 尝试加载已有记忆
        memory_file = self._session_dir / f"{session_name}_memory.json" if session_name else None
        if memory_file and memory_file.exists():
            try:
                self.memory = ConversationMemory.load_from_disk(str(memory_file))
                print(f"✅ 已加载上下文记忆 ({len(self.memory.entities)} 个实体)")
            except Exception as e:
                print(f"⚠️ 加载记忆失败，使用新实例: {e}")
        
        # 统计信息
        self._resolution_count = 0
        self._extraction_count = 0
    
    def process_user_input(self, user_input: str) -> ProcessedInput:
        """处理用户输入（带实体提取和指代消解）
        
        这是增强版的核心方法，在原有解析基础上增加：
        1. 实体提取与记忆
        2. 代词指代消解
        3. 输入规范化
        
        Args:
            user_input: 用户原始输入
            
        Returns:
            ProcessedInput 对象，包含处理后的所有信息
        """
        # 1. 解析意图（使用原有的解析器）
        try:
            from src.core.intent_parser import IntentParser, ParsedIntent
            parser = IntentParser(self.config)
            intent = parser.parse(user_input)
        except Exception as e:
            # 如果解析失败，创建一个默认的intent对象
            class DefaultIntent:
                type = type('IntentType', (object,), {'value': 'unknown'})()
                entities = {}
            
            intent = DefaultIntent()
        
        # 2. 提取并记忆实体
        self.memory.extract_and_memorize(user_input, intent)
        self._extraction_count += 1
        
        # 3. 指代消解
        resolved_input = self.memory.resolve_references(user_input)
        was_modified = (resolved_input != user_input)
        
        if was_modified:
            self._resolution_count += 1
        
        # 4. 构建返回结果
        extracted_entities = self.memory.active_entities[:5]
        entities_info = []
        
        for entity_key in extracted_entities:
            if entity_key in self.memory.entities:
                ent = self.memory.entities[entity_key]
                entities_info.append({
                    'type': ent.entity_type,
                    'value': ent.value,
                    'aliases': ent.aliases[:2],
                    'confidence': ent.confidence
                })
        
        return ProcessedInput(
            original=user_input,
            resolved=resolved_input,
            intent=intent,
            extracted_entities=extracted_entities,
            entities_info=entities_info,
            was_modified=was_modified
        )
    
    def record_execution_result(self, result: Dict[str, Any]):
        """记录执行结果并更新记忆
        
        在原有更新逻辑基础上，额外：
        - 记录到意图链
        - 更新实体引用次数
        - 自动保存记忆（每5次交互）
        
        Args:
            result: 执行结果字典
        """
        # 调用父类的更新方法
        super().update_context(result)
        
        # 提取意图信息
        intent_obj = result.get('intent')
        original_input = result.get('original_input', '')
        success = result.get('success', False)
        summary = result.get('summary', '') or result.get('message', '')[:100]
        
        # 记录到意图链
        if intent_obj or original_input:
            self.memory.track_intent(
                intent=intent_obj or type('Intent', (object,), {'value': result.get('type', 'unknown')})(),
                user_input=original_input,
                success=success,
                result_summary=summary
            )
        
        # 自动保存记忆（每5次交互或重要操作）
        should_save = (self.memory.total_interactions % 5 == 0) or \
                    (result.get('type') in ['scan_result', 'plan_execution_result'])
        
        if should_save:
            self._auto_save_memory()
    
    def get_enhanced_context_summary(self) -> str:
        """获取增强版上下文摘要（包含记忆信息）
        
        Returns:
            格式化的上下文字符串，用于AI Prompt
        """
        # 获取基础上下文
        base_context = super().get_context_summary()
        
        # 获取记忆上下文
        memory_context = self.memory.get_context_for_prompt()
        
        # 合并
        enhanced_context = f"{base_context}\n{memory_context}"
        
        return enhanced_context
    
    def get_active_entities_summary(self) -> str:
        """获取当前活跃实体的简要摘要"""
        if not self.memory.active_entities:
            return "暂无活跃实体"
        
        parts = ["🎯 当前讨论的对象:"]
        
        for i, entity_key in enumerate(self.memory.active_entities[:8], 1):
            if entity_key in self.memory.entities:
                ent = self.memory.entities[entity_key]
                alias_str = f" ({ent.aliases[0]})" if ent.aliases else ""
                ref_count = f"[×{ent.reference_count}]" if ent.reference_count > 1 else ""
                
                parts.append(f"  {i}. [{ent.entity_type}] {ent.value}{alias_str}{ref_count}")
        
        return "\n".join(parts)
    
    def get_recent_intents_summary(self, count: int = 3) -> str:
        """获取最近意图的摘要"""
        recent = self.memory.intent_chain[-count:]
        
        if not recent:
            return "暂无历史操作记录"
        
        parts = [f"📋 最近{min(count, len(recent))}次操作:"]
        
        for node in reversed(recent):
            status = "✅" if node.success else "❌"
            time_ago = self._format_time_ago(node.timestamp)
            
            parts.append(
                f"  {status} [{time_ago}] "
                f"{node.intent_type}: "
                f"{node.intent_text[:50]}{'...' if len(node.intent_text) > 50 else ''}"
            )
        
        return "\n".join(parts)
    
    def resolve_entity_by_alias(self, alias: str) -> Optional[str]:
        """通过别名查找实体
        
        Args:
            alias: 别名或部分匹配字符串
            
        Returns:
            匹配到的实体value，未找到则返回None
        """
        alias_lower = alias.lower()
        
        # 精确匹配别名
        for key, ent in self.memory.entities.items():
            if alias_lower in [a.lower() for a in ent.aliases]:
                return ent.value
        
        # 模糊匹配值
        for key, ent in self.memory.items():
            if alias_lower in ent.value.lower():
                return ent.value
        
        return None
    
    def clear_memory(self):
        """清空所有记忆"""
        self.memory.clear()
        print("🧹 上下文记忆已清空")
    
    def save_session_with_memory(self):
        """保存会话（包括记忆）"""
        super().save_session()
        self._auto_save_memory(force=True)
        print("💾 会话和记忆已保存")
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取增强版统计信息"""
        base_stats = {
            'session_name': self.session_name,
            'message_count': len(self.history.messages),
            'plan_exists': self.plan_state.current_plan is not None
        }
        
        memory_stats = self.memory.get_statistics()
        
        enhanced_stats = {
            **base_stats,
            **memory_stats,
            'pronoun_resolutions': self._resolution_count,
            'entity_extractions': self._extraction_count,
            'memory_file_exists': (self._session_dir / f"{self.session_name}_memory.json").exists() if self.session_name else False
        }
        
        return enhanced_stats
    
    # ========== 私有辅助方法 ==========
    
    def _auto_save_memory(self, force: bool = False):
        """自动保存记忆到磁盘"""
        if not self.session_name:
            return
        
        should_save = force or (self.memory.total_interactions % 5 == 0)
        
        if should_save and self.session_name:
            memory_file = self._session_dir / f"{self.session_name}_memory.json"
            try:
                self.memory.save_to_disk(str(memory_file))
            except Exception as e:
                print(f"⚠️ 记忆保存失败: {e}")
    
    @staticmethod
    def _format_time_ago(dt: datetime) -> str:
        """格式化时间差为可读字符串"""
        delta = datetime.now() - dt
        seconds = int(delta.total_seconds())
        
        if seconds < 60:
            return f"{seconds}秒前"
        elif seconds < 3600:
            return f"{seconds // 60}分钟前"
        elif seconds < 86400:
            return f"{seconds // 3600}小时前"
        else:
            return f"{seconds // 86400}天前"


# ========== 工厂函数 ==========

def create_enhanced_conversation_manager(config: Config, session_name: str = None) -> EnhancedConversationManager:
    """创建增强版会话管理器的工厂函数
    
    Args:
        config: 配置对象
        session_name: 会话名称（可选）
        
    Returns:
        EnhancedConversationManager 实例
    """
    return EnhancedConversationManager(config, session_name)


# ========== 测试代码 ==========

if __name__ == "__main__":
    print("=== 🧪 增强版会话管理器测试 ===\n")
    
    # 创建模拟配置
    class MockConfig:
        pass
    
    config = MockConfig()
    
    # 初始化管理器
    manager = EnhancedConversationManager(config, session_name="test_session")
    
    print("📝 测试1: 用户输入处理")
    test_inputs = [
        "扫描 src/auth/login.py 文件",
        "查看 authenticate_user 函数",
        "修复它",  # 应该被解析为 "修复 src/auth/login.py"
        "分析 SQL注入 漏洞",
        "那个函数有什么问题",  # 应该被解析为 "authenticate_user函数有什么问题"
    ]
    
    for user_input in test_inputs:
        processed = manager.process_user_input(user_input)
        
        status = "🔄 已修改" if processed.was_modified else "✓ 原样"
        print(f"\n   输入: {user_input}")
        print(f"   {status}: {processed.resolved}")
        
        if processed.extracted_entities:
            print(f"   提取实体: {len(processed.extracted_entities)} 个")
            for ent_info in processed.entities_info[:3]:
                print(f"      • [{ent_info['type']}] {ent_info['value']}")
    
    print("\n\n📊 测试2: 统计信息")
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n\n🧠 测试3: 上下文摘要")
    context = manager.get_enhanced_context_summary()
    print(context)
    
    print("\n\n✅ 所有测试完成！")
