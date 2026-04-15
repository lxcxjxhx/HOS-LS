"""对话式安全代理模块

提供自然语言交互的安全分析功能。
"""

import asyncio
import re
import time
from typing import Dict, List, Any, Optional, AsyncIterator
from dataclasses import dataclass
from enum import Enum

from rich.console import Console

from src.ai.intent.classifier import AIIntentClassifier
from src.ai.intent.intent_model import IntentType, IntentEntity
from src.ai.entity.extractor import AIEntityExtractor

console = Console()


class Intent(Enum):
    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLAIN = "explain"
    COMPARE = "compare"
    SEARCH = "search"
    HELP = "help"
    EXIT = "exit"
    STATUS = "status"
    RESUME = "resume"
    UNKNOWN = "unknown"


@dataclass
class ConversationMessage:
    role: str
    content: str
    timestamp: float
    metadata: Dict[str, Any]


class ConversationalSecurityAgent:
    """对话式安全代理

    处理自然语言输入，协调多Agent流水线执行安全分析。
    """

    def __init__(self, config: Optional[Any] = None):
        self.config = config
        self.context_memory = None
        self.pipeline = None
        self.ui = None
        self._conversation_history: List[ConversationMessage] = []
        self._last_scan_target: Optional[str] = None
        self._checkpoint_manager = None
        self._incremental_index = None
        self._intent_classifier: Optional[AIIntentClassifier] = None
        self._entity_extractor: Optional[AIEntityExtractor] = None
        self._use_ai = True

    def set_ai_enabled(self, enabled: bool) -> None:
        """设置是否启用AI增强"""
        self._use_ai = enabled

    async def _get_intent_classifier(self) -> AIIntentClassifier:
        """获取意图分类器（延迟初始化）"""
        if self._intent_classifier is None:
            self._intent_classifier = AIIntentClassifier(self.config)
            await self._intent_classifier.initialize()
        return self._intent_classifier

    async def _get_entity_extractor(self) -> AIEntityExtractor:
        """获取实体提取器（延迟初始化）"""
        if self._entity_extractor is None:
            self._entity_extractor = AIEntityExtractor(self.config)
            await self._entity_extractor.initialize()
        return self._entity_extractor

    async def process_message(self, user_input: str) -> str:
        """处理用户消息

        Args:
            user_input: 用户输入的自然语言

        Returns:
            响应字符串
        """
        timestamp = time.time()

        if not user_input or not user_input.strip():
            return "请输入有效的命令或问题。"

        user_input = user_input.strip()

        if user_input.startswith("/"):
            return await self.execute_command(user_input, [])

        intent = await self.analyze_intent(user_input)

        entities = []
        if self.context_memory:
            entities = self.context_memory.extract_entities(user_input)
            for entity in entities:
                self.context_memory.add_entity(entity)

        self._conversation_history.append(ConversationMessage(
            role="user",
            content=user_input,
            timestamp=timestamp,
            metadata={"intent": intent.value if intent else "unknown"}
        ))

        if intent == Intent.SCAN or intent == Intent.ANALYZE:
            target = self._extract_target(user_input)
            self._last_scan_target = target
            response = await self.execute_scan(target, {})
        elif intent == Intent.RESUME:
            response = await self.execute_resume()
        elif intent == Intent.EXPLAIN:
            target = self._extract_target(user_input)
            response = await self.execute_explain(target)
        elif intent == Intent.SEARCH:
            query = self._extract_search_query(user_input)
            response = await self.execute_search(query)
        elif intent == Intent.HELP:
            response = self._get_help_text()
        elif intent == Intent.EXIT:
            response = "再见！"
        elif intent == Intent.STATUS:
            response = await self.execute_status()
        else:
            response = await self.execute_general(user_input)

        self._conversation_history.append(ConversationMessage(
            role="assistant",
            content=response,
            timestamp=time.time(),
            metadata={"intent": intent.value if intent else "unknown"}
        ))

        return response

    async def analyze_intent(self, user_input: str) -> Intent:
        """分析用户意图

        Args:
            user_input: 用户输入

        Returns:
            识别的意图
        """
        if self._use_ai:
            try:
                classifier = await self._get_intent_classifier()
                result = await classifier.classify(user_input)

                if result.is_confident:
                    intent_map = {
                        IntentType.SCAN: Intent.SCAN,
                        IntentType.ANALYZE: Intent.ANALYZE,
                        IntentType.EXPLAIN: Intent.EXPLAIN,
                        IntentType.SEARCH: Intent.SEARCH,
                        IntentType.HELP: Intent.HELP,
                        IntentType.EXIT: Intent.EXIT,
                        IntentType.STATUS: Intent.STATUS,
                        IntentType.RESUME: Intent.RESUME,
                        IntentType.COMPARE: Intent.COMPARE,
                    }
                    return intent_map.get(result.intent, Intent.UNKNOWN)
            except Exception:
                pass

        return self._fallback_intent_match(user_input)

    def _fallback_intent_match(self, user_input: str) -> Intent:
        """Fallback意图匹配（保留原有逻辑）"""
        user_lower = user_input.lower()

        intent_keywords = {
            Intent.SCAN: ["扫描", "scan", "检查", "检测", "analyze"],
            Intent.ANALYZE: ["分析", "深度分析", "详细分析", "详细检查"],
            Intent.EXPLAIN: ["解释", "explain", "说明", "是什么", "什么意思"],
            Intent.SEARCH: ["搜索", "search", "查找", "找", "grep"],
            Intent.HELP: ["帮助", "help", "命令", "如何使用"],
            Intent.EXIT: ["退出", "exit", "quit", "再见"],
            Intent.STATUS: ["状态", "status", "情况", "进度"],
            Intent.RESUME: ["继续", "resume", "恢复", "续扫", "断点"],
        }

        for intent, keywords in intent_keywords.items():
            for keyword in keywords:
                if keyword in user_lower:
                    return intent

        return Intent.UNKNOWN

    def _extract_target(self, user_input: str) -> str:
        """提取目标路径

        Args:
            user_input: 用户输入

        Returns:
            目标路径
        """
        if self._use_ai:
            try:
                import asyncio
                extractor = asyncio.get_event_loop().run_until_complete(
                    self._get_entity_extractor()
                )
                result = extractor.extract(user_input)
                if result.target_path:
                    return result.target_path
            except Exception:
                pass

        patterns = [
            r'(?:扫描|分析|检查)\s+(.+)',
            r'(?:scan|analyze)\s+(.+)',
            r'@file\s+(.+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, user_input)
            if match:
                return match.group(1).strip()

        if self.context_memory:
            entities = self.context_memory.extract_entities(user_input)
            for entity in entities:
                if entity.type == "file":
                    return entity.value

        return "."

    def _extract_search_query(self, user_input: str) -> str:
        """提取搜索查询

        Args:
            user_input: 用户输入

        Returns:
            搜索查询字符串
        """
        patterns = [
            r'(?:搜索|search|查找)\s+["\']?(.+?)["\']?$',
            r'@grep\s+["\']?(.+?)["\']?$',
            r'@search\s+["\']?(.+?)["\']?$',
        ]

        for pattern in patterns:
            match = re.search(pattern, user_input)
            if match:
                return match.group(1).strip()

        return user_input

    async def execute_scan(self, target: str, options: Dict[str, Any]) -> str:
        """执行安全扫描

        Args:
            target: 扫描目标
            options: 扫描选项

        Returns:
            扫描结果
        """
        if self.ui:
            self.ui.print_info(f"正在扫描目标: {target}")

        try:
            if self.config:
                self.config.pure_ai = True

            from src.core.scanner import create_scanner
            scanner = create_scanner(self.config)

            result = await asyncio.wait_for(
                scanner.scan(target),
                timeout=300.0
            )

            finding_count = len(result.findings) if result.findings else 0

            response = f"扫描完成！发现 {finding_count} 个安全问题。"

            if result.findings and self.ui:
                self.ui.print_findings_table([
                    {
                        "rule_name": f.rule_name,
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "location": f"{f.location.file}:{f.location.line}" if hasattr(f.location, 'file') else str(f.location),
                        "description": f.description[:100] if hasattr(f, 'description') else ""
                    }
                    for f in result.findings[:10]
                ])

            return response

        except asyncio.TimeoutError:
            return "扫描超时，请尝试缩小扫描范围。"
        except Exception as e:
            return f"扫描失败: {str(e)}"

    async def execute_resume(self) -> str:
        """执行断点续扫

        Returns:
            续扫结果
        """
        if not self._checkpoint_manager:
            return "无可用的断点信息，请先执行一次完整扫描。"

        try:
            latest = self._checkpoint_manager.get_latest_checkpoint()
            if not latest:
                return "未找到可恢复的断点。"

            if self.ui:
                self.ui.print_info(f"正在从断点恢复: {latest.current_step}")

            if self._incremental_index:
                current_files = self._incremental_index.get_indexed_files()
                changes = self._incremental_index.detect_changes(current_files)

                if not changes["changed"] and not changes["added"]:
                    return "没有检测到文件变更，扫描已完整。"

                target = self._last_scan_target or "."
                return await self.execute_scan(target, {"resume": True})

            return "断点续扫功能暂不可用。"

        except Exception as e:
            return f"恢复失败: {str(e)}"

    async def execute_explain(self, target: str) -> str:
        """执行解释功能

        Args:
            target: 目标路径

        Returns:
            解释结果
        """
        try:
            from src.ai.pure_ai.context_builder import ContextBuilder

            builder = ContextBuilder(self.config)
            context = builder.build_context(target)

            response = f"文件分析: {target}\n\n"
            response += f"- 函数数量: {len(context['file_structure'].get('functions', []))}\n"
            response += f"- 类数量: {len(context['file_structure'].get('classes', []))}\n"
            response += f"- 导入语句: {len(context['imports'])}\n"
            response += f"- 函数调用: {len(context['function_calls'])}\n"

            return response

        except Exception as e:
            return f"解释失败: {str(e)}"

    async def execute_search(self, query: str) -> str:
        """执行搜索功能

        Args:
            query: 搜索查询

        Returns:
            搜索结果
        """
        if self.ui:
            self.ui.print_info(f"搜索: {query}")

        return f"搜索功能开发中，查询内容: {query}"

    async def execute_status(self) -> str:
        """执行状态查询

        Returns:
            系统状态
        """
        status = "系统状态:\n"
        status += f"- 对话历史: {len(self._conversation_history)} 条\n"

        if self.context_memory:
            stats = self.context_memory.get_entity_stats()
            status += f"- 实体数量: {stats.get('total_entities', 0)}\n"
            status += f"- 活跃实体: {stats.get('active_entities', 0)}\n"

        if self._checkpoint_manager:
            checkpoints = self._checkpoint_manager.list_checkpoints()
            status += f"- 断点数量: {len(checkpoints)}\n"

        if self._incremental_index:
            indexed_files = self._incremental_index.get_indexed_files()
            status += f"- 索引文件: {len(indexed_files)}\n"

        return status

    async def execute_general(self, user_input: str) -> str:
        """执行通用查询

        Args:
            user_input: 用户输入

        Returns:
            响应
        """
        return f"我理解您的请求: {user_input[:50]}...\n\n请使用 /help 查看可用命令。"

    async def execute_command(self, command: str, args: List[str]) -> str:
        """执行内置命令

        Args:
            command: 命令
            args: 参数

        Returns:
            命令结果
        """
        command_lower = command.lower()

        if command_lower in ["/help", "/h", "/?"]:
            return self._get_help_text()
        elif command_lower in ["/exit", "/quit", "/q"]:
            return "再见！"
        elif command_lower in ["/clear", "/cls"]:
            self._conversation_history.clear()
            if self.context_memory:
                self.context_memory.clear()
            return "已清除对话历史。"
        elif command_lower in ["/history", "/hist"]:
            return self._get_history_summary()
        elif command_lower.startswith("/scan"):
            target = " ".join(args) if args else self._last_scan_target or "."
            return await self.execute_scan(target, {})
        elif command_lower.startswith("/status"):
            return await self.execute_status()
        elif command_lower.startswith("/resume"):
            return await self.execute_resume()
        else:
            return f"未知命令: {command}，请使用 /help 查看可用命令。"

    def _get_help_text(self) -> str:
        """获取帮助文本"""
        return """可用命令:

  /scan [目标]    - 扫描指定目标（默认当前目录）
  /resume         - 从断点恢复扫描
  /status         - 显示系统状态
  /explain <目标> - 解释文件/函数
  /search <查询>  - 搜索代码
  /history        - 显示对话历史
  /clear          - 清除对话历史
  /exit           - 退出对话

自然语言示例:
  - "扫描 src 目录"
  - "分析 auth.py 文件有什么漏洞"
  - "继续上次的扫描"
  - "这个文件里有什么安全问题"
"""

    def _get_history_summary(self) -> str:
        """获取历史摘要"""
        if not self._conversation_history:
            return "暂无对话历史。"

        recent = self._conversation_history[-10:]
        summary = "最近对话:\n"

        for i, msg in enumerate(recent, 1):
            role = "用户" if msg.role == "user" else "助手"
            content = msg.content[:50] + "..." if len(msg.content) > 50 else msg.content
            summary += f"{i}. [{role}] {content}\n"

        return summary

    async def stream_response(self, user_input: str) -> AsyncIterator[str]:
        """流式响应

        Args:
            user_input: 用户输入

        Yields:
            响应片段
        """
        response = await self.process_message(user_input)

        for chunk in response:
            yield chunk

    def set_context_memory(self, context_memory) -> None:
        """设置上下文记忆管理器"""
        self.context_memory = context_memory

    def set_checkpoint_manager(self, checkpoint_manager) -> None:
        """设置断点管理器"""
        self._checkpoint_manager = checkpoint_manager

    def set_incremental_index(self, incremental_index) -> None:
        """设置增量索引管理器"""
        self._incremental_index = incremental_index

    def set_pipeline(self, pipeline) -> None:
        """设置多Agent流水线"""
        self.pipeline = pipeline

    def set_ui(self, ui) -> None:
        """设置终端UI"""
        self.ui = ui

    def get_conversation_history(self) -> List[ConversationMessage]:
        """获取对话历史"""
        return self._conversation_history.copy()

    def clear_history(self) -> None:
        """清除对话历史"""
        self._conversation_history.clear()

    def should_resume_scan(self) -> bool:
        """检查是否应该恢复扫描"""
        return self._checkpoint_manager is not None and \
               len(self._checkpoint_manager.list_checkpoints()) > 0
