"""AI驱动的智能意图解析器

核心设计理念：
- 移除所有机械式硬编码关键词匹配
- 采用纯AI语义理解作为主要解析方式
- 仅保留少量明确的特殊命令语法（@file:, @func:, /help等）
- 对于无法识别的输入，默认交给AI处理
- 支持alias system和fuzzy match，提供智能输入纠正
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
import re

# 计算编辑距离的函数
def levenshtein_distance(s1: str, s2: str) -> int:
    """计算两个字符串之间的编辑距离"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


class IntentType(Enum):
    """意图类型枚举"""
    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    FIX = "fix"
    PIPELINE = "pipeline"
    PLAN = "plan"
    GIT = "git"
    INFO = "info"
    CODE_TOOL = "code_tool"
    CONVERSION = "conversion"
    GENERAL = "general"  # 通用对话/AI直接回答
    AI_CHAT = "ai_chat"  # 纯AI对话模式（新增）


class AliasManager:
    """别名管理器"""
    
    # 核心别名映射
    CORE_ALIASES = {
        # yes/no/modify 相关别名
        "y": "yes",
        "n": "no",
        "m": "modify",
        "modif": "modify",
        "ok": "yes",
        "cancel": "no",
        "confirm": "yes",
        "deny": "no",
        "change": "modify",
        # 扫描相关别名
        "扫描": "scan",
        "检测": "scan",
        "漏洞": "scan",
        "安全检查": "scan",
        # AI相关别名
        "ai": "ai_chat",
        "聊天": "ai_chat",
        "对话": "ai_chat",
        # 其他命令别名
        "帮助": "help",
        "退出": "exit",
        "清屏": "clear",
    }
    
    @classmethod
    def resolve_alias(cls, text: str) -> str:
        """解析别名
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的文本
        """
        text = text.strip().lower()
        return cls.CORE_ALIASES.get(text, text)
    
    @classmethod
    def has_alias(cls, text: str) -> bool:
        """检查是否存在别名
        
        Args:
            text: 用户输入文本
            
        Returns:
            是否存在别名
        """
        text = text.strip().lower()
        return text in cls.CORE_ALIASES


class FuzzyMatcher:
    """模糊匹配器"""
    
    # 标准命令列表
    STANDARD_COMMANDS = [
        "yes", "no", "modify", "scan", "ai_chat", "help", "exit", "clear",
        "analyze", "exploit", "fix", "plan", "report"
    ]
    
    @classmethod
    def fuzzy_match(cls, text: str, max_distance: int = 2) -> Optional[str]:
        """模糊匹配命令
        
        Args:
            text: 用户输入文本
            max_distance: 最大编辑距离
            
        Returns:
            匹配的标准命令，如果没有匹配则返回None
        """
        text = text.strip().lower()
        
        # 首先检查精确匹配
        if text in cls.STANDARD_COMMANDS:
            return text
        
        # 计算与每个标准命令的编辑距离
        best_match = None
        best_distance = float('inf')
        
        for command in cls.STANDARD_COMMANDS:
            distance = levenshtein_distance(text, command)
            if distance <= max_distance and distance < best_distance:
                best_match = command
                best_distance = distance
        
        return best_match
    
    @classmethod
    def auto_correct(cls, text: str) -> str:
        """自动纠正输入
        
        Args:
            text: 用户输入文本
            
        Returns:
            纠正后的文本
        """
        # 先尝试别名解析
        resolved = AliasManager.resolve_alias(text)
        if resolved != text:
            return resolved
        
        # 再尝试模糊匹配
        matched = cls.fuzzy_match(text)
        if matched:
            return matched
        
        return text


@dataclass
class ParsedIntent:
    """解析后的意图"""
    type: IntentType
    confidence: float
    entities: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    suggested_pipeline: Optional[List[str]] = None
    sub_intents: Optional[List['ParsedIntent']] = field(default_factory=list)
    
    def __post_init__(self):
        if self.confidence > 1.0:
            self.confidence = 1.0
        elif self.confidence < 0.0:
            self.confidence = 0.0
    
    def has_multiple_intents(self) -> bool:
        """检查是否包含多个意图"""
        return len(self.sub_intents) > 0


class SpecialCommandDetector:
    """特殊命令语法检测器
    
    仅处理明确的、非歧义的命令格式：
    - @file:path - 文件读取
    - @func:name - 函数搜索  
    - /help, /exit, /clear - 系统命令
    """
    
    SPECIAL_PATTERNS = {
        'file_read': re.compile(r'^@file:\s*(.+?)(?:\s|$)', re.IGNORECASE),
        'func_search': re.compile(r'^@func:\s*(.+?)(?:\s|$)', re.IGNORECASE),
        'system_help': re.compile(r'^/help$|^帮助$|^help me$'),
        'system_exit': re.compile(r'^/exit$|^/quit$|^退出$|^q$'),
        'system_clear': re.compile(r'^/clear$|^清屏$|^cls$'),
    }
    
    @classmethod
    def detect(cls, text: str) -> Optional[ParsedIntent]:
        """检测是否为特殊命令
        
        Args:
            text: 用户输入
            
        Returns:
            解析后的意图，如果不是特殊命令则返回None
        """
        text = text.strip()
        
        # 文件读取命令
        match = cls.SPECIAL_PATTERNS['file_read'].match(text)
        if match:
            return ParsedIntent(
                type=IntentType.CODE_TOOL,
                confidence=1.0,
                entities={'action': 'read_file', 'path': match.group(1).strip()},
                raw_text=text,
                suggested_pipeline=None
            )
        
        # 函数搜索命令
        match = cls.SPECIAL_PATTERNS['func_search'].match(text)
        if match:
            return ParsedIntent(
                type=IntentType.CODE_TOOL,
                confidence=1.0,
                entities={'action': 'search_function', 'func_name': match.group(1).strip()},
                raw_text=text,
                suggested_pipeline=None
            )
        
        # 帮助命令
        if cls.SPECIAL_PATTERNS['system_help'].match(text):
            return ParsedIntent(
                type=IntentType.INFO,
                confidence=1.0,
                entities={'topic': 'help'},
                raw_text=text,
                suggested_pipeline=None
            )
        
        # 退出/清屏等系统命令（不进入意图解析流程）
        if cls.SPECIAL_PATTERNS['system_exit'].match(text) or cls.SPECIAL_PATTERNS['system_clear'].match(text):
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=1.0,
                entities={'system_command': text},
                raw_text=text,
                suggested_pipeline=None
            )
        
        return None


class AIIntentParser:
    """基于AI的意图解析器（规则书优化版本）
    
    使用大语言模型进行真正的语义理解，
    配合 PromptRulebook 系统动态组装提示词。
    
    能够区分：
    - "介绍一下C语言安全问题" → 通用知识问答 (AI_CHAT)
    - "扫描当前目录" → 功能调用 (SCAN)
    - "HOS-LS能做什么？" → 工具介绍 (AI_CHAT)
    
    Token优化：使用规则书后，prompt从~600t降至~250t
    """
    
    def __init__(self, ai_client=None):
        self.ai_client = ai_client
        from src.core.prompt_rulebook import HOSLSRulebookFactory
        self.rulebook = HOSLSRulebookFactory.create_intent_parser_rulebook()
    
    async def parse(self, text: str) -> ParsedIntent:
        """使用AI解析用户意图（规则书版本）
        
        Args:
            text: 用户输入文本
            
        Returns:
            AI解析后的意图
        """
        if not self.ai_client:
            return self._fallback_intent(text)
        
        try:
            from src.ai.models import AIRequest
            
            assembled = self.rulebook.assemble_prompt(
                user_input=text,
                max_system_tokens=500
            )
            
            prompt = f"""用户输入: {text}

你是一个智能意图识别助手，负责理解用户的自然语言输入并识别其中的意图。

请仔细分析用户的输入，识别其中的所有意图和需求，包括：
1. 主要意图
2. 子意图（如果有多个步骤）
3. 提取相关实体（如目标路径、文件数量等）

请返回JSON格式（只返回JSON，不要其他内容）:
{{
  "intent": "主要意图类型",
  "confidence": 0.0-1.0,
  "entities": {{
    "user_question": "用户的原始问题（如果是知识问答）",
    "target_path": "目标路径（如果能提取到）",
    "pure_ai": true/false,
    "test_mode": true/false,
    "test_file_count": 数字（如果用户指定了文件数量）
  }},
  "sub_intents": [
    {{
      "intent": "子意图类型",
      "confidence": 0.0-1.0,
      "entities": {{}}
    }}
  ]
}}

意图类型参考：
- scan: 代码安全扫描
- ai_chat: 通用知识问答
- info: 工具咨询
- general: 通用对话

注意：
1. 请使用AI语义理解来识别用户需求，不要使用固定编码识别
2. 如果用户请求包含多个步骤（例如：先回答问题，然后扫描文件），请在 sub_intents 中列出所有子任务
3. 确保识别所有的用户需求，不要遗漏任何步骤
4. 对于包含"然后"、"接着"、"之后"等连接词的请求，通常表示多个步骤
5. 请准确提取用户提到的参数，如文件数量、目标路径等"""

            request = AIRequest(
                prompt=prompt,
                system_prompt=assembled['system'],
                max_tokens=400,
                temperature=0.1
            )
            
            response = await self.ai_client.generate(request)
            result = self._parse_ai_response(response.content)
            
            try:
                intent_type = IntentType(result.get("intent", "general"))
                confidence = float(result.get("confidence", 0.7))
                entities = result.get("entities", {})
                
                # 处理子意图
                sub_intents = []
                for sub_intent_data in result.get("sub_intents", []):
                    try:
                        sub_intent_type = IntentType(sub_intent_data.get("intent", "general"))
                        sub_confidence = float(sub_intent_data.get("confidence", 0.7))
                        sub_entities = sub_intent_data.get("entities", {})
                        
                        sub_intent = ParsedIntent(
                            type=sub_intent_type,
                            confidence=max(0.3, min(sub_confidence, 1.0)),
                            entities=sub_entities,
                            raw_text=text,
                            suggested_pipeline=self._get_suggested_pipeline(sub_intent_type)
                        )
                        sub_intents.append(sub_intent)
                    except (ValueError, TypeError):
                        pass
                
                return ParsedIntent(
                    type=intent_type,
                    confidence=max(0.3, min(confidence, 1.0)),
                    entities=entities,
                    raw_text=text,
                    suggested_pipeline=self._get_suggested_pipeline(intent_type),
                    sub_intents=sub_intents
                )
                
            except (ValueError, TypeError):
                return self._fallback_intent(text)
                
        except Exception as e:
            return self._fallback_intent(text)
    
    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """解析AI响应"""
        import json
        
        content = content.strip()
        
        # 尝试直接解析
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # 提取JSON部分
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
                
        return {"intent": "general", "confidence": 0.5}
    
    def _get_suggested_pipeline(self, intent_type: IntentType) -> Optional[List[str]]:
        """获取建议的Pipeline"""
        pipeline_map = {
            IntentType.SCAN: ["scan", "report"],
            IntentType.ANALYZE: ["scan", "reason", "report"],
            IntentType.EXPLOIT: ["scan", "reason", "poc"],
            IntentType.FIX: ["scan", "reason", "fix"],
            IntentType.AI_CHAT: None,  # AI直接回答，不需要Pipeline
            IntentType.GENERAL: None,
        }
        return pipeline_map.get(intent_type)
    
    def _fallback_intent(self, text: str) -> ParsedIntent:
        """回退意图（当AI不可用时）"""
        # 简单的规则匹配，尝试识别多步骤指令
        sub_intents = []
        
        # 检查是否包含扫描相关的指令
        if any(keyword in text for keyword in ['扫描', 'scan', '检测', '漏洞']):
            sub_intent = ParsedIntent(
                type=IntentType.SCAN,
                confidence=0.7,
                entities={"target_path": ".", "pure_ai": True, "test_mode": True, "test_file_count": 1},
                raw_text=text,
                suggested_pipeline=["scan"]
            )
            sub_intents.append(sub_intent)
        
        # 检查是否包含AI回答相关的指令
        if any(keyword in text for keyword in ['解释', '回答', '说明', '介绍']):
            sub_intent = ParsedIntent(
                type=IntentType.AI_CHAT,
                confidence=0.7,
                entities={"user_question": text},
                raw_text=text,
                suggested_pipeline=None
            )
            sub_intents.append(sub_intent)
        
        return ParsedIntent(
            type=IntentType.GENERAL,
            confidence=0.5,
            entities={"raw_input": text},
            raw_text=text,
            suggested_pipeline=None,
            sub_intents=sub_intents
        )


class IntentParser:
    """统一的意图解析器（AI优先架构）
    
    新的解析流程：
    1. 检测特殊命令语法（@file:, @func:, /help等）→ 直接返回
    2. 调用AI进行语义理解 → 返回AI解析结果
    3. 如果AI不可用 → 返回GENERAL意图，让后续流程自行处理
    """
    
    def __init__(self, ai_client=None):
        self.ai_parser = AIIntentParser(ai_client) if ai_client else None
    
    def parse(self, text: str) -> ParsedIntent:
        """解析用户意图（同步版本）
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的意图对象
        """
        import asyncio
        
        if not text or not text.strip():
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.0,
                raw_text=text
            )
        
        # 第一步：自动纠正输入
        corrected_text = FuzzyMatcher.auto_correct(text)
        if corrected_text != text:
            # 添加纠正信息到实体中
            entities = {"original_input": text, "corrected_input": corrected_text}
        else:
            entities = {}
        
        # 第二步：检测特殊命令语法
        special_intent = SpecialCommandDetector.detect(corrected_text)
        if special_intent:
            # 如果有纠正，将纠正信息添加到实体中
            if entities:
                special_intent.entities.update(entities)
            return special_intent
        
        # 第三步：使用AI解析（核心！）
        if self.ai_parser:
            try:
                ai_intent = asyncio.run(self.ai_parser.parse(corrected_text))
                # 添加纠正信息到实体中
                if entities:
                    ai_intent.entities.update(entities)
                # 检查是否包含多个意图
                if ai_intent.has_multiple_intents():
                    return ai_intent
                # 如果AI没有识别出多个意图，尝试使用规则匹配
                multi_intent = self._detect_multi_intent(corrected_text)
                if multi_intent.has_multiple_intents():
                    # 添加纠正信息到实体中
                    if entities:
                        multi_intent.entities.update(entities)
                    return multi_intent
                return ai_intent
            except Exception as e:
                pass
        
        # 第四步：尝试规则匹配检测多意图
        multi_intent = self._detect_multi_intent(corrected_text)
        if multi_intent.has_multiple_intents():
            # 添加纠正信息到实体中
            if entities:
                multi_intent.entities.update(entities)
            return multi_intent
        
        # 第五步：最终回退（不应该到达这里，除非AI完全不可用）
        final_intent = ParsedIntent(
            type=IntentType.GENERAL,
            confidence=0.3,
            entities={"raw_input": text, **entities},
            raw_text=text,
            suggested_pipeline=None
        )
        return final_intent
    
    def _detect_multi_intent(self, text: str) -> ParsedIntent:
        """使用规则匹配检测多意图
        
        Args:
            text: 用户输入文本
            
        Returns:
            包含多意图的ParsedIntent对象
        """
        sub_intents = []
        
        # 检查是否包含AI回答相关的指令
        if any(keyword in text for keyword in ['解释', '回答', '说明', '介绍', '什么是', '如何', '怎样']):
            sub_intent = ParsedIntent(
                type=IntentType.AI_CHAT,
                confidence=0.8,
                entities={"user_question": text},
                raw_text=text,
                suggested_pipeline=None
            )
            sub_intents.append(sub_intent)
        
        # 检查是否包含扫描相关的指令
        if any(keyword in text for keyword in ['扫描', 'scan', '检测', '漏洞', '安全检查']):
            # 提取目标路径
            target_path = self.extract_target_path(text)
            # 检测是否为纯AI模式
            pure_ai = self.detect_pure_ai_mode(text)
            # 检测是否为测试模式
            test_mode, test_file_count = self.detect_test_mode(text)
            
            sub_intent = ParsedIntent(
                type=IntentType.SCAN,
                confidence=0.8,
                entities={"target_path": target_path, "pure_ai": pure_ai, "test_mode": test_mode, "test_file_count": test_file_count},
                raw_text=text,
                suggested_pipeline=["scan"]
            )
            sub_intents.append(sub_intent)
        
        # 检查是否包含报告相关的指令
        if any(keyword in text for keyword in ['报告', '生成报告', 'report']):
            sub_intent = ParsedIntent(
                type=IntentType.INFO,
                confidence=0.7,
                entities={"topic": "报告生成"},
                raw_text=text,
                suggested_pipeline=["report"]
            )
            sub_intents.append(sub_intent)
        
        # 创建主意图
        if sub_intents:
            # 如果有多个子意图，主意图设为GENERAL
            main_intent = ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.9,
                entities={"raw_input": text},
                raw_text=text,
                suggested_pipeline=None,
                sub_intents=sub_intents
            )
            return main_intent
        else:
            # 如果没有子意图，返回普通意图
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.5,
                entities={"raw_input": text},
                raw_text=text,
                suggested_pipeline=None
            )
    
    async def parse_async(self, text: str) -> ParsedIntent:
        """异步解析用户意图"""
        if not text or not text.strip():
            return ParsedIntent(type=IntentType.GENERAL, confidence=0.0, raw_text=text)
        
        # 第一步：自动纠正输入
        corrected_text = FuzzyMatcher.auto_correct(text)
        if corrected_text != text:
            # 添加纠正信息到实体中
            entities = {"original_input": text, "corrected_input": corrected_text}
        else:
            entities = {}
        
        # 第二步：检测特殊命令语法
        special_intent = SpecialCommandDetector.detect(corrected_text)
        if special_intent:
            # 如果有纠正，将纠正信息添加到实体中
            if entities:
                special_intent.entities.update(entities)
            return special_intent
        
        # 第三步：使用AI解析
        if self.ai_parser:
            ai_intent = await self.ai_parser.parse(corrected_text)
            # 添加纠正信息到实体中
            if entities:
                ai_intent.entities.update(entities)
            # 检查是否包含多个意图
            if ai_intent.has_multiple_intents():
                return ai_intent
            # 如果AI没有识别出多个意图，尝试使用规则匹配
            multi_intent = self._detect_multi_intent(corrected_text)
            if multi_intent.has_multiple_intents():
                # 添加纠正信息到实体中
                if entities:
                    multi_intent.entities.update(entities)
                return multi_intent
            return ai_intent
        
        # 第四步：尝试规则匹配检测多意图
        multi_intent = self._detect_multi_intent(corrected_text)
        if multi_intent.has_multiple_intents():
            # 添加纠正信息到实体中
            if entities:
                multi_intent.entities.update(entities)
            return multi_intent
        
        # 第五步：最终回退
        return ParsedIntent(
            type=IntentType.GENERAL,
            confidence=0.3,
            entities={"raw_input": text, **entities},
            raw_text=text
        )
    
    @staticmethod
    def extract_target_path(text: str) -> str:
        """从文本中提取目标路径"""
        patterns = [
            r'"([a-zA-Z]:\\[\\\w\s.-]+)"',
            r'([a-zA-Z]:\\[\\\w\s.-]+?)(?:\s+(?:的|扫描|分析)|$)',
            r'"(.*?)"',
            r'(?:目录|文件夹|folder)\s*(.+?)(?:\s|$)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                path = match.group(1).strip()
                if path:
                    return path
                    
        return "."
    
    @staticmethod
    def detect_pure_ai_mode(text: str) -> bool:
        """检测是否需要使用纯AI模式"""
        pure_ai_indicators = ['纯', 'pure', 'pure-ai', '轻量', '快速']
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in pure_ai_indicators)
    
    @staticmethod
    def detect_test_mode(text: str) -> tuple:
        """检测测试模式及文件数量"""
        test_match = re.search(r'(?:只|仅|测试)?(?:扫描)?(\d+)个?文件?', text)
        if test_match or '测试' in text or 'test' in text.lower():
            count = int(test_match.group(1)) if test_match else 1
            count = min(count, 5)
            return True, count
        return False, 0
