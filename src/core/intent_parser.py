"""AI驱动的智能意图解析器

核心设计理念：
- 移除所有机械式硬编码关键词匹配
- 采用纯AI语义理解作为主要解析方式
- 仅保留少量明确的特殊命令语法（@file:, @func:, /help等）
- 对于无法识别的输入，默认交给AI处理
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
import re


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


@dataclass
class ParsedIntent:
    """解析后的意图"""
    type: IntentType
    confidence: float
    entities: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    suggested_pipeline: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.confidence > 1.0:
            self.confidence = 1.0
        elif self.confidence < 0.0:
            self.confidence = 0.0


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
    """基于AI的意图解析器（唯一的主要解析器）
    
    使用大语言模型进行真正的语义理解，
    能够区分：
    - "介绍一下C语言安全问题" → 通用知识问答 (AI_CHAT)
    - "扫描当前目录" → 功能调用 (SCAN)
    - "HOS-LS能做什么？" → 工具介绍 (AI_CHAT)
    """
    
    def __init__(self, ai_client=None):
        self.ai_client = ai_client
    
    async def parse(self, text: str) -> ParsedIntent:
        """使用AI解析用户意图
        
        Args:
            text: 用户输入文本
            
        Returns:
            AI解析后的意图
        """
        if not self.ai_client:
            return self._fallback_intent(text)
        
        try:
            from src.ai.models import AIRequest
            
            prompt = f"""你是一个用户意图识别专家。请分析用户的真实意图。

用户输入: {text}

可用的意图类型及其含义:
- **scan**: 用户想要执行代码安全扫描、漏洞检测、代码审计
- **analyze**: 用户想要深度分析代码、评估风险、查看详情
- **exploit**: 用户想要生成POC、攻击脚本、验证漏洞
- **fix**: 用户想要修复建议、补丁代码、解决方案
- **plan**: 用户想要生成执行方案、操作计划
- **git**: 用户想要执行Git相关操作
- **info**: 用户想要了解系统功能、使用帮助
- **code_tool**: 用户想要使用代码工具（读取文件、搜索函数等，但必须使用@file:或@func:语法）
- **conversion**: 用户想要CLI和自然语言互转
- **general**: 其他无法分类的请求
- **ai_chat**: 通用知识问答、闲聊、介绍性内容（如"C语言安全问题"、"这个工具能做什么"）

**重要判断原则**:
1. 如果用户问的是**编程语言/技术领域的知识问题**（如"C语言安全问题"、"SQL注入原理"），选择 **ai_chat**
2. 如果用户问的是**关于HOS-LS工具本身的问题**（如"HOS-LS能做什么"、"怎么用"），根据具体内容选择 **info** 或 **ai_chat**
3. 如果用户明确要求**执行某个功能**（如"扫描"、"分析"、"生成POC"），选择对应的功能类型
4. 如果用户只是**闲聊或打招呼**，选择 **ai_chat**

请返回JSON格式（只返回JSON，不要其他内容）:
{{
  "intent": "意图类型",
  "confidence": 0.0-1.0,
  "entities": {{
    "user_question": "用户的原始问题（如果是知识问答）",
    "target_path": "目标路径（如果能提取到）",
    "pure_ai": true/false,
    "test_mode": true/false
  }}
}}"""

            request = AIRequest(
                prompt=prompt,
                system_prompt="你是HOS-LS的意图识别引擎，能够准确理解用户的真实需求，区分功能调用和知识问答。",
                max_tokens=400,
                temperature=0.1  # 低温度确保稳定输出
            )
            
            response = await self.ai_client.generate(request)
            result = self._parse_ai_response(response.content)
            
            try:
                intent_type = IntentType(result.get("intent", "general"))
                confidence = float(result.get("confidence", 0.7))
                entities = result.get("entities", {})
                
                return ParsedIntent(
                    type=intent_type,
                    confidence=max(0.3, min(confidence, 1.0)),
                    entities=entities,
                    raw_text=text,
                    suggested_pipeline=self._get_suggested_pipeline(intent_type)
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
        return ParsedIntent(
            type=IntentType.GENERAL,
            confidence=0.5,
            entities={"raw_input": text},
            raw_text=text,
            suggested_pipeline=None
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
        
        # 第一步：检测特殊命令语法
        special_intent = SpecialCommandDetector.detect(text)
        if special_intent:
            return special_intent
        
        # 第二步：使用AI解析（核心！）
        if self.ai_parser:
            try:
                ai_intent = asyncio.run(self.ai_parser.parse(text))
                return ai_intent
            except Exception as e:
                pass
        
        # 第三步：最终回退（不应该到达这里，除非AI完全不可用）
        return ParsedIntent(
            type=IntentType.GENERAL,
            confidence=0.3,
            entities={"raw_input": text},
            raw_text=text,
            suggested_pipeline=None
        )
    
    async def parse_async(self, text: str) -> ParsedIntent:
        """异步解析用户意图"""
        if not text or not text.strip():
            return ParsedIntent(type=IntentType.GENERAL, confidence=0.0, raw_text=text)
        
        special_intent = SpecialCommandDetector.detect(text)
        if special_intent:
            return special_intent
        
        if self.ai_parser:
            return await self.ai_parser.parse(text)
        
        return ParsedIntent(
            type=IntentType.GENERAL,
            confidence=0.3,
            entities={"raw_input": text},
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
