"""智能意图解析器

结合规则匹配和AI理解，准确解析用户意图。
支持中英文混合输入，提供置信度评估。
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
    PIPELINE = "pipeline"  # Agent Pipeline相关
    PLAN = "plan"  # Plan管理相关
    GIT = "git"
    INFO = "info"
    CODE_TOOL = "code_tool"  # 代码库工具
    CONVERSION = "conversion"  # CLI/自然语言转换
    GENERAL = "general"


@dataclass
class ParsedIntent:
    """解析后的意图"""
    type: IntentType
    confidence: float  # 0.0 - 1.0
    entities: Dict[str, Any] = field(default_factory=dict)  # 提取的实体（路径、参数等）
    raw_text: str = ""
    suggested_pipeline: Optional[List[str]] = None  # 建议的Pipeline
    
    def __post_init__(self):
        if self.confidence > 1.0:
            self.confidence = 1.0
        elif self.confidence < 0.0:
            self.confidence = 0.0


class RuleBasedIntentParser:
    """基于规则的意图解析器"""
    
    INTENT_PATTERNS = {
        IntentType.SCAN: {
            "keywords": {
                "zh": ["扫描", "检查", "检测", "测试", "scan"],
                "en": ["scan", "check", "test", "inspect"]
            },
            "patterns": [
                r"扫描(.+?)(?:的|目录|项目|文件)?",
                r"scan\s+(.+?)(?:\s|$)",
                r"(?:只|仅)扫描(\d+)个文件",
                r"用(?:纯AI|pure.?ai)模式(?:扫描|分析)"
            ],
            "default_confidence": 0.9,
            "suggested_pipeline": ["scan", "report"]
        },
        IntentType.ANALYZE: {
            "keywords": {
                "zh": ["分析", "评估", "风险", "analyze", "analyse"],
                "en": ["analyze", "assess", "evaluate", "risk"]
            },
            "patterns": [
                r"分析(.+?)(?:的|漏洞|安全性|代码)?",
                r"(?:深度|全面)分析",
                r"评估(?:代码)?安全性"
            ],
            "default_confidence": 0.85,
            "suggested_pipeline": ["scan", "reason", "report"]
        },
        IntentType.EXPLOIT: {
            "keywords": {
                "zh": ["攻击", "poc", "利用", "exploit", "漏洞利用"],
                "en": ["exploit", "poc", "attack", "generate exploit"]
            },
            "patterns": [
                r"生成?(?:漏洞)?(?:的)?POC",
                r"创建攻击脚本",
                r"验证(?:漏洞|POC)"
            ],
            "default_confidence": 0.88,
            "suggested_pipeline": ["scan", "reason", "poc"]
        },
        IntentType.FIX: {
            "keywords": {
                "zh": ["修复", "补丁", "patch", "fix", "修复建议"],
                "en": ["fix", "patch", "repair", "suggest fix"]
            },
            "patterns": [
                r"(?:提供|生成)修复建议?",
                r"生成修复补丁",
                r"如何修复"
            ],
            "default_confidence": 0.87,
            "suggested_pipeline": ["scan", "reason", "fix"]
        },
        IntentType.PLAN: {
            "keywords": {
                "zh": ["方案", "计划", "plan", "生成方案", "创建方案"],
                "en": ["plan", "generate plan", "create plan"]
            },
            "patterns": [
                r"(?:生成|创建|制定)(?:方案|计划)",
                r"(?:修改|更新)方案",
                r"执行方案",
                r"列出方案"
            ],
            "default_confidence": 0.92,
            "suggested_pipeline": None  # Plan类型不直接对应Pipeline
        },
        IntentType.GIT: {
            "keywords": {
                "zh": ["git", "commit", "提交", "分支", "diff", "差异", "状态"],
                "en": ["git", "commit", "branch", "diff", "status"]
            },
            "patterns": [
                r"git\s+(?:commit|提交)",
                r"(?:创建|切换)分支",
                r"(?:查看|显示)(?:差异|diff)",
                r"git状态?"
            ],
            "default_confidence": 0.95,
            "suggested_pipeline": None
        },
        IntentType.CODE_TOOL: {
            "keywords": {
                "zh": ["@file:", "@func:", "搜索代码", "列出目录", "项目摘要"],
                "en": ["@file:", "@func:", "search code", "list dir", "project summary"]
            },
            "patterns": [
                r"@file:(.+?)(?:\s|$)",
                r"@func:(.+?)(?:\s|$)",
                r"搜索代码[:\s](.+?)(?:\s|$)",
                r"列出目录[:\s]*(.+?)(?:\s|$)",
                r"项目(?:信息|摘要)"
            ],
            "default_confidence": 0.98,
            "suggested_pipeline": None
        },
        IntentType.CONVERSION: {
            "keywords": {
                "zh": ["转换为CLI", "转为CLI", "解释CLI", "CLI命令", "转换命令"],
                "en": ["convert to CLI", "to CLI", "explain CLI", "CLI command"]
            },
            "patterns": [
                r"(?:转换|转)(?:为|到)[:\s]*CLI",
                r"解释(?:CLI|命令)[:\s]*(.+)",
                r"CLI命令[:\s]*(.+)"
            ],
            "default_confidence": 0.93,
            "suggested_pipeline": None
        },
        IntentType.INFO: {
            "keywords": {
                "zh": ["帮助", "help", "信息", "info", "说明"],
                "en": ["help", "info", "information"]
            },
            "patterns": [r"^/help$", r"^帮助$"],
            "default_confidence": 1.0,
            "suggested_pipeline": None
        }
    }
    
    def parse(self, text: str) -> ParsedIntent:
        """基于规则解析意图
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的意图对象
        """
        if not text or not text.strip():
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.0,
                raw_text=text
            )
        
        text_lower = text.lower().strip()
        best_intent = None
        best_confidence = 0.0
        entities = {}
        
        for intent_type, config in self.INTENT_PATTERNS.items():
            confidence = config["default_confidence"]
            
            # 关键词匹配
            keywords_matched = False
            for lang_keywords in config["keywords"].values():
                for keyword in lang_keywords:
                    if keyword.lower() in text_lower:
                        keywords_matched = True
                        break
                if keywords_matched:
                    break
            
            if not keywords_matched:
                continue
                
            # 正则提取实体
            matched_pattern = False
            for pattern in config["patterns"]:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    matched_pattern = True
                    groups = match.groups()
                    if groups:
                        for i, group in enumerate(groups):
                            if group and group.strip():
                                entities[f"group_{i}"] = group.strip()
                    break
            
            if matched_pattern or keywords_matched:
                if not matched_pattern:
                    confidence *= 0.9  # 仅关键词匹配，略微降低置信度
                    
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_intent = intent_type
        
        if best_intent:
            return ParsedIntent(
                type=best_intent,
                confidence=best_confidence,
                entities=entities,
                raw_text=text,
                suggested_pipeline=self.INTENT_PATTERNS[best_intent].get("suggested_pipeline")
            )
        
        return ParsedIntent(
            type=IntentType.GENERAL,
            confidence=0.3,
            raw_text=text,
            suggested_pipeline=["scan", "report"]
        )


class AIIntentParser:
    """基于AI的意图解析器（用于复杂场景）"""
    
    def __init__(self, ai_client=None):
        self.ai_client = ai_client
        
    async def enhance(self, rule_intent: ParsedIntent, text: str) -> ParsedIntent:
        """使用AI增强规则解析结果
        
        Args:
            rule_intent: 规则解析的结果
            text: 原始文本
            
        Returns:
            AI增强后的意图
        """
        if not self.ai_client:
            return rule_intent
            
        try:
            from src.ai.models import AIRequest
            
            prompt = f"""你是一个用户意图识别专家。分析用户的输入，判断其真实意图。

用户输入: {text}
规则解析结果: {rule_intent.type.value} (置信度: {rule_intent.confidence:.0%})

可用的意图类型:
- scan: 代码安全扫描
- analyze: 深度分析/评估
- exploit: 漏洞利用/POC生成
- fix: 修复建议/补丁
- plan: 方案/计划管理
- git: Git操作
- code_tool: 代码库工具(读取文件、搜索函数等)
- conversion: CLI/自然语言转换
- info: 帮助/信息查询
- general: 通用对话

请返回JSON格式:
{{"intent": "意图类型", "confidence": 0.0-1.0, "entities": {{}}}}

只返回JSON，不要其他内容。"""

            request = AIRequest(
                prompt=prompt,
                system_prompt="你是用户意图识别专家。",
                max_tokens=200,
                temperature=0.1  # 低温度确保稳定输出
            )
            
            response = await self.ai_client.generate(request)
            
            result = self._parse_ai_response(response.content)
            
            try:
                intent_type = IntentType(result.get("intent", rule_intent.type.value))
                confidence = float(result.get("confidence", rule_intent.confidence))
                entities = result.get("entities", {})
                
                return ParsedIntent(
                    type=intent_type,
                    confidence=max(confidence, rule_intent.confidence),
                    entities={**rule_intent.entities, **entities},
                    raw_text=text,
                    suggested_pipeline=rule_intent.suggested_pipeline
                )
            except (ValueError, TypeError):
                return rule_intent
                
        except Exception as e:
            return rule_intent
    
    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """解析AI响应"""
        import json
        
        json_match = re.search(r'\{[^{}]+\}', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
                
        return {"intent": "general", "confidence": 0.5}


class IntentParser:
    """统一的意图解析器（规则+AI）
    
    使用策略：
    1. 优先使用规则匹配（快速、准确）
    2. 如果置信度 < 0.8 且AI可用，使用AI增强
    3. 返回最优结果
    """
    
    def __init__(self, ai_client=None):
        self.rule_parser = RuleBasedIntentParser()
        self.ai_parser = AIIntentParser(ai_client) if ai_client else None
        
    def parse(self, text: str) -> ParsedIntent:
        """解析用户意图（同步版本）
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的意图对象
        """
        import asyncio
        
        rule_intent = self.rule_parser.parse(text)
        
        if rule_intent.confidence < 0.8 and self.ai_parser:
            try:
                enhanced_intent = asyncio.run(
                    self.ai_parser.enhance(rule_intent, text)
                )
                return enhanced_intent
            except Exception:
                pass
                
        return rule_intent
    
    async def parse_async(self, text: str) -> ParsedIntent:
        """异步解析用户意图
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的意图对象
        """
        rule_intent = self.rule_parser.parse(text)
        
        if rule_intent.confidence < 0.8 and self.ai_parser:
            try:
                return await self.ai_parser.enhance(rule_intent, text)
            except Exception:
                pass
                
        return rule_intent
    
    @staticmethod
    def extract_target_path(text: str) -> str:
        """从文本中提取目标路径
        
        支持格式：
        - Windows绝对路径：C:\\path\\to\\project
        - 相对路径：./src, src/
        - 引号路径："path with spaces"
        
        Args:
            text: 用户输入
            
        Returns:
            提取到的路径，默认为"."
        """
        patterns = [
            r'"([a-zA-Z]:\\[\\\w\s.-]+)"',  # 带引号的Windows路径
            r'([a-zA-Z]:\\[\\\w\s.-]+?)(?:\s+(?:的|扫描|分析)|$)',  # Windows路径
            r'"(.*?)"',  # 带引号的通用路径
            r'(?:目录|文件夹|folder)\s*(.+?)(?:\s|$)',  # 目录后面的路径
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
        """检测是否需要使用纯AI模式
        
        Args:
            text: 用户输入
            
        Returns:
            是否启用纯AI模式
        """
        pure_ai_indicators = ['纯', 'pure', 'pure-ai', '轻量', '快速']
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in pure_ai_indicators)
    
    @staticmethod
    def detect_test_mode(text: str) -> tuple:
        """检测测试模式及文件数量
        
        Returns:
            (是否测试模式, 文件数量)
        """
        test_match = re.search(r'(?:只|仅|测试)?(?:扫描)?(\d+)个?文件?', text)
        if test_match or '测试' in text or 'test' in text.lower():
            count = int(test_match.group(1)) if test_match else 1
            return True, count
        return False, 0
