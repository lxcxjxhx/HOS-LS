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
            from src.core.module_capabilities import get_module_capabilities
            
            # 获取模块能力信息
            module_capabilities = get_module_capabilities()
            available_modules = list(module_capabilities.get_all_capabilities().keys())
            
            # 检测是否为长文本
            is_long_text = len(text) > 500
            
            # 检测是否为多任务命令
            is_multi_task = 'tasks' in rule_intent.entities
            
            if is_multi_task:
                # 多任务命令处理
                prompt = f"""你是一个用户意图识别专家。分析用户的输入，判断其真实意图和任务顺序。

用户输入: {text}
规则解析结果: 多任务命令

可用的功能模块:
{', '.join(available_modules)}

请分析：
1. 任务的具体内容和顺序
2. 是否需要纯AI模式
3. 是否为测试模式及文件数量
4. 每个任务需要使用哪些功能模块

请返回JSON格式:
{
  "intent": "general",
  "confidence": 0.0-1.0,
  "entities": {
    "tasks": [
      {
        "type": "任务类型",
        "content": "任务内容",
        "modules": ["使用的模块"]
      }
    ],
    "pure_ai": true/false,
    "test_mode": true/false,
    "test_file_count": 1
  }
}

只返回JSON，不要其他内容。"""
                
                request = AIRequest(
                    prompt=prompt,
                    system_prompt="你是用户意图识别专家，擅长分析复杂的多任务命令，能够理解口语化表达和长文本。",
                    max_tokens=500,
                    temperature=0.1
                )
                
                response = await self.ai_client.generate(request)
                
                result = self._parse_ai_response(response.content)
                
                try:
                    intent_type = IntentType(result.get("intent", rule_intent.type.value))
                    confidence = float(result.get("confidence", rule_intent.confidence))
                    entities = result.get("entities", {})
                    
                    # 确保任务列表存在
                    if 'tasks' not in entities:
                        entities['tasks'] = rule_intent.entities.get('tasks', [])
                    
                    return ParsedIntent(
                        type=intent_type,
                        confidence=max(confidence, rule_intent.confidence),
                        entities={**rule_intent.entities, **entities},
                        raw_text=text,
                        suggested_pipeline=rule_intent.suggested_pipeline
                    )
                except (ValueError, TypeError):
                    return rule_intent
            elif is_long_text:
                # 长文本命令处理
                prompt = f"""你是一个用户意图识别专家。分析用户的长文本输入，判断其真实意图。

用户输入: {text}

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

可用的功能模块:
{', '.join(available_modules)}

请分析：
1. 用户的主要意图是什么
2. 需要使用哪些功能模块
3. 是否需要纯AI模式
4. 是否为测试模式

请返回JSON格式:
{
  "intent": "意图类型",
  "confidence": 0.0-1.0,
  "entities": {
    "modules": ["使用的模块"],
    "pure_ai": true/false,
    "test_mode": true/false,
    "test_file_count": 1,
    "target": "目标路径",
    "details": "详细需求"
  }
}

只返回JSON，不要其他内容。"""
                
                request = AIRequest(
                    prompt=prompt,
                    system_prompt="你是用户意图识别专家，擅长分析长文本命令，能够理解口语化表达和复杂需求。",
                    max_tokens=400,
                    temperature=0.1
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
            else:
                # 单任务命令处理
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

可用的功能模块:
{', '.join(available_modules)}

请返回JSON格式:
{{"intent": "意图类型", "confidence": 0.0-1.0, "entities": {{"modules": ["使用的模块"]}}}}

只返回JSON，不要其他内容。"""

                request = AIRequest(
                    prompt=prompt,
                    system_prompt="你是用户意图识别专家，擅长理解口语化表达和用户需求。",
                    max_tokens=300,
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
        
        # 处理长文本
        if len(text) > 1000:
            # 长文本分块处理
            chunks = self._split_long_text(text)
            # 合并分块解析结果
            return self._parse_long_text(chunks)
        
        # 首先检查是否为多任务命令
        multi_task_info = self._detect_multi_task(text)
        if multi_task_info:
            # 对于多任务命令，优先使用AI增强
            if self.ai_parser:
                try:
                    enhanced_intent = asyncio.run(
                        self.ai_parser.enhance(multi_task_info, text)
                    )
                    return enhanced_intent
                except Exception:
                    pass
            return multi_task_info
        
        # 默认使用AI进行理解和规划
        if self.ai_parser:
            try:
                # 先进行规则解析作为基础
                rule_intent = self.rule_parser.parse(text)
                # 无论置信度如何，都使用AI增强
                enhanced_intent = asyncio.run(
                    self.ai_parser.enhance(rule_intent, text)
                )
                return enhanced_intent
            except Exception:
                # AI失败时回退到规则解析
                pass
        
        # 最后回退到规则解析
        rule_intent = self.rule_parser.parse(text)
        return rule_intent
    
    def _split_long_text(self, text: str, max_chunk_size: int = 800) -> List[str]:
        """将长文本分块
        
        Args:
            text: 长文本
            max_chunk_size: 每个分块的最大长度
            
        Returns:
            分块后的文本列表
        """
        chunks = []
        current_chunk = ""
        
        # 按句子分块
        sentences = text.split('。')
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            
            if len(current_chunk) + len(sentence) + 1 <= max_chunk_size:
                current_chunk += sentence + '。'
            else:
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = sentence + '。'
        
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks
    
    def _parse_long_text(self, chunks: List[str]) -> ParsedIntent:
        """解析长文本分块
        
        Args:
            chunks: 分块后的文本列表
            
        Returns:
            合并后的意图
        """
        # 解析每个分块
        chunk_intents = []
        for chunk in chunks:
            # 检测是否为多任务命令
            multi_task_info = self._detect_multi_task(chunk)
            if multi_task_info:
                return multi_task_info
            
            rule_intent = self.rule_parser.parse(chunk)
            chunk_intents.append(rule_intent)
        
        # 合并意图
        if not chunk_intents:
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.5,
                entities={},
                raw_text=' '.join(chunks),
                suggested_pipeline=None
            )
        
        # 确定主要意图类型
        intent_counts = {}
        for intent in chunk_intents:
            intent_counts[intent.type] = intent_counts.get(intent.type, 0) + 1
        
        main_intent_type = max(intent_counts, key=intent_counts.get)
        
        # 合并实体
        merged_entities = {}
        for intent in chunk_intents:
            for key, value in intent.entities.items():
                if key not in merged_entities:
                    merged_entities[key] = value
                elif isinstance(merged_entities[key], list) and isinstance(value, list):
                    merged_entities[key].extend(value)
                elif isinstance(merged_entities[key], dict) and isinstance(value, dict):
                    merged_entities[key].update(value)
        
        # 构建合并后的意图
        merged_intent = ParsedIntent(
            type=main_intent_type,
            confidence=0.8,
            entities=merged_entities,
            raw_text=' '.join(chunks),
            suggested_pipeline=chunk_intents[0].suggested_pipeline
        )
        
        # 如果有AI客户端，使用AI增强意图解析
        if self.ai_parser:
            import asyncio
            try:
                enhanced_intent = asyncio.run(self.ai_parser.enhance(merged_intent, ' '.join(chunks)))
                return enhanced_intent
            except Exception:
                pass
        
        return merged_intent
    
    def _detect_multi_task(self, text: str) -> Optional[ParsedIntent]:
        """检测多任务命令
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的多任务意图对象，或None
        """
        # 检测任务类型关键词
        explain_keywords = ['讲解', '解释', '说明', '介绍', 'explain', 'introduce', '工作原理', '原理', '怎么工作', '如何实现', '什么是']
        scan_keywords = ['扫描', 'scan', '测试', 'test', '检测', '检查']
        pure_ai_keywords = ['纯净', 'pure', '纯AI', 'pure-ai', '纯 AI']
        test_keywords = ['测试', 'test', '只扫描', '仅扫描', '一个文件', '1个文件', '随便扫描', '扫一份文件']
        
        # 检测是否包含讲解和扫描任务
        has_explain = any(keyword in text for keyword in explain_keywords)
        has_scan = any(keyword in text for keyword in scan_keywords)
        has_pure_ai = any(keyword in text for keyword in pure_ai_keywords)
        has_test = any(keyword in text for keyword in test_keywords)
        
        # 即使没有明确的顺序关键词，只要包含讲解和扫描任务，也视为多任务命令
        if has_explain and has_scan:
            # 构建多任务意图
            entities = {
                'tasks': [
                    {'type': 'explain', 'content': '讲解漏扫实现原理'},
                    {'type': 'scan', 'content': '使用纯净AI模式扫描文件'}
                ],
                'pure_ai': has_pure_ai or self.detect_pure_ai_mode(text),
                'test_mode': has_test or self.detect_test_mode(text)[0]
            }
            
            # 检测测试模式文件数量
            test_mode, file_count = self.detect_test_mode(text)
            if test_mode:
                entities['test_file_count'] = file_count
            
            # 检测是否指定了扫描一个文件
            if '一个文件' in text or '1个文件' in text or 'one file' in text.lower() or '只扫描' in text or '仅扫描' in text or '扫一份文件' in text or '随便扫描' in text:
                entities['test_mode'] = True
                entities['test_file_count'] = 1
            
            # 检测是否包含纯净AI模式
            if has_pure_ai:
                entities['pure_ai'] = True
            
            return ParsedIntent(
                type=IntentType.GENERAL,
                confidence=0.95,
                entities=entities,
                raw_text=text,
                suggested_pipeline=None
            )
        
        return None
    
    async def parse_async(self, text: str) -> ParsedIntent:
        """异步解析用户意图
        
        Args:
            text: 用户输入文本
            
        Returns:
            解析后的意图对象
        """
        # 首先检查是否为多任务命令
        multi_task_info = self._detect_multi_task(text)
        if multi_task_info:
            return multi_task_info
        
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
            # 限制测试模式下的文件数量，最多不超过5个
            count = min(count, 5)
            return True, count
        return False, 0
