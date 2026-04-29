"""AI 意图分类器

提供基于AI的语义意图分类，支持置信度阈值和fallback机制。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

from src.ai.intent.intent_model import IntentModel, IntentType
from src.ai.models import AIRequest
from src.ai.client import AIModelManager, get_model_manager
from src.core.config import Config, get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class FallbackIntentMatcher:
    """Fallback规则匹配器"""

    INTENT_KEYWORDS: Dict[IntentType, List[str]] = {
        IntentType.SCAN: ["扫描", "scan", "检查", "检测", "analyze", "审计"],
        IntentType.ANALYZE: ["分析", "深度分析", "详细分析", "详细检查", "分析一下"],
        IntentType.EXPLAIN: ["解释", "explain", "说明", "是什么", "什么意思", "看看"],
        IntentType.SEARCH: ["搜索", "search", "查找", "找", "grep", "查询"],
        IntentType.HELP: ["帮助", "help", "命令", "如何使用", "怎么用"],
        IntentType.EXIT: ["退出", "exit", "quit", "再见", "结束"],
        IntentType.STATUS: ["状态", "status", "情况", "进度"],
        IntentType.RESUME: ["继续", "resume", "恢复", "续扫", "断点", "接着"],
        IntentType.COMPARE: ["比较", "compare", "对比", "差异"],
    }

    def match(self, user_input: str) -> Optional[IntentType]:
        """匹配意图类型"""
        user_lower = user_input.lower()

        for intent_type, keywords in self.INTENT_KEYWORDS.items():
            for keyword in keywords:
                if keyword in user_lower:
                    return intent_type

        return None


@dataclass
class IntentClassificationResult:
    """意图分类结果"""
    intent: IntentType
    confidence: float
    method: str
    alternatives: List[tuple[IntentType, float]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_confident(self) -> bool:
        return self.confidence >= AIIntentClassifier.CONFIDENCE_THRESHOLD


class AIIntentClassifier:
    """AI意图分类器

    使用AI模型进行意图分类，支持置信度阈值判断和fallback机制。
    """

    CONFIDENCE_THRESHOLD = 0.7
    HIGH_CONFIDENCE_THRESHOLD = 0.85

    SYSTEM_PROMPT = """你是一个安全聊天中心的意图分类专家。分析用户的输入，识别其意图。

可用意图类型：
- SCAN: 安全扫描相关，如"扫描目录"、"检查漏洞"
- ANALYZE: 深度分析相关，如"分析安全问题"、"详细检查"
- EXPLAIN: 解释说明相关，如"解释这个漏洞"、"这是什么"
- SEARCH: 代码搜索相关，如"搜索密码"、"查找敏感信息"
- HELP: 帮助信息相关，如"帮助"、"如何使用"
- EXIT: 退出相关，如"退出"、"再见"
- STATUS: 状态查询相关，如"状态"、"进度如何"
- RESUME: 继续执行相关，如"继续"、"恢复扫描"
- COMPARE: 比较相关，如"比较"、"对比差异"

请以JSON格式返回结果：
{
    "intent": "意图类型",
    "confidence": 0.0-1.0的置信度,
    "reasoning": "分类理由"
}

只返回JSON，不要有其他内容。"""

    FEW_SHOT_EXAMPLES = """
示例：
输入: "扫描src目录下的安全问题"
输出: {"intent": "SCAN", "confidence": 0.95, "reasoning": "用户明确要求进行安全扫描"}

输入: "这个文件有什么漏洞"
输出: {"intent": "ANALYZE", "confidence": 0.92, "reasoning": "用户想了解文件中的安全漏洞"}

输入: "继续上次的扫描"
输出: {"intent": "RESUME", "confidence": 0.94, "reasoning": "用户想恢复之前的扫描任务"}"""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._manager: Optional[AIModelManager] = None
        self._fallback_matcher = FallbackIntentMatcher()
        self._initialized = False

    async def initialize(self) -> None:
        """初始化分类器"""
        if not self._initialized:
            self._manager = await get_model_manager(self.config)
            self._initialized = True

    async def classify(self, user_input: str) -> IntentClassificationResult:
        """分类用户意图

        Args:
            user_input: 用户输入的自然语言

        Returns:
            意图分类结果
        """
        if not self._initialized:
            await self.initialize()

        if not user_input or not user_input.strip():
            return IntentClassificationResult(
                intent=IntentType.UNKNOWN,
                confidence=0.0,
                method="empty_input"
            )

        try:
            result = await self._ai_classify(user_input)

            if result.is_confident:
                return result

            fallback_result = self._fallback_matcher.match(user_input)
            if fallback_result:
                return IntentClassificationResult(
                    intent=fallback_result,
                    confidence=0.5,
                    method="fallback_keyword"
                )

            return result

        except Exception as e:
            logger.warning(f"AI classification failed: {e}, using fallback")

            fallback_result = self._fallback_matcher.match(user_input)
            if fallback_result:
                return IntentClassificationResult(
                    intent=fallback_result,
                    confidence=0.4,
                    method="fallback_exception"
                )

            return IntentClassificationResult(
                intent=IntentType.UNKNOWN,
                confidence=0.0,
                method="error"
            )

    async def _ai_classify(self, user_input: str) -> IntentClassificationResult:
        """使用AI模型分类意图"""
        prompt = self._build_classification_prompt(user_input)

        request = AIRequest(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1,
            max_tokens=256,
            model=self.config.ai.model,
        )

        response = await self._manager.generate(request)

        return self._parse_classification_response(response.content, user_input)

    def _build_classification_prompt(self, user_input: str) -> str:
        """构建分类提示"""
        return f"{self.FEW_SHOT_EXAMPLES}\n\n输入: \"{user_input}\"\n输出:"

    def _parse_classification_response(
        self, content: str, original_input: str
    ) -> IntentClassificationResult:
        """解析AI分类响应"""
        import json
        import re

        try:
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
            else:
                data = json.loads(content)

            intent_str = data.get("intent", "UNKNOWN")
            confidence = float(data.get("confidence", 0.0))
            reasoning = data.get("reasoning", "")

            try:
                intent = IntentType(intent_str.upper())
            except ValueError:
                intent = IntentType.UNKNOWN

            return IntentClassificationResult(
                intent=intent,
                confidence=confidence,
                method="ai_model",
                metadata={"reasoning": reasoning}
            )

        except Exception as e:
            logger.error(f"Failed to parse classification response: {e}")

            return IntentClassificationResult(
                intent=IntentType.UNKNOWN,
                confidence=0.0,
                method="parse_error"
            )

    async def classify_batch(
        self, inputs: List[str]
    ) -> List[IntentClassificationResult]:
        """批量分类意图

        Args:
            inputs: 用户输入列表

        Returns:
            分类结果列表
        """
        if not self._initialized:
            await self.initialize()

        results = []
        for user_input in inputs:
            result = await self.classify(user_input)
            results.append(result)

        return results

    def get_intent_display_name(self, intent: IntentType) -> str:
        """获取意图的显示名称"""
        display_names = {
            IntentType.SCAN: "扫描",
            IntentType.ANALYZE: "分析",
            IntentType.EXPLAIN: "解释",
            IntentType.SEARCH: "搜索",
            IntentType.HELP: "帮助",
            IntentType.EXIT: "退出",
            IntentType.STATUS: "状态",
            IntentType.RESUME: "继续",
            IntentType.COMPARE: "比较",
            IntentType.UNKNOWN: "未知",
        }
        return display_names.get(intent, intent.value)
