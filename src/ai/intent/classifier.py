import re
import logging
from typing import Optional

from src.ai.intent.intent_model import IntentType, IntentResult

logger = logging.getLogger(__name__)


class AIIntentClassifier:
    """基于关键词匹配的意图分类器。
    
    使用简单的关键词/模式匹配对输入文本进行意图分类，
    作为没有AI模型时的回退方案。
    """
    
    # 渗透测试意图关键词
    PENTEST_KEYWORDS = ["渗透", "pentest", "渗透测试", "攻防", "攻击测试", "模拟攻击", "hack"]
    
    # 扫描意图关键词
    SCAN_KEYWORDS = ["扫描", "scan", "检查", "检测"]
    
    # 分析意图关键词
    ANALYZE_KEYWORDS = ["分析", "analyze", "解析", "评估"]
    
    # 解释意图关键词
    EXPLAIN_KEYWORDS = ["解释", "explain", "说明", "什么意思", "是什么"]
    
    # 搜索意图关键词
    SEARCH_KEYWORDS = ["搜索", "search", "查找", "查询"]
    
    # 帮助意图关键词
    HELP_KEYWORDS = ["帮助", "help", "怎么用", "如何使用", "用法"]
    
    # 退出意图关键词
    EXIT_KEYWORDS = ["退出", "exit", "quit", "结束", "关闭"]
    
    # 状态意图关键词
    STATUS_KEYWORDS = ["状态", "status", "进度", "当前状态"]
    
    # 恢复意图关键词
    RESUME_KEYWORDS = ["恢复", "resume", "继续", "重新开始"]
    
    # 比较意图关键词
    COMPARE_KEYWORDS = ["比较", "compare", "对比", "差异"]
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._initialized = False
    
    async def initialize(self):
        """异步初始化，目前没有AI模型加载逻辑，仅标记初始化状态。"""
        self._initialized = True
        logger.debug("AIIntentClassifier initialized")
    
    async def classify(self, text: str) -> IntentResult:
        """对输入文本进行意图分类。
        
        使用关键词匹配策略，返回最匹配的意图及其置信度。
        """
        text_lower = text.lower()
        
        # 定义意图与关键词的映射
        intent_keywords = [
            (IntentType.PENTEST, self.PENTEST_KEYWORDS),
            (IntentType.SCAN, self.SCAN_KEYWORDS),
            (IntentType.ANALYZE, self.ANALYZE_KEYWORDS),
            (IntentType.EXPLAIN, self.EXPLAIN_KEYWORDS),
            (IntentType.SEARCH, self.SEARCH_KEYWORDS),
            (IntentType.HELP, self.HELP_KEYWORDS),
            (IntentType.EXIT, self.EXIT_KEYWORDS),
            (IntentType.STATUS, self.STATUS_KEYWORDS),
            (IntentType.RESUME, self.RESUME_KEYWORDS),
            (IntentType.COMPARE, self.COMPARE_KEYWORDS),
        ]
        
        best_intent = None
        best_confidence = 0.0
        best_keyword = None
        
        for intent, keywords in intent_keywords:
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    # 根据匹配长度和位置计算置信度
                    confidence = self._calculate_confidence(text_lower, keyword)
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_intent = intent
                        best_keyword = keyword
        
        # 如果没有匹配到任何意图，返回默认的SCAN意图（低置信度）
        if best_intent is None:
            return IntentResult(
                intent=IntentType.SCAN,
                confidence=0.1,
                is_confident=False,
            )
        
        return IntentResult(
            intent=best_intent,
            confidence=best_confidence,
            is_confident=best_confidence >= 0.5,
        )
    
    def _calculate_confidence(self, text: str, keyword: str) -> float:
        """根据关键词匹配情况计算置信度。
        
        - 完全匹配（文本等于关键词）: 0.95
        - 文本以关键词开头: 0.85
        - 包含关键词: 基础值 + 长度权重
        """
        if text == keyword:
            return 0.95
        
        if text.startswith(keyword):
            return 0.85
        
        # 基础置信度
        base_confidence = 0.6
        
        # 关键词长度权重：越长的关键词匹配越有意义
        length_weight = min(len(keyword) / len(text), 0.3) if len(text) > 0 else 0
        
        # 匹配位置权重：靠前的匹配权重更高
        position = text.find(keyword)
        position_weight = max(0, 0.1 - (position / len(text)) * 0.1) if position >= 0 else 0
        
        return min(base_confidence + length_weight + position_weight, 0.9)
