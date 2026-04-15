"""AI 意图模型定义

定义意图类型枚举和意图分析结果。
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


class IntentType(Enum):
    """意图类型枚举"""
    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLAIN = "explain"
    SEARCH = "search"
    HELP = "help"
    EXIT = "exit"
    STATUS = "status"
    RESUME = "resume"
    COMPARE = "compare"
    UNKNOWN = "unknown"


@dataclass
class IntentModel:
    """意图模型

    用于存储意图分析的结构化结果。
    """

    intent: IntentType
    confidence: float
    reasoning: str = ""
    entities: List["IntentEntity"] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_confident(self) -> bool:
        """判断是否高置信度"""
        return self.confidence >= 0.7

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "intent": self.intent.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "entities": [e.to_dict() for e in self.entities],
            "metadata": self.metadata,
        }


@dataclass
class IntentEntity:
    """意图实体

    从用户输入中提取的结构化实体。
    """

    type: str
    value: str
    confidence: float = 1.0
    start_pos: int = 0
    end_pos: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "type": self.type,
            "value": self.value,
            "confidence": self.confidence,
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
            "metadata": self.metadata,
        }


@dataclass
class IntentAnalysisResult:
    """意图分析结果

    包含完整的意图分析信息。
    """

    original_input: str
    intent: IntentType
    confidence: float
    reasoning: str
    entities: List[IntentEntity] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    depth: Optional[str] = None
    scope: Optional[str] = None
    vulnerability_types: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_confident(self) -> bool:
        """判断是否高置信度"""
        return self.confidence >= 0.7

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "original_input": self.original_input,
            "intent": self.intent.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "entities": [e.to_dict() for e in self.entities],
            "required_tools": self.required_tools,
            "depth": self.depth,
            "scope": self.scope,
            "vulnerability_types": self.vulnerability_types,
            "metadata": self.metadata,
        }


INTENT_DISPLAY_NAMES: Dict[IntentType, str] = {
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

INTENT_TOOLS: Dict[IntentType, List[str]] = {
    IntentType.SCAN: ["scanner", "file_discovery"],
    IntentType.ANALYZE: ["scanner", "context_builder", "risk_analyzer"],
    IntentType.EXPLAIN: ["file_reader", "context_builder"],
    IntentType.SEARCH: ["code_search", "grep"],
    IntentType.HELP: ["help_generator"],
    IntentType.EXIT: [],
    IntentType.STATUS: ["status_checker"],
    IntentType.RESUME: ["checkpoint_manager", "incremental_index"],
    IntentType.COMPARE: ["diff_tool", "scanner"],
}
