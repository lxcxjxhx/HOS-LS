from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class IntentType(Enum):
    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLAIN = "explain"
    SEARCH = "search"
    HELP = "help"
    EXIT = "exit"
    STATUS = "status"
    RESUME = "resume"
    COMPARE = "compare"
    PENTEST = "pentest"  # NEW: 渗透测试意图


@dataclass
class IntentEntity:
    type: str
    value: str
    metadata: dict = field(default_factory=dict)


@dataclass
class IntentResult:
    intent: IntentType
    confidence: float
    is_confident: bool
    entities: list = field(default_factory=list)
