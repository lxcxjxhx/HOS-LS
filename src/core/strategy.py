"""Strategy 数据模型定义

定义策略决策系统的核心数据结构，包括策略定义、决策参数、约束条件等。
"""

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ScanDepth(str, Enum):
    """扫描深度"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class StrategyMode(str, Enum):
    """策略模式"""

    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    CONSERVATIVE = "conservative"
    FAST = "fast"
    DEEP = "deep"


class StrategySource(str, Enum):
    """策略来源"""

    USER_OVERRIDE = "user_override"  # 用户显式覆盖
    AI_GENERATED = "ai_generated"  # AI生成
    HYBRID = "hybrid"  # 混合（AI+规则）
    DEFAULT = "default"  # 默认策略
    FALLBACK = "fallback"  # 降级策略


@dataclass
class StrategyDecisions:
    """策略决策参数"""

    scan_depth: str = "medium"
    enable_poc: bool = False
    modules: List[str] = field(
        default_factory=lambda: ["auth", "injection", "xss"]
    )
    ai_model: str = "default"  # 使用默认AI模型
    batch_size: int = 8
    parallel_workers: int = 4
    safe_mode: bool = False  # 生产环境保护
    enable_attack_chain: bool = False
    enable_auth_analysis: bool = False
    output_format: str = "html"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StrategyDecisions":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class StrategyConstraints:
    """策略约束条件"""

    max_time: int = 300  # 最大执行时间（秒）
    max_cost: float = 10.0  # 最大API成本（美元）
    safe_mode: bool = False  # 是否启用安全模式
    allowed_modules: Optional[List[str]] = None  # 允许的模块列表
    disallowed_modules: Optional[List[str]] = None  # 禁止的模块列表
    production_environment: bool = False  # 是否生产环境

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StrategyConstraints":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def is_module_allowed(self, module: str) -> bool:
        """检查模块是否允许使用"""
        if self.disallowed_modules and module in self.disallowed_modules:
            return False
        if self.allowed_modules and module not in self.allowed_modules:
            return False
        return True


@dataclass
class Strategy:
    """策略定义

    包含完整的策略信息，包括决策参数、约束条件和决策理由。
    """

    strategy_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    mode: str = "balanced"
    decisions: StrategyDecisions = field(default_factory=StrategyDecisions)
    constraints: StrategyConstraints = field(default_factory=StrategyConstraints)
    reasoning: str = ""  # AI生成的决策理由
    confidence: float = 0.85  # 策略置信度（0-1）
    source: str = "default"  # 策略来源
    context_scores: Dict[str, float] = field(default_factory=dict)  # 各维度得分
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)  # 额外元数据

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "mode": self.mode,
            "decisions": self.decisions.to_dict(),
            "constraints": self.constraints.to_dict(),
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "source": self.source,
            "context_scores": self.context_scores,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Strategy":
        return cls(
            strategy_id=data.get("strategy_id", str(uuid.uuid4())[:8]),
            mode=data.get("mode", "balanced"),
            decisions=StrategyDecisions.from_dict(data.get("decisions", {})),
            constraints=StrategyConstraints.from_dict(data.get("constraints", {})),
            reasoning=data.get("reasoning", ""),
            confidence=data.get("confidence", 0.85),
            source=data.get("source", "default"),
            context_scores=data.get("context_scores", {}),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            metadata=data.get("metadata", {}),
        )

    def is_safe_for_production(self) -> bool:
        """判断是否适合生产环境"""
        if self.constraints.production_environment and not self.decisions.safe_mode:
            return False
        return True

    def get_estimated_time(self) -> int:
        """估算执行时间（秒）"""
        base_time = {
            "fast": 60,
            "balanced": 180,
            "conservative": 240,
            "aggressive": 300,
            "deep": 600,
        }.get(self.mode, 180)

        depth_multiplier = {"low": 0.5, "medium": 1.0, "high": 2.0}.get(self.decisions.scan_depth, 1.0)

        poc_multiplier = 1.5 if self.decisions.enable_poc else 1.0

        modules_multiplier = 1.0 + len(self.decisions.modules) * 0.1

        estimated = int(base_time * depth_multiplier * poc_multiplier * modules_multiplier)

        return min(estimated, self.constraints.max_time)

    def get_summary(self) -> str:
        """获取策略摘要"""
        parts = [
            f"模式: {self.mode}",
            f"深度: {self.decisions.scan_depth}",
            f"模块: {', '.join(self.decisions.modules[:3])}{'...' if len(self.decisions.modules) > 3 else ''}",
            f"POC: {'启用' if self.decisions.enable_poc else '禁用'}",
            f"预计耗时: {self.get_estimated_time()}s",
            f"置信度: {self.confidence:.0%}",
        ]
        return " | ".join(parts)


@dataclass
class StrategyWeights:
    """策略权重配置"""

    user_preference: float = 0.4
    project_risk: float = 0.3
    intent: float = 0.2
    history_feedback: float = 0.1

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, float]) -> "StrategyWeights":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def normalize(self):
        """归一化权重（确保总和为1）"""
        total = sum(asdict(self).values())
        if total > 0 and abs(total - 1.0) > 0.001:
            fields = self.__dataclass_fields__
            for field_name in fields:
                current_value = getattr(self, field_name)
                setattr(self, field_name, current_value / total)

    def validate(self) -> bool:
        """验证权重是否有效"""
        total = sum(asdict(self).values())
        return abs(total - 1.0) < 0.01

    def adjust_for_context(
        self,
        is_advanced_user: bool = False,
        is_ci_environment: bool = False,
        is_high_risk_project: bool = False,
        is_first_time_project: bool = False,
    ) -> "StrategyWeights":
        """根据上下文调整权重

        Args:
            is_advanced_user: 是否高级用户
            is_ci_environment: 是否CI环境
            is_high_risk_project: 是否高风险项目
            is_first_time_project: 是否首次使用项目

        Returns:
            调整后的新权重对象
        """
        new_weights = StrategyWeights(
            user_preference=self.user_preference,
            project_risk=self.project_risk,
            intent=self.intent,
            history_feedback=self.history_feedback,
        )

        if is_advanced_user:
            new_weights.user_preference += 0.1
            new_weights.intent -= 0.05

        if is_ci_environment:
            new_weights.project_risk += 0.1
            new_weights.intent -= 0.1

        if is_high_risk_project:
            new_weights.project_risk += 0.2
            new_weights.user_preference -= 0.1

        if is_first_time_project:
            new_weights.intent += 0.1
            new_weights.history_feedback -= 0.05

        new_weights.normalize()
        return new_weights


@dataclass
class ContextScores:
    """上下文评分结果"""

    user_score: float = 0.5  # 用户偏好得分（0-1）
    project_score: float = 0.5  # 项目风险得分（0-1）
    intent_score: float = 0.5  # 意图匹配得分（0-1）
    history_score: float = 0.5  # 历史反馈得分（0-1）

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)

    def get_weighted_sum(self, weights: StrategyWeights) -> float:
        """计算加权总分

        Args:
            weights: 权重配置

        Returns:
            加权总分
        """
        return (
            self.user_score * weights.user_preference
            + self.project_score * weights.project_risk
            + self.intent_score * weights.intent
            + self.history_score * weights.history_feedback
        )


# 预定义的策略模板
STRATEGY_TEMPLATES = {
    "fast": Strategy(
        mode="fast",
        decisions=StrategyDecisions(scan_depth="low", modules=["injection", "xss"], parallel_workers=8),
        constraints=StrategyConstraints(max_time=120),
        source="template",
    ),
    "balanced": Strategy(
        mode="balanced",
        decisions=StrategyDecisions(scan_depth="medium", modules=["auth", "injection", "xss"]),
        constraints=StrategyConstraints(max_time=300),
        source="template",
    ),
    "deep": Strategy(
        mode="deep",
        decisions=StrategyDecisions(
            scan_depth="high",
            modules=["auth", "injection", "xss", "data_exposure", "dependency"],
            enable_poc=True,
            enable_auth_analysis=True,
            enable_attack_chain=True,
        ),
        constraints=StrategyConstraints(max_time=600),
        source="template",
    ),
    "conservative": Strategy(
        mode="conservative",
        decisions=StrategyDecisions(
            scan_depth="medium",
            modules=["auth", "injection"],
            safe_mode=True,
            parallel_workers=2,
        ),
        constraints=StrategyConstraints(safe_mode=True, max_time=240),
        source="template",
    ),
}
