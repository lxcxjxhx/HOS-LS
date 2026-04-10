"""Strategy Engine 策略引擎

核心决策系统，协调权重计算、AI策略生成和安全约束检查。
实现"AI决策，而不是用户命令执行器"的核心理念。
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from .config import Config
from .strategy import (
    Strategy,
    StrategyDecisions,
    StrategyConstraints,
    StrategyWeights,
    ContextScores,
    STRATEGY_TEMPLATES,
    StrategyMode,
)
from ..memory.models import (
    UserMemory,
    ProjectMemory,
    Intent as MemoryIntent,
    RiskLevel,
)
from ..memory.manager import MemoryManager, get_memory_manager
from ..utils.logger import get_logger

logger = get_logger(__name__)


class StrategyEngine:
    """策略引擎

    协调多层输入（意图、用户偏好、项目风险、历史反馈），
    使用AI生成最优策略，并应用安全约束。
    """

    def __init__(self, config: Config, memory_manager: Optional[MemoryManager] = None):
        """初始化策略引擎

        Args:
            config: 配置对象
            memory_manager: 可选的Memory管理器实例
        """
        self.config = config
        self.memory_manager = memory_manager or get_memory_manager()
        self.weights = self._load_weights_from_config()

        from .ai_strategy_generator import AIStrategyGenerator
        self.ai_generator = AIStrategyGenerator(config)

        logger.info("StrategyEngine初始化完成")

    def _load_weights_from_config(self) -> StrategyWeights:
        """从配置加载权重"""
        strategy_config = getattr(self.config, "strategy", None)
        if strategy_config and hasattr(strategy_config, "weights"):
            weights_dict = strategy_config.weights
            if isinstance(weights_dict, dict):
                return StrategyWeights.from_dict(weights_dict)
        return StrategyWeights()

    async def generate_strategy(
        self,
        intent: MemoryIntent,
        user_context: Optional[UserMemory] = None,
        project_context: Optional[ProjectMemory] = None,
        explicit_overrides: Optional[Dict[str, Any]] = None,
        target_path: str = ".",
    ) -> Strategy:
        """生成最优策略（核心方法）

        Args:
            intent: 用户意图
            user_context: 用户上下文（可选，自动从Memory加载）
            project_context: 项目上下文（可选，自动从Memory加载）
            explicit_overrides: 用户显式覆盖参数
            target_path: 目标路径

        Returns:
            最优策略对象
        """
        logger.debug(f"开始生成策略: intent={intent.intent_type.value}")

        # 1. 加载上下文（如果未提供）
        if user_context is None:
            user_context = self.memory_manager.get_user_memory()

        if project_context is None:
            project_context = self.memory_manager.get_project_context(target_path)

        # 2. 计算上下文评分
        context_scores = self._calculate_context_scores(intent, user_context, project_context)
        logger.debug(f"上下文评分: {context_scores.to_dict()}")

        # 3. 动态调整权重
        adjusted_weights = self._adjust_weights(user_context, project_context)
        logger.debug(f"调整后权重: {adjusted_weights.to_dict()}")

        # 4. 生成策略
        if explicit_overrides:
            # 用户显式指定了参数 → 应用覆盖但保留AI解释
            strategy = self._apply_overrides(
                context_scores, adjusted_weights, explicit_overrides, intent, user_context, project_context
            )
            strategy.source = "user_override"
        else:
            # 调用AI生成策略（核心创新！）
            try:
                recent_history = self.memory_manager.get_project_executions(target_path, limit=5)
                strategy = await self.ai_generator.generate(
                    intent=intent,
                    context_scores=context_scores,
                    weights=adjusted_weights,
                    user_context=user_context,
                    project_context=project_context,
                    historical_data=recent_history,
                )
                strategy.source = "ai_generated"
                logger.info(f"AI策略已生成: mode={strategy.mode}, confidence={strategy.confidence:.2f}")
            except Exception as e:
                logger.warning(f"AI策略生成失败，回退到规则引擎: {e}")
                strategy = self._generate_fallback_strategy(
                    context_scores, adjusted_weights, intent, user_context, project_context
                )
                strategy.source = "fallback"

        # 5. 应用安全约束（不可被绕过）
        strategy = self._apply_safety_constraints(strategy, project_context)

        # 6. 记录上下文评分到策略
        strategy.context_scores = context_scores.to_dict()

        logger.debug(f"最终策略: {strategy.get_summary()}")
        return strategy

    def _calculate_context_scores(
        self,
        intent: MemoryIntent,
        user_context: UserMemory,
        project_context: ProjectMemory,
    ) -> ContextScores:
        """计算各维度得分（0-1）

        Args:
            intent: 用户意图
            user_context: 用户记忆
            project_context: 项目记忆

        Returns:
            上下文评分对象
        """
        scores = ContextScores()

        # 1. 用户偏好得分
        scores.user_score = self._calculate_user_score(intent, user_context)

        # 2. 项目风险得分
        scores.project_score = self._calculate_project_score(project_context)

        # 3. 意图匹配得分
        scores.intent_score = self._calculate_intent_score(intent)

        # 4. 历史反馈得分
        scores.history_score = self._calculate_history_score(user_context, project_context)

        return scores

    def _calculate_user_score(self, intent: MemoryIntent, user_context: UserMemory) -> float:
        """计算用户偏好得分

        根据用户习惯和当前意图计算匹配度
        """
        score = 0.5  # 基础分

        prefs = user_context.preferences
        habits = user_context.habits

        # 扫描深度偏好
        if intent.intent_type.value in ["scan", "analyze"]:
            depth_map = {"low": 0.3, "medium": 0.5, "high": 0.8}
            score += depth_map.get(prefs.scan_depth, 0.5) * 0.3

        # POC偏好
        if prefs.poc_enabled and intent.intent_type.value == "exploit":
            score += 0.2

        # 快速优先习惯
        if habits.prefers_fast_first and intent.extracted_params.get("fast"):
            score += 0.15

        # 输出风格
        if prefs.output_style == "detailed":
            score += 0.1

        # 高级用户加分
        if user_context.is_advanced_user():
            score += 0.1

        return min(max(score, 0.0), 1.0)

    def _calculate_project_score(self, project_context: ProjectMemory) -> float:
        """计算项目风险得分

        风险越高，分数越高（需要更多关注）
        """
        risk = project_context.risk_profile
        risk_map = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}

        base_score = risk_map.get(risk.overall, 0.5)

        # 考虑最大风险维度
        max_risk = risk.get_max_risk()
        max_risk_score = risk_map.get(max_risk, 0.5)

        # 综合得分
        score = (base_score + max_risk_score) / 2

        # 首次扫描加分（需要更全面的分析）
        if project_context.is_first_scan():
            score += 0.2

        # 技术栈复杂度影响
        tech_complexity = min(len(project_context.tech_stack) / 10, 0.3)
        score += tech_complexity

        return min(max(score, 0.0), 1.0)

    def _calculate_intent_score(self, intent: MemoryIntent) -> float:
        """计算意图匹配得分

        根据意图类型确定所需的分析深度
        """
        intent_intensity = {
            "scan": 0.5,
            "analyze": 0.7,
            "exploit": 0.9,
            "fix": 0.6,
            "info": 0.2,
            "git": 0.1,
            "plan": 0.4,
            "general": 0.3,
        }

        base_score = intent_intensity.get(intent.intent_type.value, 0.3)

        # 考虑显式参数
        params = intent.extracted_params
        if params.get("deep") or params.get("full_audit"):
            base_score += 0.3
        elif params.get("fast"):
            base_score -= 0.2

        # 考虑置信度
        base_score *= intent.confidence

        return min(max(base_score, 0.0), 1.0)

    def _calculate_history_score(self, user_context: UserMemory, project_context: ProjectMemory) -> float:
        """计算历史反馈得分

        基于历史执行效果评估
        """
        stats = user_context.behavior_stats
        scan_hist = project_context.scan_history

        score = 0.5  # 基础分

        # 成功率影响
        if stats.success_rate > 0.9:
            score += 0.2
        elif stats.success_rate < 0.7:
            score -= 0.2

        # 取消率影响
        if stats.cancel_rate > 0.3:
            score -= 0.15  # 经常取消 → 可能太慢或太激进

        # 项目历史平均发现数
        if scan_hist.average_findings_per_scan > 10:
            score += 0.1  # 高发现数 → 当前策略有效
        elif scan_hist.total_scans > 3 and scan_hist.average_findings_per_scan < 2:
            score -= 0.1  # 低发现数 → 可能需要调整

        # 使用频率
        if stats.usage_count < 5:
            score -= 0.1  # 新用户 → 更保守
        elif stats.usage_count > 50:
            score += 0.1  # 高级用户 → 可以更激进

        return min(max(score, 0.0), 1.0)

    def _adjust_weights(self, user_context: UserMemory, project_context: ProjectMemory) -> StrategyWeights:
        """根据上下文动态调整权重

        实现fix_3.md中的权重动态调整机制
        """
        return self.weights.adjust_for_context(
            is_advanced_user=user_context.is_advanced_user(),
            is_high_risk_project=project_context.is_high_risk(),
            is_first_time_project=project_context.is_first_scan(),
        )

    def _apply_overrides(
        self,
        context_scores: ContextScores,
        weights: StrategyWeights,
        overrides: Dict[str, Any],
        intent: MemoryIntent,
        user_context: UserMemory,
        project_context: ProjectMemory,
    ) -> Strategy:
        """应用用户显式覆盖

        用户指定的参数必须尊重，但仍需AI生成解释说明
        """
        template_key = overrides.get("mode", "balanced")
        base_strategy = STRATEGY_TEMPLATES.get(template_key, STRATEGY_TEMPLATES["balanced"])

        strategy = Strategy(
            mode=template_key,
            decisions=StrategyDecisions.from_dict({**base_strategy.decisions.to_dict(), **overrides}),
            constraints=StrategyConstraints.from_dict(base_strategy.constraints.to_dict()),
            source="user_override",
            confidence=0.95,  # 用户显式指定，高置信度
        )

        # 生成基于规则的简单解释
        reasoning_parts = []
        reasoning_parts.append(f"✓ 用户选择模式: {template_key}")

        if overrides.get("scan_depth"):
            reasoning_parts.append(f"✓ 扫描深度: {overrides['scan_depth']}")
        if overrides.get("enable_poc"):
            reasoning_parts.append(f"✓ POC生成: 已启用")
        if project_context.is_high_risk():
            reasoning_parts.append(f"⚠ 项目风险较高 ({project_context.risk_profile.overall})")
        else:
            reasoning_parts.append(f"✓ 项目风险: {project_context.risk_profile.overall}")

        strategy.reasoning = "\n".join(reasoning_parts)

        return strategy

    def _generate_fallback_strategy(
        self,
        context_scores: ContextScores,
        weights: StrategyWeights,
        intent: MemoryIntent,
        user_context: UserMemory,
        project_context: ProjectMemory,
    ) -> Strategy:
        """生成降级策略（当AI不可用时使用规则引擎）"""

        weighted_sum = context_scores.get_weighted_sum(weights)

        # 根据加权总分选择基础模板
        if weighted_sum < 0.4:
            mode = "fast"
        elif weighted_sum < 0.6:
            mode = "balanced"
        elif weighted_sum < 0.8:
            mode = "conservative"
        else:
            mode = "deep"

        base_template = STRATEGY_TEMPLATES.get(mode, STRATEGY_TEMPLATES["balanced"])

        decisions = StrategyDecisions.from_dict(base_template.decisions.to_dict())

        # 根据项目特性调整模块
        if project_context.tech_stack:
            tech_modules = {
                "flask": "auth",
                "django": "auth",
                "jwt": "auth",
                "express": "injection",
                "react": "xss",
                "sql": "injection",
            }

            for tech in project_context.tech_stack:
                tech_lower = tech.lower()
                if tech_lower in tech_modules:
                    module = tech_modules[tech_lower]
                    if module not in decisions.modules:
                        decisions.modules.append(module)

        constraints = StrategyConstraints(
            max_time=base_template.constraints.max_time,
            safe_mode=project_context.is_high_risk() or user_context.habits.works_in_production,
            production_environment=user_context.habits.works_in_production,
        )

        # 生成解释
        reasoning_parts = [
            f"模式选择: {mode} (加权分: {weighted_sum:.2f})",
            f"用户偏好权重: {weights.user_preference:.2f}",
            f"项目风险权重: {weights.project_risk:.2f}",
        ]

        if project_context.is_high_risk():
            reasoning_parts.append(f"⚠ 高风险项目 → 启用安全模式")
            decisions.safe_mode = True

        if len(project_context.tech_stack) > 0:
            reasoning_parts.append(f"技术栈检测: {', '.join(project_context.tech_stack[:3])}")

        strategy = Strategy(
            mode=mode,
            decisions=decisions,
            constraints=constraints,
            reasoning="\n".join(reasoning_parts),
            confidence=min(weighted_sum + 0.1, 1.0),
            source="fallback",
        )

        return strategy

    def _apply_safety_constraints(self, strategy: Strategy, project_context: ProjectMemory) -> Strategy:
        """应用安全约束（不可被绕过的硬性限制）

        实现fix_3.md中的自动风险控制机制
        """
        constraints = strategy.constraints

        # 生产环境保护
        if constraints.production_environment or project_context.risk_profile.overall in ["high", "critical"]:
            if not strategy.decisions.safe_mode:
                strategy.decisions.safe_mode = True
                strategy.reasoning += "\n⚠ 强制启用safe_mode（生产环境/高风险项目）"

            # 限制危险操作
            dangerous_modules = ["exploit_advanced", "dos_testing"]
            for module in dangerous_modules:
                if module in strategy.decisions.modules:
                    strategy.decisions.modules.remove(module)
                    strategy.reasoning += f"\n⚠ 移除危险模块: {module}"

        # 时间约束
        estimated_time = strategy.get_estimated_time()
        if estimated_time > constraints.max_time:
            # 自动降低深度
            depth_order = {"high": "medium", "medium": "low"}
            if strategy.decisions.scan_depth in depth_order:
                old_depth = strategy.decisions.scan_depth
                strategy.decisions.scan_depth = depth_order[old_depth]
                strategy.reasoning += f"\n⚠ 降低扫描深度: {old_depth} → {strategy.decisions.scan_depth} (超时保护)"

        # 成功率低的用户 → 更保守
        user_ctx = self.memory_manager.get_user_memory()
        if user_ctx.behavior_stats.success_rate < 0.7 and user_ctx.behavior_stats.total_scans > 5:
            if strategy.mode == "aggressive":
                strategy.mode = "balanced"
                strategy.reasoning += "\n⚠ 降低激进度（历史成功率较低）"

        return strategy

    def explain_decision(self, strategy: Strategy) -> str:
        """生成人类可读的决策解释

        用于Debug模式和Chat展示
        """
        explanation_parts = [
            "=" * 60,
            "[Strategy Decision Explanation]",
            "-" * 60,
            f"Mode: {strategy.mode}",
            f"Source: {strategy.source}",
            f"Confidence: {strategy.confidence:.0%}",
            "",
            "[Decisions]",
            f"  Scan Depth: {strategy.decisions.scan_depth}",
            f"  Modules: {', '.join(strategy.decisions.modules)}",
            f"  POC: {'Enabled' if strategy.decisions.enable_poc else 'Disabled'}",
            f"  Safe Mode: {'On' if strategy.decisions.safe_mode else 'Off'}",
            f"  Estimated Time: ~{strategy.get_estimated_time()}s",
            "",
            "[Context Scores]",
        ]

        if strategy.context_scores:
            for key, value in strategy.context_scores.items():
                explanation_parts.append(f"  {key}: {value:.2f}")

        explanation_parts.extend([
            "",
            "[Reasoning]",
        ])

        for line in strategy.reasoning.split("\n"):
            explanation_parts.append(f"  {line}")

        explanation_parts.extend([
            "",
            "=" * 60,
        ])

        return "\n".join(explanation_parts)

    def get_debug_output(self, strategy: Strategy, user_ctx: UserMemory, project_ctx: ProjectMemory) -> str:
        """生成Debug模式输出（符合fix_3.md规范）"""

        lines = [
            "[Memory System]",
            f"  User: prefers depth={user_ctx.preferences.scan_depth}, fast_first={user_ctx.habits.prefers_fast_first}",
            f"  Project: risk={project_ctx.risk_profile.overall}, tech_stack={project_ctx.tech_stack[:3] if project_ctx.tech_stack else []}",
            "",
            "[Strategy Decision]",
            f"  mode: {strategy.mode} (source: {strategy.source})",
            f"  depth: {strategy.decisions.scan_depth}",
            f"  poc: {'enabled' if strategy.decisions.enable_poc else 'disabled'}",
            f"  modules: {', '.join(strategy.decisions.modules)}",
            "",
            "[Decision Reasoning]",
        ]

        for line in strategy.reasoning.split("\n"):
            lines.append(f"  {line}")

        lines.extend([
            "",
            f"[Estimated Time: ~{strategy.get_estimated_time()}s | Confidence: {strategy.confidence:.0%}]",
        ])

        return "\n".join(lines)


# 全局实例缓存
_strategy_engine_cache: Dict[int, "StrategyEngine"] = {}


def get_strategy_engine(config: Config, memory_manager: Optional[MemoryManager] = None) -> StrategyEngine:
    """获取或创建StrategyEngine实例

    Args:
        config: 配置对象
        memory_manager: 可选的Memory管理器

    Returns:
        StrategyEngine实例
    """
    cache_key = id(config)
    if cache_key not in _strategy_engine_cache:
        _strategy_engine_cache[cache_key] = StrategyEngine(config, memory_manager)
    return _strategy_engine_cache[cache_key]
