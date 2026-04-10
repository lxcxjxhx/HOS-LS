"""AI Strategy Generator（核心创新）

使用AI API生成最优扫描策略，替代传统的硬编码规则。
这是fix_3.md中"AI决策，而不是用户命令执行器"理念的具体实现。

核心优势：
- 理解复杂权衡（如：用户要快但项目风险高）
- 生成可解释的决策理由
- 根据历史数据发现模式
- 自然语言输出便于用户理解
"""

import json
from typing import Any, Dict, List, Optional

from ..core.config import Config
from ..core.strategy import (
    Strategy,
    StrategyDecisions,
    StrategyConstraints,
    StrategyWeights,
    ContextScores,
)
from ..memory.models import (
    UserMemory,
    ProjectMemory,
    Intent as MemoryIntent,
    ExecutionLog,
)
from ..ai.client import get_model_manager, AIRequest
from ..utils.logger import get_logger

logger = get_logger(__name__)


STRATEGY_GENERATION_PROMPT = """你是一个专业的安全扫描策略专家。你的任务是根据提供的上下文信息，生成最优的安全扫描策略。

## 用户偏好
{user_preferences}

## 项目风险画像
{project_risk_profile}
技术栈: {tech_stack}
扫描历史: {scan_history_summary}

## 用户意图
意图类型: {intent_type}
原始输入: {original_text}
提取参数: {extracted_params}

## 历史执行数据（最近5次）
{historical_data}

## 权重配置
- 用户偏好权重: {user_pref_weight:.2f}
- 项目风险权重: {project_risk_weight:.2f}
- 意图权重: {intent_weight:.2f}
- 历史反馈权重: {history_weight:.2f}

## 上下文评分
- 用户得分: {user_score:.2f}
- 项目得分: {project_score:.2f}
- 意图得分: {intent_score:.2f}
- 历史得分: {history_score:.2f}

请严格按以下JSON格式输出策略决策（不要包含其他文字）：

```json
{{
  "mode": "balanced|aggressive|conservative|fast|deep",
  "decisions": {{
    "scan_depth": "low|medium|high",
    "enable_poc": true/false,
    "modules": ["module1", "module2"],
    "ai_model": "default",
    "batch_size": 8,
    "parallel_workers": 4,
    "safe_mode": true/false,
    "enable_attack_chain": true/false,
    "enable_auth_analysis": true/false,
    "output_format": "html"
  }},
  "constraints": {{
    "max_time": 300,
    "max_cost": 10.0,
    "safe_mode": false,
    "production_environment": {is_production}
  }},
  "reasoning": "详细的决策理由说明（3-5句话），包括：
    1. 为什么选择这个模式
    2. 如何权衡用户需求和项目特性
    3. 推荐哪些模块及原因
    4. 特别注意事项（如果有）",
  "confidence": 0.85
}}
```

## 决策指南

### 模式选择原则
- **fast**: 用户明确要求快速 + 项目低风险 + 首次快速检查
- **balanced**: 默认推荐，平衡速度和深度
- **deep**: 用户要求深度分析 + 高风险项目 + 需要全面审计
- **conservative**: 生产环境 + 高成功率要求 + 避免误报
- **aggressive**: 红队测试 + 漏洞赏金 + 允许较高误报率

### 扫描深度选择
- **low**: 快速检查，仅明显问题
- **medium**: 标准深度，覆盖主要漏洞类型
- **high**: 深度分析，包括复杂攻击链

### 模块推荐逻辑
根据技术栈自动推荐：
- Web框架(flask/django/express) → auth模块
- SQL数据库 → injection模块
- 前端框架(react/vue) → xss模块
- 认证相关(jwt/oauth/session) → auth_analysis
- 高风险项目 → 启用attack_chain

### 特殊情况处理
⚠️ 如果出现以下情况，必须在reasoning中说明：
1. 用户要求与项目风险冲突（如：要快但高风险）
2. 生产环境保护需求
3. 首次扫描项目的建议
4. 基于历史数据的调整建议

现在请生成策略决策：
"""


class AIStrategyGenerator:
    """AI策略生成器

    使用大语言模型生成智能化的扫描策略决策。
    """

    def __init__(self, config: Config):
        """初始化AI策略生成器

        Args:
            config: 配置对象
        """
        self.config = config
        self._client = None
        self._model_manager = None

    async def _get_client(self):
        """延迟初始化AI客户端"""
        if self._client is None:
            try:
                self._model_manager = await get_model_manager(self.config)
                self._client = self._model_manager.get_default_client()
                if not self._client:
                    raise RuntimeError("无法获取默认AI客户端")
                logger.info("AI策略生成器客户端初始化成功")
            except Exception as e:
                logger.error(f"AI策略生成器客户端初始化失败: {e}")
                raise

        return self._client

    async def generate(
        self,
        intent: MemoryIntent,
        context_scores: ContextScores,
        weights: StrategyWeights,
        user_context: UserMemory,
        project_context: ProjectMemory,
        historical_data: List[ExecutionLog] = None,
    ) -> Strategy:
        """生成AI策略（核心方法）

        Args:
            intent: 用户意图
            context_scores: 上下文评分
            weights: 权重配置
            user_context: 用户上下文
            project_context: 项目上下文
            historical_data: 历史执行数据

        Returns:
            AI生成的策略对象
        """
        client = await self._get_client()

        # 构建prompt
        prompt = self._build_prompt(
            intent, context_scores, weights, user_context, project_context, historical_data or []
        )

        logger.debug(f"发送策略生成请求到AI...")

        # 调用AI API
        try:
            request = AIRequest(
                messages=[
                    {
                        "role": "system",
                        "content": "你是HOS-LS安全扫描系统的策略决策引擎。你必须始终返回有效的JSON格式响应，不要包含任何额外的解释或markdown标记。",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,  # 低温度保证稳定性
                max_tokens=1500,
            )

            response = await client.generate(request)

            # 解析响应
            strategy_data = self._parse_ai_response(response.content)

            # 构建Strategy对象
            strategy = self._build_strategy_from_response(strategy_data, intent)

            logger.info(f"AI策略生成成功: mode={strategy.mode}, confidence={strategy.confidence:.2f}")
            return strategy

        except Exception as e:
            logger.error(f"AI策略生成失败: {e}")
            raise

    def _build_prompt(
        self,
        intent: MemoryIntent,
        context_scores: ContextScores,
        weights: StrategyWeights,
        user_context: UserMemory,
        project_context: ProjectMemory,
        historical_data: List[ExecutionLog],
    ) -> str:
        """构建prompt"""

        # 格式化用户偏好
        user_prefs = f"""- 扫描深度偏好: {user_context.preferences.scan_depth}
- 输出风格: {user_context.preferences.output_style}
- POC启用: {user_context.preferences.poc_enabled}
- 自动确认: {user_context.preferences.auto_confirm}
- 使用次数: {user_context.behavior_stats.usage_count} ({"高级用户" if user_context.is_advanced_user() else "普通用户"})
- 习惯: 快速优先={user_context.habits.prefers_fast_first}, 避免激进={user_context.habits.avoids_aggressive}, 生产环境={user_context.habits.works_in_production}"""

        # 格式化项目风险画像
        risk_profile = project_context.risk_profile
        project_risk = f"""- 整体风险: {risk_profile.overall}
- 认证风险: {risk_profile.auth_risk}
- 注入风险: {risk_profile.injection_risk}
- XSS风险: {risk_profile.xss_risk}
- 数据暴露风险: {risk_profile.data_exposure_risk}
- 是否首次扫描: {'是' if project_context.is_first_scan() else '否'}"""

        # 格式化扫描历史
        scan_hist = project_context.scan_history
        scan_history_summary = f"""总扫描次数: {scan_hist.total_scans}
上次深度: {scan_hist.last_scan_depth}
上次耗时: {scan_hist.last_scan_duration:.0f}s
上次发现数: {scan_hist.last_scan_findings}
平均发现数/次: {scan_hist.average_findings_per_scan:.1f}"""

        # 格式化历史执行数据
        if historical_data:
            hist_lines = []
            for i, log in enumerate(historical_data[-5:], 1):
                status = "✓ 成功" if log.success else "✗ 失败"
                feedback = f", 满意度: {log.user_feedback}/5" if log.user_feedback else ""
                hist_lines.append(
                    f"{i}. [{log.timestamp.strftime('%Y-%m-%d %H:%M')}] "
                    f"{status} | 耗时:{log.duration:.0f}s | 发现:{log.findings_count}个{feedback}"
                )
            historical_data_str = "\n".join(hist_lines) if hist_lines else "暂无历史数据"
        else:
            historical_data_str = "暂无历史数据"

        # 构建完整prompt
        prompt = STRATEGY_GENERATION_PROMPT.format(
            user_preferences=user_prefs,
            project_risk_profile=project_risk,
            tech_stack=", ".join(project_context.tech_stack) if project_context.tech_stack else "未检测",
            scan_history_summary=scan_history_summary,
            intent_type=intent.intent_type.value,
            original_text=intent.original_text,
            extracted_params=json.dumps(intent.extracted_params, ensure_ascii=False),
            historical_data=historical_data_str,
            user_pref_weight=weights.user_preference,
            project_risk_weight=weights.project_risk,
            intent_weight=weights.intent,
            history_weight=weights.history_feedback,
            user_score=context_scores.user_score,
            project_score=context_scores.project_score,
            intent_score=context_scores.intent_score,
            history_score=context_scores.history_score,
            is_production=str(user_context.habits.works_in_production).lower(),
        )

        return prompt

    def _parse_ai_response(self, response_content: str) -> Dict[str, Any]:
        """解析AI响应

        处理可能的markdown代码块包裹和其他格式问题
        """
        content = response_content.strip()

        # 尝试提取JSON（可能被```json ```包裹）
        if "```" in content:
            import re
            json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
            if json_match:
                content = json_match.group(1).strip()

        try:
            data = json.loads(content)
            logger.debug(f"AI响应解析成功")
            return data
        except json.JSONDecodeError as e:
            logger.error(f"AI响应JSON解析失败: {e}")
            logger.debug(f"原始响应内容: {content[:500]}...")
            raise ValueError(f"无效的AI响应格式: {e}")

    def _build_strategy_from_response(self, data: Dict[str, Any], intent: MemoryIntent) -> Strategy:
        """从AI响应构建Strategy对象"""

        decisions_data = data.get("decisions", {})
        constraints_data = data.get("constraints", {})

        decisions = StrategyDecisions(
            scan_depth=decisions_data.get("scan_depth", "medium"),
            enable_poc=decisions_data.get("enable_poc", False),
            modules=decisions_data.get("modules", ["auth", "injection", "xss"]),
            ai_model=decisions_data.get("ai_model", "default"),
            batch_size=decisions_data.get("batch_size", 8),
            parallel_workers=decisions_data.get("parallel_workers", 4),
            safe_mode=decisions_data.get("safe_mode", False),
            enable_attack_chain=decisions_data.get("enable_attack_chain", False),
            enable_auth_analysis=decisions_data.get("enable_auth_analysis", False),
            output_format=decisions_data.get("output_format", "html"),
        )

        constraints = StrategyConstraints(
            max_time=constraints_data.get("max_time", 300),
            max_cost=constraints_data.get("max_cost", 10.0),
            safe_mode=constraints_data.get("safe_mode", False),
            production_environment=constraints_data.get("production_environment", False),
        )

        strategy = Strategy(
            mode=data.get("mode", "balanced"),
            decisions=decisions,
            constraints=constraints,
            reasoning=data.get("reasoning", "AI生成的策略"),
            confidence=min(max(data.get("confidence", 0.85), 0.0), 1.0),
            source="ai_generated",
        )

        # 验证策略合理性
        strategy = self._validate_and_fix_strategy(strategy)

        return strategy

    def _validate_and_fix_strategy(self, strategy: Strategy) -> Strategy:
        """验证并修复策略中的不合理值"""

        # 验证mode
        valid_modes = ["balanced", "aggressive", "conservative", "fast", "deep"]
        if strategy.mode not in valid_modes:
            logger.warning(f"无效的策略模式: {strategy.mode}，回退到balanced")
            strategy.mode = "balanced"

        # 验证scan_depth
        valid_depths = ["low", "medium", "high"]
        if strategy.decisions.scan_depth not in valid_depths:
            logger.warning(f"无效的扫描深度: {strategy.decisions.scan_depth}，回退到medium")
            strategy.decisions.scan_depth = "medium"

        # 验证modules
        valid_modules = [
            "auth", "injection", "xss", "data_exposure",
            "dependency", "configuration", "crypto",
            "attack_chain", "auth_analysis",
        ]
        filtered_modules = [m for m in strategy.decisions.modules if m in valid_modules]
        if not filtered_modules:
            filtered_modules = ["injection", "xss"]  # 最小模块集
        strategy.decisions.modules = filtered_modules

        # 合理性约束
        if strategy.constraints.max_time < 30:
            strategy.constraints.max_time = 30
            logger.warning("最大时间过短，调整为30秒")

        if strategy.decisions.batch_size < 1:
            strategy.decisions.batch_size = 1
        elif strategy.decisions.batch_size > 64:
            strategy.decisions.batch_size = 64

        if strategy.decisions.parallel_workers < 1:
            strategy.decisions.parallel_workers = 1
        elif strategy.decisions.parallel_workers > 16:
            strategy.decisions.parallel_workers = 16

        return strategy


class CachedAIStrategyGenerator:
    """带缓存的AI策略生成器

    缓存相似上下文的策略结果，减少API调用。
    """

    def __init__(self, config: Config, ttl: int = 3600):
        """初始化

        Args:
            config: 配置对象
            ttl: 缓存有效期（秒）
        """
        self.generator = AIStrategyGenerator(config)
        self.cache: Dict[str, tuple] = {}  # key -> (strategy, timestamp)
        self.ttl = ttl

    def _generate_cache_key(
        self,
        intent: MemoryIntent,
        context_scores: ContextScores,
        project_hash: str,
    ) -> str:
        """生成缓存键"""
        import hashlib
        key_data = f"{intent.intent_type.value}_{context_scores.get_weighted_sum(StrategyWeights()):.2f}_{project_hash}"
        return hashlib.md5(key_data.encode()).hexdigest()

    async def generate(
        self,
        intent: MemoryIntent,
        context_scores: ContextScores,
        weights: StrategyWeights,
        user_context: UserMemory,
        project_context: ProjectMemory,
        historical_data: List[ExecutionLog] = None,
    ) -> Strategy:
        """生成策略（带缓存）"""
        cache_key = self._generate_cache_key(intent, context_scores, project_context.project_hash)

        # 检查缓存
        if cache_key in self.cache:
            cached_strategy, timestamp = self.cache[cache_key]
            from datetime import datetime
            if (datetime.now() - timestamp).total_seconds() < self.ttl:
                logger.debug(f"使用缓存的策略: {cache_key[:8]}...")
                return cached_strategy

        # 调用实际生成器
        strategy = await self.generator.generate(
            intent=intent,
            context_scores=context_scores,
            weights=weights,
            user_context=user_context,
            project_context=project_context,
            historical_data=historical_data,
        )

        # 更新缓存
        self.cache[cache_key] = (strategy, datetime.now())

        # 清理过期缓存
        self._cleanup_cache()

        return strategy

    def _cleanup_cache(self):
        """清理过期缓存"""
        from datetime import datetime
        now = datetime.now()
        expired_keys = [
            key for key, (_, ts) in self.cache.items()
            if (now - ts).total_seconds() > self.ttl * 2  # 保留2倍TTL
        ]
        for key in expired_keys:
            del self.cache[key]

        if expired_keys:
            logger.debug(f"清理了 {len(expired_keys)} 个过期缓存条目")

    def clear_cache(self):
        """清除所有缓存"""
        self.cache.clear()
        logger.info("策略缓存已清除")
