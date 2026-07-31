"""
细粒度成本追踪模块 (Fine-Grained Cost Tracking Module)

参考 LLMPFA 论文的方法，对 LLM 每次分析步骤的 token 消耗与费用进行精确追踪。
提供按文件、按会话、按 Agent、按模型的多维度成本归因与 ROI 指标计算。

主要功能:
    - 单步分析成本记录 (track_step)
    - 文件级成本汇总 (get_file_cost)
    - 会话级成本汇总 (get_session_cost)
    - 模型定价估算 (estimate_cost)
    - 多维度成本分解 (get_cost_breakdown)
    - ROI 指标计算 (get_roi_metrics)
    - 线程安全的单例模式

Author: HOS-LS Team
"""

from __future__ import annotations

import copy
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger("cost_tracker")


# ---------------------------------------------------------------------------
# 模型定价表 (USD / 1K tokens)
# ---------------------------------------------------------------------------
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    "gpt-4": {"prompt": 0.03, "completion": 0.06},
    "gpt-4-turbo": {"prompt": 0.01, "completion": 0.03},
    "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
    "claude-3-opus": {"prompt": 0.015, "completion": 0.075},
    "claude-3-sonnet": {"prompt": 0.003, "completion": 0.015},
    "claude-3-haiku": {"prompt": 0.00025, "completion": 0.00125},
    "deepseek-coder": {"prompt": 0.00014, "completion": 0.00028},
}

DEFAULT_PRICING: Dict[str, float] = {"prompt": 0.001, "completion": 0.002}


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass
class TokenUsage:
    """单次 LLM 调用的 token 使用量与估算费用。"""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model_name: str = "unknown"
    estimated_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.total_tokens == 0:
            self.total_tokens = self.prompt_tokens + self.completion_tokens


@dataclass
class StepCost:
    """单个分析步骤的成本记录。"""

    step_name: str = ""
    agent_name: str = ""
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    latency_ms: int = 0
    retry_count: int = 0


@dataclass
class FileAnalysisCost:
    """单个文件的完整分析成本汇总。"""

    file_path: str = ""
    steps: List[StepCost] = field(default_factory=list)
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: int = 0

    def recalculate(self) -> None:
        """根据 steps 重新计算汇总字段。"""
        self.total_tokens = sum(s.token_usage.total_tokens for s in self.steps)
        self.total_cost_usd = sum(s.token_usage.estimated_cost_usd for s in self.steps)
        self.total_latency_ms = sum(s.latency_ms for s in self.steps)


@dataclass
class ScanSessionCost:
    """一次完整扫描会话的成本汇总。"""

    session_id: str = ""
    file_costs: List[FileAnalysisCost] = field(default_factory=list)
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: int = 0
    total_files: int = 0
    total_steps: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    def recalculate(self) -> None:
        """根据 file_costs 重新计算汇总字段。"""
        self.total_tokens = sum(fc.total_tokens for fc in self.file_costs)
        self.total_cost_usd = sum(fc.total_cost_usd for fc in self.file_costs)
        self.total_latency_ms = sum(fc.total_latency_ms for fc in self.file_costs)
        self.total_files = len(self.file_costs)
        self.total_steps = sum(len(fc.steps) for fc in self.file_costs)
        if self.end_time is not None:
            self.wall_clock_ms = int((self.end_time - self.start_time) * 1000)
        else:
            self.wall_clock_ms = int((time.time() - self.start_time) * 1000)


# ---------------------------------------------------------------------------
# CostTracker 单例
# ---------------------------------------------------------------------------
class CostTracker:
    """
    细粒度成本追踪器 (Singleton, Thread-Safe)。

    参考 LLMPFA 论文思路，对 LLM 代码分析流水线中的每一步调用进行
    token 级别的费用追踪，支持按文件 / 会话 / Agent / 模型多维度聚合。

    使用方式::

        tracker = CostTracker()
        tracker.track_step(
            step_name="vulnerability_scan",
            agent_name="security_agent",
            token_usage=TokenUsage(prompt_tokens=500, completion_tokens=200, model_name="gpt-4"),
            latency_ms=1200,
        )
        session = tracker.get_session_cost()
        print(session.total_cost_usd)
    """

    _instance: Optional["CostTracker"] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "CostTracker":
        """双重检查锁定实现线程安全的单例。"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        self._mutex: threading.Lock = threading.Lock()
        self._session_id: str = str(uuid.uuid4())
        # file_path -> FileAnalysisCost
        self._file_costs: Dict[str, FileAnalysisCost] = {}
        # 全局步骤记录 (用于按 agent / model 聚合)
        self._all_steps: List[StepCost] = []
        # ROI 相关计数器
        self._findings_count: int = 0
        self._confirmed_findings_count: int = 0
        self._false_positives_eliminated: int = 0
        self._cache_hits: int = 0
        self._cache_misses: int = 0
        self._cache_tokens_saved: int = 0

        logger.info("CostTracker 初始化完成, session_id=%s", self._session_id)

    # ------------------------------------------------------------------
    # 核心追踪方法
    # ------------------------------------------------------------------
    def track_step(
        self,
        step_name: str,
        agent_name: str,
        token_usage: TokenUsage,
        latency_ms: int,
        file_path: str = "",
        retry_count: int = 0,
    ) -> StepCost:
        """
        记录单个分析步骤的成本。

        Args:
            step_name: 步骤名称, 例如 "vulnerability_scan", "context_build"。
            agent_name: 执行该步骤的 Agent 名称。
            token_usage: 本次调用的 token 使用量 (若 estimated_cost_usd 为 0
                         则自动根据模型定价表估算)。
            latency_ms: 本次调用耗时 (毫秒)。
            file_path: 关联的文件路径 (可选, 为空则不计入文件维度)。
            retry_count: 该步骤的重试次数。

        Returns:
            构建完成的 StepCost 对象。
        """
        # 如果调用方未自行估算费用, 则自动计算
        if token_usage.estimated_cost_usd == 0.0 and token_usage.total_tokens > 0:
            token_usage.estimated_cost_usd = self.estimate_cost(
                token_usage.model_name,
                token_usage.prompt_tokens,
                token_usage.completion_tokens,
            )

        step = StepCost(
            step_name=step_name,
            agent_name=agent_name,
            token_usage=token_usage,
            latency_ms=latency_ms,
            retry_count=retry_count,
        )

        with self._mutex:
            self._all_steps.append(step)

            # 文件维度聚合
            if file_path:
                if file_path not in self._file_costs:
                    self._file_costs[file_path] = FileAnalysisCost(file_path=file_path)
                fac = self._file_costs[file_path]
                fac.steps.append(step)
                fac.recalculate()

        logger.debug(
            "track_step: step=%s agent=%s model=%s tokens=%d cost=$%.6f latency=%dms",
            step_name,
            agent_name,
            token_usage.model_name,
            token_usage.total_tokens,
            token_usage.estimated_cost_usd,
            latency_ms,
        )
        return step

    # ------------------------------------------------------------------
    # 查询方法
    # ------------------------------------------------------------------
    def get_file_cost(self, file_path: str) -> FileAnalysisCost:
        """
        获取指定文件的分析成本汇总。

        Args:
            file_path: 文件路径。

        Returns:
            该文件的 FileAnalysisCost; 若未追踪过则返回空对象。
        """
        with self._mutex:
            fac = self._file_costs.get(file_path)
            if fac is None:
                logger.debug("get_file_cost: 文件 '%s' 尚无成本记录", file_path)
                return FileAnalysisCost(file_path=file_path)
            # 返回副本以避免外部修改内部状态
            return copy.deepcopy(fac)

    def get_session_cost(self) -> ScanSessionCost:
        """
        获取当前会话的完整成本汇总。

        Returns:
            ScanSessionCost 对象, 包含所有文件的成本与全局统计。
        """
        with self._mutex:
            session = ScanSessionCost(session_id=self._session_id)
            session.file_costs = copy.deepcopy(list(self._file_costs.values()))
            session.recalculate()
            return session

    # ------------------------------------------------------------------
    # 成本估算
    # ------------------------------------------------------------------
    def estimate_cost(
        self,
        model_name: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> float:
        """
        根据模型定价表估算一次 LLM 调用的费用 (USD)。

        定价表单位为 USD / 1K tokens。

        Args:
            model_name: 模型名称 (会尝试前缀匹配, 例如 "gpt-4-0613" 匹配 "gpt-4")。
            prompt_tokens: 输入 token 数。
            completion_tokens: 输出 token 数。

        Returns:
            估算费用 (USD)。
        """
        pricing = self._resolve_pricing(model_name)
        prompt_cost = (prompt_tokens / 1000.0) * pricing["prompt"]
        completion_cost = (completion_tokens / 1000.0) * pricing["completion"]
        total = prompt_cost + completion_cost
        return round(total, 10)

    def _resolve_pricing(self, model_name: str) -> Dict[str, float]:
        """
        解析模型名称对应的定价; 支持精确匹配与前缀匹配。

        Args:
            model_name: 模型名称。

        Returns:
            包含 "prompt" 和 "completion" 键的定价字典。
        """
        if model_name in MODEL_PRICING:
            return MODEL_PRICING[model_name]
        # 前缀匹配: 例如 "gpt-4-0613" -> "gpt-4"
        for known_name in sorted(MODEL_PRICING.keys(), key=len, reverse=True):
            if model_name.startswith(known_name):
                return MODEL_PRICING[known_name]
        logger.warning(
            "estimate_cost: 未知模型 '%s', 使用默认定价", model_name
        )
        return DEFAULT_PRICING

    # ------------------------------------------------------------------
    # 多维度成本分解
    # ------------------------------------------------------------------
    def get_cost_breakdown(self) -> Dict[str, Any]:
        """
        获取多维度成本分解, 包括按 Agent、按步骤类型、按模型三个维度。

        Returns:
            字典, 结构如下::

                {
                    "by_agent": {agent_name: {"tokens": int, "cost_usd": float, "calls": int, "latency_ms": int}},
                    "by_step": {step_name: {"tokens": int, "cost_usd": float, "calls": int, "latency_ms": int}},
                    "by_model": {model_name: {"tokens": int, "cost_usd": float, "calls": int, "latency_ms": int}},
                    "total_tokens": int,
                    "total_cost_usd": float,
                    "total_calls": int,
                    "total_latency_ms": int,
                }
        """
        by_agent: Dict[str, Dict[str, Any]] = {}
        by_step: Dict[str, Dict[str, Any]] = {}
        by_model: Dict[str, Dict[str, Any]] = {}

        with self._mutex:
            steps_snapshot = list(self._all_steps)

        for s in steps_snapshot:
            tu = s.token_usage
            # --- 按 Agent ---
            agent_key = s.agent_name or "unknown"
            if agent_key not in by_agent:
                by_agent[agent_key] = {
                    "tokens": 0,
                    "cost_usd": 0.0,
                    "calls": 0,
                    "latency_ms": 0,
                }
            by_agent[agent_key]["tokens"] += tu.total_tokens
            by_agent[agent_key]["cost_usd"] += tu.estimated_cost_usd
            by_agent[agent_key]["calls"] += 1
            by_agent[agent_key]["latency_ms"] += s.latency_ms

            # --- 按步骤 ---
            step_key = s.step_name or "unknown"
            if step_key not in by_step:
                by_step[step_key] = {
                    "tokens": 0,
                    "cost_usd": 0.0,
                    "calls": 0,
                    "latency_ms": 0,
                }
            by_step[step_key]["tokens"] += tu.total_tokens
            by_step[step_key]["cost_usd"] += tu.estimated_cost_usd
            by_step[step_key]["calls"] += 1
            by_step[step_key]["latency_ms"] += s.latency_ms

            # --- 按模型 ---
            model_key = tu.model_name or "unknown"
            if model_key not in by_model:
                by_model[model_key] = {
                    "tokens": 0,
                    "cost_usd": 0.0,
                    "calls": 0,
                    "latency_ms": 0,
                }
            by_model[model_key]["tokens"] += tu.total_tokens
            by_model[model_key]["cost_usd"] += tu.estimated_cost_usd
            by_model[model_key]["calls"] += 1
            by_model[model_key]["latency_ms"] += s.latency_ms

        total_tokens = sum(v["tokens"] for v in by_model.values())
        total_cost = sum(v["cost_usd"] for v in by_model.values())
        total_calls = sum(v["calls"] for v in by_model.values())
        total_latency = sum(v["latency_ms"] for v in by_model.values())

        return {
            "by_agent": by_agent,
            "by_step": by_step,
            "by_model": by_model,
            "total_tokens": total_tokens,
            "total_cost_usd": total_cost,
            "total_calls": total_calls,
            "total_latency_ms": total_latency,
        }

    # ------------------------------------------------------------------
    # ROI 指标
    # ------------------------------------------------------------------
    def record_finding(self, confirmed: bool = False) -> None:
        """
        记录一次漏洞发现。

        Args:
            confirmed: 是否为已确认的真实漏洞 (非误报)。
        """
        with self._mutex:
            self._findings_count += 1
            if confirmed:
                self._confirmed_findings_count += 1

    def record_false_positive_eliminated(self, count: int = 1) -> None:
        """
        记录消除的误报数量。

        Args:
            count: 消除的误报数。
        """
        with self._mutex:
            self._false_positives_eliminated += count

    def record_cache_event(self, hit: bool, tokens_saved: int = 0) -> None:
        """
        记录一次缓存命中/未命中事件。

        Args:
            hit: True 表示缓存命中, False 表示未命中。
            tokens_saved: 命中时节省的 token 数。
        """
        with self._mutex:
            if hit:
                self._cache_hits += 1
                self._cache_tokens_saved += tokens_saved
            else:
                self._cache_misses += 1

    def get_roi_metrics(self) -> Dict[str, Any]:
        """
        计算 ROI (投资回报率) 相关指标。

        包含以下指标:
            - cost_per_file: 每文件分析成本 (USD)
            - cost_per_finding: 每次发现的平均成本 (USD)
            - cost_per_confirmed_finding: 每个已确认漏洞的平均成本 (USD)
            - cost_per_false_positive_eliminated: 每消除一个误报的成本 (USD)
            - token_efficiency_findings_per_1k: 每 1K token 产出的发现数
            - token_efficiency_confirmed_per_1k: 每 1K token 产出的已确认漏洞数
            - cache_hit_rate: 缓存命中率 (0.0 ~ 1.0)
            - cache_savings_usd: 缓存节省的估算费用 (按平均 token 单价)
            - total_findings: 总发现数
            - total_confirmed_findings: 已确认漏洞数
            - total_false_positives_eliminated: 消除的误报数
            - total_cost_usd: 会话总费用
            - total_tokens: 会话总 token 数

        Returns:
            ROI 指标字典。
        """
        with self._mutex:
            session = ScanSessionCost(session_id=self._session_id)
            session.file_costs = copy.deepcopy(list(self._file_costs.values()))
            session.recalculate()

            total_cost = session.total_cost_usd
            total_tokens = session.total_tokens
            total_files = session.total_files or 1  # 避免除零
            findings = self._findings_count
            confirmed = self._confirmed_findings_count
            fp_eliminated = self._false_positives_eliminated
            cache_hits = self._cache_hits
            cache_misses = self._cache_misses
            cache_tokens_saved = self._cache_tokens_saved

        # --- 计算各指标 ---
        cost_per_file = total_cost / total_files if total_files > 0 else 0.0

        cost_per_finding = (
            total_cost / findings if findings > 0 else float("inf")
        )

        cost_per_confirmed = (
            total_cost / confirmed if confirmed > 0 else float("inf")
        )

        cost_per_fp = (
            total_cost / fp_eliminated if fp_eliminated > 0 else float("inf")
        )

        # token 效率 (findings / 1K tokens)
        findings_per_1k = (
            (findings / (total_tokens / 1000.0)) if total_tokens > 0 else 0.0
        )
        confirmed_per_1k = (
            (confirmed / (total_tokens / 1000.0)) if total_tokens > 0 else 0.0
        )

        # 缓存指标
        total_cache_requests = cache_hits + cache_misses
        cache_hit_rate = (
            cache_hits / total_cache_requests if total_cache_requests > 0 else 0.0
        )

        # 缓存节省的费用: 用平均 token 单价估算
        avg_cost_per_token = (
            total_cost / total_tokens if total_tokens > 0 else 0.0
        )
        cache_savings_usd = cache_tokens_saved * avg_cost_per_token

        return {
            "cost_per_file": round(cost_per_file, 8),
            "cost_per_finding": round(cost_per_finding, 8),
            "cost_per_confirmed_finding": round(cost_per_confirmed, 8),
            "cost_per_false_positive_eliminated": round(cost_per_fp, 8),
            "token_efficiency_findings_per_1k": round(findings_per_1k, 6),
            "token_efficiency_confirmed_per_1k": round(confirmed_per_1k, 6),
            "cache_hit_rate": round(cache_hit_rate, 4),
            "cache_savings_usd": round(cache_savings_usd, 8),
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "cache_tokens_saved": cache_tokens_saved,
            "total_findings": findings,
            "total_confirmed_findings": confirmed,
            "total_false_positives_eliminated": fp_eliminated,
            "total_cost_usd": round(total_cost, 8),
            "total_tokens": total_tokens,
        }

    # ------------------------------------------------------------------
    # 会话管理
    # ------------------------------------------------------------------
    def reset_session(self) -> None:
        """
        重置当前会话的所有追踪数据, 开始新的 session_id。
        """
        with self._mutex:
            self._session_id = str(uuid.uuid4())
            self._file_costs.clear()
            self._all_steps.clear()
            self._findings_count = 0
            self._confirmed_findings_count = 0
            self._false_positives_eliminated = 0
            self._cache_hits = 0
            self._cache_misses = 0
            self._cache_tokens_saved = 0

        logger.info("CostTracker 会话已重置, 新 session_id=%s", self._session_id)

    # ------------------------------------------------------------------
    # 便捷方法
    # ------------------------------------------------------------------
    def get_model_pricing(self, model_name: str) -> Dict[str, float]:
        """
        获取指定模型的定价信息。

        Args:
            model_name: 模型名称。

        Returns:
            包含 "prompt" 和 "completion" 键的定价字典 (USD / 1K tokens)。
        """
        return self._resolve_pricing(model_name)

    def list_supported_models(self) -> List[str]:
        """
        列出定价表中已知的所有模型名称。

        Returns:
            模型名称列表。
        """
        return list(MODEL_PRICING.keys())

    def __repr__(self) -> str:
        with self._mutex:
            n_files = len(self._file_costs)
            n_steps = len(self._all_steps)
        return (
            f"CostTracker(session_id={self._session_id!r}, "
            f"files_tracked={n_files}, steps_recorded={n_steps})"
        )
