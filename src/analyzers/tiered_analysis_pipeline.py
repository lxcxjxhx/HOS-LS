"""三层渐进式分析管道

对标 MultiVer 论文的多层验证方法，实现快速筛查 -> AI辅助分析 -> 深度验证的渐进式分析流程。
通过分层策略显著降低分析成本，同时保持高准确率。

架构概述:
  Tier 1 (快速筛查): 正则匹配 + 启发式评分，100+ 文件/秒
  Tier 2 (AI辅助分析): LLM单次分析 + 自一致性投票，中等深度
  Tier 3 (深度验证): 多智能体共识 + 数据流分析 + 攻击链构建
"""

import asyncio
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# 枚举与数据类定义
# ============================================================================

from src.analyzers.fast_screener import FastScreener
from src.analyzers.ai_assisted_analyzer import AIAssistedAnalyzer
from src.analyzers.deep_verifier import DeepVerifier
from src.analyzers.tiered_types import TierDecision, TieredAnalysisResult, TierResult


class TieredAnalysisPipeline:
    """三层渐进式分析管道

    对标 MultiVer 论文的多层验证方法，将分析流程分为三层：
    - Tier 1: 快速筛查（正则 + 启发式），过滤明显安全/危险的文件
    - Tier 2: AI辅助分析（LLM + 自一致性投票），对可疑文件进行中等深度分析
    - Tier 3: 深度验证（多智能体共识），对高不确定性文件进行深度分析

    核心优势：
    - 通过逐层过滤大幅减少昂贵的LLM调用次数
    - 每层都有明确的置信度阈值控制质量
    - 支持批量分析和并发控制
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """初始化三层分析管道

        Args:
            config: 管道配置，支持的键:
                - max_concurrency: 最大并发数 (默认 8)
                - skip_threshold: Tier 1 跳过阈值 (默认 0.2)
                - fast_confirm_threshold: Tier 1 快速确认阈值 (默认 0.6)
                - reject_threshold: Tier 2 拒绝阈值 (默认 0.4)
                - confirm_threshold: Tier 2 确认阈值 (默认 0.7)
                - consistency_runs: Tier 2 自一致性投票次数 (默认 3)
                - agent_concurrency: Tier 3 智能体并发数 (默认 3)
                - ai_client: AI客户端实例
        """
        self._config = config or {}
        self._max_concurrency: int = self._config.get("max_concurrency", 8)
        self._semaphore = asyncio.Semaphore(self._max_concurrency)

        # 初始化AI客户端
        self._ai_client = self._config.get("ai_client", None)

        # 初始化三层分析器
        tier1_config = {
            "skip_threshold": self._config.get("skip_threshold", 0.2),
            "fast_confirm_threshold": self._config.get("fast_confirm_threshold", 0.6),
        }
        tier2_config = {
            "consistency_runs": self._config.get("consistency_runs", 3),
            "reject_threshold": self._config.get("reject_threshold", 0.4),
            "confirm_threshold": self._config.get("confirm_threshold", 0.7),
        }
        tier3_config = {
            "agent_concurrency": self._config.get("agent_concurrency", 3),
        }

        self._tier1 = FastScreener(tier1_config)
        self._tier2 = AIAssistedAnalyzer(tier2_config, self._ai_client)
        self._tier3 = DeepVerifier(tier3_config, self._ai_client)

        # 设置并发信号量
        self._tier2.set_semaphore(self._semaphore)
        self._tier3.set_semaphore(self._semaphore)

        # 统计计数器
        self._stats = {
            "total_files": 0,
            "tier1_skip": 0,
            "tier1_fast_confirm": 0,
            "tier1_proceed_to_t2": 0,
            "tier2_reject": 0,
            "tier2_confirm": 0,
            "tier2_proceed_to_t3": 0,
            "tier3_final_reject": 0,
            "tier3_final_confirm": 0,
            "total_tokens": 0,
            "total_elapsed_ms": 0.0,
            "errors": 0,
        }

    async def analyze_file(
        self, file_path: Path, file_content: str
    ) -> TieredAnalysisResult:
        """对单个文件执行三层渐进式分析

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            TieredAnalysisResult: 完整的分析结果
        """
        overall_start = time.perf_counter()
        tier_results: List[TierResult] = []
        final_findings: List[Dict[str, Any]] = []
        total_tokens = 0

        try:
            # ======== Tier 1: 快速筛查 ========
            t1_result = self._tier1.screen(file_path, file_content)
            tier_results.append(t1_result)
            total_tokens += t1_result.token_cost

            logger.debug(
                f"Tier 1 [{file_path.name}]: "
                f"decision={t1_result.decision}, "
                f"confidence={t1_result.confidence:.2f}, "
                f"findings={len(t1_result.findings)}, "
                f"elapsed={t1_result.elapsed_ms:.1f}ms"
            )

            # Tier 1 决策路由
            if t1_result.decision == TierDecision.SKIP.value:
                self._stats["tier1_skip"] += 1
                return self._build_result(
                    file_path, TierDecision.SKIP.value, [],
                    tier_results, overall_start, total_tokens,
                )

            if t1_result.decision == TierDecision.FAST_CONFIRM.value:
                self._stats["tier1_fast_confirm"] += 1
                # 快速确认的发现标记为中等置信度（需要后续验证）
                fast_findings = [
                    {**f, "confidence": min(f.get("severity", 0.7), 0.85),
                     "verification_status": "fast_confirm_pending_review"}
                    for f in t1_result.findings
                ]
                return self._build_result(
                    file_path, TierDecision.FAST_CONFIRM.value, fast_findings,
                    tier_results, overall_start, total_tokens,
                )

            # PROCEED_TO_TIER2
            self._stats["tier1_proceed_to_t2"] += 1

            # ======== Tier 2: AI辅助分析 ========
            t2_result = await self._tier2.analyze(
                file_path, file_content, t1_result.findings
            )
            tier_results.append(t2_result)
            total_tokens += t2_result.token_cost

            logger.debug(
                f"Tier 2 [{file_path.name}]: "
                f"decision={t2_result.decision}, "
                f"confidence={t2_result.confidence:.2f}, "
                f"findings={len(t2_result.findings)}, "
                f"tokens={t2_result.token_cost}, "
                f"elapsed={t2_result.elapsed_ms:.1f}ms"
            )

            # Tier 2 决策路由
            if t2_result.decision == TierDecision.REJECT.value:
                self._stats["tier2_reject"] += 1
                return self._build_result(
                    file_path, TierDecision.REJECT.value, [],
                    tier_results, overall_start, total_tokens,
                )

            if t2_result.decision == TierDecision.CONFIRM.value:
                self._stats["tier2_confirm"] += 1
                # 合并Tier 1和Tier 2的发现
                combined = self._merge_findings(t1_result.findings, t2_result.findings)
                return self._build_result(
                    file_path, TierDecision.CONFIRM.value, combined,
                    tier_results, overall_start, total_tokens,
                )

            # PROCEED_TO_TIER3
            self._stats["tier2_proceed_to_t3"] += 1

            # ======== Tier 3: 深度验证 ========
            t3_result = await self._tier3.verify(
                file_path, file_content,
                t1_result.findings, t2_result.findings,
            )
            tier_results.append(t3_result)
            total_tokens += t3_result.token_cost

            logger.debug(
                f"Tier 3 [{file_path.name}]: "
                f"decision={t3_result.decision}, "
                f"confidence={t3_result.confidence:.2f}, "
                f"findings={len(t3_result.findings)}, "
                f"tokens={t3_result.token_cost}, "
                f"elapsed={t3_result.elapsed_ms:.1f}ms"
            )

            # Tier 3 最终决策
            if t3_result.decision == TierDecision.FINAL_CONFIRM.value:
                self._stats["tier3_final_confirm"] += 1
            else:
                self._stats["tier3_final_reject"] += 1

            # 合并所有层的发现
            all_findings = self._merge_findings(
                t1_result.findings,
                self._merge_findings(t2_result.findings, t3_result.findings),
            )

            return self._build_result(
                file_path, t3_result.decision, all_findings,
                tier_results, overall_start, total_tokens,
            )

        except Exception as exc:
            self._stats["errors"] += 1
            logger.error(f"分析管道异常 [{file_path}]: {exc}", exc_info=True)
            elapsed = (time.perf_counter() - overall_start) * 1000
            return TieredAnalysisResult(
                file_path=str(file_path),
                final_decision="ERROR",
                final_findings=[{
                    "error": str(exc),
                    "source": "pipeline_error",
                }],
                tier_results=tier_results,
                total_elapsed_ms=elapsed,
                total_tokens=total_tokens,
            )

    async def analyze_batch(
        self, files: List[Tuple[Path, str]]
    ) -> List[TieredAnalysisResult]:
        """批量分析文件

        使用信号量控制并发，避免资源耗尽。

        Args:
            files: (文件路径, 文件内容) 的列表

        Returns:
            每个文件的分析结果列表
        """
        if not files:
            return []

        batch_start = time.perf_counter()
        self._stats["total_files"] += len(files)

        logger.info(
            f"开始批量分析: {len(files)} 个文件, "
            f"最大并发: {self._max_concurrency}"
        )

        # 创建所有分析任务
        tasks = [
            self._safe_analyze_file(file_path, file_content)
            for file_path, file_content in files
        ]

        # 并发执行（信号量在 analyze_file 内部已控制）
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常结果
        final_results: List[TieredAnalysisResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"批量分析中文件异常: {files[i][0]}: {result}")
                self._stats["errors"] += 1
                final_results.append(TieredAnalysisResult(
                    file_path=str(files[i][0]),
                    final_decision="ERROR",
                    final_findings=[{"error": str(result), "source": "batch_error"}],
                    tier_results=[],
                    total_elapsed_ms=0.0,
                    total_tokens=0,
                ))
            else:
                final_results.append(result)

        batch_elapsed = (time.perf_counter() - batch_start) * 1000
        self._stats["total_elapsed_ms"] += batch_elapsed

        logger.info(
            f"批量分析完成: {len(files)} 个文件, "
            f"总耗时: {batch_elapsed:.0f}ms, "
            f"平均: {batch_elapsed / len(files):.0f}ms/文件"
        )

        return final_results

    async def _safe_analyze_file(
        self, file_path: Path, file_content: str
    ) -> TieredAnalysisResult:
        """安全包装的文件分析（捕获所有异常）

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            TieredAnalysisResult
        """
        try:
            return await self.analyze_file(file_path, file_content)
        except Exception as exc:
            logger.error(f"文件分析失败 [{file_path}]: {exc}")
            return TieredAnalysisResult(
                file_path=str(file_path),
                final_decision="ERROR",
                final_findings=[{"error": str(exc)}],
                tier_results=[],
                total_elapsed_ms=0.0,
                total_tokens=0,
            )

    def get_statistics(self) -> Dict[str, Any]:
        """获取管道运行统计信息

        Returns:
            包含各层跳过率、平均token消耗等的统计字典
        """
        total = max(self._stats["total_files"], 1)
        t1_proceeded = (
            self._stats["tier1_fast_confirm"]
            + self._stats["tier1_proceed_to_t2"]
        )
        t2_proceeded = self._stats["tier2_proceed_to_t3"]

        return {
            # 基础统计
            "total_files_analyzed": self._stats["total_files"],
            "total_errors": self._stats["errors"],
            "total_tokens_consumed": self._stats["total_tokens"],
            "total_elapsed_ms": self._stats["total_elapsed_ms"],

            # Tier 1 统计
            "tier1_skip_count": self._stats["tier1_skip"],
            "tier1_skip_rate": self._stats["tier1_skip"] / total,
            "tier1_fast_confirm_count": self._stats["tier1_fast_confirm"],
            "tier1_fast_confirm_rate": self._stats["tier1_fast_confirm"] / total,
            "tier1_proceed_to_t2_count": self._stats["tier1_proceed_to_t2"],
            "tier1_proceed_to_t2_rate": self._stats["tier1_proceed_to_t2"] / total,

            # Tier 2 统计
            "tier2_reject_count": self._stats["tier2_reject"],
            "tier2_reject_rate": (
                self._stats["tier2_reject"] / max(t1_proceeded, 1)
            ),
            "tier2_confirm_count": self._stats["tier2_confirm"],
            "tier2_confirm_rate": (
                self._stats["tier2_confirm"] / max(t1_proceeded, 1)
            ),
            "tier2_proceed_to_t3_count": self._stats["tier2_proceed_to_t3"],
            "tier2_proceed_to_t3_rate": (
                self._stats["tier2_proceed_to_t3"] / max(t1_proceeded, 1)
            ),

            # Tier 3 统计
            "tier3_final_confirm_count": self._stats["tier3_final_confirm"],
            "tier3_final_reject_count": self._stats["tier3_final_reject"],

            # 效率指标
            "llm_call_reduction_rate": (
                1.0 - (t1_proceeded + t2_proceeded) / total
                if total > 0 else 0.0
            ),
            "avg_tokens_per_file": (
                self._stats["total_tokens"] / total
            ),
            "avg_elapsed_per_file_ms": (
                self._stats["total_elapsed_ms"] / total
                if self._stats["total_files"] > 0 else 0.0
            ),
        }

    def reset_statistics(self) -> None:
        """重置统计计数器"""
        for key in self._stats:
            if isinstance(self._stats[key], float):
                self._stats[key] = 0.0
            else:
                self._stats[key] = 0

    # ---- 内部辅助方法 ----

    def _build_result(
        self,
        file_path: Path,
        final_decision: str,
        findings: List[Dict[str, Any]],
        tier_results: List[TierResult],
        overall_start: float,
        total_tokens: int,
    ) -> TieredAnalysisResult:
        """构建最终分析结果

        Args:
            file_path: 文件路径
            final_decision: 最终决策
            findings: 最终发现
            tier_results: 各层结果
            overall_start: 开始时间
            total_tokens: 总token数

        Returns:
            TieredAnalysisResult
        """
        elapsed = (time.perf_counter() - overall_start) * 1000
        self._stats["total_tokens"] += total_tokens
        return TieredAnalysisResult(
            file_path=str(file_path),
            final_decision=final_decision,
            final_findings=findings,
            tier_results=tier_results,
            total_elapsed_ms=elapsed,
            total_tokens=total_tokens,
        )

    @staticmethod
    def _merge_findings(
        findings_a: List[Dict[str, Any]],
        findings_b: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """合并两层分析的发现（去重）

        去重策略: 如果两条发现的 rule_id 和行号相同，保留置信度更高的那条。

        Args:
            findings_a: 第一层的发现
            findings_b: 第二层的发现

        Returns:
            合并后的发现列表
        """
        if not findings_a:
            return findings_b
        if not findings_b:
            return findings_a

        # 使用 (rule_id, line_number) 作为去重键
        seen: Dict[Tuple[str, int], Dict[str, Any]] = {}

        for finding in findings_a:
            key = (
                finding.get("rule_id", ""),
                finding.get("line_number", finding.get("line", 0)),
            )
            seen[key] = finding

        for finding in findings_b:
            key = (
                finding.get("rule_id", ""),
                finding.get("line_number", finding.get("line", 0)),
            )
            if key in seen:
                # 保留置信度更高的
                existing_conf = seen[key].get("confidence", seen[key].get("severity", 0))
                new_conf = finding.get("confidence", finding.get("severity", 0))
                if new_conf > existing_conf:
                    # 合并元数据
                    merged = {**seen[key], **finding}
                    seen[key] = merged
            else:
                seen[key] = finding

        return list(seen.values())
