"""Feedback Collector 反馈收集器

自动收集每次执行的元数据、用户显式反馈，
计算隐式反馈指标（取消率、重复率等）。
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .models import ExecutionLog
from .manager import get_memory_manager, MemoryManager
from ..utils.logger import get_logger

logger = get_logger(__name__)


class FeedbackCollector:
    """反馈收集器

    收集执行结果并转换为结构化的执行日志，
    支持显式用户反馈和隐式行为分析。
    """

    def __init__(self, memory_manager: Optional[MemoryManager] = None):
        """初始化反馈收集器

        Args:
            memory_manager: 可选的Memory管理器实例
        """
        self.memory_manager = memory_manager or get_memory_manager()

    def collect_execution_result(
        self,
        execution_id: str,
        strategy_used: Dict[str, Any],
        intent: str,
        target_path: str,
        result: Any,
        duration: float,
        user_satisfaction: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> ExecutionLog:
        """收集完整的执行结果

        Args:
            execution_id: 执行ID
            strategy_used: 使用的策略快照
            intent: 用户意图描述
            target_path: 目标路径
            result: 执行结果对象
            duration: 执行耗时（秒）
            user_satisfaction: 用户满意度评分（1-5）
            error_message: 错误信息（如果有）

        Returns:
            执行日志对象
        """
        # 从result中提取关键信息
        findings_count = 0
        success = True

        if isinstance(result, dict):
            success = "error" not in result
            if not success and error_message is None:
                error_message = result.get("error", "Unknown error")

            # 尝试提取findings数量
            result_data = result.get("result", {})
            if isinstance(result_data, dict):
                findings_data = result_data.get("findings", [])
                if isinstance(findings_data, list):
                    findings_count = len(findings_data)
                elif isinstance(findings_data, int):
                    findings_count = findings_data
        elif hasattr(result, "findings"):
            findings_count = len(result.findings) if hasattr(result.findings, "__len__") else 0
        elif hasattr(result, "to_dict"):
            result_dict = result.to_dict()
            findings_data = result_dict.get("findings", [])
            findings_count = len(findings_data) if isinstance(findings_data, list) else 0

        # 创建执行日志
        log = ExecutionLog(
            log_id=execution_id[:8] if len(execution_id) > 8 else execution_id,
            plan_id=execution_id,
            strategy_used=strategy_used if isinstance(strategy_used, dict) else {},
            intent=intent,
            target_path=target_path,
            duration=duration,
            findings_count=findings_count,
            success=success,
            user_feedback=user_satisfaction,
            error_message=error_message,
            timestamp=datetime.now(),
        )

        # 记录到Memory系统
        try:
            self.memory_manager.record_execution(log)
            logger.debug(
                f"执行日志已记录: {log.log_id}, findings={findings_count}, success={success}"
            )
        except Exception as e:
            logger.error(f"记录执行日志失败: {e}")

        return log

    def collect_implicit_feedback(
        self,
        log: ExecutionLog,
        was_cancelled: bool = False,
        was_interrupted: bool = False,
        repeated_similar_action: bool = False,
    ) -> Dict[str, Any]:
        """收集隐式反馈指标

        基于用户行为推断满意度，无需显式评分。

        Args:
            log: 执行日志
            was_cancelled: 是否被取消
            was_interrupted: 是否被中断
            repeated_similar_action: 是否重复相似操作

        Returns:
            隐式反馈字典
        """
        feedback = {
            "log_id": log.log_id,
            "implicit_satisfaction": self._calculate_implicit_satisfaction(
                log, was_cancelled, was_interrupted, repeated_similar_action
            ),
            "behavior_signals": {
                "cancelled": was_cancelled,
                "interrupted": was_interrupted,
                "repeated": repeated_similar_action,
                "quick_success": log.success and log.duration < 60,
                "long_duration": log.duration > 300,
                "zero_findings": log.success and log.findings_count == 0,
                "many_findings": log.findings_count > 20,
            },
            "inferred_preferences": self._infer_user_preferences(log),
        }

        logger.debug(f"隐式反馈已收集: satisfaction={feedback['implicit_satisfaction']:.2f}")
        return feedback

    def _calculate_implicit_satisfaction(
        self,
        log: ExecutionLog,
        cancelled: bool,
        interrupted: bool,
        repeated: bool,
    ) -> float:
        """计算隐式满意度分数（0-1）"""
        score = 0.7  # 基础分

        if not log.success:
            score -= 0.4  # 失败扣分
        if cancelled:
            score -= 0.3  # 取消扣分
        if interrupted:
            score -= 0.2  # 中断扣分
        if repeated:
            score += 0.1  # 重复操作可能表示满意或需要调整
        if log.success and log.findings_count > 0:
            score += min(0.2, log.findings_count * 0.01)  # 有发现加分
        if log.duration < 120 and log.success:
            score += 0.1  # 快速成功加分
        if log.duration > 600:
            score -= 0.15  # 耗时过长扣分

        return max(0.0, min(1.0, score))

    def _infer_user_preferences(self, log: ExecutionLog) -> Dict[str, Any]:
        """从执行日志推断用户偏好"""
        preferences = {}

        if log.success and log.duration < 120:
            preferences["prefers_fast"] = True
        if log.findings_count > 10:
            preferences["values_depth"] = True
        if log.strategy_used:
            mode = log.strategy_used.get("mode", "")
            if mode == "fast" and log.success:
                preferences["likes_fast_mode"] = True
            elif mode == "deep" and log.success:
                preferences["likes_deep_mode"] = True

        return preferences

    def prompt_for_feedback(self, log: ExecutionLog) -> Optional[int]:
        """提示用户提供显式反馈（可选）

        在Chat模式中调用，询问用户对本次执行的满意度。

        Args:
            log: 执行日志

        Returns:
            用户评分（1-5），如果用户跳过则返回None
        """
        # 这里只返回接口定义，实际实现在Chat UI层
        # 返回None表示用户未提供反馈
        return None


class BatchFeedbackCollector:
    """批量反馈收集器

    用于批量处理历史数据，生成统计报告。
    """

    def __init__(self, memory_manager: Optional[MemoryManager] = None):
        self.memory_manager = memory_manager or get_memory_manager()

    def collect_recent_stats(self, days: int = 7) -> Dict[str, Any]:
        """收集最近N天的统计数据

        Args:
            days: 天数

        Returns:
            统计信息字典
        """
        logs = self.memory_manager.get_recent_executions(limit=1000)

        # 过滤时间范围
        from datetime import timedelta

        cutoff = datetime.now() - timedelta(days=days)
        recent_logs = [log for log in logs if log.timestamp >= cutoff]

        if not recent_logs:
            return {
                "period_days": days,
                "total_executions": 0,
                "success_rate": 0,
                "avg_duration": 0,
                "avg_findings": 0,
                "satisfaction_distribution": {},
            }

        total = len(recent_logs)
        successful = sum(1 for log in recent_logs if log.success)
        avg_duration = sum(log.duration for log in recent_logs) / total
        avg_findings = sum(log.findings_count for log in recent_logs) / total

        # 满意度分布
        satisfaction_dist = {}
        feedback_logs = [log for log in recent_logs if log.user_feedback]
        for score in range(1, 6):
            satisfaction_dist[f"{score}_star"] = sum(
                1 for log in feedback_logs if log.user_feedback == score
            )

        # 意图分布
        intent_dist = {}
        for log in recent_logs:
            intent_type = log.intent.split(":")[0] if ":" in log.intent else log.intent
            intent_dist[intent_type] = intent_dist.get(intent_type, 0) + 1

        return {
            "period_days": days,
            "total_executions": total,
            "success_rate": successful / total,
            "avg_duration": avg_duration,
            "avg_findings": avg_findings,
            "satisfaction_distribution": satisfaction_dist,
            "intent_distribution": intent_dist,
            "cancellation_rate": sum(
                1
                for log in recent_logs
                if not log.success and "cancelled" in (log.error_message or "").lower()
            )
            / total,
        }

    def generate_improvement_suggestions(self) -> List[Dict[str, str]]:
        """基于历史数据生成改进建议

        Returns:
            建议列表
        """
        stats = self.collect_recent_stats(days=30)
        suggestions = []

        if stats["success_rate"] < 0.8:
            suggestions.append(
                {
                    "type": "warning",
                    "message": f"成功率较低 ({stats['success_rate']:.0%})，建议检查常见失败原因",
                }
            )

        if stats["avg_duration"] > 300:
            suggestions.append(
                {
                    "type": "optimization",
                    "message": f"平均耗时较长 ({stats['avg_duration']:.0f}s)，可考虑启用快速模式",
                }
            )

        if stats["avg_findings"] < 2 and stats["total_executions"] > 10:
            suggestions.append(
                {
                    "type": "info",
                    "message": "平均发现数较少，可能需要调整扫描深度或模块配置",
                }
            )

        if stats.get("cancellation_rate", 0) > 0.2:
            suggestions.append(
                {
                    "type": "ux",
                    "message": "取消率较高，建议优化策略预览或增加自动确认选项",
                }
            )

        if not suggestions:
            suggestions.append(
                {
                    "type": "good",
                    "message": "各项指标正常，继续保持！",
                }
            )

        return suggestions
