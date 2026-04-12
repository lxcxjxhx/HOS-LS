"""Strategy Optimizer 权重自优化

基于强化学习思路，根据历史执行效果动态调整策略权重，
实现fix_3.md中的自优化机制。
"""

from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta

from ..core.strategy import StrategyWeights
from ..memory.manager import get_memory_manager, MemoryManager
from ..utils.logger import get_logger

logger = get_logger(__name__)


class StrategyOptimizer:
    """策略权重优化器

    根据历史执行效果，使用简化的强化学习方法
    动态调整策略引擎的权重配置，使系统越用越智能。
    """

    def __init__(
        self,
        memory_manager: Optional[MemoryManager] = None,
        optimization_interval: int = 50,
        min_samples: int = 10,
    ):
        """初始化

        Args:
            memory_manager: 可选的Memory管理器实例
            optimization_interval: 优化间隔（每N次执行后触发）
            min_samples: 最小样本数要求
        """
        self.memory_manager = memory_manager or get_memory_manager()
        self.optimization_interval = optimization_interval
        self.min_samples = min_samples

    def should_optimize(self) -> bool:
        """检查是否应该执行优化

        Returns:
            是否达到优化条件
        """
        user_memory = self.memory_manager.get_user_memory()
        total_executions = user_memory.behavior_stats.total_scans

        return (
            total_executions >= self.min_samples
            and total_executions % self.optimization_interval == 0
        )

    async def optimize_weights(
        self,
        current_weights: StrategyWeights,
        lookback_days: int = 30,
    ) -> Tuple[StrategyWeights, Dict[str, Any]]:
        """执行权重优化

        Args:
            current_weights: 当前权重配置
            lookback_days: 回溯天数

        Returns:
            元组：(优化后的权重, 优化报告)
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "previous_weights": current_weights.to_dict(),
            "optimization_applied": False,
            "reasoning": [],
            "metrics": {},
        }

        # 收集历史数据
        logs = self.memory_manager.get_recent_executions(limit=200)

        if len(logs) < self.min_samples:
            report["reasoning"].append(f"样本不足 ({len(logs)} < {self.min_samples})，跳过优化")
            return current_weights, report

        # 过滤时间范围
        cutoff = datetime.now() - timedelta(days=lookback_days)
        recent_logs = [log for log in logs if log.timestamp >= cutoff]

        if len(recent_logs) < 5:
            report["reasoning"].append(f"近期样本过少 ({len(recent_logs)})，跳过优化")
            return current_weights, report

        # 计算指标
        metrics = self._calculate_metrics(recent_logs)
        report["metrics"] = metrics

        # 基于指标调整权重
        new_weights = StrategyWeights(
            user_preference=current_weights.user_preference,
            project_risk=current_weights.project_risk,
            intent=current_weights.intent,
            history_feedback=current_weights.history_feedback,
        )

        adjustments = []

        # 1. 成功率调整
        if metrics["success_rate"] < 0.8:
            new_weights.project_risk += 0.1  # 增加项目风险权重（更保守）
            new_weights.user_preference -= 0.05  # 降低用户偏好权重
            adjustments.append(f"成功率低 ({metrics['success_rate']:.0%}) → 提高项目风险权重")

        elif metrics["success_rate"] > 0.95:
            new_weights.user_preference += 0.05  # 成功率高 → 更信任用户
            adjustments.append(f"成功率高 ({metrics['success_rate']:.0%}) → 提高用户偏好权重")

        # 2. 满意度调整
        if "avg_satisfaction" in metrics:
            avg_sat = metrics["avg_satisfaction"]
            if avg_sat is not None and avg_sat <= 2:
                new_weights.user_preference += 0.1  # 满意度低 → 更听从用户
                new_weights.intent -= 0.05
                adjustments.append(f"满意度低 ({avg_sat:.1f}/5) → 显著提高用户权重")

            elif avg_sat is not None and avg_sat >= 4:
                adjustments.append(f"满意度高 ({avg_sat:.1f}/5) → 保持当前权重")

        # 3. 取消率调整
        if metrics["cancel_rate"] > 0.25:
            new_weights.intent += 0.08  # 高取消率 → 更关注意图匹配
            new_weights.user_preference -= 0.03
            adjustments.append(f"取消率高 ({metrics['cancel_rate']:.0%}) → 提高意图权重")

        # 4. 效率调整
        if metrics["avg_duration"] > 400 and metrics["success_rate"] > 0.85:
            new_weights.history_feedback += 0.05  # 耗时但成功 → 参考历史优化效率
            adjustments.append(f"耗时较长但成功 → 增加历史反馈权重以优化效率")

        # 归一化权重
        new_weights.normalize()

        # 检查是否有显著变化
        old_total = sum(current_weights.to_dict().values())
        new_total = sum(new_weights.to_dict().values())
        change_magnitude = abs(new_total - old_total) / old_total if old_total > 0 else 0

        if change_magnitude > 0.05:  # 变化超过5%
            report["optimization_applied"] = True
            report["new_weights"] = new_weights.to_dict()
            report["reasoning"] = adjustments
            logger.info(f"权重已优化: 变化幅度={change_magnitude:.2%}")
        else:
            report["reasoning"].append("变化不显著（<5%），保持原权重")

        return new_weights, report

    def _calculate_metrics(self, logs: List[ExecutionLog]) -> Dict[str, float]:
        """计算关键性能指标

        Args:
            logs: 执行日志列表

        Returns:
            指标字典
        """
        if not logs:
            return {}

        total = len(logs)
        successful = sum(1 for log in logs if log.success)
        cancelled = sum(
            1
            for log in logs
            if not log.success and log.error_message and "cancelled" in log.error_message.lower()
        )

        durations = [log.duration for log in logs if log.success]
        findings = [log.findings_count for log in logs if log.success]

        feedback_scores = [log.user_feedback for log in logs if log.user_feedback is not None]

        metrics = {
            "total_executions": total,
            "success_rate": successful / total,
            "cancel_rate": cancelled / total,
            "avg_duration": sum(durations) / len(durations) if durations else 0,
            "median_duration": sorted(durations)[len(durations) // 2] if durations else 0,
            "avg_findings": sum(findings) / len(findings) if findings else 0,
            "findings_per_minute": (
                (sum(findings) / (sum(durations) / 60)) if sum(durations) > 0 else 0
            ),
        }

        if feedback_scores:
            metrics["avg_satisfaction"] = sum(feedback_scores) / len(feedback_scores)
            metrics["feedback_rate"] = len(feedback_scores) / total

        return metrics

    def generate_optimization_report(self) -> Dict[str, Any]:
        """生成完整的优化报告

        Returns:
            包含当前状态、建议和历史趋势的报告
        """
        user_memory = self.memory_manager.get_user_memory()

        report = {
            "generated_at": datetime.now().isoformat(),
            "current_state": {
                "total_usage": user_memory.behavior_stats.usage_count,
                "success_rate": user_memory.behavior_stats.success_rate,
                "is_advanced_user": user_memory.is_advanced_user(),
                "auto_confirm_enabled": user_memory.preferences.auto_confirm,
            },
            "recent_performance": self._calculate_metrics(
                self.memory_manager.get_recent_executions(limit=100)
            ),
            "recommendations": self._generate_recommendations(),
            "next_optimization_in": max(
                0,
                self.optimization_interval
                - (user_memory.behavior_stats.usage_count % self.optimization_interval),
            ),
        }

        return report

    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """基于当前状态生成建议"""
        recommendations = []
        user_memory = self.memory_manager.get_user_memory()

        # 新用户引导
        if user_memory.behavior_stats.usage_count < 5:
            recommendations.append(
                {
                    "type": "info",
                    "message": "您是新用户，系统正在学习您的使用习惯。继续使用将获得更个性化的体验。",
                }
            )

        # 自动确认建议
        if not user_memory.preferences.auto_confirm and user_memory.is_advanced_user():
            recommendations.append(
                {
                    "type": "suggestion",
                    "message": "您是高级用户，可以启用'自动确认'模式以提升效率。命令：hos-ls memory set auto-confirm true",
                }
            )

        # 成功率警告
        if (
            user_memory.behavior_stats.success_rate < 0.8
            and user_memory.behavior_stats.usage_count > 10
        ):
            recommendations.append(
                {
                    "type": "warning",
                    "message": f"成功率偏低 ({user_memory.behavior_stats.success_rate:.0%})，建议检查常见失败原因或调整策略。",
                }
            )

        # 使用频率鼓励
        if user_memory.behavior_stats.usage_count >= 50:
            recommendations.append(
                {
                    "type": "achievement",
                    "message": "恭喜! 您已成为高级用户，系统将更多地参考您的个人偏好进行决策。",
                }
            )

        if not recommendations:
            recommendations.append(
                {
                    "type": "good",
                    "message": "一切正常！继续保持当前使用方式。",
                }
            )

        return recommendations


class AdaptiveLearningScheduler:
    """自适应学习调度器

    管理何时触发优化、备份等维护任务。
    """

    def __init__(self, memory_manager: Optional[MemoryManager] = None):
        self.memory_manager = memory_manager or get_memory_manager()
        self.optimizer = StrategyOptimizer(memory_manager)
        self.updater = __import__("src.memory.updater", fromlist=["MemoryUpdater"]).MemoryUpdater(
            memory_manager
        )

    async def run_maintenance_cycle(self) -> Dict[str, Any]:
        """运行一个完整的维护周期

        包括：
        1. 检查是否需要优化权重
        2. 处理未分析的执行日志
        3. 生成报告
        """
        cycle_report = {
            "started_at": datetime.now().isoformat(),
            "tasks_completed": [],
            "errors": [],
        }

        # 1. 权重优化
        if self.optimizer.should_optimize():
            try:
                from ..core.strategy import StrategyWeights

                current_weights = StrategyWeights()
                new_weights, opt_report = await self.optimizer.optimize_weights(current_weights)

                if opt_report["optimization_applied"]:
                    cycle_report["tasks_completed"].append("权重优化已完成")
                    cycle_report["weight_optimization"] = opt_report
                else:
                    cycle_report["tasks_completed"].append("权重优化检查完成（无需调整）")
            except Exception as e:
                cycle_report["errors"].append(f"权重优化失败: {e}")

        # 2. 日志分析
        try:
            recent_logs = self.memory_manager.get_recent_executions(limit=20)
            if recent_logs:
                batch_result = self.updater.batch_update_from_logs(recent_logs)
                if batch_result["successful_updates"] > 0:
                    cycle_report["tasks_completed"].append(
                        f"日志分析完成: {batch_result['successful_updates']}条已处理"
                    )
        except Exception as e:
            cycle_report["errors"].append(f"日志分析失败: {e}")

        # 3. 备份（每日一次）
        user_memory = self.memory_manager.get_user_memory()
        if user_memory.behavior_stats.usage_count % 100 == 0:  # 每100次使用备份一次
            try:
                backup_path = self.memory_manager.create_backup()
                cycle_report["tasks_completed"].append(f"备份已创建: {backup_path}")
            except Exception as e:
                cycle_report["errors"].append(f"备份失败: {e}")

        cycle_report["completed_at"] = datetime.now().isoformat()

        return cycle_report
