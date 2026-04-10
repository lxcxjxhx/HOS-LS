"""Memory Updater 自动更新逻辑

根据执行结果自动更新用户偏好、项目风险画像和技术栈，
实现fix_3.md中的自学习机制。
"""

from typing import Any, Dict, List, Optional

from .models import ExecutionLog, UserMemory, ProjectMemory
from .manager import get_memory_manager, MemoryManager
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MemoryUpdater:
    """Memory自动更新器

    根据执行结果和反馈，自动更新三层记忆数据，
    实现系统的持续学习和优化。
    """

    def __init__(self, memory_manager: Optional[MemoryManager] = None):
        """初始化

        Args:
            memory_manager: 可选的Memory管理器实例
        """
        self.memory_manager = memory_manager or get_memory_manager()

    def update_from_execution(self, log: ExecutionLog) -> Dict[str, Any]:
        """根据单次执行结果更新记忆

        Args:
            log: 执行日志

        Returns:
            更新摘要字典
        """
        updates = {
            "user_updates": [],
            "project_updates": [],
            "timestamp": log.timestamp.isoformat(),
        }

        try:
            # 1. 更新用户习惯
            user_updates = self._update_user_habits(log)
            updates["user_updates"].extend(user_updates)

            # 2. 更新项目画像（如果有目标路径）
            if log.target_path:
                project_updates = self._update_project_profile(log)
                updates["project_updates"].extend(project_updates)

            logger.debug(f"Memory已从执行日志更新: {log.log_id}")
        except Exception as e:
            logger.error(f"更新Memory失败: {e}")

        return updates

    def _update_user_habits(self, log: ExecutionLog) -> List[str]:
        """更新用户习惯"""
        updates = []
        user_memory = self.memory_manager.get_user_memory()

        if not user_memory:
            return updates

        changed = False

        # 快速成功 → 用户可能喜欢快速模式
        if log.success and log.duration < 120 and log.findings_count > 0:
            if not user_memory.habits.prefers_fast_first:
                user_memory.habits.prefers_fast_first = True
                updates.append("检测到用户偏好快速成功模式")
                changed = True

        # 长时间深度扫描且发现多问题 → 用户重视深度分析
        if log.success and log.duration > 300 and log.findings_count > 15:
            mode = log.strategy_used.get("mode", "") if isinstance(log.strategy_used, dict) else ""
            if mode == "deep":
                self.memory_manager.update_user_preference("scan_depth", "high")
                updates.append("用户似乎重视深度扫描")
                changed = True

        # 高满意度反馈 → 强化当前策略偏好
        if log.user_feedback and log.user_feedback >= 4:
            mode = log.strategy_used.get("mode", "") if isinstance(log.strategy_used, dict) else ""
            if mode:
                self.memory_manager.update_user_habit(f"likes_{mode}_mode", True)
                updates.append(f"强化了{mode}模式的偏好")
                changed = True

        # 低满意度 → 调整偏好
        if log.user_feedback and log.user_feedback <= 2:
            mode = log.strategy_used.get("mode", "") if isinstance(log.strategy_used, dict) else ""
            if mode == "aggressive":
                self.memory_manager.update_user_habit("avoids_aggressive", True)
                updates.append("用户似乎不喜欢激进策略")
                changed = True

        # 更新行为统计
        stats = user_memory.behavior_stats
        if not log.success:
            old_cancel_rate = stats.cancel_rate
            total = max(stats.total_scans, 1)
            stats.cancel_rate = (old_cancel_rate * (total - 1) + 1) / total
            updates.append(f"取消率更新: {stats.cancel_rate:.2f}")
            changed = True

        # 平均等待时间更新
        if log.success:
            old_avg = stats.avg_wait_time
            total = max(stats.total_scans, 1)
            stats.avg_wait_time = (old_avg * (total - 1) + log.duration) / total
            updates.append(f"平均等待时间更新: {stats.avg_wait_time:.0f}s")
            changed = True

        if changed:
            self.memory_manager.get_user_memory().updated_at = log.timestamp

        return updates

    def _update_project_profile(self, log: ExecutionLog) -> List[str]:
        """更新项目画像"""
        updates = []

        try:
            project_memory = self.memory_manager.get_project_context(log.target_path)

            if not project_memory:
                return updates

            changed = False

            # 更新风险画像
            if log.findings_count > 10:
                risk_level = "high"
            elif log.findings_count > 5:
                risk_level = "medium"
            elif log.findings_count > 0:
                risk_level = "low"
            else:
                risk_level = "low"

            current_risk = project_memory.risk_profile.overall
            risk_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}

            if risk_order.get(risk_level, 0) > risk_order.get(current_risk, 0):
                self.memory_manager.update_project_risk(
                    log.target_path,
                    {"overall": risk_level}
                )
                updates.append(f"项目风险升级: {current_risk} → {risk_level}")
                changed = True

            # 更新漏洞密度
            if log.findings_count > 20:
                density = "high"
            elif log.findings_count > 10:
                density = "medium"
            else:
                density = "low"

            if project_memory.risk_profile.finding_density != density:
                self.memory_manager.update_project_risk(
                    log.target_path,
                    {"finding_density": density}
                )
                updates.append(f"漏洞密度更新: {density}")
                changed = True

            # 记录扫描历史
            depth = (
                log.strategy_used.get("decisions", {}).get("scan_depth", "medium")
                if isinstance(log.strategy_used, dict)
                else "medium"
            )
            self.memory_manager.record_scan_history(
                log.target_path,
                duration=log.duration,
                findings=log.findings_count,
                depth=depth,
            )

            if changed:
                updates.append(f"扫描历史已记录")

        except Exception as e:
            logger.warning(f"更新项目画像失败: {e}")

        return updates

    def detect_tech_stack_from_log(self, log: ExecutionLog) -> List[str]:
        """尝试从执行日志中检测技术栈

        基于目标路径、发现的漏洞类型等推断技术栈。
        """
        detected_tech = []

        # 从路径推断（简单启发式）
        target_lower = log.target_path.lower() if log.target_path else ""

        tech_indicators = {
            "python": [".py", "requirements.txt", "setup.py", "Pipfile"],
            "javascript": [".js", ".jsx", "package.json", "node_modules"],
            "typescript": [".ts", ".tsx", "tsconfig.json"],
            "java": [".java", "pom.xml", "build.gradle"],
            "go": [".go", "go.mod"],
            "rust": [".rs", "Cargo.toml"],
            "flask": ["flask", "app.py"],
            "django": ["django", "settings.py"],
            "express": ["express", "server.js"],
            "react": ["react", "App.jsx"],
            "vue": ["vue", "App.vue"],
            "jwt": ["jwt", "token"],
            "sql": ["database", ".sql", "migration"],
        }

        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator in target_lower:
                    if tech not in detected_tech:
                        detected_tech.append(tech)
                    break

        # 从策略使用的模块推断
        if isinstance(log.strategy_used, dict):
            modules = log.strategy_used.get("decisions", {}).get("modules", [])
            module_tech_map = {
                "auth": ["flask", "django", "express"],
                "injection": ["sql"],
                "xss": ["javascript", "typescript", "react", "vue"],
            }
            for module in modules:
                if module in module_tech_map:
                    for tech in module_tech_map[module]:
                        if tech not in detected_tech:
                            detected_tech.append(tech)

        return detected_tech

    def batch_update_from_logs(self, logs: List[ExecutionLog]) -> Dict[str, Any]:
        """批量处理多个执行日志

        Args:
            logs: 执行日志列表

        Returns:
            批量更新摘要
        """
        summary = {
            "total_processed": len(logs),
            "successful_updates": 0,
            "failed_updates": 0,
            "key_insights": [],
        }

        for log in logs:
            try:
                updates = self.update_from_execution(log)
                if updates["user_updates"] or updates["project_updates"]:
                    summary["successful_updates"] += 1

                    # 收集关键洞察
                    for update in updates["user_updates"] + updates["project_updates"]:
                        if any(keyword in update.lower() for keyword in
                               ["偏好", "升级", "强化", "检测到"]):
                            summary["key_insights"].append(update)
            except Exception as e:
                summary["failed_updates"] += 1
                logger.error(f"批量更新失败 ({log.log_id}): {e}")

        # 去重关键洞察
        summary["key_insights"] = list(set(summary["key_insights"]))[:10]

        return summary
