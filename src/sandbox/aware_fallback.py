from datetime import datetime
from typing import List, Optional
import logging

class AwareFallbackSystem:
    """可感知降级系统 - 确保每次降级都有日志和用户通知"""

    def __init__(self, logger: Optional[logging.Logger] = None, notifier=None):
        self.logger = logger or logging.getLogger(__name__)
        self.notifier = notifier
        self.current_mode = "dynamic"
        self.fallback_history = []

    def fallback_to(self, target_mode: str, reason: str, available_methods: List[str]):
        """执行降级并通知用户

        Args:
            target_mode: 目标模式 (dynamic/static/hybrid)
            reason: 降级原因
            available_methods: 可用的检测方法列表

        Returns:
            之前的模式
        """
        previous_mode = self.current_mode

        # 1. 记录降级历史
        self.fallback_history.append({
            "from": previous_mode,
            "to": target_mode,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })

        # 2. 详细日志记录
        self.logger.warning(
            f"[FALLBACK] Mode switch: {previous_mode} -> {target_mode}\n"
            f"  Reason: {reason}\n"
            f"  Available methods: {', '.join(available_methods)}\n"
            f"  Fallback count: {len(self.fallback_history)}"
        )

        # 3. 用户通知
        if self.notifier:
            self.notifier.notify(
                title=f"⚠️ 检测模式切换: {previous_mode} → {target_mode}",
                message=f"原因: {reason}\n可用方法: {', '.join(available_methods)}",
                level="warning"
            )

        # 4. 打印到控制台（确保可见）
        print(f"\n{'='*60}")
        print(f"⚠️  [FALLBACK] 检测模式切换")
        print(f"{'='*60}")
        print(f"  从: {previous_mode}")
        print(f"  到: {target_mode}")
        print(f"  原因: {reason}")
        print(f"  可用方法:")
        for method in available_methods:
            print(f"    - {method}")
        print(f"{'='*60}\n")

        # 5. 更新状态
        self.current_mode = target_mode

        return previous_mode

    def get_fallback_report(self) -> dict:
        """生成降级报告"""
        return {
            "current_mode": self.current_mode,
            "fallback_count": len(self.fallback_history),
            "history": self.fallback_history,
            "available_methods": self._get_available_methods()
        }

    def _get_available_methods(self) -> List[str]:
        """获取当前可用的检测方法"""
        if self.current_mode == "dynamic":
            return ["Docker执行", "本地运行时执行", "静态污点分析"]
        elif self.current_mode == "static":
            return ["静态污点分析", "正则模式匹配", "AI启发式分析"]
        else:
            return ["混合分析"]


class ConsoleNotifier:
    """控制台通知器"""

    def notify(self, title: str, message: str, level: str = "info"):
        colors = {"warning": "\033[93m", "error": "\033[91m", "info": "\033[94m"}
        color = colors.get(level, "")
        reset = "\033[0m"
        print(f"{color}{title}{reset}\n{message}\n")
