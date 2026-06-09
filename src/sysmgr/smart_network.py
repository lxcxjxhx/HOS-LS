"""智能网络编排器

根据目标类型和工具需求，自动决策最佳网络模式。
"""

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class TargetType(Enum):
    """目标网络类型"""
    INTERNAL = "internal"
    EXTERNAL = "external"
    MIXED = "mixed"


class ToolNetworkRequirement(Enum):
    """工具网络需求类型"""
    NEEDS_PROXY = "needs_proxy"
    NEEDS_DIRECT = "needs_direct"
    ADAPTIVE = "adaptive"


# 工具网络需求配置文件
TOOL_NETWORK_PROFILES: dict[str, ToolNetworkRequirement] = {
    # 需要代理才能正常工作（模板下载、外部API）
    "nuclei": ToolNetworkRequirement.NEEDS_PROXY,
    "subfinder": ToolNetworkRequirement.NEEDS_PROXY,
    # 需要直连目标
    "nmap": ToolNetworkRequirement.NEEDS_DIRECT,
    "sqlmap": ToolNetworkRequirement.NEEDS_DIRECT,
    "masscan": ToolNetworkRequirement.NEEDS_DIRECT,
    # 自适应：根据目标网络类型决定
    "httpx": ToolNetworkRequirement.ADAPTIVE,
    "ffuf": ToolNetworkRequirement.ADAPTIVE,
    "katana": ToolNetworkRequirement.ADAPTIVE,
    "dirsearch": ToolNetworkRequirement.ADAPTIVE,
}

# 内部域名后缀
INTERNAL_DOMAINS = (".local", ".internal", ".lan", ".corp", ".intranet", ".home")


@dataclass
class NetworkQualityRecord:
    """网络质量记录"""
    tool: str
    network_mode: str
    consecutive_failures: int = 0
    total_success: int = 0
    total_failure: int = 0
    last_error: Optional[str] = None


@dataclass
class NetworkSwitchRecord:
    """网络切换记录"""
    tool: str
    from_mode: str
    to_mode: str
    reason: str
    target: str


class SmartNetworkOrchestrator:
    """智能网络编排器

    根据目标类型和工具网络需求，自动推荐最佳网络模式。
    """

    FAILURE_THRESHOLD = 3  # 连续失败次数阈值，触发自动切换

    def __init__(self):
        self._quality_records: dict[str, NetworkQualityRecord] = {}
        self._switch_history: list[NetworkSwitchRecord] = []

    def classify_target(self, target: str) -> TargetType:
        """自动检测目标网络类型

        Args:
            target: 目标地址，支持 IP、CIDR、域名、逗号分隔的多目标

        Returns:
            TargetType: INTERNAL / EXTERNAL / MIXED
        """
        targets = [t.strip() for t in target.split(",") if t.strip()]
        if not targets:
            return TargetType.EXTERNAL

        results = [self._classify_single(t) for t in targets]

        if len(results) == 1:
            return results[0]

        has_internal = TargetType.INTERNAL in results
        has_external = TargetType.EXTERNAL in results

        if has_internal and has_external:
            return TargetType.MIXED
        elif has_internal:
            return TargetType.INTERNAL
        else:
            return TargetType.EXTERNAL

    def _classify_single(self, target: str) -> TargetType:
        """分类单个目标"""
        # 检查 localhost
        localhost = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if target.lower() in localhost:
            return TargetType.INTERNAL

        # 尝试解析为 IP
        try:
            ip = ipaddress.ip_address(target.split("/")[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return TargetType.INTERNAL
            return TargetType.EXTERNAL
        except ValueError:
            pass

        # 尝试解析域名
        try:
            resolved = socket.gethostbyname(target)
            ip = ipaddress.ip_address(resolved)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return TargetType.INTERNAL
            return TargetType.EXTERNAL
        except (socket.gaierror, ValueError):
            pass

        # 域名后缀判断
        if target.lower().endswith(INTERNAL_DOMAINS):
            return TargetType.INTERNAL

        # 无法解析的域名，默认为外部
        return TargetType.EXTERNAL

    def get_tool_network_mode(self, tool: str, target_type: TargetType) -> str:
        """获取工具的网络模式（基于工具需求档案）

        Args:
            tool: 工具名称
            target_type: 目标网络类型

        Returns:
            str: "proxy" | "direct"
        """
        profile = TOOL_NETWORK_PROFILES.get(tool)
        if profile is None:
            # 未知工具，默认自适应
            profile = ToolNetworkRequirement.ADAPTIVE

        if profile == ToolNetworkRequirement.NEEDS_PROXY:
            return "proxy"
        elif profile == ToolNetworkRequirement.NEEDS_DIRECT:
            return "direct"
        else:  # ADAPTIVE
            return "direct" if target_type == TargetType.INTERNAL else "proxy"

    def record_success(self, tool: str, network_mode: str) -> None:
        """记录成功请求"""
        key = f"{tool}:{network_mode}"
        record = self._quality_records.get(key)
        if record is None:
            record = NetworkQualityRecord(tool=tool, network_mode=network_mode)
            self._quality_records[key] = record
        record.total_success += 1
        record.consecutive_failures = 0
        logger.debug("[SNO] success: %s via %s (total_ok=%d)", tool, network_mode, record.total_success)

    def record_failure(self, tool: str, network_mode: str, error: str) -> None:
        """记录失败请求"""
        key = f"{tool}:{network_mode}"
        record = self._quality_records.get(key)
        if record is None:
            record = NetworkQualityRecord(tool=tool, network_mode=network_mode)
            self._quality_records[key] = record
        record.total_failure += 1
        record.consecutive_failures += 1
        record.last_error = error
        logger.debug(
            "[SNO] failure: %s via %s (consecutive=%d, total_fail=%d): %s",
            tool, network_mode, record.consecutive_failures, record.total_failure, error,
        )

    def should_switch_network(self, tool: str, network_mode: str) -> bool:
        """检查是否应该切换网络模式（连续失败达到阈值）"""
        key = f"{tool}:{network_mode}"
        record = self._quality_records.get(key)
        if record is None:
            return False
        return record.consecutive_failures >= self.FAILURE_THRESHOLD

    def get_switch_history(self) -> list[NetworkSwitchRecord]:
        """获取网络切换历史"""
        return list(self._switch_history)

    def _record_switch(self, tool: str, from_mode: str, to_mode: str, reason: str, target: str) -> None:
        """记录一次网络切换"""
        record = NetworkSwitchRecord(
            tool=tool, from_mode=from_mode, to_mode=to_mode, reason=reason, target=target,
        )
        self._switch_history.append(record)
        logger.info("[SNO] switch: %s %s -> %s (%s) target=%s", tool, from_mode, to_mode, reason, target)

    def get_recommended_mode(self, target: str, tool: str) -> str:
        """获取推荐的网络模式

        综合考虑目标类型、工具需求和历史网络质量。

        Args:
            target: 目标地址
            tool: 工具名称

        Returns:
            str: "proxy" | "direct"
        """
        target_type = self.classify_target(target)
        recommended = self.get_tool_network_mode(tool, target_type)

        # 检查当前推荐模式是否质量不佳
        if self.should_switch_network(tool, recommended):
            fallback = "proxy" if recommended == "direct" else "direct"
            self._record_switch(
                tool=tool,
                from_mode=recommended,
                to_mode=fallback,
                reason=f"连续 {self.FAILURE_THRESHOLD} 次失败，自动切换",
                target=target,
            )
            recommended = fallback

        logger.info(
            "[SNO] recommend: tool=%s target=%s type=%s mode=%s",
            tool, target, target_type.value, recommended,
        )
        return recommended

    def get_quality_summary(self) -> dict:
        """获取网络质量摘要（用于调试/报告）"""
        summary = {}
        for key, record in self._quality_records.items():
            summary[key] = {
                "tool": record.tool,
                "network_mode": record.network_mode,
                "consecutive_failures": record.consecutive_failures,
                "total_success": record.total_success,
                "total_failure": record.total_failure,
                "last_error": record.last_error,
            }
        return summary
