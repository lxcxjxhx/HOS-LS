"""策略规划器

根据目标分析结果规划最优扫描策略。
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.tools.ai_decision_engine import ToolsRegistry, ScanStrategy, TargetProfile
from src.utils.logger import get_logger

logger = get_logger(__name__)


class StrategyPlanner:
    """策略规划器

    根据目标画像选择最优工具组合和扫描参数。
    """

    TOOL_CAPABILITIES = {
        "semgrep": {
            "types": ["source"],
            "strengths": ["代码静态分析", "SAST", "最佳实践"],
            "weaknesses": ["需要源码"],
            "execution_time": "fast",
            "parallel_safe": True,
        },
        "trivy": {
            "types": ["docker", "service"],
            "strengths": ["容器镜像扫描", "漏洞库"],
            "weaknesses": ["需要容器环境"],
            "execution_time": "medium",
            "parallel_safe": True,
        },
        "gitleaks": {
            "types": ["source"],
            "strengths": ["密钥泄露检测"],
            "weaknesses": ["需要git仓库"],
            "execution_time": "fast",
            "parallel_safe": True,
        },
        "code_vuln_scanner": {
            "types": ["source", "web"],
            "strengths": ["代码漏洞扫描", "动态分析"],
            "weaknesses": ["覆盖范围有限"],
            "execution_time": "medium",
            "parallel_safe": True,
        },
        "sqlmap": {
            "types": ["web", "api"],
            "strengths": ["SQL注入检测", "数据库枚举"],
            "weaknesses": ["可能被WAF拦截"],
            "execution_time": "slow",
            "parallel_safe": False,
        },
        "nuclei": {
            "types": ["web", "api", "service"],
            "strengths": ["CVE检测", "模板扫描", "快速"],
            "weaknesses": ["依赖模板质量"],
            "execution_time": "medium",
            "parallel_safe": True,
        },
        "zap": {
            "types": ["web", "api"],
            "strengths": ["Web漏洞扫描", "主动/被动扫描"],
            "weaknesses": ["需要目标可访问"],
            "execution_time": "slow",
            "parallel_safe": True,
        },
        "http_security": {
            "types": ["web", "api"],
            "strengths": ["头部检测", "快速测试"],
            "weaknesses": ["覆盖范围有限"],
            "execution_time": "fast",
            "parallel_safe": True,
        },
        "api_security": {
            "types": ["api"],
            "strengths": ["REST API", "GraphQL测试"],
            "weaknesses": ["需要API端点"],
            "execution_time": "medium",
            "parallel_safe": True,
        },
        "fuzzing": {
            "types": ["web", "api"],
            "strengths": ["内容发现", "参数模糊测试"],
            "weaknesses": ["可能触发防护"],
            "execution_time": "slow",
            "parallel_safe": False,
        },
    }

    def __init__(self, tools_registry: Optional[ToolsRegistry] = None):
        self.tools_registry = tools_registry or ToolsRegistry()

    def plan(
        self,
        target: TargetProfile,
        timeout: int = 300,
        parallel: bool = True,
        prefer_fast: bool = False,
    ) -> ScanStrategy:
        """规划扫描策略

        Args:
            target: 目标画像
            timeout: 超时时间
            parallel: 是否并行
            prefer_fast: 是否优先快速扫描

        Returns:
            扫描策略
        """
        available_tools = self.tools_registry.get_available_tools()
        available_names = [t.name for t in available_tools]

        selected_tools = self._select_tools(target, available_names)

        if prefer_fast:
            selected_tools = self._prioritize_fast_tools(selected_tools)

        execution_order = self._determine_order(selected_tools, target)

        tool_params = self._generate_params(selected_tools, target)

        parallel = self._can_parallel(execution_order)

        return ScanStrategy(
            target=target.url,
            selected_tools=selected_tools,
            execution_order=execution_order,
            tool_params=tool_params,
            timeout=timeout,
            parallel=parallel,
            fallback_enabled=True,
            confidence=0.8,
        )

    def _select_tools(
        self,
        target: TargetProfile,
        available_tools: List[str],
    ) -> List[str]:
        """选择工具

        Args:
            target: 目标画像
            available_tools: 可用工具列表

        Returns:
            选中的工具列表
        """
        target_type = target.type
        fingerprint = target.fingerprint

        required_capabilities = []

        if target_type == "web":
            required_capabilities = ["web"]
        elif target_type == "api":
            required_capabilities = ["api"]
        elif target_type == "docker":
            required_capabilities = ["docker"]
        else:
            required_capabilities = ["web", "api", "service"]

        if fingerprint.get("is_api") and "api" not in required_capabilities:
            required_capabilities.append("api")

        if fingerprint.get("framework"):
            required_capabilities.append("source")

        selected = []

        for capability in required_capabilities:
            for tool, info in self.TOOL_CAPABILITIES.items():
                if tool in available_tools and capability in info["types"]:
                    if tool not in selected:
                        selected.append(tool)

        for tool in available_tools:
            if tool not in selected and tool in self.TOOL_CAPABILITIES:
                info = self.TOOL_CAPABILITIES[tool]
                if "source" in info["types"] and tool in ["semgrep", "gitleaks"]:
                    selected.append(tool)

        max_tools = 5
        if len(selected) > max_tools:
            selected = self._prioritize_tools(selected)

        return selected

    def _prioritize_tools(self, tools: List[str]) -> List[str]:
        """优先选择最重要工具

        Args:
            tools: 工具列表

        Returns:
            优先级排序后的工具列表
        """
        priority_order = [
            "semgrep",
            "gitleaks",
            "zap",
            "nuclei",
            "api_security",
            "sqlmap",
            "http_security",
            "fuzzing",
            "trivy",
            "code_vuln_scanner",
        ]

        def get_priority(tool: str) -> int:
            for i, priority_tool in enumerate(priority_order):
                if tool == priority_tool:
                    return i
            return len(priority_order)

        return sorted(tools, key=get_priority)

    def _prioritize_fast_tools(self, tools: List[str]) -> List[str]:
        """优先选择快速工具

        Args:
            tools: 工具列表

        Returns:
            排序后的工具列表
        """
        fast_tools = []
        slow_tools = []

        for tool in tools:
            info = self.TOOL_CAPABILITIES.get(tool, {})
            if info.get("execution_time") == "fast":
                fast_tools.append(tool)
            else:
                slow_tools.append(tool)

        return fast_tools + slow_tools

    def _determine_order(
        self,
        tools: List[str],
        target: TargetProfile,
    ) -> List[str]:
        """确定执行顺序

        Args:
            tools: 工具列表
            target: 目标画像

        Returns:
            执行顺序
        """
        order = []
        passive_first = ["semgrep", "gitleaks", "http_security"]
        active_later = ["zap", "nuclei", "sqlmap", "fuzzing"]

        for tool in passive_first:
            if tool in tools:
                order.append(tool)

        for tool in active_later:
            if tool in tools:
                order.append(tool)

        for tool in tools:
            if tool not in order:
                order.append(tool)

        return order

    def _can_parallel(self, tools: List[str]) -> bool:
        """判断是否可以并行

        Args:
            tools: 工具列表

        Returns:
            是否可以并行
        """
        for tool in tools:
            info = self.TOOL_CAPABILITIES.get(tool, {})
            if not info.get("parallel_safe", True):
                return False
        return True

    def _generate_params(
        self,
        tools: List[str],
        target: TargetProfile,
    ) -> Dict[str, Dict[str, Any]]:
        """生成工具参数

        Args:
            tools: 工具列表
            target: 目标画像

        Returns:
            工具参数字典
        """
        params = {}

        target_type = target.type
        fingerprint = target.fingerprint

        for tool in tools:
            tool_params = {}

            if tool == "zap":
                tool_params = {
                    "risk": 1,
                    "level": 2,
                    "max_children": 10,
                }
                if target_type == "api":
                    tool_params["api_scan"] = True

            elif tool == "nuclei":
                tool_params = {
                    "severity": "medium,high,critical",
                    "rate_limit": 150,
                    "template_dir": "nuclei-templates",
                }

            elif tool == "sqlmap":
                tool_params = {
                    "risk": 1,
                    "level": 2,
                    "batch": True,
                    "timeout": 60,
                }

            elif tool == "api_security":
                tool_params = {
                    "test_graphql": fingerprint.get("graphql") is not None,
                    "test_openapi": True,
                }

            elif tool == "fuzzing":
                tool_params = {
                    "mode": "discover",
                    "wordlist": "common",
                    "max_iterations": 1000,
                }

            elif tool == "semgrep":
                tool_params = {
                    "rules": "auto",
                    "timeout": 60,
                }

            elif tool == "gitleaks":
                tool_params = {
                    "verbose": True,
                    "report_format": "json",
                }

            if tool_params:
                params[tool] = tool_params

        return params

    def optimize_for_result(
        self,
        current_strategy: ScanStrategy,
        result_feedback: Dict[str, Any],
    ) -> ScanStrategy:
        """根据结果反馈优化策略

        Args:
            current_strategy: 当前策略
            result_feedback: 结果反馈

        Returns:
            优化后的策略
        """
        findings_count = result_feedback.get("findings_count", 0)
        false_positive_rate = result_feedback.get("false_positive_rate", 0.0)
        execution_time = result_feedback.get("execution_time", 0)

        tool_params = current_strategy.tool_params.copy()

        if false_positive_rate > 0.5:
            for tool in ["sqlmap", "fuzzing"]:
                if tool in tool_params:
                    tool_params[tool]["risk"] = min(
                        tool_params[tool].get("risk", 1) + 1, 3
                    )

        if findings_count == 0:
            if "zap" in tool_params:
                tool_params["zap"]["level"] = min(
                    tool_params["zap"].get("level", 2) + 1, 5
                )

        return ScanStrategy(
            target=current_strategy.target,
            selected_tools=current_strategy.selected_tools,
            execution_order=current_strategy.execution_order,
            tool_params=tool_params,
            timeout=current_strategy.timeout,
            parallel=current_strategy.parallel,
            fallback_enabled=True,
            confidence=min(current_strategy.confidence + 0.1, 1.0),
        )


def plan_scan_strategy(
    target: TargetProfile,
    timeout: int = 300,
) -> ScanStrategy:
    """规划扫描策略的便捷函数

    Args:
        target: 目标画像
        timeout: 超时时间

    Returns:
        扫描策略
    """
    planner = StrategyPlanner()
    return planner.plan(target, timeout=timeout)
