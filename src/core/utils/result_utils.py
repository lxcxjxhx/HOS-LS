"""结果处理工具函数

提供结果相关的工具函数，包括结果聚合、摘要生成、结果验证等。
"""

from typing import Dict, List, Any
from src.core.base_agent import AgentResult, AgentStatus


def aggregate_findings(results: Dict[str, AgentResult]) -> List[Any]:
    """聚合所有发现的问题

    Args:
        results: Agent执行结果字典

    Returns:
        List[Any]: 聚合后的问题列表
    """
    all_findings = []
    for result in results.values():
        if result.findings:
            all_findings.extend(result.findings)
    return all_findings


def generate_summary(results: Dict[str, AgentResult], findings: List[Any]) -> Dict[str, Any]:
    """生成执行摘要

    Args:
        results: Agent执行结果字典
        findings: 发现的问题列表

    Returns:
        Dict[str, Any]: 摘要字典
    """
    success_count = sum(1 for r in results.values() if r.is_success)
    total_count = len(results)
    success_rate = success_count / max(total_count, 1)
    
    severity_counts = _count_by_severity(findings)
    
    return {
        'total_agents_executed': total_count,
        'total_findings': len(findings),
        'by_severity': severity_counts,
        'success_rate': success_rate
    }


def validate_result(result: AgentResult) -> bool:
    """验证结果是否有效

    Args:
        result: Agent执行结果

    Returns:
        bool: 结果是否有效
    """
    return (
        result is not None and
        result.status == AgentStatus.COMPLETED and
        result.error is None
    )


def _count_by_severity(findings: List[Any]) -> Dict[str, int]:
    """按严重程度统计问题数量

    Args:
        findings: 发现的问题列表

    Returns:
        Dict[str, int]: 按严重程度统计的字典
    """
    severity_counts = {}
    for finding in findings:
        if isinstance(finding, dict):
            severity = finding.get('severity', 'unknown')
        else:
            severity = getattr(finding, 'severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return severity_counts