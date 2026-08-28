"""安全扫描器 — 分析模块

提取自 SecurityScanner 的文件分析相关方法。
"""

from typing import Any, Dict, List, Optional

from rich.console import Console

from src.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


def semantic_analyze(
    file_info: Any,
    local_analyzer: Any,
    config_debug: bool = False,
) -> List:
    """本地语义分析文件

    Args:
        file_info: 文件信息
        local_analyzer: 本地语义分析器实例
        config_debug: 是否启用调试输出

    Returns:
        发现的安全问题列表
    """
    findings = []

    try:
        # 读取文件内容
        with open(file_info.path, "r", encoding="utf-8") as f:
            code_content = f.read()

        if config_debug:
            console.print(f"[dim][DEBUG] 执行本地语义分析: {file_info.path}[/dim]")

        # 执行本地语义分析
        semantic_result = local_analyzer.analyze(
            code=code_content, file_path=str(file_info.path)
        )

        # 如果检测到漏洞，转换为 Finding 对象
        if semantic_result.is_vulnerable:
            from src.core.engine import Finding, Location, Severity

            # 将 RiskLevel 转换为 Severity
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(semantic_result.risk_level.value, Severity.MEDIUM)

            # 创建 Finding 对象
            finding = Finding(
                rule_id="SEMANTIC-ANALYSIS",
                rule_name=f"语义分析: {semantic_result.reason[:50]}",
                description=semantic_result.reason,
                severity=severity,
                location=Location(
                    file=str(file_info.path),
                    line=1,
                    column=0,
                ),
                confidence=semantic_result.confidence,
                message=semantic_result.reason,
                code_snippet=(
                    code_content[:200] + "..." if len(code_content) > 200 else code_content
                ),
                fix_suggestion="; ".join(semantic_result.recommendations[:3]),
                references=[],
            )
            findings.append(finding)

            if config_debug:
                console.print(f"[dim][DEBUG] 语义分析发现漏洞: {semantic_result.reason}[/dim]")
                console.print(
                    f"[dim][DEBUG] 攻击链路: {' -> '.join(semantic_result.attack_chain)}[/dim]"
                )

    except Exception as e:
        if config_debug:
            console.print(f"[dim][DEBUG] 语义分析失败: {e}[/dim]")

    return findings
