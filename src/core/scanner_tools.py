"""工具预扫描与本地构建回退方法

从 SecurityScanner 类中提取的独立函数。
"""

from typing import Any, Dict, List, Optional
from pathlib import Path

from rich.console import Console

console = Console()


async def tool_prescan(
    tool_orchestrator,
    custom_tool_chain,
    config_debug: bool,
    nvd_adapter,
    project_root: str,
    target: str,
) -> list:
    """执行基于工具的预扫描

    Args:
        tool_orchestrator: 工具编排器实例
        custom_tool_chain: 自定义工具链配置
        config_debug: 是否启用调试输出
        nvd_adapter: NVD适配器实例
        project_root: 项目根路径
        target: 扫描目标

    Returns:
        工具发现的安全问题列表
    """
    if not tool_orchestrator:
        return []

    findings = []
    tool_chain = custom_tool_chain if custom_tool_chain else ["semgrep", "bandit"]

    if config_debug:
        console.print(f"[dim][DEBUG] 开始工具链预扫描，使用工具: {tool_chain}[/dim]")

    try:
        from src.analyzers.finding_verifier import FindingVerifier

        nvd_db_path: Optional[str] = None
        if nvd_adapter and hasattr(nvd_adapter, "db_path"):
            nvd_db_path = str(nvd_adapter.db_path) if nvd_adapter.db_path else None

        finding_verifier = FindingVerifier(project_root, nvd_db_path or "")
        tool_orchestrator.set_verifier(finding_verifier)
        tool_orchestrator.set_project_root(project_root)

        tool_results = tool_orchestrator.execute_chain(tool_chain, target)

        if config_debug:
            console.print(f"[dim][DEBUG] 工具链扫描完成，发现 {len(tool_results)} 个问题[/dim]")

        from src.core.engine import Finding, Location, Severity

        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNKNOWN": Severity.INFO,
        }

        for result in tool_results:
            severity = severity_map.get(result.get("severity", "UNKNOWN"), Severity.INFO)

            metadata = result.get("metadata", {}).copy()
            metadata["source"] = result.get("source", "unknown")
            metadata["tool_confidence"] = result.get("tool_confidence", 0.5)
            if result.get("source_tools"):
                metadata["source_tools"] = result.get("source_tools")
            if result.get("cwe_id"):
                metadata["cwe_id"] = result.get("cwe_id")
            if result.get("cve_id"):
                metadata["cve_id"] = result.get("cve_id")

            finding = Finding(
                rule_id=f"TOOL-{result.get('source', 'unknown').upper()}-{result.get('cwe_id', 'UNKNOWN') or result.get('check_id', 'UNKNOWN')}",
                rule_name=f"[{result.get('source', 'tool').upper()}] {result.get('cwe_id') or result.get('check_id', 'VULN')}",
                description=result.get("description", ""),
                severity=severity,
                location=Location(
                    file=result.get("file", ""), line=result.get("line", 0), column=0
                ),
                confidence=result.get("confidence", 0.5),
                message=result.get("description", ""),
                code_snippet=metadata.get("code_snippet", ""),
                fix_suggestion=metadata.get("remediation", ""),
                references=[],
                metadata=metadata,
            )
            findings.append(finding)

        if tool_results and config_debug:
            stats = tool_orchestrator.get_statistics()
            console.print(f"[dim][DEBUG] 工具执行统计: {stats}[/dim]")

    except Exception as e:
        if config_debug:
            console.print(f"[dim][DEBUG] 工具链预扫描失败: {e}[/dim]")

    return findings


async def fallback_local_build(
    agent,
    target: str,
    config_debug: bool,
) -> list:
    """本地构建fallback（当Docker不可用时）

    Args:
        agent: ContainerizedBuildAgent实例
        target: 目标路径
        config_debug: 是否启用调试输出

    Returns:
        发现的问题列表
    """
    findings: list = []

    try:
        from src.sandbox.build_agent.project_analyzer import ProjectAnalyzer

        console.print("[bold cyan][TOOL] 分析项目类型...[/bold cyan]")
        analyzer = ProjectAnalyzer(target)
        project_info = analyzer.analyze()

        console.print(f"[bold cyan][INFO] 项目类型: {project_info.project_type.value}[/bold cyan]")
        console.print(
            f"[bold cyan][INFO] 构建命令: {' '.join(project_info.build_command)}[/bold cyan]"
        )
        console.print(
            f"[bold cyan][INFO] 运行命令: {' '.join(project_info.run_command)}[/bold cyan]"
        )

        project_type = project_info.project_type.value

        if project_type == "java_maven":
            console.print("[bold cyan][TOOL] 尝试使用Maven本地构建...[/bold cyan]")
            try:
                import subprocess

                result = subprocess.run(
                    ["mvn", "--version"], capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    console.print("[bold green][OK] Maven已安装[/bold green]")
                    console.print(
                        "[bold cyan][TOOL] 执行构建: mvn clean package -DskipTests[/bold cyan]"
                    )

                    build_result = subprocess.run(
                        ["mvn", "clean", "package", "-DskipTests"],
                        cwd=target,
                        capture_output=True,
                        text=True,
                        timeout=600,
                    )

                    if build_result.returncode == 0:
                        console.print("[bold green][OK] Maven构建成功[/bold green]")

                        jar_files = list(Path(target).rglob("target/*.jar"))
                        if jar_files:
                            console.print(
                                f"[bold cyan][INFO] 找到 {len(jar_files)} 个JAR文件[/bold cyan]"
                            )

                            for jar in jar_files[:3]:
                                console.print(f"[bold cyan][INFO] JAR: {jar.name}[/bold cyan]")

                            console.print(
                                "[bold yellow][WARN] 动态测试需要运行服务，请配置Docker环境[/bold yellow]"
                            )
                        else:
                            console.print("[bold yellow][WARN] 未找到构建产物[/bold yellow]")
                    else:
                        console.print("[bold red][ERROR] Maven构建失败[/bold red]")
                        console.print(f"[dim]{build_result.stdout[-500:]}[/dim]")
                else:
                    console.print("[bold yellow][WARN] Maven未安装，跳过构建[/bold yellow]")
            except FileNotFoundError:
                console.print("[bold yellow][WARN] Maven未安装，跳过构建[/bold yellow]")
            except Exception as e:
                console.print(f"[bold yellow][WARN] Maven构建出错: {e}[/bold yellow]")

        elif project_type == "java_gradle":
            console.print("[bold yellow][WARN] Gradle构建暂未实现fallback[/bold yellow]")

        elif project_type == "node_js":
            console.print("[bold yellow][WARN] Node.js构建暂未实现fallback[/bold yellow]")

        elif project_type == "python":
            console.print("[bold yellow][WARN] Python项目暂不需要构建[/bold yellow]")
            console.print("[bold yellow][WARN] 动态测试需要运行服务，请配置Docker环境[/bold yellow]")

        else:
            console.print(f"[bold yellow][WARN] 不支持的项目类型: {project_type}[/bold yellow]")

    except Exception as e:
        console.print(f"[bold red][ERROR] 本地构建分析失败: {e}[/bold red]")
        if config_debug:
            import traceback

            console.print(f"[dim]{traceback.format_exc()}[/dim]")

    return findings
