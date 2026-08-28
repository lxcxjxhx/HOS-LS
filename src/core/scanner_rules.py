"""RAG 知识库检索分析模块

基于 RAG 知识库检索进行漏洞检测，减少纯 AI 扫描的 token 消耗。
"""

from typing import List, Optional

from rich.console import Console

from src.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


def rule_analyze(
    file_info,
    ai_findings: Optional[List] = None,
    config_debug: bool = False,
    config_pure_ai: bool = False,
) -> list:
    """基于 RAG 知识库检索的漏洞检测

    仅用于 RAG 知识库检索和类似漏洞检测，减少纯 AI 扫描的 token 消耗

    Args:
        file_info: 文件信息
        ai_findings: AI分析结果，用于调整RAG检索策略
        config_debug: 是否启用调试模式
        config_pure_ai: 是否为纯AI模式

    Returns:
        发现的安全问题列表
    """
    # 纯AI模式下跳过RAG分析
    if config_pure_ai:
        return []

    findings = []

    try:
        # 读取文件内容
        with open(file_info.path, "r", encoding="utf-8") as f:
            file_content = f.read()

        if config_debug:
            console.print(f"[dim][DEBUG] 执行 RAG 知识库检索分析: {file_info.path}[/dim]")

        # 导入 RAG 知识库
        from src.storage.rag_knowledge_base import get_rag_knowledge_base

        # 获取 RAG 知识库实例
        rag_kb = get_rag_knowledge_base()

        # 基于文件类型和AI分析结果构建更精确的搜索查询
        search_query = file_content
        if file_info.language:
            language = file_info.language.value
            # 根据文件类型添加前缀，提高检索相关性
            if language == "python":
                search_query = f"Python code: {file_content}"
            elif language == "javascript":
                search_query = f"JavaScript code: {file_content}"
            elif language == "html":
                search_query = f"HTML code: {file_content}"

        # 如果有AI分析结果，根据AI发现的漏洞类型调整搜索查询
        if ai_findings:
            # 提取AI发现的漏洞类型
            ai_vulnerability_types = []
            for ai_finding in ai_findings:
                for vuln_type in [
                    "sql_injection",
                    "command_injection",
                    "ssrf",
                    "xss",
                    "csrf",
                    "hardcoded_credentials",
                    "weak_crypto",
                    "insecure_random",
                    "sensitive_data_exposure",
                ]:
                    if (
                        vuln_type in ai_finding.rule_name.lower()
                        or vuln_type in ai_finding.description.lower()
                    ):
                        ai_vulnerability_types.append(vuln_type)
                        break

            # 如果有AI发现的漏洞类型，在搜索查询中添加这些类型
            if ai_vulnerability_types:
                vuln_types_str = ", ".join(ai_vulnerability_types)
                search_query = f"{search_query} 相关漏洞: {vuln_types_str}"
                if config_debug:
                    console.print(
                        f"[dim][DEBUG] 根据AI分析结果调整RAG搜索查询，添加漏洞类型: {vuln_types_str}[/dim]"
                    )

        # 搜索 RAG 知识库
        search_results = rag_kb.search_knowledge(search_query)

        if search_results:
            if config_debug:
                console.print(f"[dim][DEBUG] RAG 知识库检索发现 {len(search_results)} 个相关结果[/dim]")

            # 过滤低相关性结果
            relevant_results = [
                result for result in search_results if result.confidence >= 0.75
            ]

            if relevant_results:
                if config_debug:
                    console.print(f"[dim][DEBUG] 过滤后保留 {len(relevant_results)} 个高相关性结果[/dim]")

                # 转换知识库结果为 Finding 对象
                from src.core.engine import Finding, Location, Severity

                for knowledge in relevant_results:
                    # 提取严重级别
                    severity_str = None
                    for tag in knowledge.tags:
                        if tag in ["critical", "high", "medium", "low", "info"]:
                            severity_str = tag
                            break

                    if not severity_str:
                        # 根据置信度设置默认严重级别
                        if knowledge.confidence >= 0.9:
                            severity_str = "high"
                        elif knowledge.confidence >= 0.8:
                            severity_str = "medium"
                        else:
                            severity_str = "low"

                    # 检查知识内容是否与文件类型相关
                    is_relevant = True
                    if file_info.language:
                        language = file_info.language.value
                        # 简单的相关性检查
                        if language == "python" and "python" not in knowledge.content.lower():
                            # 对于Python文件，确保知识内容与Python相关
                            if not any(
                                keyword in knowledge.content.lower()
                                for keyword in ["python", "pip", "django", "flask"]
                            ):
                                is_relevant = False
                        elif (
                            language == "javascript"
                            and "javascript" not in knowledge.content.lower()
                        ):
                            # 对于JavaScript文件，确保知识内容与JavaScript相关
                            if not any(
                                keyword in knowledge.content.lower()
                                for keyword in ["javascript", "node", "react", "vue"]
                            ):
                                is_relevant = False

                    # 如果有AI分析结果，检查知识内容是否与AI发现相关
                    if ai_findings and is_relevant:
                        is_relevant_to_ai = False
                        for ai_finding in ai_findings:
                            if any(
                                keyword in knowledge.content.lower()
                                for keyword in ai_finding.rule_name.lower().split()
                            ):
                                is_relevant_to_ai = True
                                # 提高与AI发现相关的RAG结果的置信度
                                knowledge.confidence = min(1.0, knowledge.confidence + 0.1)
                                break
                        if not is_relevant_to_ai:
                            # 如果知识内容与AI发现无关，降低置信度
                            knowledge.confidence = max(0.5, knowledge.confidence - 0.1)
                            # 如果置信度低于阈值，标记为不相关
                            if knowledge.confidence < 0.7:
                                is_relevant = False

                    if is_relevant:
                        # 创建 Finding 对象
                        finding = Finding(
                            rule_id=f"RAG-{knowledge.id[:8]}",
                            rule_name=knowledge.content[:50],
                            description=knowledge.content,
                            severity=Severity(severity_str),
                            location=Location(file=str(file_info.path), line=1, column=0),
                            confidence=knowledge.confidence,
                            message=knowledge.content,
                            code_snippet=(
                                file_content[:200] + "..."
                                if len(file_content) > 200
                                else file_content
                            ),
                            fix_suggestion="根据 RAG 知识库建议进行修复",
                            references=[],
                            metadata={
                                "knowledge_id": knowledge.id,
                                "knowledge_source": knowledge.source,
                                "rag_knowledge": True,
                            },
                        )
                        findings.append(finding)

        # 限制每个文件的RAG结果数量
        max_findings = 5
        if len(findings) > max_findings:
            # 按置信度排序，保留高置信度的结果
            findings.sort(key=lambda x: x.confidence, reverse=True)
            findings = findings[:max_findings]
            if config_debug:
                console.print(f"[dim][DEBUG] 限制RAG知识库结果数量为 {max_findings}[/dim]")

    except Exception as e:
        if config_debug:
            console.print(f"[dim][DEBUG] RAG 知识库检索分析失败: {e}[/dim]")

    return findings
