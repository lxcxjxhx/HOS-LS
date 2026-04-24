"""安全扫描器模块

提供核心的安全扫描功能，集成文件发现、代码分析和 AI 分析。
"""

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from src.core.config import Config
from src.core.engine import ScanEngine, ScanResult, BaseScanner, ScanMode
from src.core.scan_state import ScanState
from src.utils.file_discovery import FileDiscoveryEngine, FileInfo
from src.utils.file_prioritizer import FilePrioritizer
from src.ai.analyzer import AIAnalyzer
from src.ai.models import AnalysisContext, AnalysisLevel, SecurityAnalysisResult, VulnerabilityFinding
from src.ai.local_semantic_analyzer import get_local_analyzer
from src.ai.priority_evaluator import get_ai_priority_evaluator
from src.attack.chain_analyzer import get_ai_attack_chain_builder
from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.cst_analyzer import CSTAnalyzer
from src.scanner.library_matcher import get_library_matcher
from src.integration.web_search import get_web_searcher, search_vulnerability_info, search_library_info
from src.tools.orchestrator import ToolOrchestrator, STANDARD_TOOL_CHAIN, AggregatedFinding

console = Console()


class SecurityScanner:
    """安全扫描器

    集成文件发现、代码分析和 AI 分析功能。
    """

    def __init__(self, config: Config):
        """初始化安全扫描器

        Args:
            config: 扫描配置
        """
        self.config = config
        self.scan_engine = ScanEngine(config)
        self.file_discovery = FileDiscoveryEngine()
        self.file_prioritizer = FilePrioritizer()  # 文件优先级评估器
        self.ast_analyzer = ASTAnalyzer()
        self.cst_analyzer = CSTAnalyzer()
        self.ai_analyzer = None
        self.local_analyzer = get_local_analyzer()  # 本地语义分析器
        self.library_matcher = get_library_matcher()  # 库匹配器
        self.priority_evaluator = None
        self.web_searcher = None
        
        # 纯AI模式下跳过初始化可能导致模型加载的组件
        if not config.pure_ai:
            self.priority_evaluator = get_ai_priority_evaluator()  # 优先级评估器
            self.web_searcher = get_web_searcher()  # 网络搜索器
        
        # 初始化规则注册表（仅用于知识库检索，不加载硬编码规则）
        from src.rules.registry import get_registry
        self.rule_registry = get_registry()
        
        # 初始化 AST 分析器
        try:
            self.ast_analyzer.initialize()
            if self.config.debug:
                console.print(f"[dim][DEBUG] AST 分析器初始化成功[/dim]")
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] AST 分析器初始化失败: {e}[/dim]")
        
        if config.ai.enabled and not config.pure_ai:
            try:
                self.ai_analyzer = AIAnalyzer(config)
                self.attack_chain_builder = get_ai_attack_chain_builder()
                if self.config.debug:
                    console.print(f"[dim][DEBUG] AI 分析器初始化成功[/dim]")
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] AI 分析器初始化失败: {e}[/dim]")
        
        # 初始化纯AI分析器
        self.pure_ai_analyzer = None
        self.ai_file_prioritizer = None
        if config.pure_ai:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 开始初始化纯AI分析器[/dim]")
            try:
                from src.ai.pure_ai_analyzer import PureAIAnalyzer
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 导入PureAIAnalyzer成功[/dim]")
                self.pure_ai_analyzer = PureAIAnalyzer(config)
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 纯AI分析器初始化成功[/dim]")
                
                # 初始化AI文件优先级评估器
                try:
                    from src.utils.ai_file_prioritizer import AIFilePrioritizer
                    # 等待纯AI分析器完全初始化
                    if self.pure_ai_analyzer and hasattr(self.pure_ai_analyzer, 'client') and self.pure_ai_analyzer.client:
                        self.ai_file_prioritizer = AIFilePrioritizer(
                            ai_client=self.pure_ai_analyzer.client,
                            config=config
                        )
                        if self.config.debug:
                            if self.ai_file_prioritizer.enabled:
                                console.print("[dim][DEBUG] AI文件优先级评估器初始化成功并已启用[/dim]")
                            else:
                                console.print("[dim][DEBUG] AI文件优先级评估器初始化成功但未启用（客户端不可用）[/dim]")
                    else:
                        if self.config.debug:
                            console.print("[dim][DEBUG] AI文件优先级评估器未初始化：纯AI分析器客户端未就绪[/dim]")
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AI文件优先级评估器初始化失败: {e}[/dim]")
                
            except Exception as e:
                console.print(f"[dim][DEBUG] 纯AI分析器初始化失败: {e}[/dim]")
                import traceback
                traceback.print_exc()
        
        if config.debug:
            console.print(f"[dim][DEBUG] 安全扫描器初始化完成，规则注册表已就绪（仅用于知识库检索）[/dim]")
            console.print(f"[dim][DEBUG] 本地语义分析器已启用[/dim]")
            if config.ai.enabled:
                console.print(f"[dim][DEBUG] 攻击链路分析器已启用[/dim]")

        self.is_vuln_lab_mode = config.scan_mode == ScanMode.VULN_LAB
        if self.is_vuln_lab_mode:
            console.print(f"[bold yellow]🎯 靶场对抗模式已启用[/bold yellow]")

        self._init_nvd_adapter()

        self.tool_orchestrator: Optional[ToolOrchestrator] = None
        self.tool_chain_enabled = getattr(config, 'tools_enabled', False)
        self.custom_tool_chain = getattr(config, 'tool_chain', None)
        if self.tool_chain_enabled:
            try:
                from src.tools.orchestrator import create_orchestrator
                tool_config = {'semgrep_rules_dir': getattr(config, 'semgrep_rules_dir', None)}
                self.tool_orchestrator = create_orchestrator(tool_config)
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 工具编排器初始化成功[/dim]")
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 工具编排器初始化失败: {e}[/dim]")

    def _init_nvd_adapter(self):
        """初始化NVD适配器"""
        if self.config.pure_ai:
            return

        try:
            from src.scanner.nvd_adapter import get_nvd_adapter
            self.nvd_adapter = get_nvd_adapter()
            if self.nvd_adapter.is_available():
                db_type = self.nvd_adapter.get_db_type()
                console.print(f"[cyan]📦 NVD漏洞数据库已启用 ({db_type})[/cyan]")
                if self.config.debug:
                    stats = self.nvd_adapter._query_engine.conn.get_vulnerability_stats() if hasattr(self.nvd_adapter, '_query_engine') and self.nvd_adapter._query_engine else {}
                    if stats:
                        console.print(f"[dim][DEBUG] NVD数据库统计: {stats}[/dim]")
            else:
                console.print(f"[yellow][!] NVD vulnerability DB unavailable, using built-in DB[/yellow]")
        except Exception as e:
            self.nvd_adapter = None
            if self.config.debug:
                console.print(f"[dim][DEBUG] NVD适配器初始化失败: {e}[/dim]")

    async def _tool_prescan(self, target: str) -> List:
        """执行基于工具的预扫描

        Args:
            target: 扫描目标

        Returns:
            工具发现的安全问题列表
        """
        if not self.tool_orchestrator:
            return []

        findings = []
        tool_chain = self.custom_tool_chain if self.custom_tool_chain else STANDARD_TOOL_CHAIN

        if self.config.debug:
            console.print(f"[dim][DEBUG] 开始工具链预扫描，使用工具: {tool_chain}[/dim]")

        try:
            tool_results = self.tool_orchestrator.execute_chain(tool_chain, target)

            if self.config.debug:
                console.print(f"[dim][DEBUG] 工具链扫描完成，发现 {len(tool_results)} 个问题[/dim]")

            from src.core.engine import Finding, Location, Severity

            severity_map = {
                'CRITICAL': Severity.CRITICAL,
                'HIGH': Severity.HIGH,
                'MEDIUM': Severity.MEDIUM,
                'LOW': Severity.LOW,
                'UNKNOWN': Severity.INFO
            }

            for result in tool_results:
                severity = severity_map.get(result.get('severity', 'UNKNOWN'), Severity.INFO)

                metadata = result.get('metadata', {}).copy()
                metadata['source'] = result.get('source', 'unknown')
                metadata['tool_confidence'] = result.get('tool_confidence', 0.5)
                if result.get('source_tools'):
                    metadata['source_tools'] = result.get('source_tools')
                if result.get('cwe_id'):
                    metadata['cwe_id'] = result.get('cwe_id')
                if result.get('cve_id'):
                    metadata['cve_id'] = result.get('cve_id')

                finding = Finding(
                    rule_id=f"TOOL-{result.get('source', 'unknown').upper()}-{result.get('cwe_id', 'UNKNOWN') or result.get('check_id', 'UNKNOWN')}",
                    rule_name=f"[{result.get('source', 'tool').upper()}] {result.get('cwe_id') or result.get('check_id', 'VULN')}",
                    description=result.get('description', ''),
                    severity=severity,
                    location=Location(
                        file=result.get('file', ''),
                        line=result.get('line', 0),
                        column=0
                    ),
                    confidence=result.get('confidence', 0.5),
                    message=result.get('description', ''),
                    code_snippet=metadata.get('code_snippet', ''),
                    fix_suggestion=metadata.get('remediation', ''),
                    references=[],
                    metadata=metadata
                )
                findings.append(finding)

            if tool_results and self.config.debug:
                stats = self.tool_orchestrator.get_statistics()
                console.print(f"[dim][DEBUG] 工具执行统计: {stats}[/dim]")

        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 工具链预扫描失败: {e}[/dim]")

        return findings

    async def scan(self, target: Union[str, Path]) -> ScanResult:
        """执行异步扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
            """
        from tqdm import tqdm
        from datetime import datetime

        # 开始时间
        start_time = time.time()
        start_datetime = datetime.now()

        # 验证目标路径解析
        resolved_target = Path(target).resolve()
        if self.config.debug:
            console.print(f"[dim][DEBUG] 原始目标路径: {target}[/dim]")
            console.print(f"[dim][DEBUG] 解析后目标路径: {resolved_target}[/dim]")
            console.print(f"[dim][DEBUG] 目标是否存在: {resolved_target.exists()}[/dim]")
            console.print(f"[dim][DEBUG] 目标是否为目录: {resolved_target.is_dir()}[/dim]")

        console.print(f"[bold cyan][SCAN] Scanning target:[/bold cyan] [bold green]{target}[/bold green]")
        console.print(f"[bold cyan][TIME] Start time:[/bold cyan] [bold]{time.strftime('%Y-%m-%d %H:%M:%S')}[/bold]")

        # 纯AI模式下确保分析器已初始化
        if self.config.pure_ai and self.pure_ai_analyzer:
            if not self.pure_ai_analyzer.initialized:
                console.print("[cyan]Initializing pure AI analyzer...[/cyan]")
                try:
                    await asyncio.wait_for(
                        self.pure_ai_analyzer._initialize(),
                        timeout=60.0
                    )
                    if not self.pure_ai_analyzer.initialized:
                        console.print("[red]X Pure AI analyzer initialization failed, scan will skip AI analysis[/red]")
                        console.print("[yellow]! Please check API key configuration and network connection[/yellow]")
                except asyncio.TimeoutError:
                    console.print("[red]X Pure AI analyzer initialization timeout[/red]")
                    console.print("[yellow]! Please check network connection or increase timeout[/yellow]")
                except Exception as e:
                    console.print(f"[red]X Pure AI analyzer initialization error: {e}[/red]")
                    if self.config.debug:
                        import traceback
                        traceback.print_exc()
        
        # 发现文件
        with console.status("[bold blue]... Discovering files...[/bold blue]", spinner="dots"):
            files = self._discover_files(target)
        console.print(f"[bold cyan][OK] Found[/bold cyan] [bold green]{len(files)}[/bold green] files")

        # 分析文件
        console.print("[bold cyan][TOOL] Analyzing files...[/bold cyan]")
        findings, analyzed_count = await self._analyze_files(files)
        console.print(f"[bold cyan][OK] Found[/bold cyan] [bold red]{len(findings)}[/bold red] security issues")

        # 创建结果对象（暂时不设置end_time，在最后再设置）
        from src.core.engine import ScanStatus
        result = ScanResult(
            target=str(target),
            status=ScanStatus.COMPLETED,
            start_time=start_datetime
        )
        result.metadata['total_files'] = analyzed_count

        # 纯AI模式：跳过所有后处理步骤，直接汇总结果
        if self.config.pure_ai:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 纯AI模式：跳过所有后处理步骤[/dim]")
            
            # 直接汇总结果
            console.print("[bold cyan][INFO] Summarizing results...[/bold cyan]")
            from src.core.engine import Finding, Location, Severity
            for finding in findings:
                # Convert VulnerabilityFinding to Finding
                if hasattr(finding, 'severity') and isinstance(finding.severity, str):
                    # Map string severity to Severity enum
                    severity_map = {
                        'critical': Severity.CRITICAL,
                        'high': Severity.HIGH,
                        'medium': Severity.MEDIUM,
                        'low': Severity.LOW,
                        'info': Severity.INFO
                    }
                    severity = severity_map.get(finding.severity.lower(), Severity.INFO)
                else:
                    severity = Severity.INFO
                
                # Create Finding object
                def _get_location(obj, default_file='unknown'):
                    """安全获取 location 属性"""
                    if hasattr(obj, 'file'):
                        return obj.file, getattr(obj, 'line', 0), getattr(obj, 'column', 0)
                    elif isinstance(obj, dict):
                        return obj.get('file', default_file), obj.get('line', 0), obj.get('column', 0)
                    else:
                        return default_file, 0, 0

                loc_file, loc_line, loc_col = _get_location(finding.location)
                finding_obj = Finding(
                    rule_id=finding.rule_id,
                    rule_name=finding.rule_name,
                    description=finding.description,
                    severity=severity,
                    location=Location(file=loc_file, line=loc_line, column=loc_col),
                    confidence=finding.confidence,
                    message=finding.description,
                    fix_suggestion=finding.fix_suggestion,
                    metadata=finding.metadata if hasattr(finding, 'metadata') else {}
                )
                result.add_finding(finding_obj)

            # 添加调试日志
            if hasattr(self, 'pure_ai_analyzer') and self.pure_ai_analyzer and hasattr(self.pure_ai_analyzer, 'debug_logs'):
                result.debug_logs = self.pure_ai_analyzer.debug_logs

            # 添加Token使用记录
            if hasattr(self, 'pure_ai_analyzer') and self.pure_ai_analyzer:
                token_tracker = self.pure_ai_analyzer.pipeline.token_tracker if hasattr(self.pure_ai_analyzer, 'pipeline') and self.pure_ai_analyzer.pipeline else None
                if token_tracker:
                    result.token_records = token_tracker._token_usage[-100:]  # 最近100条

        else:
            # 正常模式：执行所有后处理步骤
            # 漏洞优先级评估
            console.print("[bold cyan][INFO] Evaluating vulnerability priority...[/bold cyan]")
            prioritized_findings = self._prioritize_findings(findings, files)
            
            # 汇总结果
            console.print("[bold cyan][INFO] Summarizing results...[/bold cyan]")
            for finding in prioritized_findings:
                result.add_finding(finding)
            
            # 执行攻击链路分析（如果启用了AI且不是纯AI模式）
            if self.config.ai.enabled and not self.config.pure_ai and getattr(self, 'attack_chain_builder', None) is not None and result.findings:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 开始执行攻击链路分析[/dim]")
                
                try:
                    # 转换ScanResult为SecurityAnalysisResult
                    ai_findings = []
                    for finding in result.findings:
                        # 创建VulnerabilityFinding对象
                        # 处理 severity 可能是字符串或枚举对象的情况
                        if hasattr(finding.severity, 'name'):
                            severity_value = finding.severity.name.lower()
                        else:
                            severity_value = str(finding.severity).lower()
                        vuln_finding = VulnerabilityFinding(
                            rule_id=finding.rule_id,
                            rule_name=finding.rule_name,
                            description=finding.description,
                            severity=severity_value,
                            confidence=finding.confidence,
                            location={
                                "file": finding.location.file,
                                "line": finding.location.line,
                                "column": finding.location.column
                            },
                            code_snippet=finding.code_snippet,
                            fix_suggestion=finding.fix_suggestion,
                            explanation=finding.message,
                            references=finding.references,
                            exploit_scenario=""
                        )
                        ai_findings.append(vuln_finding)
                    
                    # 创建SecurityAnalysisResult
                    security_result = SecurityAnalysisResult(
                        findings=ai_findings,
                        risk_score=0.0,
                        summary=f"Found {len(ai_findings)} potential issues",
                        recommendations=[],
                        metadata={}
                    )
                    
                    # 执行攻击链路分析
                    attack_chain_result = await self.attack_chain_builder.build_attack_chains(security_result)
                    
                    # 生成可视化数据
                    visualization_data = self.attack_chain_builder.get_visualization_data(attack_chain_result)
                    
                    # 将攻击链路分析结果添加到ScanResult中
                    result.metadata['attack_chain'] = {
                        'summary': attack_chain_result.summary,
                        'risk_score': attack_chain_result.risk_score,
                        'paths': attack_chain_result.paths,
                        'visualization': visualization_data
                    }
                    
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 攻击链路分析完成，识别出 {len(attack_chain_result.paths)} 条攻击路径[/dim]")
                        console.print(f"[dim][DEBUG] 总体风险评分: {attack_chain_result.risk_score:.2f}[/dim]")
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 攻击链路分析失败: {e}[/dim]")
            
            # 执行本地攻击链分析（纯AI模式下跳过）
            if result.findings and not self.config.pure_ai:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 开始执行本地攻击链分析[/dim]")
                
                try:
                    from src.core.attack_chain_analyzer import AttackChainAnalyzer
                    from src.core.result_aggregator import AggregatedFinding
                    
                    # 转换为AggregatedFinding
                    aggregated_findings = []
                    for finding in result.findings:
                        # 简化的AggregatedFinding创建
                        agg_finding = AggregatedFinding(
                            rule_id=finding.rule_id,
                            rule_name=finding.rule_name,
                            description=finding.description,
                            severity=finding.severity,
                            file_path=finding.location.file,
                            line=finding.location.line,
                            column=finding.location.column,
                            confidence=finding.confidence,
                            message=finding.message,
                            code_snippet=finding.code_snippet,
                            fix_suggestion=finding.fix_suggestion,
                            references=finding.references,
                            metadata=finding.metadata
                        )
                        aggregated_findings.append(agg_finding)
                    
                    # 执行攻击链分析
                    analyzer = AttackChainAnalyzer()
                    chain_result = analyzer.analyze(aggregated_findings)
                    
                    # 将攻击链分析结果添加到ScanResult中
                    result.metadata['local_attack_chain'] = {
                        'summary': chain_result.summary,
                        'critical_chains': [{
                            'description': chain.description,
                            'risk_level': chain.risk_level,
                            'status': chain.status,
                            'steps': [{
                                'rule_name': step.finding.rule_name,
                                'description': step.description
                            } for step in chain.steps]
                        } for chain in chain_result.critical_chains]
                    }
                    
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 本地攻击链分析完成，识别出 {len(chain_result.critical_chains)} 条关键攻击链[/dim]")
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 本地攻击链分析失败: {e}[/dim]")
            
            # 执行漏洞优先级评估（如果启用了AI且不是纯AI模式）
            if self.config.ai.enabled and self.priority_evaluator is not None and result.findings:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 开始执行漏洞优先级评估[/dim]")
                
                try:
                    # 转换ScanResult为SecurityAnalysisResult
                    ai_findings = []
                    for finding in result.findings:
                        # 创建VulnerabilityFinding对象
                        # 处理 severity 可能是字符串或枚举对象的情况
                        if hasattr(finding.severity, 'name'):
                            severity_value = finding.severity.name.lower()
                        else:
                            severity_value = str(finding.severity).lower()
                        vuln_finding = VulnerabilityFinding(
                            rule_id=finding.rule_id,
                            rule_name=finding.rule_name,
                            description=finding.description,
                            severity=severity_value,
                            confidence=finding.confidence,
                            location={
                                "file": finding.location.file,
                                "line": finding.location.line,
                                "column": finding.location.column
                            },
                            code_snippet=finding.code_snippet,
                            fix_suggestion=finding.fix_suggestion,
                            explanation=finding.message,
                            references=finding.references,
                            exploit_scenario=""
                        )
                        ai_findings.append(vuln_finding)
                    
                    # 创建SecurityAnalysisResult
                    security_result = SecurityAnalysisResult(
                        findings=ai_findings,
                        risk_score=0.0,
                        summary=f"Found {len(ai_findings)} potential issues",
                        recommendations=[],
                        metadata={}
                    )
                    
                    # 执行优先级评估
                    priority_result = await self.priority_evaluator.prioritize_findings(security_result, AnalysisContext(
                        file_path=str(target),
                        code_content="",
                        language="python"  # 默认语言
                    ))
                    
                    # 将优先级评估结果添加到ScanResult中
                    result.metadata['priority_analysis'] = {
                        'summary': priority_result.summary,
                        'priority_distribution': priority_result.metadata.get('priority_distribution', {}),
                        'prioritized_findings': [finding.rule_name for finding in priority_result.prioritized_findings]
                    }
                    
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 优先级评估完成[/dim]")
                        console.print(f"[dim][DEBUG] {priority_result.summary}[/dim]")
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 优先级评估失败: {e}[/dim]")
            
            # 集成 LangGraph 深度分析（如果启用了 AI 且发现了漏洞，纯AI模式下跳过）
            if self.config.ai.enabled and not self.config.pure_ai and result.findings:
                try:
                    print("🔍 开始执行 LangGraph 深度分析")
                    print("🚀 启动多Agent安全分析流程")
                    
                    # 导入 LangGraph 流程
                    from src.core.langgraph_flow import run_scan
                    
                    # 执行 LangGraph 扫描
                    langgraph_result = await run_scan(str(target), self.config)
                    
                    if langgraph_result and langgraph_result.findings:
                        print(f"[green]OK[/green] LangGraph deep analysis found {len(langgraph_result.findings)} issues")
                        
                        # 检查是否已经有 LangGraph 深度分析的结果
                        has_langgraph_finding = any(finding.rule_id == 'LANGGRAPH-ANALYSIS' for finding in result.findings)
                        
                        # 如果没有，将 LangGraph 分析结果添加到最终结果中
                        if not has_langgraph_finding:
                            for finding in langgraph_result.findings:
                                result.add_finding(finding)
                            
                            # 添加 LangGraph 分析元数据
                            if hasattr(langgraph_result, 'metadata'):
                                result.metadata['langgraph_analysis'] = langgraph_result.metadata
                        else:
                            print("[yellow]! LangGraph analysis result already exists, skipping duplicate[/yellow]")

                    print("[green]OK[/green] LangGraph deep analysis completed")
                    print("[cyan]INFO[/cyan] CREWAI multi-expert analysis integrated into scan results")

                except Exception as e:
                    print(f"[red]X[/red] LangGraph deep analysis failed: {e}")
            
            # 集成自学习机制
            if self.config.ai.enabled and not self.config.pure_ai:
                try:
                    from src.storage.rag_knowledge_base import get_rag_knowledge_base
                    from src.learning.self_learning import Knowledge, KnowledgeType
                    import hashlib
                    
                    # 获取 RAG 知识库实例
                    rag_kb = get_rag_knowledge_base()
                    
                    # 转换扫描结果为 RAG 知识库所需格式
                    learning_results = []
                    for finding in result.findings:
                        # 过滤掉 LangGraph 深度分析的结果，避免重复判断
                        if finding.rule_id == 'LANGGRAPH-ANALYSIS':
                            continue
                        
                        # 创建知识内容
                        content = f"{finding.rule_name}: {finding.description}\n\n严重级别: {finding.severity}\n置信度: {finding.confidence}\n\n修复建议: {finding.fix_suggestion}"
                        
                        learning_results.append({
                            "content": content,
                            "knowledge_type": "ai_learning",
                            "source": "auto_learning",
                            "confidence": finding.confidence,
                            "tags": [finding.severity, finding.rule_name],
                            "metadata": {
                                "rule_id": finding.rule_id,
                                "file_path": finding.location.file,
                                "line": finding.location.line,
                                "code_snippet": finding.code_snippet
                            }
                        })
                    
                    # 自动记录学习结果到 RAG 知识库
                    rag_kb.auto_record_learning(learning_results)
                    
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 自学习完成，已更新 RAG 知识库[/dim]")
                        
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 自学习集成失败: {e}[/dim]")
        
        # 计算扫描耗时
        end_time = time.time()
        scan_time = end_time - start_time
        
        # 统计不同优先级的漏洞数量
        priority_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in result.findings:
            try:
                # 处理 severity 可能是字符串或枚举对象的情况
                if hasattr(finding.severity, 'name'):
                    severity_name = finding.severity.name.lower()
                else:
                    severity_name = str(finding.severity).lower()
                if severity_name in priority_counts:
                    priority_counts[severity_name] += 1
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 处理严重性级别失败: {e}[/dim]")
                continue
        
        console.print()
        console.print(f"[bold cyan][TIME] Scan duration:[/bold cyan] [bold]{scan_time:.2f}[/bold] seconds")
        console.print(f"[bold cyan][OK] Scan completed[/bold cyan]")

        result.end_time = datetime.now()
        if self.config.debug:
            console.print(f"[dim][DEBUG] 扫描完成，总计发现 {len(result.findings)} 个问题[/dim]")

        if self.tool_orchestrator and self.tool_chain_enabled:
            tool_stats = self.tool_orchestrator.get_statistics()
            result.metadata['tool_statistics'] = tool_stats
            if tool_stats.get('total_findings', 0) > 0:
                console.print(f"[bold cyan][TOOL] Tool execution statistics:[/bold cyan]")
                for tool, stats in tool_stats.get('tool_statistics', {}).items():
                    status = "[OK]" if stats.get('is_available', False) else "[X]"
                    findings_count = stats.get('findings_count', 0)
                    exec_time = stats.get('execution_time', 0)
                    console.print(f"  {status} {tool}: {findings_count} findings, {exec_time:.2f}s")

        return result

    def scan_sync(self, target: Union[str, Path]) -> ScanResult:
        """执行同步扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
        """
        return asyncio.run(self.scan(target))

    def _discover_files(self, target: Union[str, Path]) -> List[FileInfo]:
        """发现文件

        Args:
            target: 扫描目标

        Returns:
            发现的文件信息列表
        """
        target_path = Path(target)
        
        if target_path.is_file():
            # 单个文件
            file_info = self.file_discovery.get_file_metadata(target_path)
            return [file_info]
        else:
            # 目录
            return self.file_discovery.discover_files(target_path)

    async def _analyze_files(self, files: List[FileInfo]) -> Tuple[List, int]:
        """分析文件

        Args:
            files: 文件信息列表

        Returns:
            (发现的安全问题列表, 实际分析的文件数量)
        """
        findings = []
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

        if self.tool_orchestrator and self.tool_chain_enabled:
            tool_target = str(Path(files[0].path).parent) if files else "."
            console.print("[bold cyan][TOOL] Running tool chain pre-scan...[/bold cyan]")
            tool_findings = await self._tool_prescan(tool_target)
            if tool_findings:
                console.print(f"[bold cyan][OK] Tool chain pre-scan found[/bold cyan] [bold red]{len(tool_findings)}[/bold red] [bold cyan]security issues[/bold cyan]")
                findings.extend(tool_findings)

        # 评估文件优先级
        prioritized_files = []

        # 显示文件优先级评估信息
        if not self.config.quiet:
            console.print("[bold cyan][SCAN] Evaluating file priority...[/bold cyan]")
        
        # 纯AI模式下使用专门的文件优先级评估器
        if self.config.pure_ai:
            # 导入并使用纯净AI模式的文件优先级评估器
            try:
                from src.ai.pure_ai.file_prioritizer import FilePrioritizer as PureAIFilePrioritizer
                pure_ai_prioritizer = PureAIFilePrioritizer()
                if self.config.debug:
                    console.print("[dim][DEBUG] 使用纯净AI模式的文件优先级评估器[/dim]")
                
                # 第一步：使用传统评估快速筛选出高优先级文件
                quick_prioritized = []
                for file_info in files:
                    score, priority = self.file_prioritizer.evaluate_file_priority(Path(file_info.path))
                    quick_prioritized.append((file_info, score, priority))
                
                # 按传统分数排序，取前20个文件进行AI评估（减少数量）
                quick_prioritized.sort(key=lambda x: x[1], reverse=True)
                top_files = quick_prioritized[:20]  # 只对前20个文件进行AI评估
                
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 快速筛选后，对前{len(top_files)}个文件进行AI优先级评估[/dim]")
                
                # 第二步：对筛选出的文件进行AI优先级评估（分批处理）
                async def calculate_ai_priorities():
                    results = []
                    batch_size = 5  # 每次处理5个文件
                    
                    for i in range(0, len(top_files), batch_size):
                        batch = top_files[i:i+batch_size]
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] 处理文件批次 {i//batch_size + 1}/{(len(top_files)+batch_size-1)//batch_size}[/dim]")
                        
                        tasks = []
                        for file_info, _, _ in batch:
                            tasks.append(pure_ai_prioritizer.calculate_priority(file_info.path))
                        
                        # 处理当前批次
                        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                        results.extend(batch_results)
                    
                    return results
                
                # 执行异步计算
                ai_results = await calculate_ai_priorities()
                
                # 处理AI评估结果
                for (file_info, _, _), ai_result in zip(top_files, ai_results):
                    if isinstance(ai_result, Exception):
                        # 处理异常，使用传统评估结果
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] AI评估失败: {ai_result}，使用传统评估结果[/dim]")
                        score, priority = self.file_prioritizer.evaluate_file_priority(Path(file_info.path))
                    else:
                        # 正常处理AI评估结果
                        score = ai_result['priority_score']
                        # 根据分数确定优先级级别
                        if score >= 0.7:
                            priority = 'high'
                        elif score >= 0.4:
                            priority = 'medium'
                        else:
                            priority = 'low'
                    prioritized_files.append((file_info, score, priority))
                
                # 确保至少有一些文件
                if not prioritized_files:
                    # 回退到传统评估
                    for file_info in files[:10]:  # 只评估前10个
                        score, priority = self.file_prioritizer.evaluate_file_priority(Path(file_info.path))
                        prioritized_files.append((file_info, score, priority))
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 纯净AI文件优先级评估器初始化失败，使用传统评估: {e}[/dim]")
                # 回退到传统评估
                for file_info in files[:20]:  # 只评估前20个
                    score, priority = self.file_prioritizer.evaluate_file_priority(Path(file_info.path))
                    prioritized_files.append((file_info, score, priority))
        else:
            # 使用传统的基于规则的评估
            for file_info in files:
                score, priority = self.file_prioritizer.evaluate_file_priority(Path(file_info.path))
                prioritized_files.append((file_info, score, priority))
        
        # 按优先级排序
        prioritized_files.sort(key=lambda x: x[1], reverse=True)
        
        # 测试模式：只处理指定数量的优先级最高的文件
        # 在 pure-ai 模式下：限制文件数量，但所有文件都进行 AI 分析（不跳过）
        if self.config.test_mode:
            test_file_count = getattr(self.config, 'test_file_count', 10)
            original_count = len(prioritized_files)
            if not self.config.pure_ai:
                prioritized_files = prioritized_files[:test_file_count]
                console.print(f"[yellow][!] Test mode enabled, only processing first {test_file_count} highest priority files (total {original_count})[/yellow]")
            else:
                # pure-ai 模式：限制数量，但所有文件都进入 AI 分析
                prioritized_files = prioritized_files[:test_file_count]
                console.print(f"[yellow][!] Test mode enabled, processing {len(prioritized_files)} files with AI analysis (total {original_count})[/yellow]")
        
        if self.config.debug:
            console.print(f"[dim][DEBUG] 文件优先级评估完成，总计 {len(prioritized_files)} 个文件[/dim]")
            high_count = sum(1 for _, _, p in prioritized_files if p == 'high')
            medium_count = sum(1 for _, _, p in prioritized_files if p == 'medium')
            low_count = sum(1 for _, _, p in prioritized_files if p == 'low')
            console.print(f"[dim][DEBUG] 高优先级: {high_count}, 中优先级: {medium_count}, 低优先级: {low_count}[/dim]")
        
        # 文件类型过滤配置
        file_type_analysis_config = {
            'python': {
                'static': True,
                'rule': True,
                'semantic': True,
                'library': True,
                'web': True,
                'ai': True
            },
            'javascript': {
                'static': True,
                'rule': True,
                'semantic': True,
                'library': True,
                'web': True,
                'ai': True
            },
            'html': {
                'static': True,
                'rule': True,
                'semantic': True,
                'library': False,
                'web': True,
                'ai': True
            },
            'css': {
                'static': False,
                'rule': False,
                'semantic': False,
                'library': False,
                'web': False,
                'ai': False
            },
            'json': {
                'static': False,
                'rule': True,
                'semantic': False,
                'library': False,
                'web': False,
                'ai': False
            },
            'markdown': {
                'static': False,
                'rule': False,
                'semantic': False,
                'library': False,
                'web': False,
                'ai': False
            },
            'txt': {
                'static': False,
                'rule': False,
                'semantic': False,
                'library': False,
                'web': False,
                'ai': False
            },
            'unknown': {
                'static': False,
                'rule': True,
                'semantic': False,
                'library': False,
                'web': False,
                'ai': False
            }
        }
        
        # 显示文件分析信息
        if not self.config.quiet:
            console.print("[bold cyan][TOOL] Analyzing files...[/bold cyan]")

        # 纯AI模式：先进行配置扫描，再用批量AI分析
        if self.config.pure_ai:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 纯AI模式：使用批量分析[/dim]")

            # 获取测试模式下的目标文件列表
            target_files = prioritized_files if self.config.test_mode else files

            # Step 1: 快速配置扫描 - 找出配置文件中的硬编码凭证
            try:
                from src.analyzers.config_scanner import ConfigScanner

                config_scanner = ConfigScanner()
                config_files = [f for f in target_files if config_scanner.is_config_file(f.path)]

                if config_files:
                    console.print(f"[yellow][SCAN] Scanning {len(config_files)} config files...[/yellow]")
                    config_result = config_scanner.scan_files([f.path for f in config_files])

                    if config_result.findings:
                        console.print(f"[yellow][!] Found {len(config_result.findings)} sensitive info in {config_result.files_with_findings} config files[/yellow]")

                        # 导入配置发现增强器
                        from src.analyzers.config_finding_enhancer import enhance_config_finding

                        # 将配置扫描发现转换为标准 Finding 格式
                        # 标记为verified=True，表示这是已知风险，AI不应降低其严重级别
                        for cf in config_result.findings:
                            from src.core.engine import Finding, Location, Severity

                            # 增强发现：结合上下文评估实际风险等级，提供详细描述和针对性修复建议
                            enhanced = enhance_config_finding(cf)

                            location = Location(
                                file=cf.file_path,
                                line=cf.line_number
                            )

                            finding = Finding(
                                rule_id=enhanced['rule_id'],
                                rule_name=enhanced['description'].split('，')[0] if '，' in enhanced['description'] else enhanced['description'][:30],
                                description=enhanced['description'],
                                severity=Severity[enhanced['severity']],
                                location=location,
                                code_snippet=cf.value,
                                fix_suggestion=enhanced['remediation'],
                                metadata={
                                    'source': 'config_scanner',
                                    'verified': True,
                                    'risk_factors': enhanced.get('risk_factors', [])
                                }
                            )
                            findings.append(finding)
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 配置扫描失败: {e}[/dim]")

            # Step 1.5: 轻量级代码漏洞扫描 - 使用正则模式快速检测常见漏洞
            try:
                from src.analyzers.code_vuln_scanner import CodeVulnScanner
                from src.core.file_filter import SecurityFileFilter, RiskLevel

                code_vuln_scanner = CodeVulnScanner()
                file_filter = SecurityFileFilter()

                # 智能筛选：只对可疑文件进行完整扫描
                for file_info, _, _ in prioritized_files:
                    file_path = file_info.path
                    if code_vuln_scanner.is_code_file(file_path) or code_vuln_scanner.is_mybatis_mapper(file_path):
                        # 使用文件过滤器预判风险
                        classified = file_filter.classify_file(file_path)

                        # 只有中高风险文件才进行完整代码扫描
                        if classified.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
                            vuln_findings = code_vuln_scanner.scan_file(file_path)

                            if vuln_findings:
                                from src.core.engine import Finding, Location, Severity

                                severity_map = {
                                    'critical': Severity.CRITICAL,
                                    'high': Severity.HIGH,
                                    'medium': Severity.MEDIUM,
                                    'low': Severity.LOW
                                }

                                for vf in vuln_findings:
                                    location = Location(
                                        file=vf.file_path,
                                        line=vf.line_number
                                    )

                                    finding = Finding(
                                        rule_id=vf.vuln_type,
                                        rule_name=vf.description,
                                        description=vf.description,
                                        severity=severity_map.get(vf.level.value, Severity.MEDIUM),
                                        location=location,
                                        code_snippet=vf.code_snippet,
                                        fix_suggestion=vf.remediation,
                                        metadata={'source': 'code_vuln_scanner', 'verified': True}
                                    )
                                    findings.append(finding)

                                console.print(f"[yellow]! Found {len(vuln_findings)} code vulnerabilities in {Path(file_path).name} (risk level: {classified.risk_level.value})[/yellow]")
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 代码漏洞扫描失败: {e}[/dim]")
                    import traceback
                    traceback.print_exc()

            # Step 2: 依赖声明文件库版本CVE匹配
            # 对pom.xml, build.gradle, package.json等依赖文件进行NVD CVE匹配
            try:
                dependency_findings = await self._dependency_cve_scan(prioritized_files)
                findings.extend(dependency_findings)
            except Exception as e:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 依赖CVE扫描失败: {e}[/dim]")

            # Step 3: 批量AI分析（仅对非Java/非配置文件进行深度AI分析）
            ai_findings = []
            if self.pure_ai_analyzer:
                try:
                    # 初始化扫描状态
                    scan_state = ScanState.create(
                        total_files=len(prioritized_files),
                        max_duration=getattr(self.config, 'max_duration', 0),
                        max_files=getattr(self.config, 'max_files', 0)
                    )
                    state_file = Path(self.config.report.output).parent / '.scan_state.json' if self.config.report.output else Path('.') / '.scan_state.json'

                    # 尝试加载续传状态
                    if getattr(self.config, 'resume', False):
                        loaded_state = ScanState.load(str(state_file))
                        if loaded_state:
                            scan_state = loaded_state
                            console.print(f"[yellow][!] Resuming scan from previous state: {len(scan_state.completed_files)}/{scan_state.total_files} files completed[/yellow]")
                            # 合并已有发现
                            for f in scan_state.findings:
                                if hasattr(f, 'to_finding'):
                                    ai_findings.append(f.to_finding())
                                elif isinstance(f, dict):
                                    from src.core.engine import Finding
                                    finding_kwargs = {
                                        'rule_id': f.get('rule_id', ''),
                                        'rule_name': f.get('rule_name', ''),
                                        'description': f.get('description', ''),
                                        'severity': f.get('severity', 'INFO'),
                                        'location': f.get('location', {}),
                                        'confidence': f.get('confidence', 0.5),
                                        'message': f.get('message', ''),
                                        'code_snippet': f.get('code_snippet', ''),
                                        'fix_suggestion': f.get('fix_suggestion', ''),
                                        'references': f.get('references', []),
                                        'metadata': f.get('metadata', {})
                                    }
                                    ai_findings.append(Finding(**finding_kwargs))

                    # 检查是否启用截断模式
                    truncate_mode = getattr(self.config, 'truncate_output', False)

                    # 过滤待处理文件（跳过已完成的）
                    pending_files = []
                    for i, (file_info, _, _) in enumerate(prioritized_files):
                        if scan_state.completed_files and file_info.path in scan_state.completed_files:
                            if self.config.debug:
                                console.print(f"[dim][DEBUG] Skipping already completed file: {file_info.path}[/dim]")
                            continue
                        pending_files.append((i, file_info))

                    console.print(f"[bold cyan][TOOL] AI analyzing {len(pending_files)} files...[/bold cyan]")

                    # 执行批量分析
                    if pending_files:
                        batch_results = await self.pure_ai_analyzer.analyze_batch(
                            [file_info for _, file_info in pending_files],
                            max_concurrent=3
                        )

                        # 收集结果
                        for idx, (i, file_info) in enumerate(pending_files):
                            result = batch_results[idx]
                            ai_findings.extend(result)

                            # 更新扫描状态
                            findings_dicts = []
                            for f in result:
                                if hasattr(f, 'to_dict'):
                                    findings_dicts.append(f.to_dict())
                                elif hasattr(f, '__dict__'):
                                    findings_dicts.append(f.__dict__)
                            scan_state.add_completed_file(file_info.path, findings_dicts)

                            # 实时显示发现的问题
                            if result:
                                console.print(f"Scanning file: {Path(file_info.path).name}")
                                for finding in result:
                                    severity_color = "red" if finding.severity in ["critical", "high"] else "yellow" if finding.severity == "medium" else "blue"
                                    console.print(f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]")

                            # 检查是否需要截断
                            if truncate_mode:
                                should_trunc, reason = scan_state.should_truncate()
                                if should_trunc:
                                    scan_state.mark_truncated(reason)
                                    console.print(f"[yellow][!] Scan truncated: {reason} after {len(scan_state.completed_files)} files[/yellow]")
                                    break

                            # 定期保存状态
                            if len(scan_state.completed_files) % 10 == 0:
                                scan_state.save(str(state_file))

                        # 最终保存状态
                        scan_state.save(str(state_file))

                    # 收集调试日志（从 pure_ai_analyzer 获取）
                    if self.pure_ai_analyzer and hasattr(self.pure_ai_analyzer, 'debug_logs'):
                        debug_logs = self.pure_ai_analyzer.debug_logs
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AI批量分析失败: {e}[/dim]")
                        import traceback
                        traceback.print_exc()
                    else:
                        console.print(f"[red]AI analysis failed: {e}[/red]")
            
            findings.extend(ai_findings)

            # 合并重复发现：相同规则ID优先使用更高级别
            findings = self._merge_duplicate_findings(findings)

            # 后处理：确保已验证来源的发现不被低级别发现覆盖
            # config_scanner 和 code_vuln_scanner 的发现是已知的、可复现的安全风险
            # 应该使用它们自己确定的严重级别，而不是被 AI 分析器的判定覆盖
            findings = self._protect_verified_sources(findings)

            if self.config.debug:
                console.print(f"[dim][DEBUG] 纯AI模式批量分析完成，发现 {len(ai_findings)} 个问题[/dim]")
        else:
            # 正常模式：逐个文件分析
            for file_info, score, priority in prioritized_files:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 分析文件: {file_info.path} (优先级: {priority}, 分数: {score:.2f})[/dim]")
                
                # 获取文件类型配置
                file_type = file_info.language.value if file_info.language else 'unknown'
                analysis_config = file_type_analysis_config.get(file_type, file_type_analysis_config['unknown'])
                
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 文件类型: {file_type}, 分析配置: {analysis_config}[/dim]")
                
                # 正常模式：执行所有分析
                # 显示实时扫描信息
                console.print(f"Scanning file: {Path(file_info.path).name}")
                
                # 静态分析
                static_findings = []
                if analysis_config['static']:
                    static_findings = self._static_analyze(file_info)
                    findings.extend(static_findings)
                    
                    # 实时显示发现的问题
                    if static_findings:
                        for finding in static_findings:
                            severity_color = "red" if finding.severity in ["critical", "high"] else "yellow" if finding.severity == "medium" else "blue"
                            console.print(f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]")
                
                # 本地语义分析（始终启用，轻量级）
                semantic_findings = []
                if analysis_config['semantic']:
                    semantic_findings = self._semantic_analyze(file_info)
                    findings.extend(semantic_findings)
                    
                    # 实时显示发现的问题
                    if semantic_findings:
                        for finding in semantic_findings:
                            severity_color = "red" if finding.severity in ["critical", "high"] else "yellow" if finding.severity == "medium" else "blue"
                            console.print(f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]")
                
                # 库匹配分析
                library_findings = []
                if analysis_config['library']:
                    library_findings = self._library_analyze(file_info)
                    findings.extend(library_findings)
                    
                    # 实时显示发现的问题
                    if library_findings:
                        for finding in library_findings:
                            severity_color = "red" if finding.severity in ["critical", "high"] else "yellow" if finding.severity == "medium" else "blue"
                            console.print(f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]")
                
                # AI 分析（如果启用 --ai 参数，对所有文件进行分析）
                ai_findings = []
                if self.ai_analyzer and self.config.ai.enabled and analysis_config['ai']:
                    ai_findings = await self._ai_analyze(file_info)
                    findings.extend(ai_findings)
                    
                    # 实时显示发现的问题
                    if ai_findings:
                        for finding in ai_findings:
                            severity_color = "red" if finding.severity in ["critical", "high"] else "yellow" if finding.severity == "medium" else "blue"
                            console.print(f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]")
                
                # 规则分析（结合AI分析结果）
                rule_findings = []
                if analysis_config['rule']:
                    rule_findings = self._rule_analyze(file_info, ai_findings)
                    findings.extend(rule_findings)
                    
                    # 实时显示发现的问题
                    if rule_findings:
                        for finding in rule_findings:
                            severity_color = "red" if finding.severity in ["critical", "high"] else "yellow" if finding.severity == "medium" else "blue"
                            console.print(f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]")
                
                # 网络搜索分析（结合AI分析结果）
                web_findings = []
                if analysis_config['web'] and self.web_searcher:
                    web_findings = await self._web_search_analyze(file_info, library_findings)
                    # 利用AI分析结果过滤网络搜索结果
                    if ai_findings:
                        web_findings = self._filter_web_findings_by_ai(web_findings, ai_findings)
                    findings.extend(web_findings)
                    
                    # 实时显示发现的问题
                    if web_findings:
                        for finding in web_findings:
                            severity_color = "red" if finding.severity in ["critical", "high"] else "yellow" if finding.severity == "medium" else "blue"
                            console.print(f"→ [{severity_color}]Found {finding.rule_name}[/{severity_color}]")
                
                if self.config.debug:
                    total_findings = len(static_findings) + len(rule_findings) + len(semantic_findings) + len(library_findings) + len(web_findings) + len(ai_findings)
                    console.print(f"[dim][DEBUG] 文件分析完成，发现 {total_findings} 个问题[/dim]")

        return findings, len(prioritized_files)

    def _static_analyze(self, file_info: FileInfo) -> List:
        """静态分析文件

        Args:
            file_info: 文件信息

        Returns:
            发现的安全问题列表
        """
        findings = []
        
        try:
            # 读取文件内容
            with open(file_info.path, 'r', encoding='utf-8') as f:
                file_content = f.read()
            
            # 创建分析上下文
            from src.analyzers.base import AnalysisContext
            context = AnalysisContext(
                file_path=str(file_info.path),
                file_content=file_content,
                language=file_info.language.value
            )
            
            # 检查 AST 分析器是否初始化成功
            if not hasattr(self.ast_analyzer, '_parsers') or not self.ast_analyzer._parsers:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] AST 分析器未初始化，可能缺少 tree-sitter 库[/dim]")
                # 尝试初始化分析器
                try:
                    self.ast_analyzer.initialize()
                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 初始化 AST 分析器失败: {e}[/dim]")
            
            # 使用 AST 分析器
            try:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 使用 AST 分析器分析: {file_info.path}[/dim]")
                
                ast_result = self.ast_analyzer.analyze(context)
                
                if ast_result.issues:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AST 分析发现 {len(ast_result.issues)} 个问题[/dim]")
                    
                    for issue in ast_result.issues:
                        converted = self._convert_to_finding(issue)
                        if converted:
                            findings.append(converted)
                else:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AST 分析未发现问题: {file_info.path}[/dim]")
                
            except Exception as e:
                error_msg = f"AST 分析失败: {e}"
                if self.config.debug:
                    console.print(f"[dim][DEBUG] {error_msg}[/dim]")
                # 添加错误信息到结果中，让用户知道静态分析失败
                from src.core.engine import Finding, Location, Severity
                error_finding = Finding(
                    rule_id="STATIC-ANALYSIS-ERROR",
                    rule_name="静态分析失败",
                    description=error_msg,
                    severity=Severity.INFO,
                    location=Location(
                        file=str(file_info.path),
                        line=1,
                        column=0
                    ),
                    confidence=0.5,
                    message=error_msg,
                    code_snippet="",
                    fix_suggestion="请确保安装了 tree-sitter 相关依赖",
                    references=[],
                    metadata={"error": str(e)}
                )
                findings.append(error_finding)
            
            # 使用 CST 分析器（仅 Python）
            if file_info.language.value == 'python':
                try:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 使用 CST 分析器分析: {file_info.path}[/dim]")
                    
                    cst_result = self.cst_analyzer.analyze(context)
                    
                    if cst_result.issues:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] CST 分析发现 {len(cst_result.issues)} 个问题[/dim]")
                        
                        for issue in cst_result.issues:
                            converted = self._convert_to_finding(issue)
                            if converted:
                                findings.append(converted)
                    else:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] CST 分析未发现问题: {file_info.path}[/dim]")
                
                except Exception as e:
                    error_msg = f"CST 分析失败: {e}"
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] {error_msg}[/dim]")
                    # 添加错误信息到结果中
                    from src.core.engine import Finding, Location, Severity
                    error_finding = Finding(
                        rule_id="CST-ANALYSIS-ERROR",
                        rule_name="CST 分析失败",
                        description=error_msg,
                        severity=Severity.INFO,
                        location=Location(
                            file=str(file_info.path),
                            line=1,
                            column=0
                        ),
                        confidence=0.5,
                        message=error_msg,
                        code_snippet="",
                        fix_suggestion="请确保安装了 tree-sitter 相关依赖",
                        references=[],
                        metadata={"error": str(e)}
                    )
                    findings.append(error_finding)
            
            # 去重静态分析结果
            findings = self._deduplicate_findings(findings)
                
        except Exception as e:
            error_msg = f"静态分析失败: {e}"
            if self.config.debug:
                console.print(f"[dim][DEBUG] {error_msg}[/dim]")
            # 添加错误信息到结果中
            from src.core.engine import Finding, Location, Severity
            error_finding = Finding(
                rule_id="STATIC-ANALYSIS-ERROR",
                rule_name="静态分析失败",
                description=error_msg,
                severity=Severity.INFO,
                location=Location(
                    file=str(file_info.path),
                    line=1,
                    column=0
                ),
                confidence=0.5,
                message=error_msg,
                code_snippet="",
                fix_suggestion="请检查文件是否可读取",
                references=[],
                metadata={"error": str(e)}
            )
            findings.append(error_finding)
        
        return findings

    def _rule_analyze(self, file_info: FileInfo, ai_findings: List = None) -> List:
        """基于 RAG 知识库检索的漏洞检测

        仅用于 RAG 知识库检索和类似漏洞检测，减少纯 AI 扫描的 token 消耗

        Args:
            file_info: 文件信息
            ai_findings: AI分析结果，用于调整RAG检索策略

        Returns:
            发现的安全问题列表
        """
        # 纯AI模式下跳过RAG分析
        if self.config.pure_ai:
            return []
            
        findings = []
        
        try:
            # 读取文件内容
            with open(file_info.path, 'r', encoding='utf-8') as f:
                file_content = f.read()
            
            if self.config.debug:
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
                if language == 'python':
                    search_query = f"Python code: {file_content}"
                elif language == 'javascript':
                    search_query = f"JavaScript code: {file_content}"
                elif language == 'html':
                    search_query = f"HTML code: {file_content}"
            
            # 如果有AI分析结果，根据AI发现的漏洞类型调整搜索查询
            if ai_findings:
                # 提取AI发现的漏洞类型
                ai_vulnerability_types = []
                for ai_finding in ai_findings:
                    for vuln_type in ['sql_injection', 'command_injection', 'ssrf', 'xss', 'csrf', 
                                     'hardcoded_credentials', 'weak_crypto', 'insecure_random', 'sensitive_data_exposure']:
                        if vuln_type in ai_finding.rule_name.lower() or vuln_type in ai_finding.description.lower():
                            ai_vulnerability_types.append(vuln_type)
                            break
                
                # 如果有AI发现的漏洞类型，在搜索查询中添加这些类型
                if ai_vulnerability_types:
                    vuln_types_str = ', '.join(ai_vulnerability_types)
                    search_query = f"{search_query} 相关漏洞: {vuln_types_str}"
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 根据AI分析结果调整RAG搜索查询，添加漏洞类型: {vuln_types_str}[/dim]")
            
            # 搜索 RAG 知识库
            search_results = rag_kb.search_knowledge(search_query)
            
            if search_results:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] RAG 知识库检索发现 {len(search_results)} 个相关结果[/dim]")
                
                # 过滤低相关性结果
                relevant_results = [result for result in search_results if result.confidence >= 0.75]
                
                if relevant_results:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 过滤后保留 {len(relevant_results)} 个高相关性结果[/dim]")
                    
                    # 转换知识库结果为 Finding 对象
                    from src.core.engine import Finding, Location, Severity
                    
                    for knowledge in relevant_results:
                        # 提取严重级别
                        severity_str = None
                        for tag in knowledge.tags:
                            if tag in ['critical', 'high', 'medium', 'low', 'info']:
                                severity_str = tag
                                break
                        
                        if not severity_str:
                            # 根据置信度设置默认严重级别
                            if knowledge.confidence >= 0.9:
                                severity_str = 'high'
                            elif knowledge.confidence >= 0.8:
                                severity_str = 'medium'
                            else:
                                severity_str = 'low'
                        
                        # 检查知识内容是否与文件类型相关
                        is_relevant = True
                        if file_info.language:
                            language = file_info.language.value
                            # 简单的相关性检查
                            if language == 'python' and 'python' not in knowledge.content.lower():
                                # 对于Python文件，确保知识内容与Python相关
                                if not any(keyword in knowledge.content.lower() for keyword in ['python', 'pip', 'django', 'flask']):
                                    is_relevant = False
                            elif language == 'javascript' and 'javascript' not in knowledge.content.lower():
                                # 对于JavaScript文件，确保知识内容与JavaScript相关
                                if not any(keyword in knowledge.content.lower() for keyword in ['javascript', 'node', 'react', 'vue']):
                                    is_relevant = False
                        
                        # 如果有AI分析结果，检查知识内容是否与AI发现相关
                        if ai_findings and is_relevant:
                            is_relevant_to_ai = False
                            for ai_finding in ai_findings:
                                if any(keyword in knowledge.content.lower() for keyword in ai_finding.rule_name.lower().split()):
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
                                location=Location(
                                    file=str(file_info.path),
                                    line=1,
                                    column=0
                                ),
                                confidence=knowledge.confidence,
                                message=knowledge.content,
                                code_snippet=file_content[:200] + "..." if len(file_content) > 200 else file_content,
                                fix_suggestion="根据 RAG 知识库建议进行修复",
                                references=[],
                                metadata={
                                    "knowledge_id": knowledge.id,
                                    "knowledge_source": knowledge.source,
                                    "rag_knowledge": True
                                }
                            )
                            findings.append(finding)
            
            # 限制每个文件的RAG结果数量
            max_findings = 5
            if len(findings) > max_findings:
                # 按置信度排序，保留高置信度的结果
                findings.sort(key=lambda x: x.confidence, reverse=True)
                findings = findings[:max_findings]
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 限制RAG知识库结果数量为 {max_findings}[/dim]")
            
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] RAG 知识库检索分析失败: {e}[/dim]")
        
        return findings
    
    def _deduplicate_findings(self, findings: List) -> List:
        """去重发现的问题
        
        基于 (rule_id, file_path, line_number, code_snippet) 进行去重
        
        Args:
            findings: 发现的问题列表
            
        Returns:
            去重后的问题列表
        """
        seen = set()
        unique_findings = []
        
        for finding in findings:
            # 创建唯一键
            file_path = getattr(finding.location, 'file', '')
            line = getattr(finding.location, 'line', 0)
            rule_id = finding.rule_id
            code_snippet = finding.code_snippet[:50] if finding.code_snippet else ''  # 前50字符
            
            key = (rule_id, file_path, line, code_snippet)
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings

    def _merge_duplicate_findings(self, findings: List) -> List:
        """合并重复发现，相同规则ID和文件优先使用更高级别

        当多个发现在同一文件具有相同规则ID时，保留最严重级别的发现。
        对于已验证的发现（verified=True），不会被AI发现的同名低级别发现覆盖。
        不同文件的相同规则ID发现会分别保留。

        Args:
            findings: 发现的问题列表

        Returns:
            合并后的问题列表
        """
        seen = {}  # (rule_id, file_path) -> (finding, severity_level)

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

        def get_severity_level(severity):
            if hasattr(severity, 'value'):
                sev_str = severity.value.lower()
            elif hasattr(severity, 'name'):
                sev_str = severity.name.lower()
            else:
                sev_str = str(severity).lower()
            return severity_order.get(sev_str, 999)

        def get_metadata(finding) -> dict:
            metadata = getattr(finding, 'metadata', None)
            if metadata is None:
                return {}
            if isinstance(metadata, dict):
                return metadata
            return {}

        for finding in findings:
            rule_id = finding.rule_id
            file_path = getattr(finding.location, 'file', '') if hasattr(finding, 'location') else ''
            key = (rule_id, file_path)

            current_level = get_severity_level(finding.severity)
            metadata = get_metadata(finding)
            is_verified = metadata.get('verified', False)

            if key not in seen:
                seen[key] = (finding, current_level)
            else:
                existing_finding, existing_level = seen[key]
                existing_metadata = get_metadata(existing_finding)
                existing_verified = existing_metadata.get('verified', False)

                if is_verified and not existing_verified:
                    seen[key] = (finding, current_level)
                elif is_verified == existing_verified:
                    if current_level < existing_level:
                        seen[key] = (finding, current_level)

        return [f for f, _ in seen.values()]

    def _protect_verified_sources(self, findings: List) -> List:
        """保护已验证来源的发现不被覆盖

        config_scanner 和 code_vuln_scanner 的发现是已知的、可复现的安全风险。
        这些发现使用自己确定的严重级别，不应该被 AI 分析器的判定覆盖。

        Args:
            findings: 合并后的发现列表

        Returns:
            处理后的发现列表
        """
        verified_sources = {'config_scanner', 'code_vuln_scanner'}
        verified_findings = {}  # (rule_id, file_path) -> finding

        def get_metadata_source(finding) -> str:
            metadata = getattr(finding, 'metadata', None)
            if metadata is None:
                return ''
            if isinstance(metadata, dict):
                return metadata.get('source', '')
            return ''

        def get_metadata(finding) -> dict:
            metadata = getattr(finding, 'metadata', None)
            if metadata is None:
                return {}
            if isinstance(metadata, dict):
                return metadata
            return {}

        # 首先收集所有来自已验证来源的发现
        for f in findings:
            source = get_metadata_source(f)
            if source in verified_sources:
                key = (f.rule_id, getattr(f.location, 'file', '') if hasattr(f, 'location') else '')
                if key not in verified_findings:
                    verified_findings[key] = f

        # 如果有已验证来源的发现，用它们替换列表中相同 key 的发现
        if not verified_findings:
            return findings

        result = []
        for f in findings:
            source = get_metadata_source(f)
            key = (f.rule_id, getattr(f.location, 'file', '') if hasattr(f, 'location') else '')

            if key in verified_findings and source not in verified_sources:
                # 来自 AI 分析器的发现被已验证来源的发现替换
                result.append(verified_findings[key])
            else:
                result.append(f)

        return result

    def _convert_to_finding(self, issue) -> Optional:
        """将分析问题转换为标准 Finding 对象

        Args:
            issue: 分析问题对象

        Returns:
            标准 Finding 对象
        """
        try:
            from src.core.engine import Finding, Location, Severity
            
            # 转换严重级别
            severity_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
                'info': Severity.INFO
            }
            
            # 清理和规范化字段
            if hasattr(issue, 'severity'):
                severity_str = getattr(issue, 'severity', 'medium').lower()
            elif isinstance(issue, dict) and 'severity' in issue:
                severity_str = str(issue['severity']).lower()
            else:
                severity_str = 'medium'
            severity = severity_map.get(severity_str, Severity.MEDIUM)
            
            # 获取并清理描述
            if hasattr(issue, 'description'):
                description = getattr(issue, 'description', '').strip()
            elif isinstance(issue, dict) and 'description' in issue:
                description = str(issue['description']).strip()
            else:
                description = ''
            
            # 清理规则名称
            if hasattr(issue, 'rule_name'):
                rule_name = getattr(issue, 'rule_name', 'Unknown Issue').strip()
            elif isinstance(issue, dict) and 'rule_name' in issue:
                rule_name = str(issue['rule_name']).strip()
            else:
                # 根据 rule_id 生成规则名称
                if hasattr(issue, 'rule_id'):
                    rule_id = getattr(issue, 'rule_id', '').strip()
                elif isinstance(issue, dict) and 'rule_id' in issue:
                    rule_id = str(issue['rule_id']).strip()
                else:
                    rule_id = ''
                
                # 规则 ID 到规则名称的映射
                rule_name_map = {
                    'AST-DANGEROUS-FUNCTION': '危险函数调用',
                    'AST-SENSITIVE-PARAM': '敏感参数缺少类型注解',
                    'AST-MISSING-DOCSTRING': '函数缺少文档字符串',
                    'AST-MISSING-CLASS-DOCSTRING': '类缺少文档字符串',
                    'AST-WILDCARD-IMPORT': '通配符导入',
                    'AST-DANGEROUS-MODULE': '危险模块导入',
                    'AST-SENSITIVE-VARIABLE': '敏感变量定义',
                    'AST-HARDCODED-SECRET': '硬编码敏感信息',
                    'AST-CONSTANT-CONDITION': '常量条件',
                    'AST-INFINITE-LOOP': '可能的无限循环',
                    'AST-EMPTY-EXCEPT': '空的异常处理块',
                    'AST-GENERIC-EXCEPTION': '通用异常',
                    'AST-RETURN-SENSITIVE': '返回敏感信息',
                    'AST-SQL-INJECTION': 'SQL 注入风险',
                    'AST-XSS': 'XSS 风险',
                    'AST-COMMAND-INJECTION': '命令注入风险',
                    'AST-SENSITIVE-ATTRIBUTE': '类中存在敏感属性'
                }
                
                rule_name = rule_name_map.get(rule_id, '未知问题')
            
            # 清理代码片段
            if hasattr(issue, 'code_snippet'):
                code_snippet = getattr(issue, 'code_snippet', '').strip()
            elif isinstance(issue, dict) and 'code_snippet' in issue:
                code_snippet = str(issue['code_snippet']).strip()
            else:
                code_snippet = ''
            
            # 清理修复建议
            if hasattr(issue, 'fix_suggestion'):
                fix_suggestion = getattr(issue, 'fix_suggestion', '').strip()
            elif isinstance(issue, dict) and 'fix_suggestion' in issue:
                fix_suggestion = str(issue['fix_suggestion']).strip()
            else:
                fix_suggestion = ''
            
            # 创建位置对象
            if hasattr(issue, 'location'):
                location_dict = issue.location if isinstance(issue.location, dict) else {}
            elif isinstance(issue, dict) and 'location' in issue:
                location_dict = issue['location'] if isinstance(issue['location'], dict) else {}
            else:
                location_dict = {}
            
            # 获取文件路径
            if hasattr(issue, 'file_path'):
                file_path = getattr(issue, 'file_path', '')
            elif isinstance(issue, dict) and 'file_path' in issue:
                file_path = issue['file_path']
            elif 'file' in location_dict:
                file_path = location_dict['file']
            else:
                file_path = ''
            
            location = Location(
                file=file_path,
                line=location_dict.get('line', 0),
                column=location_dict.get('column', 0),
                end_line=location_dict.get('end_line', 0),
                end_column=location_dict.get('end_column', 0)
            )
            
            # 获取其他字段
            if hasattr(issue, 'rule_id'):
                rule_id = getattr(issue, 'rule_id', 'UNKNOWN')
            elif isinstance(issue, dict) and 'rule_id' in issue:
                rule_id = issue['rule_id']
            else:
                rule_id = 'UNKNOWN'
            
            if hasattr(issue, 'confidence'):
                confidence = getattr(issue, 'confidence', 0.5)
            elif isinstance(issue, dict) and 'confidence' in issue:
                confidence = issue['confidence']
            else:
                confidence = 0.5
            
            if hasattr(issue, 'references'):
                references = getattr(issue, 'references', [])
            elif isinstance(issue, dict) and 'references' in issue:
                references = issue['references']
            else:
                references = []
            
            # 处理 metadata 字段
            metadata = {}
            if hasattr(issue, 'metadata'):
                metadata = getattr(issue, 'metadata', {})
            elif isinstance(issue, dict) and 'metadata' in issue:
                metadata = issue['metadata']
            
            # 处理 exploit_status 字段
            if hasattr(issue, 'exploit_status'):
                metadata['exploit_status'] = getattr(issue, 'exploit_status', 'possible')
            elif isinstance(issue, dict) and 'exploit_status' in issue:
                metadata['exploit_status'] = issue['exploit_status']
            
            # 创建 Finding 对象
            finding = Finding(
                rule_id=rule_id,
                rule_name=rule_name,
                description=description,
                severity=severity,
                location=location,
                confidence=confidence,
                message=description,  # 使用清理后的描述作为消息
                code_snippet=code_snippet,
                fix_suggestion=fix_suggestion,
                references=references,
                metadata=metadata
            )
            
            return finding
        except Exception:
            return None

    def _semantic_analyze(self, file_info: FileInfo) -> List:
        """本地语义分析文件

        Args:
            file_info: 文件信息

        Returns:
            发现的安全问题列表
        """
        findings = []
        
        try:
            # 读取文件内容
            with open(file_info.path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            if self.config.debug:
                console.print(f"[dim][DEBUG] 执行本地语义分析: {file_info.path}[/dim]")
            
            # 执行本地语义分析
            semantic_result = self.local_analyzer.analyze(
                code=code_content,
                file_path=str(file_info.path)
            )
            
            # 如果检测到漏洞，转换为 Finding 对象
            if semantic_result.is_vulnerable:
                from src.core.engine import Finding, Location, Severity
                
                # 将 RiskLevel 转换为 Severity
                severity_map = {
                    'critical': Severity.CRITICAL,
                    'high': Severity.HIGH,
                    'medium': Severity.MEDIUM,
                    'low': Severity.LOW,
                    'info': Severity.INFO,
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
                    code_snippet=code_content[:200] + "..." if len(code_content) > 200 else code_content,
                    fix_suggestion="; ".join(semantic_result.recommendations[:3]),
                    references=[],
                )
                findings.append(finding)
                
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 语义分析发现漏洞: {semantic_result.reason}[/dim]")
                    console.print(f"[dim][DEBUG] 攻击链路: {' -> '.join(semantic_result.attack_chain)}[/dim]")
                
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 语义分析失败: {e}[/dim]")
        
        return findings
    
    def _library_analyze(self, file_info: FileInfo) -> List:
        """库匹配分析文件

        Args:
            file_info: 文件信息

        Returns:
            发现的安全问题列表
        """
        findings = []
        
        try:
            # 读取文件内容
            with open(file_info.path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            if self.config.debug:
                console.print(f"[dim][DEBUG] 执行库匹配分析: {file_info.path}[/dim]")
            
            # 检测代码中使用的库
            libraries = self.library_matcher.detect_libraries(
                code_content,
                file_info.language.value
            )
            
            if libraries:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 检测到 {len(libraries)} 个库[/dim]")
                
                # 匹配库漏洞
                vulnerabilities = self.library_matcher.match_vulnerabilities(libraries)
                
                if vulnerabilities:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 发现 {len(vulnerabilities)} 个库漏洞[/dim]")
                    
                    # 转换为 Finding 对象
                    from src.core.engine import Finding, Location, Severity
                    
                    for vuln in vulnerabilities:
                        cvss_score = vuln.metadata.get('cvss_score', 0)
                        kev_exploited = vuln.metadata.get('kev_exploited', False)
                        exploit_count = vuln.metadata.get('exploit_count', 0)
                        poc_stars = vuln.metadata.get('poc_stars', 0)

                        severity_map = {
                            'critical': Severity.CRITICAL,
                            'high': Severity.HIGH,
                            'medium': Severity.MEDIUM,
                            'low': Severity.LOW,
                            'info': Severity.INFO
                        }
                        severity = severity_map.get(vuln.severity, Severity.MEDIUM)

                        nvd_info = ""
                        if cvss_score > 0:
                            nvd_info = f"CVSS: {cvss_score}"
                        if kev_exploited:
                            nvd_info += " | KEV: 是"
                        if exploit_count > 0:
                            nvd_info += f" | Exploit: {exploit_count}"
                        if poc_stars > 0:
                            nvd_info += f" | PoC Stars: {poc_stars}"

                        finding = Finding(
                            rule_id=f"NVD-{vuln.cve_id}",
                            rule_name=f"库漏洞: {vuln.library_name} ({vuln.cve_id})",
                            description=vuln.description,
                            severity=severity,
                            location=Location(
                                file=str(file_info.path),
                                line=1,
                                column=0
                            ),
                            confidence=min(1.0, (cvss_score or 0) / 10.0 + 0.3),
                            message=f"{vuln.library_name} 库存在漏洞 {vuln.cve_id}，受影响版本: {', '.join(vuln.affected_versions) if vuln.affected_versions else '未知'} | {nvd_info}",
                            code_snippet=code_content[:200] + "..." if len(code_content) > 200 else code_content,
                            fix_suggestion=f"升级到版本 {vuln.fix_version}" if vuln.fix_version else "请查看官方安全公告",
                            references=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve_id}"]
                        )
                        findings.append(finding)
        
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 库匹配分析失败: {e}[/dim]")

        return findings

    async def _dependency_cve_scan(self, prioritized_files: List) -> List:
        """依赖声明文件库版本CVE匹配扫描

        对pom.xml, build.gradle, package.json等依赖声明文件进行：
        1. 提取依赖库和版本
        2. 通过NVD数据库匹配已知CVE漏洞

        Args:
            prioritized_files: 优先级排序后的文件列表

        Returns:
            发现的安全问题列表
        """
        findings = []

        DEPENDENCY_FILES = {
            'pom.xml', 'build.gradle', 'build.gradle.kts',
            'package.json', 'requirements.txt', 'Pipfile', 'Pipfile.lock',
            'Gemfile', 'Gemfile.lock', 'go.mod', 'go.sum',
            'Cargo.toml', 'composer.json', 'package-lock.json',
            'yarn.lock', 'pnpm-lock.yaml'
        }

        DEPENDENCY_EXTENSIONS = {
            '.yml', '.yaml', '.properties', '.xml'
        }

        dependency_files = []
        for file_info, _, _ in prioritized_files:
            file_name = Path(file_info.path).name
            file_ext = Path(file_info.path).suffix.lower()

            if file_name in DEPENDENCY_FILES or file_ext in DEPENDENCY_EXTENSIONS:
                dependency_files.append(file_info)

        if not dependency_files:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 未发现依赖声明文件，跳过库CVE匹配[/dim]")
            return findings

        if self.config.debug:
            console.print(f"[dim][DEBUG] 发现 {len(dependency_files)} 个依赖声明文件[/dim]")

        try:
            from src.scanner.library_matcher import get_library_matcher
            library_matcher = get_library_matcher()

            if not library_matcher._nvd_available:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] NVD数据库不可用，跳过库CVE匹配[/dim]")
                return findings

            for file_info in dependency_files:
                try:
                    with open(file_info.path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    file_name = Path(file_info.path).name.lower()

                    language = 'java'
                    if file_name == 'package.json' or file_name == 'package-lock.json' or file_name == 'yarn.lock' or file_name == 'pnpm-lock.yaml':
                        language = 'javascript'
                    elif file_name in ('requirements.txt', 'Pipfile', 'Pipfile.lock'):
                        language = 'python'
                    elif file_name in ('Gemfile', 'Gemfile.lock', 'composer.json'):
                        language = 'ruby' if file_name.startswith('Gemfile') else 'php'
                    elif file_name in ('go.mod', 'go.sum'):
                        language = 'go'
                    elif file_name == 'Cargo.toml':
                        language = 'rust'

                    libraries = library_matcher.detect_libraries(content, language)

                    if libraries:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] {file_name} 检测到 {len(libraries)} 个依赖库[/dim]")

                        vulnerabilities = library_matcher.match_vulnerabilities(libraries)

                        if vulnerabilities:
                            from src.core.engine import Finding, Location, Severity

                            for vuln in vulnerabilities:
                                cvss_score = vuln.metadata.get('cvss_score', 0)
                                kev_exploited = vuln.metadata.get('kev_exploited', False)
                                exploit_count = vuln.metadata.get('exploit_count', 0)
                                poc_stars = vuln.metadata.get('poc_stars', 0)

                                severity_map = {
                                    'CRITICAL': Severity.CRITICAL,
                                    'HIGH': Severity.HIGH,
                                    'MEDIUM': Severity.MEDIUM,
                                    'LOW': Severity.LOW,
                                }
                                severity = severity_map.get(vuln.severity.upper(), Severity.MEDIUM)

                                nvd_info = f"CVSS: {cvss_score}" if cvss_score > 0 else ""
                                if kev_exploited:
                                    nvd_info += " | KEV: 已遭利用"
                                if exploit_count > 0:
                                    nvd_info += f" | Exploit: {exploit_count}"
                                if poc_stars > 0:
                                    nvd_info += f" | PoC: {poc_stars}★"

                                affected_versions_str = ', '.join(vuln.affected_versions[:5]) if vuln.affected_versions else '未知'
                                if len(vuln.affected_versions) > 5:
                                    affected_versions_str += f" 等{len(vuln.affected_versions)}个版本"

                                finding = Finding(
                                    rule_id=f"NVD-{vuln.cve_id}",
                                    rule_name=f"{vuln.library_name} 存在已知漏洞",
                                    description=f"{vuln.library_name} 版本 {vuln.affected_versions[0] if vuln.affected_versions else '未知'} 存在CVE漏洞",
                                    severity=severity,
                                    location=Location(
                                        file=str(file_info.path),
                                        line=1,
                                        column=0
                                    ),
                                    confidence=min(1.0, (cvss_score or 0) / 10.0 + 0.3),
                                    message=f"{vuln.library_name} 存在 {vuln.cve_id}，受影响版本: {affected_versions_str} | {nvd_info}",
                                    code_snippet=f"检测到库: {vuln.library_name}",
                                    fix_suggestion=f"升级到安全版本: {vuln.fix_version}" if vuln.fix_version else "请查看官方安全公告并升级",
                                    references=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve_id}"],
                                    metadata={
                                        'source': 'nvd_library_matcher',
                                        'cve_id': vuln.cve_id,
                                        'library_name': vuln.library_name,
                                        'affected_versions': vuln.affected_versions,
                                        'fix_version': vuln.fix_version,
                                        'verified': True,
                                        'cvss_score': cvss_score,
                                        'kev_exploited': kev_exploited,
                                        'exploit_count': exploit_count,
                                        'poc_stars': poc_stars
                                    }
                                )
                                findings.append(finding)

                            console.print(f"[yellow]! Found {len(vulnerabilities)} dependency vulnerabilities in {file_name} (CVSS>=5.0)[/yellow]")

                except Exception as e:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 分析依赖文件 {file_info.path} 失败: {e}[/dim]")

        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 库CVE匹配扫描失败: {e}[/dim]")

        return findings

    async def _web_search_analyze(self, file_info: FileInfo, library_findings: List) -> List:
        """网络搜索分析

        Args:
            file_info: 文件信息
            library_findings: 库匹配分析结果

        Returns:
            发现的安全问题列表
        """
        findings = []
        
        try:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 执行网络搜索分析: {file_info.path}[/dim]")
            
            # 读取文件内容
            with open(file_info.path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            # 分析文件内容，提取可能的漏洞类型
            potential_vulnerabilities = self._extract_potential_vulnerabilities(code_content, file_info)
            
            # 对每个潜在漏洞类型进行网络搜索
            for vulnerability_type in potential_vulnerabilities:
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 搜索漏洞信息: {vulnerability_type}[/dim]")
                
                search_results = await search_vulnerability_info(vulnerability_type)
                
                if search_results:
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 网络搜索发现 {len(search_results)} 个相关结果[/dim]")
                    
                    # 过滤低相关性结果
                    relevant_results = [result for result in search_results if result.relevance >= 0.7]
                    
                    if relevant_results:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] 过滤后保留 {len(relevant_results)} 个高相关性结果[/dim]")
                        
                        # 转换搜索结果为 Finding 对象
                        from src.core.engine import Finding, Location, Severity
                        
                        for result in relevant_results:
                            # 根据相关性调整严重级别
                            if result.relevance >= 0.9:
                                severity = Severity.HIGH
                            elif result.relevance >= 0.8:
                                severity = Severity.MEDIUM
                            else:
                                severity = Severity.LOW
                            
                            finding = Finding(
                                rule_id=f"WEB-SEARCH-{vulnerability_type[:10].upper()}",
                                rule_name=f"网络搜索: {vulnerability_type}",
                                description=f"网络搜索发现相关安全信息: {result.title}",
                                severity=severity,
                                location=Location(
                                    file=str(file_info.path),
                                    line=1,
                                    column=0
                                ),
                                confidence=result.relevance,
                                message=result.snippet,
                                code_snippet=code_content[:200] + "..." if len(code_content) > 200 else code_content,
                                fix_suggestion=f"参考: {result.url}",
                                references=[result.url],
                                metadata={
                                    "search_query": vulnerability_type,
                                    "search_title": result.title,
                                    "search_url": result.url,
                                    "search_relevance": result.relevance
                                }
                            )
                            findings.append(finding)
            
            # 对库漏洞进行网络搜索
            for library_finding in library_findings:
                if "LIBRARY-VULN" in library_finding.rule_id:
                    library_name = library_finding.rule_name.split(': ')[1].split(' (')[0]
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] 搜索库漏洞信息: {library_name}[/dim]")
                    
                    search_results = await search_library_info(library_name)
                    
                    if search_results:
                        if self.config.debug:
                            console.print(f"[dim][DEBUG] 网络搜索发现 {len(search_results)} 个库漏洞相关结果[/dim]")
                        
                        # 过滤低相关性结果
                        relevant_results = [result for result in search_results if result.relevance >= 0.7]
                        
                        if relevant_results:
                            if self.config.debug:
                                console.print(f"[dim][DEBUG] 过滤后保留 {len(relevant_results)} 个高相关性结果[/dim]")
                            
                            # 转换搜索结果为 Finding 对象
                            from src.core.engine import Finding, Location, Severity
                            
                            for result in relevant_results:
                                # 根据相关性调整严重级别
                                if result.relevance >= 0.9:
                                    severity = Severity.HIGH
                                elif result.relevance >= 0.8:
                                    severity = Severity.MEDIUM
                                else:
                                    severity = Severity.LOW
                                
                                finding = Finding(
                                    rule_id=f"WEB-SEARCH-LIBRARY-{library_name[:10].upper()}",
                                    rule_name=f"网络搜索: {library_name} 漏洞",
                                    description=f"网络搜索发现库安全信息: {result.title}",
                                    severity=severity,
                                    location=library_finding.location,
                                    confidence=result.relevance,
                                    message=result.snippet,
                                    code_snippet=library_finding.code_snippet,
                                    fix_suggestion=f"参考: {result.url}",
                                    references=[result.url],
                                    metadata={
                                        "library_name": library_name,
                                        "search_title": result.title,
                                        "search_url": result.url,
                                        "search_relevance": result.relevance
                                    }
                                )
                                findings.append(finding)
            
            # 去重网络搜索结果
            unique_findings = []
            seen = set()
            for finding in findings:
                # 基于漏洞类型和URL去重
                key = (finding.rule_name, finding.references[0] if finding.references else "")
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(finding)
            findings = unique_findings
            
            # 限制每个文件的网络搜索结果数量
            max_findings = 5  # 减少最大结果数量，避免过多重复
            if len(findings) > max_findings:
                # 按置信度排序，保留高置信度的结果
                findings.sort(key=lambda x: x.confidence, reverse=True)
                findings = findings[:max_findings]
                if self.config.debug:
                    console.print(f"[dim][DEBUG] 限制网络搜索结果数量为 {max_findings}[/dim]")
            
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 网络搜索分析失败: {e}[/dim]")
        
        return findings
    
    def _extract_potential_vulnerabilities(self, code: str, file_info: Optional[FileInfo] = None) -> List[str]:
        """从代码中提取潜在的漏洞类型

        Args:
            code: 代码内容
            file_info: 文件信息，用于根据文件类型过滤漏洞类型

        Returns:
            潜在漏洞类型列表
        """
        potential_vulnerabilities = []
        
        # 基于文件类型的漏洞类型映射
        file_type_vulnerabilities = {
            'python': ['command_injection', 'hardcoded_credentials', 'insecure_random', 'weak_crypto'],
            'javascript': ['xss', 'csrf', 'command_injection', 'hardcoded_credentials'],
            'html': ['xss', 'csrf'],
            'css': [],
            'json': ['hardcoded_credentials'],
            'markdown': [],
            'txt': []
        }
        
        # 基础漏洞类型模式
        vulnerability_patterns = {
            'sql_injection': ['sql', 'query', 'execute', 'cursor', 'dbapi', 'psycopg2', 'sqlite3'],
            'xss': ['html', 'render', 'template', 'escape', 'innerHTML', 'outerHTML', 'document.write'],
            'command_injection': ['subprocess', 'os.system', 'exec', 'eval', 'popen', 'spawn', 'shell'],
            'hardcoded_credentials': ['password', 'api_key', 'secret', 'token', 'key', 'auth', 'credential'],
            'insecure_random': ['random', 'randint', 'randrange', 'rand', 'choice'],
            'weak_crypto': ['md5', 'sha1', 'des', 'rc4', '3des', 'md4'],
            'sensitive_data_exposure': ['personal', 'credit card', 'ssn', 'pii', 'private', 'confidential'],
            'csrf': ['csrf', 'token', 'session', 'anti-forgery', 'xsrf'],
            'ssrf': ['request', 'url', 'fetch', 'get', 'post', 'http', 'https', 'curl']
        }
        
        # 根据文件类型过滤漏洞类型
        allowed_vulnerabilities = []
        if file_info and file_info.language:
            language = file_info.language.value.lower()
            allowed_vulnerabilities = file_type_vulnerabilities.get(language, list(vulnerability_patterns.keys()))
        else:
            # 对于未知类型的文件，只检查基本的漏洞类型，避免误报
            allowed_vulnerabilities = ['hardcoded_credentials']
        
        code_lower = code.lower()
        
        # 计算代码长度，用于过滤小型文件
        code_length = len(code)
        
        for vuln_type, keywords in vulnerability_patterns.items():
            # 检查是否在允许的漏洞类型列表中
            if vuln_type not in allowed_vulnerabilities:
                continue
            
            # 增加关键词匹配阈值，减少误报
            match_count = 0
            for keyword in keywords:
                if keyword in code_lower:
                    match_count += 1
            
            # 根据漏洞类型设置不同的匹配阈值
            if vuln_type == 'command_injection':
                # command_injection 需要至少2个关键词匹配，因为其关键词如 'exec'、'eval' 太常见
                if match_count >= 2:
                    potential_vulnerabilities.append(vuln_type)
            elif vuln_type == 'hardcoded_credentials':
                # hardcoded_credentials 需要至少2个关键词匹配
                if match_count >= 2:
                    potential_vulnerabilities.append(vuln_type)
            elif code_length < 100:
                # 小型文件需要至少2个关键词匹配
                if match_count >= 2:
                    potential_vulnerabilities.append(vuln_type)
            else:
                # 正常文件需要至少1个关键词匹配
                if match_count >= 1:
                    potential_vulnerabilities.append(vuln_type)
        
        # 去重
        return list(set(potential_vulnerabilities))

    async def _ai_analyze(self, file_info: FileInfo) -> List:
        """AI 分析文件

        Args:
            file_info: 文件信息

        Returns:
            发现的安全问题列表
        """
        findings = []
        
        try:
            if self.config.debug:
                console.print(f"[dim][DEBUG] 开始执行完整 AI 分析: {file_info.path}[/dim]")
            
            # 读取文件内容
            with open(file_info.path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            # 创建分析上下文
            context = AnalysisContext(
                file_path=str(file_info.path),
                code_content=code_content,
                language=file_info.language.value,
                analysis_level=AnalysisLevel.FILE
            )
            
            if self.config.debug:
                console.print(f"[dim][DEBUG] 调用 AI 分析器...[/dim]")
            
            # 执行 AI 分析
            ai_result = await self.ai_analyzer.analyze(context)
            
            if self.config.debug:
                console.print(f"[dim][DEBUG] AI 分析完成，发现 {len(ai_result.findings)} 个问题[/dim]")
            
            # 转换 AI 结果为标准格式
            for finding in ai_result.findings:
                converted = self._convert_to_finding(finding)
                if converted:
                    findings.append(converted)
                    if self.config.debug:
                        console.print(f"[dim][DEBUG] AI 发现: {converted.rule_name}[/dim]")
                
        except Exception as e:
            if self.config.debug:
                console.print(f"[dim][DEBUG] AI 分析失败: {e}[/dim]")
        
        return findings
    
    def _prioritize_findings(self, findings: List, files: List[FileInfo]) -> List:
        """评估漏洞优先级

        Args:
            findings: 发现的漏洞列表
            files: 文件信息列表

        Returns:
            按优先级排序的漏洞列表
        """
        # 创建文件路径到文件信息的映射
        file_info_map = {file_info.path: file_info for file_info in files}
        
        # 漏洞类型优先级映射
        vulnerability_priority = {
            'sql_injection': 5,
            'command_injection': 5,
            'ssrf': 4,
            'xss': 3,
            'csrf': 3,
            'hardcoded_credentials': 4,
            'weak_crypto': 4,
            'insecure_random': 3,
            'sensitive_data_exposure': 4
        }
        
        # 文件类型优先级映射
        file_type_priority = {
            'python': 3,
            'javascript': 3,
            'html': 2,
            'css': 1,
            'json': 2,
            'markdown': 0,
            'txt': 0
        }
        
        # 计算每个漏洞的优先级分数
        prioritized_findings = []
        for finding in findings:
            # 基础分数
            score = 0
            
            # 基于严重级别
            severity_score = {
                'CRITICAL': 10,
                'HIGH': 8,
                'MEDIUM': 5,
                'LOW': 3,
                'INFO': 1
            }
            # 处理 severity 可能是字符串或枚举对象的情况
            if hasattr(finding.severity, 'name'):
                severity_key = finding.severity.name
            else:
                severity_key = str(finding.severity).upper()
            score += severity_score.get(severity_key, 3)
            
            # 基于置信度
            score += finding.confidence * 2
            
            # 基于漏洞类型
            for vuln_type, vuln_score in vulnerability_priority.items():
                if vuln_type in finding.rule_name.lower() or vuln_type in finding.description.lower():
                    score += vuln_score
                    break
            
            # 基于文件类型
            file_path = finding.location.file
            if file_path in file_info_map:
                file_info = file_info_map[file_path]
                if file_info.language:
                    file_type = file_info.language.value
                    score += file_type_priority.get(file_type, 2)
            
            # 基于分析类型
            if 'AI' in finding.rule_id:
                score += 2  # AI 分析结果优先级更高
            elif 'RAG' in finding.rule_id:
                score += 1  # RAG 结果优先级次之
            
            # 存储分数
            finding.metadata['priority_score'] = score
            prioritized_findings.append(finding)
        
        # 按优先级分数排序，降序
        prioritized_findings.sort(key=lambda x: x.metadata.get('priority_score', 0), reverse=True)
        
        return prioritized_findings
    
    def _filter_web_findings_by_ai(self, web_findings: List, ai_findings: List) -> List:
        """利用AI分析结果过滤网络搜索结果

        Args:
            web_findings: 网络搜索结果
            ai_findings: AI分析结果

        Returns:
            过滤后的网络搜索结果
        """
        if not ai_findings:
            return web_findings
        
        # 提取AI发现的漏洞类型
        ai_vulnerability_types = set()
        for ai_finding in ai_findings:
            # 从AI分析结果中提取漏洞类型
            for vuln_type in ['sql_injection', 'command_injection', 'ssrf', 'xss', 'csrf', 
                             'hardcoded_credentials', 'weak_crypto', 'insecure_random', 'sensitive_data_exposure']:
                if vuln_type in ai_finding.rule_name.lower() or vuln_type in ai_finding.description.lower():
                    ai_vulnerability_types.add(vuln_type)
        
        # 过滤网络搜索结果
        filtered_findings = []
        for web_finding in web_findings:
            # 检查网络搜索结果是否与AI发现的漏洞类型相关
            is_relevant = False
            for vuln_type in ai_vulnerability_types:
                if vuln_type in web_finding.rule_name.lower() or vuln_type in web_finding.description.lower():
                    is_relevant = True
                    # 提高与AI发现相关的网络搜索结果的置信度
                    web_finding.confidence = min(1.0, web_finding.confidence + 0.1)
                    break
            
            # 如果没有AI发现的漏洞类型，保留高置信度的网络搜索结果
            if is_relevant or web_finding.confidence >= 0.8:
                filtered_findings.append(web_finding)
        
        return filtered_findings


def create_scanner(config: Config) -> SecurityScanner:
    """创建安全扫描器

    Args:
        config: 扫描配置

    Returns:
        安全扫描器实例
    """
    return SecurityScanner(config)
