"""安全扫描器模块

提供核心的安全扫描功能，集成文件发现、代码分析和 AI 分析。
"""

import asyncio
from pathlib import Path
from typing import List, Optional, Union

from src.core.config import Config
from src.core.engine import ScanEngine, ScanResult, BaseScanner
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
        self.priority_evaluator = get_ai_priority_evaluator()  # 优先级评估器
        self.web_searcher = get_web_searcher()  # 网络搜索器
        
        # 初始化规则注册表（仅用于知识库检索，不加载硬编码规则）
        from src.rules.registry import get_registry
        self.rule_registry = get_registry()
        
        if config.ai.enabled:
            self.ai_analyzer = AIAnalyzer(config)
            self.attack_chain_builder = get_ai_attack_chain_builder()
        
        if config.debug:
            print(f"[DEBUG] 安全扫描器初始化完成，规则注册表已就绪（仅用于知识库检索）")
            print(f"[DEBUG] 本地语义分析器已启用")
            if config.ai.enabled:
                print(f"[DEBUG] 攻击链路分析器已启用")

    async def scan(self, target: Union[str, Path]) -> ScanResult:
        """执行异步扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
        """
        if self.config.debug:
            print(f"[DEBUG] 开始扫描目标: {target}")
        
        # 发现文件
        files = self._discover_files(target)
        
        if self.config.debug:
            print(f"[DEBUG] 发现 {len(files)} 个文件")
        
        # 分析文件
        findings = await self._analyze_files(files)
        
        if self.config.debug:
            print(f"[DEBUG] 发现 {len(findings)} 个安全问题")
        
        # 创建结果对象
        from src.core.engine import ScanStatus
        result = ScanResult(
            target=str(target),
            status=ScanStatus.COMPLETED
        )
        
        # 汇总结果
        for finding in findings:
            result.add_finding(finding)
        
        if self.config.debug:
            print(f"[DEBUG] 扫描完成，总计发现 {len(result.findings)} 个问题")
        
        # 执行攻击链路分析（如果启用了AI）
        if self.config.ai.enabled and hasattr(self, 'attack_chain_builder') and result.findings:
            if self.config.debug:
                print(f"[DEBUG] 开始执行攻击链路分析")
            
            try:
                # 转换ScanResult为SecurityAnalysisResult
                ai_findings = []
                for finding in result.findings:
                    # 创建VulnerabilityFinding对象
                    vuln_finding = VulnerabilityFinding(
                        rule_id=finding.rule_id,
                        rule_name=finding.rule_name,
                        description=finding.description,
                        severity=finding.severity.name.lower(),
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
                    print(f"[DEBUG] 攻击链路分析完成，识别出 {len(attack_chain_result.paths)} 条攻击路径")
                    print(f"[DEBUG] 总体风险评分: {attack_chain_result.risk_score:.2f}")
            except Exception as e:
                if self.config.debug:
                    print(f"[DEBUG] 攻击链路分析失败: {e}")
        
        # 执行漏洞优先级评估（如果启用了AI）
        if self.config.ai.enabled and hasattr(self, 'priority_evaluator') and result.findings:
            if self.config.debug:
                print(f"[DEBUG] 开始执行漏洞优先级评估")
            
            try:
                # 转换ScanResult为SecurityAnalysisResult
                ai_findings = []
                for finding in result.findings:
                    # 创建VulnerabilityFinding对象
                    vuln_finding = VulnerabilityFinding(
                        rule_id=finding.rule_id,
                        rule_name=finding.rule_name,
                        description=finding.description,
                        severity=finding.severity.name.lower(),
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
                    print(f"[DEBUG] 优先级评估完成")
                    print(f"[DEBUG] {priority_result.summary}")
            except Exception as e:
                if self.config.debug:
                    print(f"[DEBUG] 优先级评估失败: {e}")
        
        # 集成自学习机制
        if self.config.ai.enabled:
            try:
                from src.storage.rag_knowledge_base import get_rag_knowledge_base
                from src.learning.self_learning import Knowledge, KnowledgeType
                from datetime import datetime
                import hashlib
                
                # 获取 RAG 知识库实例
                rag_kb = get_rag_knowledge_base()
                
                # 转换扫描结果为 RAG 知识库所需格式
                learning_results = []
                for finding in result.findings:
                    # 创建知识内容
                    content = f"{finding.rule_name}: {finding.description}\n\n严重级别: {finding.severity.value}\n置信度: {finding.confidence}\n\n修复建议: {finding.fix_suggestion}"
                    
                    learning_results.append({
                        "content": content,
                        "knowledge_type": "ai_learning",
                        "source": "auto_learning",
                        "confidence": finding.confidence,
                        "tags": [finding.severity.value, finding.rule_name],
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
                    print(f"[DEBUG] 自学习完成，已更新 RAG 知识库")
                    
            except Exception as e:
                if self.config.debug:
                    print(f"[DEBUG] 自学习集成失败: {e}")
        
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

    async def _analyze_files(self, files: List[FileInfo]) -> List:
        """分析文件

        Args:
            files: 文件信息列表

        Returns:
            发现的安全问题列表
        """
        findings = []
        
        # 评估文件优先级
        prioritized_files = []
        for file_info in files:
            score, priority = self.file_prioritizer.evaluate_file_priority(Path(file_info.path))
            prioritized_files.append((file_info, score, priority))
        
        # 按优先级排序
        prioritized_files.sort(key=lambda x: x[1], reverse=True)
        
        if self.config.debug:
            print(f"[DEBUG] 文件优先级评估完成，总计 {len(prioritized_files)} 个文件")
            high_count = sum(1 for _, _, p in prioritized_files if p == 'high')
            medium_count = sum(1 for _, _, p in prioritized_files if p == 'medium')
            low_count = sum(1 for _, _, p in prioritized_files if p == 'low')
            print(f"[DEBUG] 高优先级: {high_count}, 中优先级: {medium_count}, 低优先级: {low_count}")
        
        for file_info, score, priority in prioritized_files:
            if self.config.debug:
                print(f"[DEBUG] 分析文件: {file_info.path} (优先级: {priority}, 分数: {score:.2f})")
            
            # 静态分析
            static_findings = self._static_analyze(file_info)
            findings.extend(static_findings)
            
            # 规则分析
            rule_findings = self._rule_analyze(file_info)
            findings.extend(rule_findings)
            
            # 本地语义分析（始终启用，轻量级）
            semantic_findings = self._semantic_analyze(file_info)
            findings.extend(semantic_findings)
            
            # 库匹配分析
            library_findings = self._library_analyze(file_info)
            findings.extend(library_findings)
            
            # 网络搜索分析
            web_findings = await self._web_search_analyze(file_info, library_findings)
            findings.extend(web_findings)
            
            # AI 分析（如果启用 --ai 参数，对所有文件进行分析）
            if self.ai_analyzer and self.config.ai.enabled:
                ai_findings = await self._ai_analyze(file_info)
                findings.extend(ai_findings)
            
            if self.config.debug:
                ai_findings_count = len(ai_findings) if (self.ai_analyzer and self.config.ai.enabled) else 0
                total_findings = len(static_findings) + len(rule_findings) + len(semantic_findings) + len(library_findings) + len(web_findings) + ai_findings_count
                print(f"[DEBUG] 文件分析完成，发现 {total_findings} 个问题")
        
        return findings

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
            
            # 使用 AST 分析器
            try:
                if self.config.debug:
                    print(f"[DEBUG] 使用 AST 分析器分析: {file_info.path}")
                
                ast_result = self.ast_analyzer.analyze(context)
                
                if ast_result.issues:
                    if self.config.debug:
                        print(f"[DEBUG] AST 分析发现 {len(ast_result.issues)} 个问题")
                    
                    for issue in ast_result.issues:
                        converted = self._convert_to_finding(issue)
                        if converted:
                            findings.append(converted)
                
            except Exception as e:
                if self.config.debug:
                    print(f"[DEBUG] AST 分析失败: {e}")
            
            # 使用 CST 分析器（仅 Python）
            if file_info.language.value == 'python':
                try:
                    if self.config.debug:
                        print(f"[DEBUG] 使用 CST 分析器分析: {file_info.path}")
                    
                    cst_result = self.cst_analyzer.analyze(context)
                    
                    if cst_result.issues:
                        if self.config.debug:
                            print(f"[DEBUG] CST 分析发现 {len(cst_result.issues)} 个问题")
                        
                        for issue in cst_result.issues:
                            converted = self._convert_to_finding(issue)
                            if converted:
                                findings.append(converted)
                
                except Exception as e:
                    if self.config.debug:
                        print(f"[DEBUG] CST 分析失败: {e}")
            
            # 去重静态分析结果
            findings = self._deduplicate_findings(findings)
                
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] 静态分析失败: {e}")
        
        return findings

    def _rule_analyze(self, file_info: FileInfo) -> List:
        """基于 RAG 知识库检索的漏洞检测

        仅用于 RAG 知识库检索和类似漏洞检测，减少纯 AI 扫描的 token 消耗

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
            
            if self.config.debug:
                print(f"[DEBUG] 执行 RAG 知识库检索分析: {file_info.path}")
            
            # 导入 RAG 知识库
            from src.storage.rag_knowledge_base import get_rag_knowledge_base
            
            # 获取 RAG 知识库实例
            rag_kb = get_rag_knowledge_base()
            
            # 搜索 RAG 知识库
            search_results = rag_kb.search_knowledge(file_content)
            
            if search_results:
                if self.config.debug:
                    print(f"[DEBUG] RAG 知识库检索发现 {len(search_results)} 个相关结果")
                
                # 转换知识库结果为 Finding 对象
                from src.core.engine import Finding, Location, Severity
                
                for knowledge in search_results:
                    # 检查置信度
                    if knowledge.confidence >= 0.7:
                        # 提取严重级别
                        severity_str = None
                        for tag in knowledge.tags:
                            if tag in ['critical', 'high', 'medium', 'low', 'info']:
                                severity_str = tag
                                break
                        
                        if not severity_str:
                            severity_str = 'medium'
                        
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
            
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] RAG 知识库检索分析失败: {e}")
        
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
                rule_name = 'Unknown Issue'
            
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
                references=references
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
                print(f"[DEBUG] 执行本地语义分析: {file_info.path}")
            
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
                    print(f"[DEBUG] 语义分析发现漏洞: {semantic_result.reason}")
                    print(f"[DEBUG] 攻击链路: {' -> '.join(semantic_result.attack_chain)}")
                
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] 语义分析失败: {e}")
        
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
                print(f"[DEBUG] 执行库匹配分析: {file_info.path}")
            
            # 检测代码中使用的库
            libraries = self.library_matcher.detect_libraries(
                code_content,
                file_info.language.value
            )
            
            if libraries:
                if self.config.debug:
                    print(f"[DEBUG] 检测到 {len(libraries)} 个库")
                
                # 匹配库漏洞
                vulnerabilities = self.library_matcher.match_vulnerabilities(libraries)
                
                if vulnerabilities:
                    if self.config.debug:
                        print(f"[DEBUG] 发现 {len(vulnerabilities)} 个库漏洞")
                    
                    # 转换为 Finding 对象
                    from src.core.engine import Finding, Location, Severity
                    
                    for vuln in vulnerabilities:
                        # 转换严重级别
                        severity_map = {
                            'critical': Severity.CRITICAL,
                            'high': Severity.HIGH,
                            'medium': Severity.MEDIUM,
                            'low': Severity.LOW,
                            'info': Severity.INFO
                        }
                        severity = severity_map.get(vuln.severity, Severity.MEDIUM)
                        
                        # 创建 Finding 对象
                        finding = Finding(
                            rule_id=f"LIBRARY-VULN-{vuln.cve_id}",
                            rule_name=f"库漏洞: {vuln.library_name} ({vuln.cve_id})",
                            description=vuln.description,
                            severity=severity,
                            location=Location(
                                file=str(file_info.path),
                                line=1,
                                column=0
                            ),
                            confidence=0.9,
                            message=f"{vuln.library_name} 库存在漏洞 {vuln.cve_id}，受影响版本: {', '.join(vuln.affected_versions)}",
                            code_snippet=code_content[:200] + "..." if len(code_content) > 200 else code_content,
                            fix_suggestion=f"升级到版本 {vuln.fix_version}" if vuln.fix_version else "请查看官方安全公告",
                            references=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve_id}"]
                        )
                        findings.append(finding)
        
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] 库匹配分析失败: {e}")
        
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
                print(f"[DEBUG] 执行网络搜索分析: {file_info.path}")
            
            # 读取文件内容
            with open(file_info.path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            # 分析文件内容，提取可能的漏洞类型
            potential_vulnerabilities = self._extract_potential_vulnerabilities(code_content)
            
            # 对每个潜在漏洞类型进行网络搜索
            for vulnerability_type in potential_vulnerabilities:
                if self.config.debug:
                    print(f"[DEBUG] 搜索漏洞信息: {vulnerability_type}")
                
                search_results = await search_vulnerability_info(vulnerability_type)
                
                if search_results:
                    if self.config.debug:
                        print(f"[DEBUG] 网络搜索发现 {len(search_results)} 个相关结果")
                    
                    # 转换搜索结果为 Finding 对象
                    from src.core.engine import Finding, Location, Severity
                    
                    for result in search_results:
                        finding = Finding(
                            rule_id=f"WEB-SEARCH-{vulnerability_type[:10].upper()}",
                            rule_name=f"网络搜索: {vulnerability_type}",
                            description=f"网络搜索发现相关安全信息: {result.title}",
                            severity=Severity.MEDIUM,
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
                        print(f"[DEBUG] 搜索库漏洞信息: {library_name}")
                    
                    search_results = await search_library_info(library_name)
                    
                    if search_results:
                        if self.config.debug:
                            print(f"[DEBUG] 网络搜索发现 {len(search_results)} 个库漏洞相关结果")
                        
                        # 转换搜索结果为 Finding 对象
                        from src.core.engine import Finding, Location, Severity
                        
                        for result in search_results:
                            finding = Finding(
                                rule_id=f"WEB-SEARCH-LIBRARY-{library_name[:10].upper()}",
                                rule_name=f"网络搜索: {library_name} 漏洞",
                                description=f"网络搜索发现库安全信息: {result.title}",
                                severity=Severity.MEDIUM,
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
            
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] 网络搜索分析失败: {e}")
        
        return findings
    
    def _extract_potential_vulnerabilities(self, code: str) -> List[str]:
        """从代码中提取潜在的漏洞类型

        Args:
            code: 代码内容

        Returns:
            潜在漏洞类型列表
        """
        potential_vulnerabilities = []
        
        # 简单的关键词匹配
        vulnerability_patterns = {
            'sql_injection': ['sql', 'query', 'execute', 'cursor'],
            'xss': ['html', 'render', 'template', 'escape'],
            'command_injection': ['subprocess', 'os.system', 'exec', 'eval'],
            'hardcoded_credentials': ['password', 'api_key', 'secret', 'token'],
            'insecure_random': ['random', 'randint', 'randrange'],
            'weak_crypto': ['md5', 'sha1', 'des', 'rc4'],
            'sensitive_data_exposure': ['personal', 'credit card', 'ssn', 'pii'],
            'csrf': ['csrf', 'token', 'session'],
            'ssrf': ['request', 'url', 'fetch', 'get']
        }
        
        code_lower = code.lower()
        
        for vuln_type, keywords in vulnerability_patterns.items():
            for keyword in keywords:
                if keyword in code_lower:
                    potential_vulnerabilities.append(vuln_type)
                    break
        
        return potential_vulnerabilities

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
                print(f"[DEBUG] 开始执行完整 AI 分析: {file_info.path}")
            
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
                print(f"[DEBUG] 调用 AI 分析器...")
            
            # 执行 AI 分析
            ai_result = await self.ai_analyzer.analyze(context)
            
            if self.config.debug:
                print(f"[DEBUG] AI 分析完成，发现 {len(ai_result.findings)} 个问题")
            
            # 转换 AI 结果为标准格式
            for finding in ai_result.findings:
                converted = self._convert_to_finding(finding)
                if converted:
                    findings.append(converted)
                    if self.config.debug:
                        print(f"[DEBUG] AI 发现: {converted.rule_name}")
                
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] AI 分析失败: {e}")
        
        return findings


def create_scanner(config: Config) -> SecurityScanner:
    """创建安全扫描器

    Args:
        config: 扫描配置

    Returns:
        安全扫描器实例
    """
    return SecurityScanner(config)
