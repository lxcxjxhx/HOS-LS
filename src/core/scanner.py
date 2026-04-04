"""安全扫描器模块

提供核心的安全扫描功能，集成文件发现、代码分析和 AI 分析。
"""

import asyncio
from pathlib import Path
from typing import List, Optional, Union

from src.core.config import Config
from src.core.engine import ScanEngine, ScanResult, BaseScanner
from src.utils.file_discovery import FileDiscoveryEngine, FileInfo
from src.ai.analyzer import AIAnalyzer
from src.ai.models import AnalysisContext, AnalysisLevel, SecurityAnalysisResult, VulnerabilityFinding
from src.ai.local_semantic_analyzer import get_local_analyzer
from src.ai.priority_evaluator import get_ai_priority_evaluator
from src.attack.chain_analyzer import get_ai_attack_chain_builder
from src.analyzers.ast_analyzer import ASTAnalyzer
from src.analyzers.cst_analyzer import CSTAnalyzer
from src.scanner.library_matcher import get_library_matcher


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
        self.ast_analyzer = ASTAnalyzer()
        self.cst_analyzer = CSTAnalyzer()
        self.ai_analyzer = None
        self.local_analyzer = get_local_analyzer()  # 本地语义分析器
        self.library_matcher = get_library_matcher()  # 库匹配器
        self.priority_evaluator = get_ai_priority_evaluator()  # 优先级评估器
        
        # 加载规则
        from src.rules.registry import get_registry
        self.rule_registry = get_registry()
        self.rule_registry.load_builtin_rules()
        
        if config.ai.enabled:
            self.ai_analyzer = AIAnalyzer(config)
            self.attack_chain_builder = get_ai_attack_chain_builder()
        
        if config.debug:
            print(f"[DEBUG] 安全扫描器初始化完成，加载了 {len(self.rule_registry.list_rules())} 个规则")
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
        
        for file_info in files:
            if self.config.debug:
                print(f"[DEBUG] 分析文件: {file_info.path}")
            
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
            
            # AI 分析（如果启用 --ai 参数）
            if self.ai_analyzer and self.config.ai.enabled:
                ai_findings = await self._ai_analyze(file_info)
                findings.extend(ai_findings)
            
            if self.config.debug:
                total_findings = len(static_findings) + len(rule_findings) + len(semantic_findings) + len(library_findings)
                if self.ai_analyzer and self.config.ai.enabled:
                    total_findings += len(ai_findings)
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
        """使用规则注册表中的规则分析文件

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
            
            # 获取适用于当前语言的规则
            rules = self.rule_registry.get_rules_by_language(file_info.language.value)
            
            if self.config.debug:
                print(f"[DEBUG] 应用 {len(rules)} 个规则到文件")
            
            # 应用规则
            for rule in rules:
                if rule.is_enabled():
                    try:
                        # 构建目标对象，包含内容和文件路径
                        target = {
                            'content': file_content,
                            'file_path': str(file_info.path)
                        }
                        rule_findings = rule.check(target)
                        for finding in rule_findings:
                            converted = self._convert_to_finding(finding)
                            if converted:
                                findings.append(converted)
                    except Exception as e:
                        if self.config.debug:
                            print(f"[DEBUG] 规则 {rule.id} 执行失败: {e}")
            
            # 去重：基于 (rule_id, line, code_snippet) 去重
            findings = self._deduplicate_findings(findings)
            
            if self.config.debug:
                print(f"[DEBUG] 去重后发现问题数: {len(findings)}")
                
        except Exception as e:
            if self.config.debug:
                print(f"[DEBUG] 规则分析失败: {e}")
        
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
            severity_str = getattr(issue, 'severity', 'medium').lower()
            severity = severity_map.get(severity_str, Severity.MEDIUM)
            
            # 获取并清理描述
            description = getattr(issue, 'description', '').strip()
            # 清理规则名称
            rule_name = getattr(issue, 'rule_name', 'Unknown Issue').strip()
            # 清理代码片段
            code_snippet = getattr(issue, 'code_snippet', '').strip()
            # 清理修复建议
            fix_suggestion = getattr(issue, 'fix_suggestion', '').strip()
            
            # 创建位置对象
            location = Location(
                file=getattr(issue, 'file_path', str(issue.location.get('file', ''))),
                line=getattr(issue, 'line', issue.location.get('line', 0)),
                column=getattr(issue, 'column', issue.location.get('column', 0)),
                end_line=getattr(issue, 'end_line', issue.location.get('end_line', 0)),
                end_column=getattr(issue, 'end_column', issue.location.get('end_column', 0))
            )
            
            # 创建 Finding 对象
            finding = Finding(
                rule_id=getattr(issue, 'rule_id', 'UNKNOWN'),
                rule_name=rule_name,
                description=description,
                severity=severity,
                location=location,
                confidence=getattr(issue, 'confidence', 0.5),
                message=description,  # 使用清理后的描述作为消息
                code_snippet=code_snippet,
                fix_suggestion=fix_suggestion,
                references=getattr(issue, 'references', [])
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
