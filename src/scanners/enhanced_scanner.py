#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
核心安全检测模块 - 增强版 (优化版)

功能：
1. 正则表达式检测 (预编译优化)
2. AST 抽象语法树分析
3. 上下文感知检测
4. 误报过滤机制
5. 置信度评分
6. 行号和代码片段提取
7. 并行扫描支持
8. 智能文件过滤 (.gitignore)
9. 缓存机制
"""

import os
import re
import json
import logging
import time
from typing import List, Dict, Any, Optional, Tuple, Set
from colorama import Fore, Style

# 延迟导入，避免循环导入
CoreIntegration = None
LLMResponse = None
EmbeddingResult = None
SelfLearningEngine = None
AttackRecord = None
VulnerabilityAssessor = None
VulnerabilityAssessment = None
ASTScanner = None
ParallelSecurityScanner = None
ScanConfig = None
AttackSurfaceAnalyzer = None
AttackPlanner = None
DynamicExecutor = None
HttpRequest = None
APICrawler = None
APIEndpoint = None
AISecurityDetector = None
AISecurityIssue = None

# 延迟导入函数
def _lazy_import():
    global CoreIntegration, LLMResponse, EmbeddingResult, SelfLearningEngine, AttackRecord, VulnerabilityAssessor, VulnerabilityAssessment
    global ASTScanner, ParallelSecurityScanner, ScanConfig, AttackSurfaceAnalyzer, AttackPlanner, DynamicExecutor, HttpRequest, APICrawler, APIEndpoint, AISecurityDetector, AISecurityIssue
    global MultiModelCoordinator, VulnerabilityChainAnalyzer, SQLInjectionAgent, XSSAgent, CommandInjectionAgent, SandboxAnalyzer
    
    from core import CoreIntegration, LLMResponse, EmbeddingResult, SelfLearningEngine, AttackRecord, VulnerabilityAssessor, VulnerabilityAssessment
    from scanners.ai_security_detector import AISecurityDetector, AISecurityIssue
    from scanners.api_crawler import APICrawler, APIEndpoint
    from scanners.ast_scanner import ASTScanner
    from scanners.attack_planner import AttackPlanner
    from scanners.attack_surface_analyzer import AttackSurfaceAnalyzer
    from scanners.dynamic_executor import DynamicExecutor, HttpRequest
    from scanners.parallel_scanner import ParallelSecurityScanner, ScanConfig
    from scanners.sandbox_analyzer import SandboxAnalyzer
    from utils.advanced_features import MultiModelCoordinator, VulnerabilityChainAnalyzer, SQLInjectionAgent, XSSAgent, CommandInjectionAgent

logger = logging.getLogger(__name__)

# 导出模块
__all__ = ['EnhancedSecurityScanner']


class EnhancedSecurityScanner:
    """增强型安全扫描器 (优化版)"""
    
    def __init__(self, target: str, rules_file: str = None, silent: bool = False, 
                 use_parallel: bool = True, max_workers: int = 4, use_smart_scan: bool = True):
        """初始化扫描器
        
        Args:
            target: 要扫描的目标路径
            rules_file: 规则文件路径（可选）
            silent: 是否启用静默模式
            use_parallel: 是否使用并行扫描
            max_workers: 最大工作进程数
            use_smart_scan: 是否使用智能扫描模式
        """
        # 执行延迟导入
        _lazy_import()
        
        self.target = target
        self.silent = silent
        self.rules_file = rules_file
        self.use_parallel = use_parallel
        self.max_workers = max_workers
        self.use_smart_scan = use_smart_scan
        
        # 使用规则管理器
        from rules import RuleManager
        self.rule_manager = RuleManager(rules_file)
        self.rules = self.rule_manager.rules
        self.false_positive_filters = self.rule_manager.false_positive_filters
        self.compiled_rules = self.rule_manager.compiled_rules
        
        self.results = {
            "target": target,
            "code_security": [],
            "injection_security": [],
            "ai_security": [],
            "container_security": [],
            "cloud_security": [],
            "privacy_security": [],
            "permission_security": [],
            "network_security": [],
            "dependency_security": [],
            "config_security": [],
            "supply_chain_security": [],
            "compliance_governance": []
        }
        self.high_risk = 0
        self.medium_risk = 0
        self.low_risk = 0
        self.files_to_scan = []
        self.file_priority_engine = None
        self.file_priorities = {}
        
        # 初始化文件优先级引擎
        if self.use_smart_scan:
            try:
                from core import FilePriorityEngine
                self.file_priority_engine = FilePriorityEngine(self.target)
            except Exception as e:
                logger.warning(f"初始化文件优先级引擎失败：{e}")
                self.use_smart_scan = False
        
        # 初始化测试用例生成器
        self.test_case_generator = None
        try:
            from core import TestCaseGenerator
            self.test_case_generator = TestCaseGenerator()
        except Exception as e:
            logger.warning(f"初始化测试用例生成器失败：{e}")
        
        # 初始化风险评估引擎
        self.risk_assessment_engine = None
        try:
            from core import RiskAssessmentEngine
            self.risk_assessment_engine = RiskAssessmentEngine()
        except Exception as e:
            logger.warning(f"初始化风险评估引擎失败：{e}")
        
        self.ast_scanner = ASTScanner() if ASTScanner else None
        self.attack_surface_analyzer = AttackSurfaceAnalyzer() if AttackSurfaceAnalyzer else None
        self.attack_planner = AttackPlanner() if AttackPlanner else None
        self.dynamic_executor = DynamicExecutor() if DynamicExecutor else None
        self.vulnerability_assessor = VulnerabilityAssessor() if VulnerabilityAssessor else None
        self.api_crawler = APICrawler(self.target) if APICrawler and self.target.startswith(('http://', 'https://')) else None
        self.self_learning_engine = SelfLearningEngine() if SelfLearningEngine else None
        self.ai_security_detector = AISecurityDetector() if AISecurityDetector else None
        self.core_integration = CoreIntegration() if CoreIntegration else None
        self.multi_model_coordinator = MultiModelCoordinator() if MultiModelCoordinator else None
        self.vulnerability_chain_analyzer = VulnerabilityChainAnalyzer() if VulnerabilityChainAnalyzer else None
        self.sql_injection_agent = SQLInjectionAgent('SQLInjectionAgent') if SQLInjectionAgent else None
        self.xss_agent = XSSAgent('XSSAgent') if XSSAgent else None
        self.command_injection_agent = CommandInjectionAgent('CommandInjectionAgent') if CommandInjectionAgent else None
        self.sandbox_analyzer = SandboxAnalyzer() if SandboxAnalyzer else None
        self.stats = {
            'total_files': 0,
            'scanned_files': 0,
            'scan_time': 0.0,
            'method': 'parallel' if use_parallel else 'sequential',
            'smart_scan': self.use_smart_scan
        }
        
        # 模块健康状态
        self.module_health = {
            'ast_scanner': {'available': self.ast_scanner is not None, 'status': 'ok', 'errors': 0},
            'attack_surface_analyzer': {'available': self.attack_surface_analyzer is not None, 'status': 'ok', 'errors': 0},
            'attack_planner': {'available': self.attack_planner is not None, 'status': 'ok', 'errors': 0},
            'dynamic_executor': {'available': self.dynamic_executor is not None, 'status': 'ok', 'errors': 0},
            'vulnerability_assessor': {'available': self.vulnerability_assessor is not None, 'status': 'ok', 'errors': 0},
            'api_crawler': {'available': self.api_crawler is not None, 'status': 'ok', 'errors': 0},
            'self_learning_engine': {'available': self.self_learning_engine is not None, 'status': 'ok', 'errors': 0},
            'ai_security_detector': {'available': self.ai_security_detector is not None, 'status': 'ok', 'errors': 0},
            'core_integration': {'available': self.core_integration is not None, 'status': 'ok', 'errors': 0},
            'multi_model_coordinator': {'available': self.multi_model_coordinator is not None, 'status': 'ok', 'errors': 0},
            'vulnerability_chain_analyzer': {'available': self.vulnerability_chain_analyzer is not None, 'status': 'ok', 'errors': 0},
            'sql_injection_agent': {'available': self.sql_injection_agent is not None, 'status': 'ok', 'errors': 0},
            'xss_agent': {'available': self.xss_agent is not None, 'status': 'ok', 'errors': 0},
            'command_injection_agent': {'available': self.command_injection_agent is not None, 'status': 'ok', 'errors': 0},
            'sandbox_analyzer': {'available': self.sandbox_analyzer is not None, 'status': 'ok', 'errors': 0},
            'file_priority_engine': {'available': self.file_priority_engine is not None, 'status': 'ok', 'errors': 0},
            'test_case_generator': {'available': self.test_case_generator is not None, 'status': 'ok', 'errors': 0},
            'risk_assessment_engine': {'available': self.risk_assessment_engine is not None, 'status': 'ok', 'errors': 0}
        }
    

    
    def scan(self) -> Dict[str, Any]:
        """执行完整扫描"""
        start_time = time.time()
        
        if not self.silent:
            print(f'{Fore.BLUE}开始增强安全扫描...{Style.RESET_ALL}')
            print(f'{Fore.CYAN}扫描模式：{"并行" if self.use_parallel else "串行"}{Style.RESET_ALL}')
        
        # 当目标是URL时，使用串行扫描（API爬虫）
        if self.target.startswith(('http://', 'https://')):
            if not self.silent:
                print(f'{Fore.CYAN}目标是URL，使用串行扫描...{Style.RESET_ALL}')
            return self._sequential_scan()
        
        # 使用并行扫描器 (如果可用且启用)
        if self.use_parallel and ParallelSecurityScanner:
            try:
                return self._parallel_scan()
            except Exception as e:
                logger.warning(f"并行扫描失败，回退到串行扫描：{e}")
                return self._sequential_scan()
        else:
            return self._sequential_scan()
    
    def _parallel_scan(self) -> Dict[str, Any]:
        """使用并行扫描器"""
        if not self.silent:
            print(f'{Fore.CYAN}使用并行扫描器 (工作进程：{self.max_workers})...{Style.RESET_ALL}')
        
        config = ScanConfig(
            target=self.target,
            max_workers=self.max_workers,
            use_gitignore=True,
            use_cache=True
        )
        
        scanner = ParallelSecurityScanner(config)
        results = scanner.scan()
        summary = scanner.get_summary()
        
        self.results = results
        self.high_risk = summary['high_risk']
        self.medium_risk = summary['medium_risk']
        self.low_risk = summary['low_risk']
        self.stats = {
            'total_files': summary.get('total_files', 0),
            'scanned_files': summary.get('scanned_files', 0),
            'scan_time': summary.get('scan_time', 0.0),
            'method': 'parallel'
        }
        
        if not self.silent:
            print(f'{Fore.GREEN}扫描完成!{Style.RESET_ALL}')
            print(f'{Fore.RED}高风险：{self.high_risk}{Style.RESET_ALL}')
            print(f'{Fore.YELLOW}中风险：{self.medium_risk}{Style.RESET_ALL}')
            print(f'{Fore.GREEN}低风险：{self.low_risk}{Style.RESET_ALL}')
            print(f'{Fore.CYAN}扫描耗时：{self.stats["scan_time"]:.2f}秒{Style.RESET_ALL}')
        
        return self.results
    
    def _sequential_scan(self) -> Dict[str, Any]:
        """串行扫描 (向后兼容)"""
        start_time = time.time()
        
        if not self.silent:
            print(f'{Fore.CYAN}使用串行扫描器...{Style.RESET_ALL}')
        
        # 1. API爬虫（如果目标是URL）
        if self.api_crawler:
            self._crawl_api_endpoints()
        
        # 2. 初始化文件列表
        if not self.files_to_scan:
            self._initialize_files_to_scan()
        
        # 3. 根据文件优先级执行不同扫描策略
        if self.use_smart_scan and self.file_priorities:
            self._scan_with_priority_strategy()
        else:
            # 传统扫描策略
            # 2. AST 分析（如果可用）
            if self.ast_scanner:
                self._scan_with_ast()
            
            # 3. 攻击面分析（如果可用）
            if self.attack_surface_analyzer:
                self._scan_with_attack_surface()
            
            # 4. 攻击策略生成（如果可用）
            if self.attack_planner:
                self._generate_attack_strategy()
            
            # 5. 动态执行攻击（如果可用）
            if self.dynamic_executor and 'attack_strategies' in self.results:
                self._execute_attacks()
            
            # 5. 正则检测 (使用预编译规则)
            self._scan_with_regex()
            
            # 3. 上下文分析
            self._analyze_context()
            
            # 4. 误报过滤
            self._filter_false_positives()
            
            # 5. 计算置信度
            self._calculate_confidence()
            
            # 6. 核心技术集成（如果可用）
            if self.core_integration and os.environ.get('DISABLE_CORE_INTEGRATION') != 'true':
                self._integrate_core_technologies()
            
            # 7. AI安全检测（如果可用）
            if self.ai_security_detector and os.environ.get('DISABLE_AI_ANALYSIS') != 'true':
                self._detect_ai_security_issues()
            
            # 8. 自学习（如果可用）
            if self.self_learning_engine:
                self._perform_self_learning()
            
            # 9. 多模型协同攻击（如果可用）
            if self.multi_model_coordinator:
                self._coordinate_multi_model_attack()
            
            # 10. 漏洞链分析（如果可用）
            if self.vulnerability_chain_analyzer:
                self._analyze_vulnerability_chain()
            
            # 11. 攻击代理执行（如果可用）
            if self.sql_injection_agent or self.xss_agent or self.command_injection_agent:
                self._execute_attack_agents()
            
            # 12. 沙盒分析（如果可用）
            if self.sandbox_analyzer:
                self._perform_sandbox_analysis()
            
            # 13. 权限安全扫描
            self._scan_permission_security()
        
        # 执行风险评估
        if self.risk_assessment_engine:
            if not self.silent:
                print(f'{Fore.CYAN}执行风险评估...{Style.RESET_ALL}')
            
            # 收集传统规则检测到的问题
            traditional_issues = []
            for category, issues in self.results.items():
                if isinstance(issues, list):
                    traditional_issues.extend(issues)
            
            # 收集 AI 语义分析结果
            ai_analysis = self.results.get('ai_analysis', {})
            
            # 执行风险评估
            assessment = self.risk_assessment_engine.assess_risk(traditional_issues, ai_analysis)
            
            # 生成风险评估报告
            risk_report = self.risk_assessment_engine.generate_risk_report(
                assessment,
                os.path.join(os.path.dirname(self.target), 'hos_ls_risk_report.json')
            )
            
            # 将风险评估结果添加到扫描结果中
            self.results['risk_assessment'] = assessment
            self.results['risk_report'] = risk_report
            
            if not self.silent:
                print(f'{Fore.GREEN}风险评估完成!{Style.RESET_ALL}')
                print(f'{Fore.CYAN}混合风险评分：{assessment.get("hybrid_score", 0):.2f}{Style.RESET_ALL}')
                print(f'{Fore.CYAN}风险等级：{assessment.get("risk_level", "None")}{Style.RESET_ALL}')
        
        self.stats['scan_time'] = time.time() - start_time
        
        if not self.silent:
            print(f'{Fore.GREEN}扫描完成!{Style.RESET_ALL}')
            print(f'{Fore.RED}高风险：{self.high_risk}{Style.RESET_ALL}')
            print(f'{Fore.YELLOW}中风险：{self.medium_risk}{Style.RESET_ALL}')
            print(f'{Fore.GREEN}低风险：{self.low_risk}{Style.RESET_ALL}')
        
        return self.results
    
    def _scan_with_priority_strategy(self):
        """根据文件优先级执行不同扫描策略"""
        if not self.silent:
            print(f'{Fore.CYAN}使用智能优先级扫描策略...{Style.RESET_ALL}')
        
        # 按优先级分组文件
        high_priority_files = []
        medium_priority_files = []
        low_priority_files = []
        
        for file_path, score in self.file_priorities.items():
            if score >= 90:
                high_priority_files.append(file_path)
            elif score >= 60:
                medium_priority_files.append(file_path)
            else:
                low_priority_files.append(file_path)
        
        if not self.silent:
            print(f'{Fore.CYAN}高优先级文件: {len(high_priority_files)}{Style.RESET_ALL}')
            print(f'{Fore.CYAN}中优先级文件: {len(medium_priority_files)}{Style.RESET_ALL}')
            print(f'{Fore.CYAN}低优先级文件: {len(low_priority_files)}{Style.RESET_ALL}')
        
        # 1. 高优先级文件：深度扫描
        if high_priority_files:
            if not self.silent:
                print(f'{Fore.CYAN}深度扫描高优先级文件...{Style.RESET_ALL}')
            
            # 保存原始文件列表
            original_files = self.files_to_scan
            
            # 设置为高优先级文件
            self.files_to_scan = high_priority_files
            
            # 执行深度扫描
            if self.ast_scanner:
                self._scan_with_ast()
            if self.attack_surface_analyzer:
                self._scan_with_attack_surface()
            if self.attack_planner:
                self._generate_attack_strategy()
            if self.dynamic_executor and 'attack_strategies' in self.results:
                self._execute_attacks()
            self._scan_with_regex()
            self._analyze_context()
            self._filter_false_positives()
            self._calculate_confidence()
            if self.core_integration and os.environ.get('DISABLE_CORE_INTEGRATION') != 'true':
                self._integrate_core_technologies()
            if self.ai_security_detector and os.environ.get('DISABLE_AI_ANALYSIS') != 'true':
                self._detect_ai_security_issues()
            if self.multi_model_coordinator:
                self._coordinate_multi_model_attack()
            if self.vulnerability_chain_analyzer:
                self._analyze_vulnerability_chain()
            if self.sql_injection_agent or self.xss_agent or self.command_injection_agent:
                self._execute_attack_agents()
            if self.sandbox_analyzer:
                self._perform_sandbox_analysis()
            
            # 生成测试用例（仅对高优先级文件）
            if self.test_case_generator:
                if not self.silent:
                    print(f'{Fore.CYAN}为高优先级文件生成测试用例...{Style.RESET_ALL}')
                
                # 创建测试输出目录
                test_output_dir = os.path.join(os.path.dirname(self.target), 'hos_ls_tests')
                os.makedirs(test_output_dir, exist_ok=True)
                
                # 生成测试用例
                self.test_case_generator.generate_tests_for_files(
                    high_priority_files,
                    test_output_dir
                )
            
            # 恢复原始文件列表
            self.files_to_scan = original_files
        
        # 2. 中优先级文件：标准扫描
        if medium_priority_files:
            if not self.silent:
                print(f'{Fore.CYAN}标准扫描中优先级文件...{Style.RESET_ALL}')
            
            # 保存原始文件列表
            original_files = self.files_to_scan
            
            # 设置为中优先级文件
            self.files_to_scan = medium_priority_files
            
            # 执行标准扫描
            if self.ast_scanner:
                self._scan_with_ast()
            self._scan_with_regex()
            self._analyze_context()
            self._filter_false_positives()
            self._calculate_confidence()
            if self.ai_security_detector and os.environ.get('DISABLE_AI_ANALYSIS') != 'true':
                self._detect_ai_security_issues()
            
            # 恢复原始文件列表
            self.files_to_scan = original_files
        
        # 3. 低优先级文件：快速扫描
        if low_priority_files:
            if not self.silent:
                print(f'{Fore.CYAN}快速扫描低优先级文件...{Style.RESET_ALL}')
            
            # 保存原始文件列表
            original_files = self.files_to_scan
            
            # 设置为低优先级文件
            self.files_to_scan = low_priority_files
            
            # 执行快速扫描
            self._scan_with_regex()
            
            # 恢复原始文件列表
            self.files_to_scan = original_files
        
        # 4. 执行自学习和权限安全扫描
        if self.self_learning_engine:
            self._perform_self_learning()
        self._scan_permission_security()
    
    def _scan_with_ast(self):
        """使用 AST 分析扫描"""
        if not self.silent:
            print(f'{Fore.CYAN}AST 分析...{Style.RESET_ALL}')
        
        try:
            ast_results = self.ast_scanner.analyze(self.target)
            
            # 更新 AST 扫描器统计信息
            if hasattr(self.ast_scanner, 'stats'):
                stats = self.ast_scanner.stats
                if not self.silent:
                    print(f'{Fore.CYAN}  AST 扫描统计：扫描 {stats["files_scanned"]} 个文件，'
                          f'跳过 {stats["files_skipped"]} 个，解析错误 {stats["parse_errors"]} 个，'
                          f'发现问题 {stats["issues_found"]} 个{Style.RESET_ALL}')
                
                # 更新健康状态
                if stats['parse_errors'] > 10:
                    self.module_health['ast_scanner']['status'] = 'degraded'
                    self.module_health['ast_scanner']['errors'] = stats['parse_errors']
            
            for issue in ast_results:
                category = 'code_security'
                self.results[category].append({
                    'file': issue['file'],
                    'line_number': issue['line_number'],
                    'issue': issue['issue'],
                    'severity': issue['severity'].lower(),
                    'details': issue['details'],
                    'code_snippet': issue['code_snippet'],
                    'detection_method': 'ast',
                    'confidence': 0.9,
                    'category': category
                })
                
                if issue['severity'] == 'HIGH':
                    self.high_risk += 1
                elif issue['severity'] == 'MEDIUM':
                    self.medium_risk += 1
                else:
                    self.low_risk += 1
            
            self.module_health['ast_scanner']['status'] = 'ok'
        except Exception as e:
            logger.error(f"AST 扫描失败：{e}")
            self.module_health['ast_scanner']['status'] = 'error'
            self.module_health['ast_scanner']['errors'] += 1
    
    def _scan_with_attack_surface(self):
        """使用攻击面分析扫描"""
        if not self.silent:
            print(f'{Fore.CYAN}攻击面分析...{Style.RESET_ALL}')
        
        try:
            attack_surface_result = self.attack_surface_analyzer.analyze(self.target)
            
            # 添加攻击面分析结果到扫描结果
            self.results['attack_surface'] = attack_surface_result
            
            # 处理高风险的 Prompt 注入点
            for injection_point in attack_surface_result.get('prompt_injection_points', []):
                self.results['ai_security'].append({
                    'file': injection_point['file'],
                    'line_number': injection_point['line_number'],
                    'issue': 'Prompt 注入点',
                    'severity': 'high',
                    'details': f"发现 Prompt 注入点: {injection_point['prompt_content']}",
                    'code_snippet': injection_point['prompt_content'],
                    'detection_method': 'attack_surface',
                    'confidence': 0.85,
                    'category': 'ai_security'
                })
                self.high_risk += 1
            
            # 处理 Tool 调用
            for tool_call in attack_surface_result.get('tool_calls', []):
                self.results['ai_security'].append({
                    'file': tool_call['file'],
                    'line_number': tool_call['line_number'],
                    'issue': f"Tool 调用: {tool_call['tool_name']}",
                    'severity': 'medium',
                    'details': f"发现 Tool 调用: {tool_call['tool_name']}",
                    'code_snippet': f"tool.call('{tool_call['tool_name']}')",
                    'detection_method': 'attack_surface',
                    'confidence': 0.75,
                    'category': 'ai_security'
                })
                self.medium_risk += 1
            
            # 处理 API 依赖
            for api_endpoint in attack_surface_result.get('api_dependencies', {}).get('apis', []):
                self.results['network_security'].append({
                    'file': 'API 依赖',
                    'line_number': 0,
                    'issue': f'API 调用: {api_endpoint}',
                    'severity': 'medium',
                    'details': f"发现 API 调用: {api_endpoint}",
                    'code_snippet': api_endpoint,
                    'detection_method': 'attack_surface',
                    'confidence': 0.7,
                    'category': 'network_security'
                })
                self.medium_risk += 1
                
        except Exception as e:
            logger.error(f"攻击面分析失败：{e}")
    
    def _generate_attack_strategy(self):
        """生成攻击策略"""
        if not self.silent:
            print(f'{Fore.CYAN}攻击策略生成...{Style.RESET_ALL}')
        
        try:
            # 收集目标信息
            target_info = {
                'target': self.target,
                'attack_surface': self.results.get('attack_surface', {}),
                'vulnerabilities': []
            }
            
            # 收集已发现的漏洞
            for category, issues in self.results.items():
                if isinstance(issues, list):
                    for issue in issues:
                        target_info['vulnerabilities'].append({
                            'type': issue.get('issue', 'unknown'),
                            'severity': issue.get('severity', 'medium'),
                            'file': issue.get('file', 'unknown')
                        })
            
            # 生成三种模式的攻击策略
            strategies = {
                'template': self.attack_planner.generate_strategy(target_info, 'template'),
                'llm': self.attack_planner.generate_strategy(target_info, 'llm'),
                'agent': self.attack_planner.generate_strategy(target_info, 'agent')
            }
            
            # 添加攻击策略到扫描结果
            self.results['attack_strategies'] = strategies
            
            # 分析目标代码，生成更具体的攻击建议
            if os.path.isfile(self.target):
                with open(self.target, 'r', encoding='utf-8', errors='ignore') as f:
                    code_content = f.read()
                target_analysis = self.attack_planner.analyze_target(code_content)
                self.results['target_analysis'] = target_analysis
            elif os.path.isdir(self.target):
                # 分析目录中的关键文件
                for root, dirs, files in os.walk(self.target):
                    for file in files:
                        if file.endswith(('.py', '.js', '.ts')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    code_content = f.read()
                                if len(code_content) > 1000:
                                    target_analysis = self.attack_planner.analyze_target(code_content[:1000])
                                    if target_analysis['vulnerabilities']:
                                        if 'target_analysis' not in self.results:
                                            self.results['target_analysis'] = target_analysis
                                        else:
                                            self.results['target_analysis']['vulnerabilities'].extend(target_analysis['vulnerabilities'])
                            except Exception:
                                pass
            
        except Exception as e:
            logger.error(f"攻击策略生成失败：{e}")
    
    def _crawl_api_endpoints(self):
        """爬取API端点"""
        if not self.silent:
            print(f'{Fore.CYAN}爬取API端点...{Style.RESET_ALL}')
        
        try:
            # 执行API爬虫
            endpoints = self.api_crawler.crawl()
            analyzed_endpoints = self.api_crawler.analyze_api_endpoints()
            
            # 存储API端点信息
            api_info = {
                'endpoints': [],
                'summary': {
                    'total_endpoints': len(analyzed_endpoints),
                    'high_risk': sum(1 for ep in analyzed_endpoints if ep.risk_level == 'high'),
                    'medium_risk': sum(1 for ep in analyzed_endpoints if ep.risk_level == 'medium'),
                    'low_risk': sum(1 for ep in analyzed_endpoints if ep.risk_level == 'low')
                }
            }
            
            # 转换API端点为字典格式
            for endpoint in analyzed_endpoints:
                api_info['endpoints'].append({
                    'url': endpoint.url,
                    'method': endpoint.method,
                    'params': endpoint.params,
                    'headers': endpoint.headers,
                    'body': endpoint.body,
                    'description': endpoint.description,
                    'risk_level': endpoint.risk_level
                })
            
            # 添加到扫描结果
            self.results['api_endpoints'] = api_info
            
            # 为高风险API端点生成安全建议
            for endpoint in analyzed_endpoints:
                if endpoint.risk_level in ['high', 'medium']:
                    # 添加到扫描结果中
                    self.results['network_security'].append({
                        'file': 'api_analysis',
                        'line_number': 0,
                        'issue': f'API endpoint with {endpoint.risk_level} risk',
                        'severity': endpoint.risk_level,
                        'details': f'API endpoint: {endpoint.url} - {endpoint.description}',
                        'code_snippet': f'Method: {endpoint.method}, Params: {endpoint.params}',
                        'detection_method': 'api_crawler',
                        'confidence': 0.8,
                        'category': 'network_security'
                    })
            
            if not self.silent:
                print(f'{Fore.GREEN}API爬虫完成，发现 {len(analyzed_endpoints)} 个API端点{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"API爬虫失败：{e}")
    
    def _integrate_core_technologies(self):
        """集成核心技术"""
        if not self.silent:
            print(f'{Fore.CYAN}集成核心技术...{Style.RESET_ALL}')
        
        try:
            # 遍历所有文件，执行核心技术集成
            for file_path in self.files_to_scan:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 优化AST解析
                    ast_result = self.core_integration.optimize_ast_parsing(content)
                    
                    # 处理危险函数调用
                    for call in ast_result['dangerous_calls']:
                        self.results['code_security'].append({
                            'file': file_path,
                            'line_number': call['line_number'],
                            'issue': f"Dangerous function call: {call['function']}",
                            'severity': 'high',
                            'details': f"Dangerous function {call['function']} detected",
                            'code_snippet': content.split('\n')[call['line_number']-1].strip(),
                            'detection_method': 'ast_optimized',
                            'confidence': 0.9,
                            'category': 'code_security'
                        })
                        self.high_risk += 1
                    
                    # 增强污点分析
                    taint_issues = self.core_integration.enhance_taint_analysis(content)
                    for issue in taint_issues:
                        self.results['code_security'].append({
                            'file': file_path,
                            'line_number': issue['sink_line'],
                            'issue': 'Taint vulnerability',
                            'severity': issue['severity'],
                            'details': issue['message'],
                            'code_snippet': content.split('\n')[issue['sink_line']-1].strip(),
                            'detection_method': 'taint_enhanced',
                            'confidence': 0.85,
                            'category': 'code_security'
                        })
                        if issue['severity'] == 'high':
                            self.high_risk += 1
                        elif issue['severity'] == 'medium':
                            self.medium_risk += 1
                        else:
                            self.low_risk += 1
                    
                except Exception as e:
                    logger.debug(f"核心技术集成失败：{e}")
            
            if not self.silent:
                print(f'{Fore.GREEN}核心技术集成完成{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"核心技术集成失败：{e}")
    
    def _detect_ai_security_issues(self):
        """检测AI安全问题"""
        if not self.silent:
            print(f'{Fore.CYAN}检测AI安全问题...{Style.RESET_ALL}')
        
        try:
            # 确保文件列表已初始化
            if not self.files_to_scan:
                self._initialize_files_to_scan()
            
            # 遍历所有文件，检测AI安全问题
            for file_path in self.files_to_scan:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 检测AI安全问题
                    issues = self.ai_security_detector.detect_ai_security_issues(content, file_path)
                    
                    # 处理检测结果
                    for issue in issues:
                        # 添加到扫描结果中
                        self.results['ai_security'].append({
                            'file': issue.file_path,
                            'line_number': issue.line_number,
                            'issue': issue.issue_type,
                            'severity': issue.severity,
                            'details': issue.details['description'],
                            'code_snippet': issue.code_snippet,
                            'detection_method': 'ai_security',
                            'confidence': issue.confidence,
                            'category': 'ai_security'
                        })
                        
                        # 更新风险计数
                        if issue.severity == 'high':
                            self.high_risk += 1
                        elif issue.severity == 'medium':
                            self.medium_risk += 1
                        else:
                            self.low_risk += 1
                    
                except Exception as e:
                    logger.debug(f"检测 {file_path} 的AI安全问题失败：{e}")
            
            if not self.silent:
                ai_security_issues = self.results.get('ai_security', [])
                if ai_security_issues:
                    print(f'{Fore.GREEN}检测到 {len(ai_security_issues)} 个AI安全问题{Style.RESET_ALL}')
                else:
                    print(f'{Fore.GREEN}未检测到AI安全问题{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"AI安全检测失败：{e}")
    
    def _initialize_files_to_scan(self):
        """初始化文件扫描列表"""
        if not self.silent:
            print(f'{Fore.CYAN}初始化文件扫描列表...{Style.RESET_ALL}')
        
        if self.use_smart_scan and self.file_priority_engine:
            try:
                # 使用文件优先级引擎
                if not self.files_to_scan:
                    self.files_to_scan = self.file_priority_engine.load_project_files()
                
                # 构建向量库
                self.file_priority_engine.build_vector_store()
                
                # 计算文件优先级
                self.file_priorities = self.file_priority_engine.calculate_file_priority()
                
                # 按优先级排序文件列表
                sorted_files = sorted(
                    self.file_priorities.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                self.files_to_scan = [file_path for file_path, _ in sorted_files]
                
                if not self.silent:
                    print(f'{Fore.GREEN}智能文件优先级排序完成，共 {len(self.files_to_scan)} 个文件{Style.RESET_ALL}')
                    # 显示前10个高优先级文件
                    print(f'{Fore.CYAN}高优先级文件 (前10个):{Style.RESET_ALL}')
                    for i, (file_path, score) in enumerate(sorted_files[:10]):
                        priority_level = self.file_priority_engine._get_priority_level(score)
                        print(f'{Fore.YELLOW}{i+1}. {file_path} (Score: {score:.2f}, Level: {priority_level}){Style.RESET_ALL}')
                
            except Exception as e:
                logger.error(f"智能文件扫描失败：{e}")
                # 回退到传统方法
                self._initialize_files_to_scan_traditional()
        else:
            # 使用传统方法
            self._initialize_files_to_scan_traditional()
    
    def _initialize_files_to_scan_traditional(self):
        """使用传统方法初始化文件扫描列表"""
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in [
                'node_modules', 'venv', '.venv', '__pycache__',
                '.git', 'dist', 'build', 'target', '.trae'
            ]]
            
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env', '.tf', '.toml', '.ini')):
                    file_path = os.path.join(root, file)
                    if file_path not in self.files_to_scan:
                        self.files_to_scan.append(file_path)
    
    def _perform_self_learning(self):
        """执行自学习"""
        if not self.silent:
            print(f'{Fore.CYAN}执行自学习...{Style.RESET_ALL}')
        
        try:
            # 从执行结果中提取攻击记录
            execution_results = self.results.get('execution_results', {})
            
            # 处理HTTP请求结果
            for http_request in execution_results.get('http_requests', []):
                # 创建攻击记录
                record = AttackRecord(
                    attack_type=http_request['attack_type'],
                    payload=http_request['payload'],
                    target=http_request['url'],
                    is_successful=http_request['status_code'] in [200, 201, 204],
                    response=str(http_request['status_code']) + (f" - {http_request['error']}" if http_request['error'] else ""),
                    timestamp=time.time(),
                    severity='high' if http_request['attack_type'] in ['sql_injection', 'command_injection'] else 'medium',
                    confidence=0.7,
                    details=http_request
                )
                self.self_learning_engine.add_attack_record(record)
            
            # 处理命令执行结果
            for cmd_exec in execution_results.get('command_execution', []):
                # 创建攻击记录
                record = AttackRecord(
                    attack_type='command_injection',
                    payload=cmd_exec['payload'],
                    target='local',
                    is_successful=cmd_exec['exit_code'] == 0,
                    response=cmd_exec.get('stdout', '') + cmd_exec.get('stderr', ''),
                    timestamp=time.time(),
                    severity='high',
                    confidence=0.8,
                    details=cmd_exec
                )
                self.self_learning_engine.add_attack_record(record)
            
            # 分析攻击模式
            self.self_learning_engine.analyze_attack_patterns()
            
            # 生成Payload模板
            self.self_learning_engine.generate_payload_templates()
            
            # 生成新规则
            new_rules = self.self_learning_engine.generate_new_rules()
            if new_rules:
                # 保存新规则
                rules_file = os.path.join(os.path.dirname(__file__), '..', 'rules', 'auto_generated_rules.json')
                with open(rules_file, 'w', encoding='utf-8') as f:
                    json.dump(new_rules, f, indent=2, ensure_ascii=False)
                if not self.silent:
                    print(f'{Fore.GREEN}生成了 {len(new_rules)} 个新规则并保存到 {rules_file}{Style.RESET_ALL}')
            
            # 优化Payload
            for attack_type in ['sql_injection', 'xss', 'command_injection']:
                optimized_payloads = self.self_learning_engine.optimize_payloads(attack_type, 3)
                if optimized_payloads:
                    if not self.silent:
                        print(f'{Fore.GREEN}为 {attack_type} 优化了 {len(optimized_payloads)} 个Payload{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"自学习失败：{e}")
    
    def _execute_attacks(self):
        """执行攻击策略"""
        if not self.silent:
            print(f'{Fore.CYAN}动态执行攻击...{Style.RESET_ALL}')
        
        try:
            execution_results = {
                'http_requests': [],
                'fuzzing': [],
                'xss_tests': [],
                'command_execution': [],
                'vulnerability_assessments': []
            }
            
            # 从攻击策略中提取攻击链
            strategies = self.results.get('attack_strategies', {})
            for strategy_name, strategy in strategies.items():
                if 'attack_chain' in strategy:
                    attack_chain = strategy['attack_chain']
                    for step in attack_chain.get('steps', []):
                        attack_type = step.get('attack_type')
                        payload = step.get('payload')
                        target_param = step.get('target')
                        
                        # 生成测试请求
                        if attack_type in ['sql_injection', 'xss', 'ssrf']:
                            # 构建测试URL（使用示例URL）
                            test_url = f"http://localhost:8080/test"
                            
                            # 发送HTTP请求
                            request = HttpRequest(
                                method="GET",
                                url=test_url,
                                params={target_param: payload}
                            )
                            
                            result = self.dynamic_executor.send_http_request(request)
                            http_result = {
                                'strategy': strategy_name,
                                'attack_type': attack_type,
                                'payload': payload,
                                'url': test_url,
                                'status_code': result.status_code,
                                'response_time': result.response_time,
                                'error': result.error
                            }
                            execution_results['http_requests'].append(http_result)
                            
                            # 执行漏洞评估
                            if self.vulnerability_assessor:
                                response_content = result.error if result.error else str(result.status_code)
                                assessment = self.vulnerability_assessor.assess_response(
                                    response_content,
                                    attack_type,
                                    payload
                                )
                                if assessment.is_vulnerable:
                                    execution_results['vulnerability_assessments'].append({
                                        'strategy': strategy_name,
                                        'attack_type': attack_type,
                                        'payload': payload,
                                        'severity': assessment.severity,
                                        'confidence': assessment.confidence,
                                        'details': assessment.details
                                    })
                                    
                                    # 添加到扫描结果中
                                    category = 'injection_security' if attack_type in ['sql_injection', 'xss'] else 'network_security'
                                    self.results[category].append({
                                        'file': 'dynamic_analysis',
                                        'line_number': 0,
                                        'issue': f'{attack_type} vulnerability',
                                        'severity': assessment.severity,
                                        'details': assessment.details.get('evidence', 'Vulnerability detected'),
                                        'code_snippet': f'Payload: {payload}',
                                        'detection_method': 'dynamic',
                                        'confidence': assessment.confidence,
                                        'category': category
                                    })
                            
                            # 执行Fuzzing
                            if attack_type == 'sql_injection':
                                fuzz_payloads = self.dynamic_executor.generate_fuzz_payloads(attack_type, 5)
                                fuzz_results = self.dynamic_executor.fuzz_api(
                                    url=test_url,
                                    params={target_param: "test"},
                                    payloads=fuzz_payloads
                                )
                                for fr in fuzz_results:
                                    fuzz_result = {
                                        'strategy': strategy_name,
                                        'attack_type': attack_type,
                                        'payload': fr.payload,
                                        'status_code': fr.status_code,
                                        'is_vulnerable': fr.is_vulnerable
                                    }
                                    execution_results['fuzzing'].append(fuzz_result)
                                    
                                    # 执行漏洞评估
                                    if self.vulnerability_assessor and fr.is_vulnerable:
                                        response_content = str(fr.status_code)
                                        assessment = self.vulnerability_assessor.assess_response(
                                            response_content,
                                            attack_type,
                                            fr.payload
                                        )
                                        if assessment.is_vulnerable:
                                            execution_results['vulnerability_assessments'].append({
                                                'strategy': strategy_name,
                                                'attack_type': attack_type,
                                                'payload': fr.payload,
                                                'severity': assessment.severity,
                                                'confidence': assessment.confidence,
                                                'details': assessment.details
                                            })
                            
                            # 执行XSS测试
                            if attack_type == 'xss':
                                xss_results = self.dynamic_executor.test_xss(
                                    url=test_url,
                                    param=target_param
                                )
                                for xr in xss_results:
                                    xss_result = {
                                        'strategy': strategy_name,
                                        'payload': xr['payload'],
                                        'url': xr['url'],
                                        'is_vulnerable': xr['is_vulnerable']
                                    }
                                    execution_results['xss_tests'].append(xss_result)
                                    
                                    # 执行漏洞评估
                                    if self.vulnerability_assessor and xr['is_vulnerable']:
                                        response_content = xr['url']  # 简化处理
                                        assessment = self.vulnerability_assessor.assess_response(
                                            response_content,
                                            attack_type,
                                            xr['payload']
                                        )
                                        if assessment.is_vulnerable:
                                            execution_results['vulnerability_assessments'].append({
                                                'strategy': strategy_name,
                                                'attack_type': attack_type,
                                                'payload': xr['payload'],
                                                'severity': assessment.severity,
                                                'confidence': assessment.confidence,
                                                'details': assessment.details
                                            })
                        
                        # 模拟命令执行
                        elif attack_type == 'command_injection':
                            command_result = self.dynamic_executor.simulate_command_execution(payload)
                            cmd_result = {
                                'strategy': strategy_name,
                                'payload': payload,
                                'exit_code': command_result.get('exit_code'),
                                'stdout': command_result.get('stdout'),
                                'stderr': command_result.get('stderr')
                            }
                            execution_results['command_execution'].append(cmd_result)
                            
                            # 执行漏洞评估
                            if self.vulnerability_assessor:
                                response_content = command_result.get('stdout', '') + command_result.get('stderr', '')
                                assessment = self.vulnerability_assessor.assess_response(
                                    response_content,
                                    attack_type,
                                    payload
                                )
                                if assessment.is_vulnerable:
                                    execution_results['vulnerability_assessments'].append({
                                        'strategy': strategy_name,
                                        'attack_type': attack_type,
                                        'payload': payload,
                                        'severity': assessment.severity,
                                        'confidence': assessment.confidence,
                                        'details': assessment.details
                                    })
                                    
                                    # 添加到扫描结果中
                                    self.results['injection_security'].append({
                                        'file': 'dynamic_analysis',
                                        'line_number': 0,
                                        'issue': 'Command injection vulnerability',
                                        'severity': assessment.severity,
                                        'details': assessment.details.get('evidence', 'Vulnerability detected'),
                                        'code_snippet': f'Payload: {payload}',
                                        'detection_method': 'dynamic',
                                        'confidence': assessment.confidence,
                                        'category': 'injection_security'
                                    })
            
            # 添加执行结果到扫描结果
            self.results['execution_results'] = execution_results
            
        except Exception as e:
            logger.error(f"攻击执行失败：{e}")
    
    def _scan_with_regex(self):
        """使用预编译正则表达式扫描"""
        if not self.silent:
            print(f'{Fore.CYAN}正则检测...{Style.RESET_ALL}')
        
        for category, rules in self.compiled_rules.items():
            if not self.silent:
                print(f'{Fore.CYAN}扫描 {category}...{Style.RESET_ALL}')
            
            for rule_name, rule_data in rules.items():
                compiled_patterns = rule_data['compiled_patterns']
                rule = rule_data['rule']
                
                self._apply_compiled_rule(category, rule_name, rule, compiled_patterns)
    
    def _apply_compiled_rule(self, category: str, rule_name: str, rule: Dict, compiled_patterns: List[re.Pattern]):
        """应用预编译规则"""
        severity = rule.get('severity', 'MEDIUM').lower()
        exclude_patterns = rule.get('exclude_patterns', [])
        
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in [
                'node_modules', 'venv', '.venv', '__pycache__',
                '.git', 'dist', 'build', 'target', '.trae'
            ]]
            
            for file in files:
                if not file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env', '.tf', '.toml', '.ini')):
                    continue
                
                file_path = os.path.join(root, file)
                
                # 添加文件路径到files_to_scan
                if file_path not in self.files_to_scan:
                    self.files_to_scan.append(file_path)
                
                if self._is_fp_path(file_path):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                    
                    for compiled_pattern in compiled_patterns:
                        try:
                            matches = compiled_pattern.finditer(content)
                            
                            for match in matches:
                                line_number = content[:match.start()].count('\n') + 1
                                code_snippet = lines[line_number - 1] if line_number <= len(lines) else ''
                                
                                if self._matches_exclude(content, line_number, exclude_patterns):
                                    continue
                                
                                issue = {
                                    'file': file_path,
                                    'line_number': line_number,
                                    'issue': rule.get('name', rule_name),
                                    'severity': severity,
                                    'details': rule.get('description', ''),
                                    'code_snippet': code_snippet.strip(),
                                    'match': match.group(0),
                                    'detection_method': 'compiled_regex',
                                    'confidence': rule.get('confidence', 0.7),
                                    'weight': rule.get('weight', 1.0),
                                    'cwe': rule.get('cwe', ''),
                                    'owasp': rule.get('owasp', ''),
                                    'fix': rule.get('fix', ''),
                                    'category': category
                                }
                                
                                self.results[category].append(issue)
                                
                                if severity == 'high':
                                    self.high_risk += 1
                                elif severity == 'medium':
                                    self.medium_risk += 1
                                else:
                                    self.low_risk += 1
                        
                        except re.error as e:
                            logger.debug(f"正则表达式错误：{e}")
                
                except Exception as e:
                    logger.error(f"读取文件 {file_path} 时出错：{e}")
    
    def _is_fp_path(self, file_path: str) -> bool:
        """检查是否是误报路径"""
        return self.rule_manager.is_fp_path(file_path)
    
    def _matches_exclude(self, content: str, line_number: int, exclude_patterns: List[str]) -> bool:
        """检查是否匹配排除模式"""
        return self.rule_manager.matches_exclude(content, line_number, exclude_patterns)
    
    def _analyze_context(self):
        """分析上下文，调整风险等级"""
        if not self.silent:
            print(f'{Fore.CYAN}上下文分析...{Style.RESET_ALL}')
        
        for category, issues in self.results.items():
            if not isinstance(issues, list):
                continue
            
            for issue in issues:
                try:
                    with open(issue['file'], 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                    
                    line_number = issue.get('line_number', 1)
                    start = max(0, line_number - 10)
                    end = min(len(lines), line_number + 10)
                    context = '\n'.join(lines[start:end])
                    
                    # 1. 检查安全上下文
                    if self._has_safe_context(context, issue):
                        if issue['severity'] == 'high':
                            issue['severity'] = 'medium'
                            self.high_risk -= 1
                            self.medium_risk += 1
                        elif issue['severity'] == 'medium':
                            issue['severity'] = 'low'
                            self.medium_risk -= 1
                            self.low_risk += 1
                        
                        issue['context_analysis'] = '检测到安全处理代码'
                    
                    # 2. 检查危险上下文
                    elif self._has_dangerous_context(context, issue):
                        if issue['severity'] == 'low':
                            issue['severity'] = 'medium'
                            self.low_risk -= 1
                            self.medium_risk += 1
                        elif issue['severity'] == 'medium':
                            issue['severity'] = 'high'
                            self.medium_risk -= 1
                            self.high_risk += 1
                        
                        issue['context_analysis'] = '检测到危险处理代码'
                    
                    # 3. 检查AI特定的上下文
                    elif 'ai_security' in category:
                        if self._has_ai_safe_context(context, issue):
                            if issue['severity'] == 'high':
                                issue['severity'] = 'medium'
                                self.high_risk -= 1
                                self.medium_risk += 1
                            elif issue['severity'] == 'medium':
                                issue['severity'] = 'low'
                                self.medium_risk -= 1
                                self.low_risk += 1
                            
                            issue['context_analysis'] = '检测到AI安全处理代码'
                
                except Exception as e:
                    logger.debug(f"上下文分析失败：{e}")
    
    def _has_safe_context(self, context: str, issue: Dict) -> bool:
        """检查是否有安全的上下文"""
        safe_patterns = [
            r'os\.environ\.get',
            r'getenv',
            r'load_dotenv',
            r'validate',
            r'sanitize',
            r'filter',
            r'check',
            r'verify',
            r'timeout\s*=',
            r'verify\s*=\s*True',
            r'ast\.literal_eval',
            r'yaml\.safe_load',
            r'parameterized',
            r'prepared\s+statement'
        ]
        
        for pattern in safe_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _has_dangerous_context(self, context: str, issue: Dict) -> bool:
        """检查是否有危险的上下文"""
        dangerous_patterns = [
            r'exec\s*\(',
            r'eval\s*\(',
            r'compile\s*\(',
            r'os\.system\s*\(',
            r'subprocess\..*shell\s*=\s*True',
            r'pickle\.load',
            r'yaml\.load\s*\([^)]*\)',
            r'input\s*\(',
            r'open\s*\([^)]*request\.',
            r'os\.path\.join\s*\([^)]*request\.'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _has_ai_safe_context(self, context: str, issue: Dict) -> bool:
        """检查是否有AI安全的上下文"""
        ai_safe_patterns = [
            r'prompt\s*template',
            r'system\s*prompt',
            r'input\s*validation',
            r'sanitize\s*input',
            r'filter\s*prompt',
            r'validate\s*user\s*input',
            r'limit\s*prompt\s*length',
            r'token\s*limit',
            r'content\s*filter',
            r'safety\s*check',
            r'rate\s*limit',
            r'throttle',
            r'context\s*isolation'
        ]
        
        for pattern in ai_safe_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _filter_false_positives(self):
        """过滤误报"""
        if not self.silent:
            print(f'{Fore.CYAN}过滤误报...{Style.RESET_ALL}')
        
        file_patterns = self.false_positive_filters.get('file_patterns', [])
        code_patterns = self.false_positive_filters.get('code_patterns', [])
        path_patterns = self.false_positive_filters.get('path_patterns', [])
        context_patterns = self.false_positive_filters.get('context_patterns', [])
        
        for category, issues in self.results.items():
            if not isinstance(issues, list):
                continue
            
            filtered_issues = []
            for issue in issues:
                is_fp = False
                
                # 1. 检查文件路径模式
                file_path = issue.get('file', '')
                file_name = os.path.basename(file_path)
                
                # 检查路径模式
                for pattern in path_patterns:
                    if pattern in file_path:
                        is_fp = True
                        break
                
                # 2. 检查文件名称模式
                if not is_fp:
                    for pattern in file_patterns:
                        regex_pattern = pattern.replace('*', '.*').replace('?', '.')
                        if re.match(regex_pattern, file_name, re.IGNORECASE):
                            is_fp = True
                            break
                
                # 3. 检查代码模式
                if not is_fp and code_patterns:
                    code_snippet = issue.get('code_snippet', '')
                    for pattern in code_patterns:
                        try:
                            if re.search(pattern, code_snippet, re.IGNORECASE):
                                is_fp = True
                                break
                        except re.error:
                            if pattern in code_snippet:
                                is_fp = True
                                break
                
                # 4. 检查上下文模式
                if not is_fp and context_patterns:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            lines = content.splitlines()
                        
                        line_number = issue.get('line_number', 1)
                        start = max(0, line_number - 10)
                        end = min(len(lines), line_number + 10)
                        context = '\n'.join(lines[start:end])
                        
                        for pattern in context_patterns:
                            try:
                                if re.search(pattern, context, re.IGNORECASE):
                                    is_fp = True
                                    break
                            except re.error:
                                if pattern in context:
                                    is_fp = True
                                    break
                    except Exception:
                        pass
                
                # 5. 检查特定类型的误报
                if not is_fp:
                    # 检查硬编码敏感信息的误报
                    if issue.get('issue', '').startswith('硬编码敏感信息'):
                        code_snippet = issue.get('code_snippet', '')
                        # 排除示例和占位符
                        placeholders = ['your_', 'example', 'placeholder', 'xxx', 'change_me', 'todo', 'fixme', 'test', 'demo', 'sample']
                        if any(p in code_snippet.lower() for p in placeholders):
                            is_fp = True
                    
                    # 检查网络访问的误报
                    elif issue.get('issue', '').startswith('网络访问代码'):
                        code_snippet = issue.get('code_snippet', '')
                        # 检查是否有超时和验证设置
                        if 'timeout' in code_snippet.lower() and 'verify' in code_snippet.lower():
                            is_fp = True
                    
                    # 检查命令注入的误报
                    elif '命令注入' in issue.get('issue', ''):
                        code_snippet = issue.get('code_snippet', '')
                        # 检查是否使用了安全的参数列表
                        if 'shell=False' in code_snippet or '[' in code_snippet and ']' in code_snippet:
                            is_fp = True
                
                if not is_fp:
                    filtered_issues.append(issue)
                else:
                    severity = issue.get('severity', 'low')
                    if severity == 'high':
                        self.high_risk -= 1
                    elif severity == 'medium':
                        self.medium_risk -= 1
                    else:
                        self.low_risk -= 1
            
            self.results[category] = filtered_issues
    
    def _calculate_confidence(self):
        """计算置信度评分"""
        for category, issues in self.results.items():
            if not isinstance(issues, list):
                continue
            
            for issue in issues:
                base_confidence = issue.get('confidence', 0.7)
                
                if issue.get('detection_method') == 'ast':
                    base_confidence += 0.1
                
                if issue.get('code_snippet'):
                    base_confidence += 0.05
                
                if issue.get('cwe') or issue.get('owasp'):
                    base_confidence += 0.05
                
                issue['final_confidence'] = min(max(base_confidence, 0.0), 1.0)
    
    def _coordinate_multi_model_attack(self):
        """协调多模型攻击"""
        if not self.silent:
            print(f'{Fore.CYAN}协调多模型攻击...{Style.RESET_ALL}')
        
        try:
            # 构建攻击面信息
            attack_surface = {
                'endpoints': self.results.get('api_endpoints', {}).get('endpoints', []),
                'vulnerabilities': []
            }
            
            # 收集已发现的漏洞类型
            for category, issues in self.results.items():
                if isinstance(issues, list):
                    for issue in issues:
                        issue_type = issue.get('issue', 'unknown')
                        if 'sql' in issue_type.lower():
                            attack_surface['vulnerabilities'].append('sql_injection')
                        elif 'xss' in issue_type.lower():
                            attack_surface['vulnerabilities'].append('xss')
                        elif 'command' in issue_type.lower() and 'injection' in issue_type.lower():
                            attack_surface['vulnerabilities'].append('command_injection')
            
            # 执行多模型协同攻击
            result = self.multi_model_coordinator.coordinate_attack(self.target, attack_surface)
            
            # 添加到扫描结果
            self.results['multi_model_attack'] = result
            
            # 处理攻击结果
            for agent_name, agent_result in result.get('results', {}).items():
                if 'attack_results' in agent_result and 'results' in agent_result['attack_results']:
                    for attack in agent_result['attack_results']['results']:
                        if attack.get('is_successful'):
                            self.results['injection_security'].append({
                                'file': 'multi_model_attack',
                                'line_number': 0,
                                'issue': f'{agent_name} 攻击成功',
                                'severity': 'high',
                                'details': f'攻击成功: {attack.get("payload")}',
                                'code_snippet': attack.get('payload'),
                                'detection_method': 'multi_model',
                                'confidence': 0.9,
                                'category': 'injection_security'
                            })
                            self.high_risk += 1
            
            if not self.silent:
                success_rate = result.get('analysis', {}).get('success_rate', 0)
                print(f'{Fore.GREEN}多模型协同攻击完成，成功率：{success_rate:.2f}{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"多模型协同攻击失败：{e}")
    
    def _analyze_vulnerability_chain(self):
        """分析漏洞链"""
        if not self.silent:
            print(f'{Fore.CYAN}分析漏洞链...{Style.RESET_ALL}')
        
        try:
            # 收集所有漏洞
            vulnerabilities = []
            for category, issues in self.results.items():
                if isinstance(issues, list):
                    for issue in issues:
                        vuln = {
                            'type': issue.get('issue', 'unknown'),
                            'severity': issue.get('severity', 'low'),
                            'file': issue.get('file', 'unknown'),
                            'line': issue.get('line_number', 0)
                        }
                        vulnerabilities.append(vuln)
            
            # 执行漏洞链分析
            analysis = self.vulnerability_chain_analyzer.analyze_vulnerability_chain(vulnerabilities)
            
            # 添加到扫描结果
            self.results['vulnerability_chain'] = analysis
            
            # 处理高风险漏洞链
            for chain in analysis.get('high_risk_chains', []):
                self.results['code_security'].append({
                    'file': chain.get('start', {}).get('file', 'unknown'),
                    'line_number': chain.get('start', {}).get('line', 0),
                    'issue': f'漏洞链: {chain.get("relationship")}',
                    'severity': 'high',
                    'details': f'高风险漏洞链: {chain.get("relationship")}',
                    'code_snippet': chain.get('start', {}).get('type', 'unknown'),
                    'detection_method': 'vulnerability_chain',
                    'confidence': 0.85,
                    'category': 'code_security'
                })
                self.high_risk += 1
            
            if not self.silent:
                total_chains = analysis.get('total_chains', 0)
                high_risk_chains = len(analysis.get('high_risk_chains', []))
                print(f'{Fore.GREEN}漏洞链分析完成，共发现 {total_chains} 条漏洞链，其中高风险 {high_risk_chains} 条{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"漏洞链分析失败：{e}")
    
    def _execute_attack_agents(self):
        """执行攻击代理"""
        if not self.silent:
            print(f'{Fore.CYAN}执行攻击代理...{Style.RESET_ALL}')
        
        try:
            # 构建攻击面信息
            attack_surface = {
                'endpoints': self.results.get('api_endpoints', {}).get('endpoints', []),
                'vulnerabilities': []
            }
            
            # 执行SQL注入攻击代理
            if self.sql_injection_agent:
                if not self.silent:
                    print(f'{Fore.CYAN}执行SQL注入攻击代理...{Style.RESET_ALL}')
                result = self.sql_injection_agent.run(self.target, attack_surface)
                self.results['sql_injection_agent'] = result
                
                # 处理攻击结果
                if result.get('analysis', {}).get('success_rate', 0) > 0:
                    for payload in result.get('analysis', {}).get('successful_payloads', []):
                        self.results['injection_security'].append({
                            'file': 'sql_injection_agent',
                            'line_number': 0,
                            'issue': 'SQL注入攻击成功',
                            'severity': 'high',
                            'details': f'SQL注入攻击成功: {payload}',
                            'code_snippet': payload,
                            'detection_method': 'sql_injection_agent',
                            'confidence': 0.9,
                            'category': 'injection_security'
                        })
                        self.high_risk += 1
            
            # 执行XSS攻击代理
            if self.xss_agent:
                if not self.silent:
                    print(f'{Fore.CYAN}执行XSS攻击代理...{Style.RESET_ALL}')
                result = self.xss_agent.run(self.target, attack_surface)
                self.results['xss_agent'] = result
                
                # 处理攻击结果
                if result.get('analysis', {}).get('success_rate', 0) > 0:
                    for payload in result.get('analysis', {}).get('successful_payloads', []):
                        self.results['injection_security'].append({
                            'file': 'xss_agent',
                            'line_number': 0,
                            'issue': 'XSS攻击成功',
                            'severity': 'medium',
                            'details': f'XSS攻击成功: {payload}',
                            'code_snippet': payload,
                            'detection_method': 'xss_agent',
                            'confidence': 0.85,
                            'category': 'injection_security'
                        })
                        self.medium_risk += 1
            
            # 执行命令注入攻击代理
            if self.command_injection_agent:
                if not self.silent:
                    print(f'{Fore.CYAN}执行命令注入攻击代理...{Style.RESET_ALL}')
                result = self.command_injection_agent.run(self.target, attack_surface)
                self.results['command_injection_agent'] = result
                
                # 处理攻击结果
                if result.get('analysis', {}).get('success_rate', 0) > 0:
                    for payload in result.get('analysis', {}).get('successful_payloads', []):
                        self.results['injection_security'].append({
                            'file': 'command_injection_agent',
                            'line_number': 0,
                            'issue': '命令注入攻击成功',
                            'severity': 'high',
                            'details': f'命令注入攻击成功: {payload}',
                            'code_snippet': payload,
                            'detection_method': 'command_injection_agent',
                            'confidence': 0.9,
                            'category': 'injection_security'
                        })
                        self.high_risk += 1
            
            if not self.silent:
                print(f'{Fore.GREEN}攻击代理执行完成{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"攻击代理执行失败：{e}")
    
    def _perform_sandbox_analysis(self):
        """执行沙盒分析"""
        if not self.silent:
            print(f'{Fore.CYAN}执行沙盒分析...{Style.RESET_ALL}')
        
        try:
            analysis_count = 0
            sandbox_issues = []
            
            # 遍历所有文件，执行沙盒分析
            for root, dirs, files in os.walk(self.target):
                dirs[:] = [d for d in dirs if d not in [
                    'node_modules', 'venv', '.venv', '__pycache__',
                    '.git', 'dist', 'build', 'target', '.trae'
                ]]
                
                for file in files:
                    if file.endswith(('.py', '.js')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # 执行沙盒分析
                            analysis = self.sandbox_analyzer.analyze(content)
                            analysis_count += 1
                            
                            # 处理分析结果
                            for issue_type, issues in analysis.items():
                                if isinstance(issues, list):
                                    for issue in issues:
                                        # 转换严重程度
                                        severity_map = {
                                            'CRITICAL': 'high',
                                            'HIGH': 'high',
                                            'MEDIUM': 'medium',
                                            'LOW': 'low'
                                        }
                                        severity = severity_map.get(issue.get('severity'), 'medium')
                                        
                                        # 添加到扫描结果
                                        self.results['code_security'].append({
                                            'file': file_path,
                                            'line_number': 0,  # 沙盒分析暂不提供行号
                                            'issue': issue.get('description', '沙盒分析问题'),
                                            'severity': severity,
                                            'details': issue.get('risk', ''),
                                            'code_snippet': issue.get('match', ''),
                                            'detection_method': 'sandbox',
                                            'confidence': issue.get('confidence', 0.8),
                                            'category': 'code_security'
                                        })
                                        
                                        # 更新风险计数
                                        if severity == 'high':
                                            self.high_risk += 1
                                        elif severity == 'medium':
                                            self.medium_risk += 1
                                        else:
                                            self.low_risk += 1
                            
                        except Exception as e:
                            logger.debug(f"沙盒分析 {file_path} 失败：{e}")
            
            # 添加沙盒分析结果到扫描结果
            self.results['sandbox_analysis'] = {
                'analyzed_files': analysis_count,
                'total_issues': len(sandbox_issues)
            }
            
            if not self.silent:
                print(f'{Fore.GREEN}沙盒分析完成，分析文件数：{analysis_count}{Style.RESET_ALL}')
            
        except Exception as e:
            logger.error(f"沙盒分析失败：{e}")
    
    def _scan_permission_security(self):
        """扫描权限安全"""
        if not self.silent:
            print(f'{Fore.CYAN}扫描权限安全...{Style.RESET_ALL}')
        
        # 检查文件权限
        for root, dirs, files in os.walk(self.target):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # 检查执行权限
                    if os.access(file_path, os.X_OK):
                        self.results["permission_security"].append({
                            "file": file_path,
                            "issue": "文件具有执行权限",
                            "severity": "medium",
                            "details": "建议仅对必要的脚本设置执行权限",
                            "code_snippet": "",
                            "detection_method": "permission_scan",
                            "confidence": 0.8,
                            "category": "permission_security"
                        })
                        self.medium_risk += 1
                    
                    # 检查AI模型文件权限
                    if file.endswith(('.pt', '.pth', '.onnx', '.h5', '.pb', '.tflite', '.safetensors', '.bin')):
                        # 获取文件权限
                        import stat
                        file_stat = os.stat(file_path)
                        permissions = oct(file_stat.st_mode)[-3:]
                        
                        # 检查是否过于宽松
                        if '7' in permissions:
                            self.results["permission_security"].append({
                                "file": file_path,
                                "issue": "AI模型文件权限过于宽松",
                                "severity": "high",
                                "details": f"当前权限: {permissions}，建议设置为 640",
                                "code_snippet": "",
                                "detection_method": "permission_scan",
                                "confidence": 0.9,
                                "category": "permission_security"
                            })
                            self.high_risk += 1
                except Exception as e:
                    logger.error(f"检查文件权限 {file_path} 时出错: {e}")
    
    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        """扫描代码内容
        
        Args:
            code: 要扫描的代码内容
            
        Returns:
            扫描结果列表
        """
        issues = []
        
        # 应用预编译规则
        for category, rules in self.compiled_rules.items():
            for rule_name, rule_data in rules.items():
                compiled_patterns = rule_data['compiled_patterns']
                rule = rule_data['rule']
                severity = rule.get('severity', 'MEDIUM').lower()
                exclude_patterns = rule.get('exclude_patterns', [])
                
                lines = code.splitlines()
                
                for compiled_pattern in compiled_patterns:
                    try:
                        matches = compiled_pattern.finditer(code)
                        
                        for match in matches:
                            line_number = code[:match.start()].count('\n') + 1
                            code_snippet = lines[line_number - 1] if line_number <= len(lines) else ''
                            
                            if self._matches_exclude(code, line_number, exclude_patterns):
                                continue
                            
                            issue = {
                                'rule_id': f"{category}.{rule_name}",
                                'file': 'code_content',
                                'line_number': line_number,
                                'issue': rule.get('name', rule_name),
                                'severity': severity,
                                'details': rule.get('description', ''),
                                'code_snippet': code_snippet.strip(),
                                'match': match.group(0),
                                'detection_method': 'compiled_regex',
                                'confidence': rule.get('confidence', 0.7),
                                'category': category
                            }
                            
                            issues.append(issue)
                    except re.error as e:
                        logger.debug(f"正则表达式错误：{e}")
        
        # 过滤误报
        code_patterns = self.false_positive_filters.get('code_patterns', [])
        filtered_issues = []
        
        for issue in issues:
            is_fp = False
            code_snippet = issue.get('code_snippet', '')
            
            for pattern in code_patterns:
                try:
                    if re.search(pattern, code_snippet, re.IGNORECASE):
                        is_fp = True
                        break
                except re.error:
                    if pattern in code_snippet:
                        is_fp = True
                        break
            
            if not is_fp:
                filtered_issues.append(issue)
        
        return filtered_issues

    def get_health_report(self) -> Dict[str, Any]:
        """获取系统健康报告"""
        available_modules = sum(1 for m in self.module_health.values() if m['available'])
        total_modules = len(self.module_health)
        error_modules = sum(1 for m in self.module_health.values() if m['status'] == 'error')
        degraded_modules = sum(1 for m in self.module_health.values() if m['status'] == 'degraded')
        
        return {
            'overall_status': 'healthy' if error_modules == 0 and degraded_modules == 0 else 
                             'degraded' if error_modules == 0 else 'unhealthy',
            'module_summary': {
                'total': total_modules,
                'available': available_modules,
                'unavailable': total_modules - available_modules,
                'error': error_modules,
                'degraded': degraded_modules,
                'ok': sum(1 for m in self.module_health.values() if m['status'] == 'ok')
            },
            'modules': self.module_health
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """获取扫描摘要"""
        total_issues = sum(
            len(issues) if isinstance(issues, list) else 0
            for issues in self.results.values()
        )
        
        # 获取健康报告
        health_report = self.get_health_report()
        
        return {
            'target': self.target,
            'total_issues': total_issues,
            'high_risk': self.high_risk,
            'medium_risk': self.medium_risk,
            'low_risk': self.low_risk,
            'scan_time': self.stats.get('scan_time', 0.0),
            'scan_method': self.stats.get('method', 'sequential'),
            'categories': {
                category: len(issues) if isinstance(issues, list) else 0
                for category, issues in self.results.items()
            },
            'health_report': health_report
        }


class SecurityScanner(EnhancedSecurityScanner):
    """兼容旧版本的扫描器"""
    pass


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = '.'
    
    scanner = EnhancedSecurityScanner(target, use_parallel=True, max_workers=4)
    results = scanner.scan()
    
    summary = scanner.get_summary()
    print(f"\n{Fore.BLUE}=== 扫描摘要 ==={Style.RESET_ALL}")
    print(f"目标：{summary['target']}")
    print(f"扫描模式：{summary['scan_method']}")
    print(f"扫描耗时：{summary['scan_time']:.2f}秒")
    print(f"总问题数：{summary['total_issues']}")
    print(f"{Fore.RED}高风险：{summary['high_risk']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}中风险：{summary['medium_risk']}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}低风险：{summary['low_risk']}{Style.RESET_ALL}")
