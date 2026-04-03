#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全发现过滤模块 v2.0 (AI协议修复版)

功能：
1. 基于硬编码规则过滤常见误报
2. 基于 AI 分析过滤误报 (强制JSON协议)
3. 提供可配置的过滤选项
4. AI失败时进入BLOCK状态（不降级）
"""

import re
import time
from typing import Dict, Any, List, Tuple, Optional, Pattern
from dataclasses import dataclass, field
from enum import Enum

from utils.ai_model_client import AIModelManager
from utils.config_manager import ConfigManager
from utils.ai_output_models import AIFindingAnalysis, AI_FILTER_PROMPT_TEMPLATE
from utils.ai_structured_response_parser import ai_structured_response_parser, AIResponseParseError


class FilterStatus(Enum):
    """过滤器状态"""
    SUCCESS = "success"
    AI_PARSE_ERROR = "ai_parse_error"
    AI_API_ERROR = "ai_api_error"
    BLOCKED = "blocked"


@dataclass
class FilterStats:
    """过滤统计信息"""
    total_findings: int = 0
    hard_excluded: int = 0
    ai_excluded: int = 0
    kept_findings: int = 0
    exclusion_breakdown: Dict[str, int] = field(default_factory=dict)
    confidence_scores: List[float] = field(default_factory=list)
    runtime_seconds: float = 0.0
    ai_parse_failures: int = 0


@dataclass
class FilterResult:
    """过滤结果"""
    status: FilterStatus
    filtered_findings: List[Dict[str, Any]]
    excluded_findings: List[Dict[str, Any]]
    stats: FilterStats
    error_message: str = ""


class HardExclusionRules:
    """硬编码排除规则"""
    
    # 预编译正则表达式模式
    _DOS_PATTERNS: List[Pattern] = [
        re.compile(r'\b(denial of service|dos attack|resource exhaustion)\b', re.IGNORECASE),
        re.compile(r'\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b', re.IGNORECASE),
        re.compile(r'\b(infinite|unbounded).*?(loop|recursion)\b', re.IGNORECASE),
    ]
    
    _RATE_LIMITING_PATTERNS: List[Pattern] = [
        re.compile(r'\b(missing|lack of|no)\s+rate\s+limit', re.IGNORECASE),
        re.compile(r'\brate\s+limiting\s+(missing|required|not implemented)', re.IGNORECASE),
        re.compile(r'\b(implement|add)\s+rate\s+limit', re.IGNORECASE),
        re.compile(r'\bunlimited\s+(requests|calls|api)', re.IGNORECASE),
    ]
    
    _RESOURCE_PATTERNS: List[Pattern] = [
        re.compile(r'\b(resource|memory|file)\s+leak\s+potential', re.IGNORECASE),
        re.compile(r'\bunclosed\s+(resource|file|connection)', re.IGNORECASE),
        re.compile(r'\b(close|cleanup|release)\s+(resource|file|connection)', re.IGNORECASE),
        re.compile(r'\bpotential\s+memory\s+leak', re.IGNORECASE),
        re.compile(r'\b(database|thread|socket|connection)\s+leak', re.IGNORECASE),
    ]
    
    _OPEN_REDIRECT_PATTERNS: List[Pattern] = [
        re.compile(r'\b(open redirect|unvalidated redirect)\b', re.IGNORECASE),
        re.compile(r'\b(redirect.(attack|exploit|vulnerability))\b', re.IGNORECASE),
        re.compile(r'\b(malicious.redirect)\b', re.IGNORECASE),
    ]
    
    _MEMORY_SAFETY_PATTERNS: List[Pattern] = [
        re.compile(r'\b(buffer overflow|stack overflow|heap overflow)\b', re.IGNORECASE),
        re.compile(r'\b(oob)\s+(read|write|access)\b', re.IGNORECASE),
        re.compile(r'\b(out.?of.?bounds?)\b', re.IGNORECASE),
        re.compile(r'\b(memory safety|memory corruption)\b', re.IGNORECASE),
        re.compile(r'\b(use.?after.?free|double.?free|null.?pointer.?dereference)\b', re.IGNORECASE),
        re.compile(r'\b(segmentation fault|segfault|memory violation)\b', re.IGNORECASE),
        re.compile(r'\b(bounds check|boundary check|array bounds)\b', re.IGNORECASE),
        re.compile(r'\b(integer overflow|integer underflow|integer conversion)\b', re.IGNORECASE),
        re.compile(r'\barbitrary.?(memory read|pointer dereference|memory address|memory pointer)\b', re.IGNORECASE),
    ]

    _REGEX_INJECTION: List[Pattern] = [
        re.compile(r'\b(regex|regular expression)\s+injection\b', re.IGNORECASE),
        re.compile(r'\b(regex|regular expression)\s+denial of service\b', re.IGNORECASE),
        re.compile(r'\b(regex|regular expression)\s+flooding\b', re.IGNORECASE),
    ]
    
    _SSRF_PATTERNS: List[Pattern] = [
        re.compile(r'\b(ssrf|server\s+.?side\s+.?request\s+.?forgery)\b', re.IGNORECASE),
    ]
    
    @classmethod
    def get_exclusion_reason(cls, finding: Dict[str, Any]) -> Optional[str]:
        """检查是否应该根据硬规则排除发现
        
        Args:
            finding: 安全发现
            
        Returns:
            排除原因，如果应该排除则返回，否则返回 None
        """
        # 检查是否在 Markdown 文件中
        file_path = finding.get('file', '')
        if file_path.lower().endswith('.md'):
            return "在 Markdown 文档文件中的发现"
        
        description = finding.get('details', '')
        issue = finding.get('issue', '')
        
        # 处理 None 值
        if description is None:
            description = ''
        if issue is None:
            issue = ''
            
        combined_text = f"{issue} {description}".lower()
        
        # 检查 DOS 模式
        for pattern in cls._DOS_PATTERNS:
            if pattern.search(combined_text):
                return "通用 DOS/资源耗尽发现（低信号）"
        
        # 检查速率限制模式
        for pattern in cls._RATE_LIMITING_PATTERNS:
            if pattern.search(combined_text):
                return "通用速率限制建议"
        
        # 检查资源模式 - 总是排除
        for pattern in cls._RESOURCE_PATTERNS:
            if pattern.search(combined_text):
                return "资源管理发现（不是安全漏洞）"
        
        # 检查开放重定向模式
        for pattern in cls._OPEN_REDIRECT_PATTERNS:
            if pattern.search(combined_text):
                return "开放重定向漏洞（影响不高）"
        
        # 检查正则注入模式
        for pattern in cls._REGEX_INJECTION:
            if pattern.search(combined_text):
                return "正则注入发现（不适用）"
        
        # 检查内存安全模式 - 如果不是 C/C++ 文件则排除
        c_cpp_extensions = {'.c', '.cc', '.cpp', '.h'}
        file_ext = ''
        if '.' in file_path:
            file_ext = f".{file_path.lower().split('.')[-1]}"
        
        # 如果文件没有 C/C++ 扩展名（包括无扩展名），排除内存安全发现
        if file_ext not in c_cpp_extensions:
            for pattern in cls._MEMORY_SAFETY_PATTERNS:
                if pattern.search(combined_text):
                    return "非 C/C++ 代码中的内存安全发现（不适用）"
        
        # 检查 SSRF 模式 - 如果仅在 HTML 文件中则排除
        html_extensions = {'.html'}
        
        # 如果文件有 HTML 扩展名，排除 SSRF 发现
        if file_ext in html_extensions:
            for pattern in cls._SSRF_PATTERNS:
                if pattern.search(combined_text):
                    return "HTML 文件中的 SSRF 发现（不适用于客户端代码）"
        
        return None


class FindingsFilter:
    """安全发现过滤器 v2.0"""
    
    def __init__(self, 
                 use_hard_exclusions: bool = True,
                 use_ai_filtering: bool = True,
                 config: Optional[Dict[str, Any]] = None,
                 custom_filtering_instructions: Optional[str] = None,
                 block_on_ai_failure: bool = True):  # 新增：AI失败时是否BLOCK
        """初始化发现过滤器
        
        Args:
            use_hard_exclusions: 是否应用硬编码排除规则
            use_ai_filtering: 是否使用 AI 进行过滤
            config: 配置字典
            custom_filtering_instructions: 自定义过滤指令
            block_on_ai_failure: AI失败时是否进入BLOCK状态（不降级）
        """
        self.use_hard_exclusions = use_hard_exclusions
        self.use_ai_filtering = use_ai_filtering
        self.custom_filtering_instructions = custom_filtering_instructions
        self.block_on_ai_failure = block_on_ai_failure
        
        # 加载配置
        self.config = config or ConfigManager().get_ai_config()
        
        # 初始化 AI 模型管理器
        self.ai_model_manager = None
        if self.use_ai_filtering:
            try:
                self.ai_model_manager = AIModelManager(self.config)
                # 验证 API 访问
                valid, error = self._validate_ai_access()
                if not valid:
                    print(f"AI 模型验证失败: {error}")
                    self.use_ai_filtering = False
            except Exception as e:
                print(f"初始化 AI 模型管理器失败: {str(e)}")
                self.use_ai_filtering = False
    
    def _validate_ai_access(self) -> tuple[bool, str]:
        """验证 AI API 访问
        
        Returns:
            (是否成功, 错误信息)
        """
        try:
            # 简单测试 AI 模型访问
            test_prompt = "Hello, are you working?"
            result = self.ai_model_manager.generate(test_prompt, max_tokens=50)
            if result['success']:
                return True, ""
            else:
                return False, result.get('error', 'Unknown error')
        except Exception as e:
            return False, str(e)
    
    def filter_findings(self, 
                       findings: List[Dict[str, Any]],
                       context: Optional[Dict[str, Any]] = None) -> FilterResult:
        """过滤安全发现以减少误报 - v2.0 (强制协议版)
        
        Args:
            findings: 安全发现列表
            context: 上下文信息
            
        Returns:
            FilterResult 包含状态和结果
        """
        start_time = time.time()
        
        if not findings:
            stats = FilterStats(total_findings=0, runtime_seconds=0.0)
            return FilterResult(
                status=FilterStatus.SUCCESS,
                filtered_findings=[],
                excluded_findings=[],
                stats=stats
            )
        
        print(f"过滤 {len(findings)} 个安全发现")
        
        # 初始化统计信息
        stats = FilterStats(total_findings=len(findings))
        
        # 步骤 1: 应用硬编码排除规则
        findings_after_hard = []
        excluded_hard = []
        
        if self.use_hard_exclusions:
            for i, finding in enumerate(findings):
                exclusion_reason = HardExclusionRules.get_exclusion_reason(finding)
                if exclusion_reason:
                    excluded_hard.append({
                        "finding": finding,
                        "index": i,
                        "exclusion_reason": exclusion_reason,
                        "filter_stage": "hard_rules"
                    })
                    stats.hard_excluded += 1
                    
                    # 跟踪排除原因
                    key = exclusion_reason.split('(')[0].strip()
                    stats.exclusion_breakdown[key] = stats.exclusion_breakdown.get(key, 0) + 1
                else:
                    findings_after_hard.append((i, finding))
            
            print(f"硬编码规则排除了 {stats.hard_excluded} 个发现")
        else:
            findings_after_hard = [(i, f) for i, f in enumerate(findings)]
        
        # 步骤 2: 应用 AI 过滤 (强制协议)
        findings_after_ai = []
        excluded_ai = []
        
        if self.use_ai_filtering and self.ai_model_manager and findings_after_hard:
            print(f"使用 AI 分析 {len(findings_after_hard)} 个发现")
            
            for orig_idx, finding in findings_after_hard:
                # 调用 AI 分析单个发现
                success, analysis_result, error_msg = self._analyze_single_finding(
                    finding, context, self.custom_filtering_instructions
                )
                
                if success and analysis_result:
                    # AI分析成功 - 处理结果
                    confidence = analysis_result.confidence_score
                    is_fp = analysis_result.is_false_positive
                    justification = analysis_result.justification
                    exclusion_reason = analysis_result.exclusion_reason
                    
                    stats.confidence_scores.append(confidence)
                    
                    if is_fp:
                        # AI 建议排除
                        excluded_ai.append({
                            "finding": finding,
                            "confidence_score": confidence,
                            "exclusion_reason": exclusion_reason or f"AI判断为误报，置信度: {confidence}",
                            "justification": justification,
                            "filter_stage": "ai_analysis"
                        })
                        stats.ai_excluded += 1
                    else:
                        # 保留发现并添加元数据
                        enriched_finding = finding.copy()
                        enriched_finding['_filter_metadata'] = {
                            'confidence_score': confidence,
                            'justification': justification,
                            'ai_verified': True
                        }
                        findings_after_ai.append(enriched_finding)
                        stats.kept_findings += 1
                else:
                    # AI 分析失败 - 根据策略处理
                    stats.ai_parse_failures += 1
                    
                    if self.block_on_ai_failure:
                        # BLOCK策略：AI失败时停止处理
                        stats.runtime_seconds = time.time() - start_time
                        return FilterResult(
                            status=FilterStatus.AI_PARSE_ERROR,
                            filtered_findings=[],
                            excluded_findings=excluded_hard + excluded_ai,
                            stats=stats,
                            error_message=f"AI分析失败: {error_msg}"
                        )
                    else:
                        # 降级策略：保留发现但标记为未验证（不推荐）
                        print(f"警告: AI分析失败，降级保留发现: {error_msg}")
                        enriched_finding = finding.copy()
                        enriched_finding['_filter_metadata'] = {
                            'confidence_score': 5.0,
                            'justification': f'AI分析失败: {error_msg}',
                            'ai_verified': False
                        }
                        findings_after_ai.append(enriched_finding)
                        stats.kept_findings += 1
        else:
            # AI 过滤禁用或无客户端 - 保留所有通过硬编码规则的发现
            for orig_idx, finding in findings_after_hard:
                enriched_finding = finding.copy()
                enriched_finding['_filter_metadata'] = {
                    'confidence_score': 10.0,
                    'justification': 'AI过滤禁用',
                    'ai_verified': False
                }
                findings_after_ai.append(enriched_finding)
                stats.kept_findings += 1
        
        # 合并所有排除的发现
        all_excluded = excluded_hard + excluded_ai
        
        # 计算最终统计信息
        stats.runtime_seconds = time.time() - start_time
        
        print(f"过滤完成: {stats.kept_findings}/{stats.total_findings} 个发现被保留 ({stats.runtime_seconds:.1f}s)")
        
        return FilterResult(
            status=FilterStatus.SUCCESS,
            filtered_findings=findings_after_ai,
            excluded_findings=all_excluded,
            stats=stats
        )
    
    def _analyze_single_finding(self, 
                              finding: Dict[str, Any], 
                              context: Optional[Dict[str, Any]] = None, 
                              custom_instructions: Optional[str] = None) -> Tuple[bool, Optional[AIFindingAnalysis], str]:
        """使用 AI 分析单个安全发现 - 强制协议版
        
        Args:
            finding: 安全发现
            context: 上下文信息
            custom_instructions: 自定义过滤指令
            
        Returns:
            (成功, 分析结果, 错误信息)
        """
        try:
            # 构建提示词（使用强制JSON模板）
            prompt = self._build_filtering_prompt(finding, context, custom_instructions)
            
            # 调用 AI 模型
            result = self.ai_model_manager.generate(prompt, max_tokens=1000)
            
            if not result['success']:
                return False, None, result.get('error', 'AI 生成失败')
            
            # 使用结构化解析器解析响应
            response_text = result['content']
            
            # 强制解析为 AIFindingAnalysis 模型
            parse_success, parsed_result, error_msg = ai_structured_response_parser.parse_strict(
                response_text, AIFindingAnalysis
            )
            
            if not parse_success:
                return False, None, f"AI输出解析失败: {error_msg}"
            
            return True, parsed_result, ""
            
        except AIResponseParseError as e:
            return False, None, f"AI响应解析错误: {str(e)}"
        except Exception as e:
            return False, None, f"未知错误: {str(e)}"
    
    def _build_filtering_prompt(self, 
                              finding: Dict[str, Any], 
                              context: Optional[Dict[str, Any]] = None, 
                              custom_instructions: Optional[str] = None) -> str:
        """构建过滤提示词 - 使用强制JSON模板
        
        Args:
            finding: 安全发现
            context: 上下文信息
            custom_instructions: 自定义过滤指令
            
        Returns:
            提示词
        """
        # 构建发现信息
        file_path = finding.get('file', 'unknown')
        line_number = finding.get('line_number', 'N/A')
        issue = finding.get('issue', 'unknown')
        severity = finding.get('severity', 'low')
        details = finding.get('details', '')
        code_snippet = finding.get('code_snippet', '')
        
        # 构建上下文信息
        context_str = ""
        if context:
            context_str = "\n上下文信息:\n"
            for key, value in context.items():
                context_str += f"- {key}: {value}\n"
        
        # 构建自定义指令
        custom_instructions_str = ""
        if custom_instructions:
            custom_instructions_str = f"\n自定义过滤指令:\n{custom_instructions}\n"
        
        # 使用强制JSON模板
        return AI_FILTER_PROMPT_TEMPLATE.format(
            file_path=file_path,
            line_number=line_number,
            issue=issue,
            severity=severity,
            details=details,
            code_snippet=code_snippet,
            context_str=context_str,
            custom_instructions_str=custom_instructions_str
        )


if __name__ == '__main__':
    # 测试过滤功能
    test_findings = [
        {
            "file": "test.py",
            "line_number": 10,
            "issue": "SQL 注入风险",
            "severity": "high",
            "details": "检测到可能的 SQL 注入风险",
            "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\""
        },
        {
            "file": "test.md",
            "line_number": 5,
            "issue": "硬编码的 API 密钥",
            "severity": "high",
            "details": "发现硬编码的 API 密钥",
            "code_snippet": "api_key = \"sk-1234567890\""
        },
        {
            "file": "test.py",
            "line_number": 20,
            "issue": "内存泄漏风险",
            "severity": "medium",
            "details": "检测到可能的内存泄漏风险",
            "code_snippet": "def func():\n    x = [1] * 1000000"
        }
    ]
    
    # 创建过滤器（禁用AI，仅测试硬规则）
    filter = FindingsFilter(use_hard_exclusions=True, use_ai_filtering=False)
    
    # 过滤发现
    result = filter.filter_findings(test_findings)
    
    print(f"\n过滤结果状态: {result.status.value}")
    print(f"保留的发现: {len(result.filtered_findings)}")
    print(f"排除的发现: {len(result.excluded_findings)}")
    print(f"统计信息: {result.stats}")
    
    if result.error_message:
        print(f"错误信息: {result.error_message}")
    
    # 打印排除的发现
    print("\n排除的发现:")
    for excluded in result.excluded_findings:
        print(f"- {excluded['finding']['issue']}: {excluded['exclusion_reason']}")
