"""增强的误报过滤模块

参考 claude-code-security-review-main 项目，实现更完善的误报过滤机制。
"""

import re
from typing import Dict, Any, List, Tuple, Optional, Pattern
import time
from dataclasses import dataclass, field

from src.ai.client import get_model_manager
from src.ai.models import AIRequest
from src.utils.logger import get_logger

logger = get_logger(__name__)


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


class HardExclusionRules:
    """硬编码排除规则"""
    
    # 预编译的正则表达式模式，提高性能
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
        re.compile(r'\b资源泄漏', re.IGNORECASE),
        re.compile(r'\b可能的资源泄漏', re.IGNORECASE),
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
        """根据硬编码规则检查是否应该排除发现
        
        Args:
            finding: 安全发现
            
        Returns:
            如果应该排除，返回排除原因，否则返回 None
        """
        # 检查是否在 Markdown 文件中
        file_path = finding.get('file_path', '')
        if file_path.lower().endswith('.md'):
            return "在 Markdown 文档文件中的发现"
        
        description = finding.get('description', '')
        rule_name = finding.get('rule_name', '')
        
        # 处理 None 值
        if description is None:
            description = ''
        if rule_name is None:
            rule_name = ''
            
        combined_text = f"{rule_name} {description}".lower()
        
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
            
        # 检查正则表达式注入模式
        for pattern in cls._REGEX_INJECTION:
            if pattern.search(combined_text):
                return "正则表达式注入发现（不适用）"
        
        # 检查内存安全模式 - 如果不是 C/C++ 文件则排除
        c_cpp_extensions = {'.c', '.cc', '.cpp', '.h'}
        file_ext = ''
        if '.' in file_path:
            file_ext = f".{file_path.lower().split('.')[-1]}"
        
        # 如果文件没有 C/C++ 扩展名（包括没有扩展名），排除内存安全发现
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


class EnhancedFindingsFilter:
    """增强的安全发现过滤器"""
    
    def __init__(self, 
                 use_hard_exclusions: bool = True,
                 use_ai_filtering: bool = True,
                 custom_filtering_instructions: Optional[str] = None):
        """初始化发现过滤器
        
        Args:
            use_hard_exclusions: 是否应用硬编码排除规则
            use_ai_filtering: 是否使用 AI 进行过滤
            custom_filtering_instructions: 可选的自定义过滤指令
        """
        self.use_hard_exclusions = use_hard_exclusions
        self.use_ai_filtering = use_ai_filtering
        self.custom_filtering_instructions = custom_filtering_instructions
        
    async def filter_findings(self, 
                           findings: List[Dict[str, Any]],
                           context: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any], FilterStats]:
        """过滤安全发现以减少误报
        
        Args:
            findings: 安全发现列表
            context: 可选的上下文信息
            
        Returns:
            (成功状态, 过滤结果, 统计信息)
        """
        start_time = time.time()
        
        if not findings:
            stats = FilterStats(total_findings=0, runtime_seconds=0.0)
            return True, {
                "filtered_findings": [],
                "excluded_findings": [],
                "analysis_summary": {
                    "total_findings": 0,
                    "kept_findings": 0,
                    "excluded_findings": 0,
                    "exclusion_breakdown": {}
                }
            }, stats
        
        logger.info(f"过滤 {len(findings)} 个安全发现")
        
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
                    
                    # 跟踪排除分类
                    key = exclusion_reason.split('(')[0].strip()
                    stats.exclusion_breakdown[key] = stats.exclusion_breakdown.get(key, 0) + 1
                else:
                    findings_after_hard.append((i, finding))
            
            logger.info(f"硬编码规则排除了 {stats.hard_excluded} 个发现")
        else:
            findings_after_hard = [(i, f) for i, f in enumerate(findings)]
        
        # 步骤 2: 应用 AI 过滤（如果启用）
        findings_after_ai = []
        excluded_ai = []
        
        if self.use_ai_filtering and findings_after_hard:
            # 处理发现
            logger.info(f"通过 AI API 处理 {len(findings_after_hard)} 个发现")
            
            for orig_idx, finding in findings_after_hard:
                # 调用 AI 分析单个发现
                success, analysis_result = await self._analyze_single_finding(
                    finding, context, self.custom_filtering_instructions
                )
                
                if success and analysis_result:
                    # 处理 AI 分析结果
                    confidence = analysis_result.get('confidence', 0.0)
                    keep_finding = analysis_result.get('keep_finding', True)
                    justification = analysis_result.get('justification', '')
                    exclusion_reason = analysis_result.get('exclusion_reason')
                    
                    stats.confidence_scores.append(confidence)
                    
                    if not keep_finding:
                        # AI 建议排除
                        excluded_ai.append({
                            "finding": finding,
                            "confidence_score": confidence,
                            "exclusion_reason": exclusion_reason or f"低置信度得分: {confidence}",
                            "justification": justification,
                            "filter_stage": "ai_api"
                        })
                        stats.ai_excluded += 1
                    else:
                        # 保留发现并添加元数据
                        enriched_finding = finding.copy()
                        enriched_finding['_filter_metadata'] = {
                            'confidence_score': confidence,
                            'justification': justification,
                        }
                        findings_after_ai.append(enriched_finding)
                        stats.kept_findings += 1
                else:
                    # AI API 调用失败 - 保留发现并添加警告
                    logger.warning(f"AI API 调用失败 for finding {orig_idx}")
                    enriched_finding = finding.copy()
                    enriched_finding['_filter_metadata'] = {
                        'confidence_score': 1.0,  # 默认高置信度
                        'justification': 'AI 过滤失败，保留发现',
                    }
                    findings_after_ai.append(enriched_finding)
                    stats.kept_findings += 1
        else:
            # AI 过滤禁用或无客户端 - 保留所有硬过滤后的发现
            for orig_idx, finding in findings_after_hard:
                enriched_finding = finding.copy()
                enriched_finding['_filter_metadata'] = {
                    'confidence_score': 1.0,  # 默认高置信度
                    'justification': 'AI 过滤禁用',
                }
                findings_after_ai.append(enriched_finding)
                stats.kept_findings += 1
        
        # 合并所有排除的发现
        all_excluded = excluded_hard + excluded_ai
        
        # 计算最终统计信息
        stats.runtime_seconds = time.time() - start_time
        
        # 构建过滤结果
        filtered_results = {
            "filtered_findings": findings_after_ai,
            "excluded_findings": all_excluded,
            "analysis_summary": {
                "total_findings": stats.total_findings,
                "kept_findings": stats.kept_findings,
                "excluded_findings": len(all_excluded),
                "hard_excluded": stats.hard_excluded,
                "ai_excluded": stats.ai_excluded,
                "exclusion_breakdown": stats.exclusion_breakdown,
                "average_confidence": sum(stats.confidence_scores) / len(stats.confidence_scores) if stats.confidence_scores else None,
                "runtime_seconds": stats.runtime_seconds
            }
        }
        
        logger.info(f"过滤完成: {stats.kept_findings}/{stats.total_findings} 个发现被保留 "
                    f"({stats.runtime_seconds:.1f}s)")
        
        return True, filtered_results, stats
    
    async def _analyze_single_finding(self, 
                                   finding: Dict[str, Any],
                                   context: Optional[Dict[str, Any]] = None,
                                   custom_instructions: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """使用 AI 分析单个安全发现
        
        Args:
            finding: 安全发现
            context: 可选的上下文信息
            custom_instructions: 可选的自定义指令
            
        Returns:
            (成功状态, 分析结果)
        """
        try:
            # 获取模型管理器
            manager = await get_model_manager()
            
            # 构建提示
            prompt = self._build_ai_filter_prompt(finding, context, custom_instructions)
            
            # 发送请求
            request = AIRequest(
                prompt=prompt,
                system_prompt="你是一个安全专家，负责审查自动化代码审计工具的发现。你的任务是过滤误报和低信号的发现，以减少警报疲劳。你必须保持高召回率（不要错过真正的漏洞），同时提高精确度。",
                temperature=0.0,
                max_tokens=1024,
            )
            
            # 生成响应
            response = await manager.generate(request)
            
            # 解析响应
            analysis_result = self._parse_ai_response(response.content)
            
            return True, analysis_result
        except Exception as e:
            logger.error(f"AI 分析单个发现失败: {str(e)}")
            return False, None
    
    def _build_ai_filter_prompt(self, 
                             finding: Dict[str, Any],
                             context: Optional[Dict[str, Any]] = None,
                             custom_instructions: Optional[str] = None) -> str:
        """构建 AI 过滤提示
        
        Args:
            finding: 安全发现
            context: 可选的上下文信息
            custom_instructions: 可选的自定义指令
            
        Returns:
            提示字符串
        """
        prompt = f"请分析以下安全发现，并判断它是否是误报。\n\n"
        
        # 添加发现信息
        prompt += f"文件路径: {finding.get('file_path', 'N/A')}\n"
        prompt += f"规则 ID: {finding.get('rule_id', 'N/A')}\n"
        prompt += f"规则名称: {finding.get('rule_name', 'N/A')}\n"
        prompt += f"严重程度: {finding.get('severity', 'N/A')}\n"
        prompt += f"置信度: {finding.get('confidence', 'N/A')}\n"
        prompt += f"描述: {finding.get('description', 'N/A')}\n"
        prompt += f"代码片段: {finding.get('code_snippet', 'N/A')}\n"
        prompt += f"修复建议: {finding.get('fix_suggestion', 'N/A')}\n"
        
        # 添加上下文信息
        if context:
            prompt += f"\n上下文信息: {context}\n"
        
        # 添加自定义指令
        if custom_instructions:
            prompt += f"\n自定义指令: {custom_instructions}\n"
        
        # 添加判断标准
        prompt += "\n判断标准:\n"
        prompt += "1. 是否存在具体的、可利用的漏洞和明确的攻击路径？\n"
        prompt += "2. 这是否代表真实的安全风险，而非理论上的最佳实践？\n"
        prompt += "3. 是否有具体的代码位置和复现步骤？\n"
        prompt += "4. 这个发现对安全团队来说是否可操作？\n"
        
        # 添加输出格式
        prompt += "\n请以 JSON 格式输出你的判断:\n"
        prompt += "{\n"
        prompt += "  \"keep_finding\": true,\n"
        prompt += "  \"confidence\": 0.8,\n"
        prompt += "  \"justification\": \"清晰的 SQL 注入漏洞，存在明确的攻击路径\",\n"
        prompt += "  \"exclusion_reason\": null\n"
        prompt += "}\n"
        
        return prompt
    
    def _parse_ai_response(self, response: str) -> Optional[Dict[str, Any]]:
        """解析 AI 响应
        
        Args:
            response: AI 响应内容
            
        Returns:
            解析后的分析结果
        """
        try:
            # 提取 JSON 部分
            import json
            # 尝试查找 JSON 开始和结束位置
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end != -1:
                json_str = response[start:end]
                result = json.loads(json_str)
                return result
            return None
        except Exception as e:
            logger.error(f"解析 AI 响应失败: {str(e)}")
            return None
