"""AI 安全分析器

提供基于 AI 的代码安全分析功能。
"""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.ai.client import AIClient, AIModelManager, get_model_manager
from src.ai.models import (
    AIProvider,
    AIRequest,
    AIResponse,
    AnalysisLevel,
    SecurityAnalysisResult,
    VulnerabilityFinding,
    AnalysisContext,
)
from src.ai.json_parser import SmartJSONParser
from src.ai.prompts import get_prompt_manager
from src.ai.cache import get_analysis_cache
from src.ai.filters.enhanced_filter import EnhancedFindingsFilter
from src.ai.classifier import AutoClassifier
from src.ai.semantic_matcher import get_ai_semantic_optimizer
from src.utils.performance_monitor import get_performance_monitor, measure_performance
from src.core.config import Config, get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)





class AIAnalyzer:
    """AI 安全分析器"""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()
        self._manager: Optional[AIModelManager] = None
        self._json_parser = SmartJSONParser()
        self._prompt_manager = get_prompt_manager(self.config)
        self._cache = get_analysis_cache()
        self._filter = EnhancedFindingsFilter(
            use_hard_exclusions=True,
            use_ai_filtering=True
        )
        self._auto_classifier = AutoClassifier(self.config)
        self._semantic_optimizer = get_ai_semantic_optimizer()
        self._performance_monitor = get_performance_monitor()
        self._system_prompt = self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        """加载系统提示"""
        return self._prompt_manager.get_prompt("security_analysis")

    async def initialize(self) -> None:
        """初始化分析器"""
        # 每次初始化都重新获取模型管理器，确保配置生效
        from src.ai.client import _manager
        # 重置全局实例，强制重新初始化
        _manager = None
        self._manager = await get_model_manager(self.config)

    async def close(self) -> None:
        """关闭分析器"""
        if self._manager:
            await self._manager.close()
            self._manager = None

    @measure_performance("ai_analysis")
    async def analyze(self, context: AnalysisContext) -> SecurityAnalysisResult:
        """执行 AI 安全分析

        Args:
            context: 分析上下文

        Returns:
            安全分析结果
        """
        # 检查缓存
        cached_result = self._cache.get(context)
        if cached_result:
            logger.info(f"Using cached analysis for {context.file_path}")
            return cached_result

        # 尝试语义匹配，减少AI调用
        if self._semantic_optimizer.is_available():
            optimization_result = await self._semantic_optimizer.optimize_analysis(
                context.code_content,
                context.language
            )
            
            if not optimization_result.get("use_ai", True):
                # 找到足够匹配的模式，直接返回结果
                matches = optimization_result.get("matches", [])
                findings = []
                
                for match in matches:
                    from src.ai.models import VulnerabilityFinding
                    finding = VulnerabilityFinding(
                        rule_id=match.get("vulnerability_type", "SEMANTIC_MATCH"),
                        rule_name=match.get("vulnerability_type", "Semantic Match"),
                        description=match.get("description", "Semantic match found"),
                        severity=match.get("severity", "medium"),
                        confidence=match.get("confidence", 0.8),
                        location={"file": context.file_path, "line": 0, "column": 0},
                        code_snippet=context.code_content,
                        fix_suggestion="",
                        explanation=f"Semantic match with score: {match.get('score', 0.0)}",
                        references=[],
                        exploit_scenario=""
                    )
                    findings.append(finding)
                
                result = SecurityAnalysisResult(
                    findings=findings,
                    risk_score=0.0,
                    summary=f"Semantic analysis found {len(findings)} potential issues",
                    recommendations=[],
                    metadata={
                        "semantic_optimized": True,
                        "match_score": optimization_result.get("confidence", 0.0)
                    }
                )
                
                # 应用自动分类
                enhanced_result = await self._auto_classifier.enhance_findings(result, context)
                
                # 缓存结果
                self._cache.set(context, enhanced_result)
                
                logger.info(f"Semantic optimization applied, skipping AI analysis for {context.file_path}")
                return enhanced_result

        await self.initialize()

        # 构建提示
        prompt = self._build_prompt(context)

        # 处理多模态内容
        multimodal_content = context.multimodal_content

        # 发送请求
        request = AIRequest(
            prompt=prompt,
            system_prompt=self._system_prompt,
            temperature=0.0,
            max_tokens=4096,
            model=self.config.ai.model,  # 使用配置的模型
            multimodal_content=multimodal_content,
        )

        response = await self._manager.generate(request)

        # 解析响应
        result = await self._parse_response(response.content, context)
        
        # 应用自动分类
        enhanced_result = await self._auto_classifier.enhance_findings(result, context)
        
        # 缓存结果
        self._cache.set(context, enhanced_result)
        
        # 输出性能统计信息
        stats = self._performance_monitor.get_statistics()
        if stats:
            logger.info(f"AI analysis performance: {stats}")
        
        return enhanced_result

    async def analyze_batch(
        self, contexts: List[AnalysisContext], max_concurrent: int = 5
    ) -> List[SecurityAnalysisResult]:
        """批量分析

        Args:
            contexts: 分析上下文列表
            max_concurrent: 最大并发数

        Returns:
            安全分析结果列表
        """
        # 分离缓存命中和未命中的上下文
        cached_results = {}
        uncached_contexts = []
        
        for i, context in enumerate(contexts):
            cached_result = self._cache.get(context)
            if cached_result:
                logger.info(f"Using cached analysis for {context.file_path}")
                cached_results[i] = cached_result
            else:
                uncached_contexts.append((i, context))
        
        # 对未缓存的上下文进行智能批处理
        results = [None] * len(contexts)
        
        # 填充缓存结果
        for i, result in cached_results.items():
            results[i] = result
        
        if not uncached_contexts:
            return results
        
        # 智能批处理：根据代码复杂度排序
        sorted_uncached = sorted(uncached_contexts, key=lambda x: self._get_priority(x[1]))
        
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_limit(index_ctx: tuple) -> tuple:
            i, ctx = index_ctx
            async with semaphore:
                # 自适应分析：根据代码复杂度调整分析深度
                result = await self._adaptive_analyze(ctx)
                return i, result

        tasks = [analyze_with_limit(idx_ctx) for idx_ctx in sorted_uncached]
        task_results = await asyncio.gather(*tasks)
        
        # 填充分析结果
        for i, result in task_results:
            results[i] = result
        
        return results
    
    def _get_priority(self, ctx: AnalysisContext) -> int:
        """获取上下文优先级

        Args:
            ctx: 分析上下文

        Returns:
            int: 优先级值（越小优先级越高）
        """
        # 基于代码长度、复杂度等因素计算优先级
        code_length = len(ctx.code_content)
        complexity_score = 0
        
        # 简单的复杂度计算
        lines = ctx.code_content.split('\n')
        complexity_score += len(lines)
        complexity_score += ctx.code_content.count('if ')
        complexity_score += ctx.code_content.count('for ')
        complexity_score += ctx.code_content.count('while ')
        complexity_score += ctx.code_content.count('def ')
        complexity_score += ctx.code_content.count('class ')
        
        # 安全敏感关键字
        sensitive_keywords = ['eval', 'exec', 'input', 'open', 'import', 'subprocess']
        for keyword in sensitive_keywords:
            complexity_score += ctx.code_content.count(keyword) * 5
        
        return -complexity_score  # 负号表示降序排序



    async def _adaptive_analyze(self, context: AnalysisContext) -> SecurityAnalysisResult:
        """自适应分析

        根据代码复杂度调整分析深度

        Args:
            context: 分析上下文

        Returns:
            安全分析结果
        """
        # 检查缓存
        cached_result = self._cache.get(context)
        if cached_result:
            logger.info(f"Using cached analysis for {context.file_path}")
            return cached_result

        code_length = len(context.code_content)
        lines = len(context.code_content.split('\n'))
        
        # 根据代码复杂度调整分析策略
        if code_length > 5000 or lines > 200:
            # 复杂代码：分块分析
            result = await self._analyze_complex_code(context)
        elif code_length > 1000 or lines > 50:
            # 中等复杂度：标准分析
            result = await self.analyze(context)
        else:
            # 简单代码：快速分析
            result = await self._analyze_simple_code(context)
        
        # 缓存结果
        self._cache.set(context, result)
        
        return result

    @measure_performance("ai_analysis_simple")
    async def _analyze_simple_code(self, context: AnalysisContext) -> SecurityAnalysisResult:
        """快速分析简单代码

        Args:
            context: 分析上下文

        Returns:
            安全分析结果
        """
        # 检查缓存
        cached_result = self._cache.get(context)
        if cached_result:
            logger.info(f"Using cached analysis for {context.file_path}")
            return cached_result

        # 使用快速分析提示词
        fast_prompt = self._prompt_manager.get_prompt("fast_analysis")
        
        prompt = f"文件路径: {context.file_path}\n语言: {context.language}\n\n代码内容:\n```\n{context.code_content}\n```"
        
        request = AIRequest(
            prompt=prompt,
            system_prompt=fast_prompt,
            temperature=0.0,
            max_tokens=2048,  # 减少token使用
            model=self.config.ai.model,  # 使用配置的模型
        )
        
        await self.initialize()
        response = await self._manager.generate(request)
        result = await self._parse_response(response.content, context)
        
        # 缓存结果
        self._cache.set(context, result)
        
        return result

    @measure_performance("ai_analysis_complex")
    async def _analyze_complex_code(self, context: AnalysisContext) -> SecurityAnalysisResult:
        """分析复杂代码

        Args:
            context: 分析上下文

        Returns:
            安全分析结果
        """
        # 检查缓存
        cached_result = self._cache.get(context)
        if cached_result:
            logger.info(f"Using cached analysis for {context.file_path}")
            return cached_result

        # 分块分析策略
        code_lines = context.code_content.split('\n')
        chunk_size = 100  # 每块100行
        chunks = []
        
        for i in range(0, len(code_lines), chunk_size):
            chunk_lines = code_lines[i:i+chunk_size]
            chunk_content = '\n'.join(chunk_lines)
            chunk_context = AnalysisContext(
                file_path=context.file_path,
                code_content=chunk_content,
                language=context.language,
                function_name=context.function_name,
                class_name=context.class_name,
                analysis_level=context.analysis_level,
                metadata={**context.metadata, 'chunk_index': i//chunk_size}
            )
            chunks.append(chunk_context)
        
        # 并行分析所有块
        results = await self.analyze_batch(chunks, max_concurrent=3)
        
        # 合并结果
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        result = SecurityAnalysisResult(
            findings=all_findings,
            risk_score=self._calculate_risk_score(all_findings),
            summary=f"分块分析完成，共 {len(all_findings)} 个问题",
            recommendations=[],
            metadata={**context.metadata, 'analyzed_chunks': len(chunks)}
        )
        
        # 缓存结果
        self._cache.set(context, result)
        
        return result

    def _build_prompt(self, context: AnalysisContext) -> str:
        """构建分析提示"""
        prompt_parts = [
            f"文件路径: {context.file_path}",
            f"语言: {context.language}",
            f"分析级别: {context.analysis_level.value}",
        ]

        if context.function_name:
            prompt_parts.append(f"函数名: {context.function_name}")
        if context.class_name:
            prompt_parts.append(f"类名: {context.class_name}")

        # 处理多模态内容
        if context.multimodal_content:
            for i, content in enumerate(context.multimodal_content):
                if content.type == "image":
                    prompt_parts.append(f"\n## 图像 {i+1}")
                    prompt_parts.append("分析此图像中可能包含的安全相关信息，如敏感数据、密码、密钥等。")
                elif content.type == "text":
                    prompt_parts.append(f"\n## 附加文本 {i+1}")
                    prompt_parts.append(content.content)

        prompt_parts.append("\n代码内容:\n```\n" + context.code_content + "\n```")

        # 添加分析要求
        prompt_parts.append("\n分析要求:")
        prompt_parts.append("1. 识别所有潜在的安全漏洞和风险")
        prompt_parts.append("2. 提供详细的漏洞描述和影响分析")
        prompt_parts.append("3. 提供具体的修复建议")
        prompt_parts.append("4. 评估漏洞的严重程度和置信度")
        prompt_parts.append("5. 提供漏洞利用场景")

        return "\n".join(prompt_parts)

    @measure_performance("ai_parse_response")
    async def _parse_response(
        self, content: str, context: AnalysisContext
    ) -> SecurityAnalysisResult:
        """解析 AI 响应"""
        # 尝试解析 JSON
        parsed = self._json_parser.parse(content)

        if parsed is None:
            return SecurityAnalysisResult(
                summary="无法解析 AI 响应",
                metadata={"raw_content": content[:500]},
            )

        # 提取发现
        findings_data = parsed.get("findings", [])
        findings = []

        for data in findings_data:
            # 移除 file_path 字段，因为 VulnerabilityFinding 不支持
            if 'file_path' in data:
                del data['file_path']
            
            # 确保 location 是字典
            location = data.get("location", {})
            if isinstance(location, str):
                location = {"file": location, "line": 0, "column": 0}
            
            finding = VulnerabilityFinding(
                rule_id=data.get("rule_id", "UNKNOWN"),
                rule_name=data.get("rule_name", "Unknown"),
                description=data.get("description", ""),
                severity=data.get("severity", "medium").lower(),
                confidence=data.get("confidence", 0.5),
                location=location,
                code_snippet=data.get("code_snippet", ""),
                fix_suggestion=data.get("fix_suggestion", ""),
                explanation=data.get("explanation", ""),
                references=data.get("references", []),
            )
            findings.append(finding)

        # 应用误报过滤
        filtered_findings = await self._filter_false_positives(findings, context)

        return SecurityAnalysisResult(
            findings=filtered_findings,
            risk_score=parsed.get("risk_score", self._calculate_risk_score(filtered_findings)),
            summary=parsed.get("summary", self._generate_summary(filtered_findings)),
            recommendations=parsed.get("recommendations", []),
            metadata={
                "file_path": context.file_path,
                "language": context.language,
                "analysis_level": context.analysis_level.value,
                "filtered_count": len(findings) - len(filtered_findings),
            },
        )

    @measure_performance("ai_filter_false_positives")
    async def _filter_false_positives(self, findings: List[VulnerabilityFinding], context: AnalysisContext) -> List[VulnerabilityFinding]:
        """过滤误报

        结合硬规则和AI分析双重过滤

        Args:
            findings: 原始发现列表
            context: 分析上下文

        Returns:
            过滤后的发现列表
        """
        # 转换为字典格式以便过滤
        findings_dict = [
            {
                "file_path": context.file_path,
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "description": finding.description,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "location": finding.location,
                "code_snippet": finding.code_snippet,
                "fix_suggestion": finding.fix_suggestion,
                "explanation": finding.explanation,
                "references": finding.references
            }
            for finding in findings
        ]

        # 应用增强过滤
        success, filtered_results, stats = await self._filter.filter_findings(findings_dict, {
            "language": context.language,
            "analysis_level": context.analysis_level.value
        })

        # 转换回 VulnerabilityFinding 对象
        filtered = []
        for finding_dict in filtered_results.get("filtered_findings", []):
            # 移除过滤元数据
            finding_dict.pop('_filter_metadata', None)
            # 移除 file_path 字段，因为 VulnerabilityFinding 不支持
            finding_dict.pop('file_path', None)
            # 创建 VulnerabilityFinding 对象
            finding = VulnerabilityFinding(**finding_dict)
            filtered.append(finding)

        return filtered

    def _apply_hard_filters(self, finding: VulnerabilityFinding, context: AnalysisContext) -> bool:
        """应用硬规则过滤

        Args:
            finding: 漏洞发现
            context: 分析上下文

        Returns:
            是否为误报
        """
        # 硬编码的误报模式（参考 claude-code-security-review-main 项目）
        false_positive_patterns = {
            # SQL注入误报模式
            "SQL_INJECTION": [
                r"cursor\.execute\(['\"].*['\"]\s*\)"  # 硬编码SQL
            ],
            # 命令注入误报模式
            "CMD_INJECTION": [
                r"subprocess\.call\(\[['\"].*['\"]\]\)"  # 硬编码命令
            ],
            # XSS误报模式
            "XSS": [
                r"<[^>]*>"  # 简单HTML标签
            ],
            # 硬编码凭据误报模式
            "HARDCODED_CREDENTIALS": [
                r"password\s*=\s*['\"]test['\"]",  # 测试密码
                r"api_key\s*=\s*['\"]test['\"]"  # 测试API密钥
            ]
        }

        import re
        patterns = false_positive_patterns.get(finding.rule_id, [])
        for pattern in patterns:
            if re.search(pattern, finding.code_snippet):
                return True

        # 测试环境代码过滤
        if "test" in context.file_path.lower() or "mock" in context.file_path.lower() or "spec" in context.file_path.lower():
            if finding.severity in ["low", "info"]:
                return True

        # 检查是否为示例代码
        if "example" in context.file_path.lower() or "sample" in context.file_path.lower():
            # 只过滤低严重级别的问题
            if finding.severity in ["low", "info"]:
                return True

        # 检查是否为文档或注释中的代码
        if "doc" in context.file_path.lower() or "docs" in context.file_path.lower():
            if finding.severity in ["low", "info"]:
                return True

        return False

    def _contextual_filter(self, finding: VulnerabilityFinding, context: AnalysisContext) -> bool:
        """上下文感知过滤

        Args:
            finding: 漏洞发现
            context: 分析上下文

        Returns:
            是否为误报
        """
        # 检查是否在安全上下文中
        safe_contexts = [
            "escape", "sanitize", "validate", "clean",
            "html.escape", "urllib.parse.quote", "re.escape",
            "sqlalchemy", "paramiko", "requests.get",
            "shlex.quote", "subprocess.run", "check_output"
        ]

        code = context.code_content.lower()
        
        # 检查安全处理函数
        for safe_context in safe_contexts:
            if safe_context in code:
                # 如果发现安全处理函数，降低误报概率
                if finding.confidence < 0.7:
                    return True

        # 检查是否在测试上下文中
        test_contexts = ["assert", "test_", "mock", "pytest", "unittest"]
        for test_context in test_contexts:
            if test_context in code:
                if finding.severity in ["low", "info"]:
                    return True

        # 检查是否为常量或硬编码值
        if finding.rule_id == "SQL_INJECTION":
            # 检查是否为硬编码SQL
            import re
            if re.match(r"['\"].*['\"]", finding.code_snippet.strip()):
                return True

        if finding.rule_id == "CMD_INJECTION":
            # 检查是否为硬编码命令
            import re
            if re.match(r"\[['\"].*['\"]\]", finding.code_snippet.strip()):
                return True

        if finding.rule_id == "XSS":
            # 检查是否为React组件或模板文件
            if context.file_path.endswith(".jsx") or context.file_path.endswith(".tsx"):
                # React 通常会自动转义，降低误报概率
                if finding.confidence < 0.8:
                    return True

        return False

    def _calculate_risk_score(self, findings: List[VulnerabilityFinding]) -> float:
        """计算风险评分

        基于漏洞的严重程度、置信度和数量计算综合风险评分
        """
        if not findings:
            return 0.0

        # 严重程度权重
        severity_weights = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 1.0,
        }

        # 计算基础分数
        total_score = 0.0
        for finding in findings:
            weight = severity_weights.get(finding.severity, 5.0)
            total_score += weight * finding.confidence

        # 考虑漏洞数量的影响
        # 漏洞越多，风险越高，添加额外的惩罚
        count_penalty = min(len(findings) * 0.5, 5.0)
        
        # 计算最终分数
        final_score = total_score + count_penalty
        
        # 确保分数在合理范围内
        return min(final_score, 10.0)

    def _generate_summary(self, findings: List[VulnerabilityFinding]) -> str:
        """生成摘要"""
        if not findings:
            return "未发现安全问题"

        severity_counts: Dict[str, int] = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        summary_parts = [f"发现 {len(findings)} 个问题："]
        for severity, count in sorted(
            severity_counts.items(), key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0])
        ):
            if count > 0:
                summary_parts.append(f"- {severity}: {count}")

        return " ".join(summary_parts)
