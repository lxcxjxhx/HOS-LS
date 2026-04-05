"""漏洞优先级评估模块

实现基于AI的漏洞优先级评估，考虑漏洞的上下文和潜在影响，生成优先级排序的漏洞报告。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from src.ai.client import AIModelManager, get_model_manager
from src.ai.models import (
    AIRequest,
    SecurityAnalysisResult,
    VulnerabilityFinding,
    AnalysisContext,
)
from src.ai.prompts import get_prompt_manager
from src.storage.rag_knowledge_base import get_rag_knowledge_base
from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)


@dataclass
class PriorityResult:
    """优先级评估结果"""
    vulnerability_id: str
    priority: int  # 1-5，1最高，5最低
    score: float  # 0-1，1最高
    factors: Dict[str, float]  # 各个因素的得分
    rationale: str  # 优先级评估的理由
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PriorityAnalysisResult:
    """优先级分析结果"""
    priority_results: List[PriorityResult]
    prioritized_findings: List[VulnerabilityFinding]
    summary: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class VulnerabilityPriorityEvaluator:
    """漏洞优先级评估器

    基于AI的漏洞优先级评估，考虑漏洞的上下文和潜在影响。
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        """初始化优先级评估器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._manager: Optional[AIModelManager] = None
        self._prompt_manager = get_prompt_manager(self.config)
        self._system_prompt = self._load_system_prompt()
        self._rag_knowledge_base = get_rag_knowledge_base()
        self._priority_factors = self._load_priority_factors()

    def _load_system_prompt(self) -> str:
        """加载优先级评估系统提示"""
        return self._prompt_manager.get_prompt("priority_evaluation")

    def _load_priority_factors(self) -> Dict[str, float]:
        """加载优先级评估因素及其权重

        Returns:
            优先级评估因素及其权重
        """
        return {
            "severity": 0.3,  # 严重程度
            "exploitability": 0.25,  # 可利用性
            "impact": 0.25,  # 影响范围
            "context": 0.1,  # 上下文因素
            "asset_value": 0.1,  # 资产价值
        }

    async def initialize(self) -> None:
        """初始化优先级评估器"""
        from src.ai.client import _manager
        _manager = None
        self._manager = await get_model_manager(self.config)

    async def evaluate_priority(self, finding: VulnerabilityFinding, context: AnalysisContext) -> PriorityResult:
        """评估漏洞优先级

        Args:
            finding: 漏洞发现
            context: 分析上下文

        Returns:
            优先级评估结果
        """
        # 计算基于规则的优先级得分
        rule_based_score = self._calculate_rule_based_score(finding, context)

        # 如果规则基于的得分足够高，直接返回
        if rule_based_score > 0.8:
            priority = self._score_to_priority(rule_based_score)
            return PriorityResult(
                vulnerability_id=finding.rule_id,
                priority=priority,
                score=rule_based_score,
                factors={"rule_based": rule_based_score},
                rationale="基于规则的优先级评估",
                metadata={"evaluation_method": "rule-based"}
            )

        # 使用AI进行更详细的优先级评估
        await self.initialize()

        # 构建评估提示
        prompt = self._build_priority_prompt(finding, context)

        # 发送评估请求
        request = AIRequest(
            prompt=prompt,
            system_prompt=self._system_prompt,
            temperature=0.1,
            max_tokens=2048,
            model=self.config.ai.model,
        )

        response = await self._manager.generate(request)

        # 解析评估结果
        priority_result = self._parse_priority_result(response.content, finding.rule_id)

        # 将评估结果添加到知识库
        self._add_priority_to_knowledge(finding, priority_result)

        return priority_result

    def _calculate_rule_based_score(self, finding: VulnerabilityFinding, context: AnalysisContext) -> float:
        """基于规则的优先级得分计算

        Args:
            finding: 漏洞发现
            context: 分析上下文

        Returns:
            优先级得分 (0-1)
        """
        # 严重程度得分
        severity_score = self._get_severity_score(finding.severity)

        # 可利用性得分
        exploitability_score = self._get_exploitability_score(finding)

        # 影响范围得分
        impact_score = self._get_impact_score(finding)

        # 上下文得分
        context_score = self._get_context_score(context)

        # 资产价值得分
        asset_value_score = self._get_asset_value_score(context)

        # 计算加权总分
        total_score = 0.0
        for factor, weight in self._priority_factors.items():
            if factor == "severity":
                total_score += severity_score * weight
            elif factor == "exploitability":
                total_score += exploitability_score * weight
            elif factor == "impact":
                total_score += impact_score * weight
            elif factor == "context":
                total_score += context_score * weight
            elif factor == "asset_value":
                total_score += asset_value_score * weight

        return min(total_score, 1.0)

    def _get_severity_score(self, severity: str) -> float:
        """获取严重程度得分

        Args:
            severity: 严重程度

        Returns:
            严重程度得分 (0-1)
        """
        severity_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1
        }
        return severity_scores.get(severity.lower(), 0.5)

    def _get_exploitability_score(self, finding: VulnerabilityFinding) -> float:
        """获取可利用性得分

        Args:
            finding: 漏洞发现

        Returns:
            可利用性得分 (0-1)
        """
        # 基于漏洞类型的可利用性得分
        exploitability_scores = {
            "sql_injection": 0.9,
            "command_injection": 0.9,
            "rce": 0.95,
            "xss": 0.7,
            "csrf": 0.6,
            "ssrf": 0.8,
            "lfi": 0.75,
            "rfi": 0.85,
            "xxe": 0.7,
            "hardcoded_credentials": 0.8,
            "weak_crypto": 0.6,
            "insecure_random": 0.5,
            "sensitive_data_exposure": 0.7,
            "authentication_bypass": 0.9,
            "authorization_issue": 0.8,
            "dos": 0.6,
            "info_disclosure": 0.5
        }

        # 提取漏洞类型
        vuln_type = finding.rule_id.split('-')[0].lower() if '-' in finding.rule_id else finding.rule_name.lower()

        # 查找可利用性得分
        for key, score in exploitability_scores.items():
            if key in vuln_type:
                return score

        return 0.5  # 默认值

    def _get_impact_score(self, finding: VulnerabilityFinding) -> float:
        """获取影响范围得分

        Args:
            finding: 漏洞发现

        Returns:
            影响范围得分 (0-1)
        """
        # 基于漏洞类型的影响范围得分
        impact_scores = {
            "sql_injection": 0.9,
            "command_injection": 0.95,
            "rce": 0.95,
            "xss": 0.6,
            "csrf": 0.7,
            "ssrf": 0.8,
            "lfi": 0.8,
            "rfi": 0.9,
            "xxe": 0.7,
            "hardcoded_credentials": 0.8,
            "weak_crypto": 0.7,
            "insecure_random": 0.6,
            "sensitive_data_exposure": 0.8,
            "authentication_bypass": 0.9,
            "authorization_issue": 0.8,
            "dos": 0.7,
            "info_disclosure": 0.6
        }

        # 提取漏洞类型
        vuln_type = finding.rule_id.split('-')[0].lower() if '-' in finding.rule_id else finding.rule_name.lower()

        # 查找影响范围得分
        for key, score in impact_scores.items():
            if key in vuln_type:
                return score

        return 0.5  # 默认值

    def _get_context_score(self, context: AnalysisContext) -> float:
        """获取上下文得分

        Args:
            context: 分析上下文

        Returns:
            上下文得分 (0-1)
        """
        # 基于文件路径和语言的上下文得分
        context_score = 0.5

        # 敏感文件路径
        sensitive_paths = ["auth", "login", "password", "secret", "api", "config", "database"]
        for path in sensitive_paths:
            if path in context.file_path.lower():
                context_score += 0.2
                break

        # 关键语言
        critical_languages = ["python", "javascript", "java", "php"]
        if context.language in critical_languages:
            context_score += 0.1

        return min(context_score, 1.0)

    def _get_asset_value_score(self, context: AnalysisContext) -> float:
        """获取资产价值得分

        Args:
            context: 分析上下文

        Returns:
            资产价值得分 (0-1)
        """
        # 基于文件路径的资产价值得分
        asset_value_score = 0.5

        # 高价值资产路径
        high_value_paths = ["production", "prod", "live", "main", "master"]
        for path in high_value_paths:
            if path in context.file_path.lower():
                asset_value_score += 0.3
                break

        return min(asset_value_score, 1.0)

    def _score_to_priority(self, score: float) -> int:
        """将得分转换为优先级

        Args:
            score: 优先级得分

        Returns:
            优先级 (1-5)
        """
        if score >= 0.9:
            return 1  # 最高优先级
        elif score >= 0.7:
            return 2
        elif score >= 0.5:
            return 3
        elif score >= 0.3:
            return 4
        else:
            return 5  # 最低优先级

    def _build_priority_prompt(self, finding: VulnerabilityFinding, context: AnalysisContext) -> str:
        """构建优先级评估提示"""
        prompt_parts = [
            f"漏洞描述: {finding.description}",
            f"代码片段: {finding.code_snippet}",
            f"文件路径: {context.file_path}",
            f"编程语言: {context.language}",
            f"严重程度: {finding.severity}",
            f"置信度: {finding.confidence}",
        ]

        if finding.rule_name:
            prompt_parts.append(f"规则名称: {finding.rule_name}")
        if finding.explanation:
            prompt_parts.append(f"漏洞解释: {finding.explanation}")
        if finding.fix_suggestion:
            prompt_parts.append(f"修复建议: {finding.fix_suggestion}")

        prompt_parts.append("\n请评估该漏洞的优先级:")
        prompt_parts.append("1. 考虑因素: 严重程度、可利用性、影响范围、上下文、资产价值")
        prompt_parts.append("2. 优先级等级: 1-5 (1最高，5最低)")
        prompt_parts.append("3. 优先级得分: 0-1 (1最高)")
        prompt_parts.append("4. 各个因素的得分: 0-1")
        prompt_parts.append("5. 优先级评估的理由")

        prompt_parts.append("\n请以JSON格式返回结果，包含以下字段:")
        prompt_parts.append("{")
        prompt_parts.append("  \"priority\": 1,")
        prompt_parts.append("  \"score\": 0.0,")
        prompt_parts.append("  \"factors\": {")
        prompt_parts.append("    \"severity\": 0.0,")
        prompt_parts.append("    \"exploitability\": 0.0,")
        prompt_parts.append("    \"impact\": 0.0,")
        prompt_parts.append("    \"context\": 0.0,")
        prompt_parts.append("    \"asset_value\": 0.0")
        prompt_parts.append("  },")
        prompt_parts.append("  \"rationale\": \"...\"")
        prompt_parts.append("}")

        return "\n".join(prompt_parts)

    def _parse_priority_result(self, content: str, vulnerability_id: str) -> PriorityResult:
        """解析优先级评估结果"""
        import json
        import re

        try:
            # 提取JSON部分
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
            else:
                # 尝试直接解析
                data = json.loads(content)

            priority = data.get("priority", 3)
            score = data.get("score", 0.5)
            factors = data.get("factors", {})
            rationale = data.get("rationale", "")

            return PriorityResult(
                vulnerability_id=vulnerability_id,
                priority=priority,
                score=score,
                factors=factors,
                rationale=rationale,
                metadata={"evaluation_method": "ai"}
            )
        except Exception as e:
            logger.error(f"优先级评估结果解析失败: {e}")
            # 返回默认优先级
            return PriorityResult(
                vulnerability_id=vulnerability_id,
                priority=3,
                score=0.5,
                factors={"severity": 0.5, "exploitability": 0.5, "impact": 0.5, "context": 0.5, "asset_value": 0.5},
                rationale="无法自动评估优先级",
                metadata={"evaluation_method": "default"}
            )

    def _add_priority_to_knowledge(self, finding: VulnerabilityFinding, priority_result: PriorityResult) -> None:
        """将优先级评估结果添加到RAG知识库

        Args:
            finding: 漏洞发现
            priority_result: 优先级评估结果
        """
        from src.learning.self_learning import Knowledge, KnowledgeType

        # 创建知识对象
        knowledge = Knowledge(
            id=f"priority_{finding.rule_id}_{priority_result.priority}",
            knowledge_type=KnowledgeType.ai_learning,
            content=f"{finding.rule_name}: 优先级 {priority_result.priority}, 得分 {priority_result.score}",
            source="auto_priority_evaluation",
            confidence=priority_result.score,
            tags=[finding.rule_name, f"priority_{priority_result.priority}"],
            metadata={
                "priority": priority_result.priority,
                "score": priority_result.score,
                "factors": priority_result.factors,
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "severity": finding.severity
            }
        )

        # 添加到RAG知识库
        self._rag_knowledge_base.add_knowledge(knowledge)

    async def evaluate_batch_priority(self, findings: List[VulnerabilityFinding], context: AnalysisContext) -> List[PriorityResult]:
        """批量评估漏洞优先级

        Args:
            findings: 漏洞发现列表
            context: 分析上下文

        Returns:
            优先级评估结果列表
        """
        priority_results = []
        ai_findings = []
        ai_indices = []

        # 首先尝试基于规则的优先级评估
        for i, finding in enumerate(findings):
            rule_based_score = self._calculate_rule_based_score(finding, context)
            if rule_based_score > 0.8:
                priority = self._score_to_priority(rule_based_score)
                priority_result = PriorityResult(
                    vulnerability_id=finding.rule_id,
                    priority=priority,
                    score=rule_based_score,
                    factors={"rule_based": rule_based_score},
                    rationale="基于规则的优先级评估",
                    metadata={"evaluation_method": "rule-based"}
                )
                priority_results.append(priority_result)
            else:
                ai_findings.append(finding)
                ai_indices.append(i)

        # 对需要AI评估的漏洞进行批量处理
        if ai_findings:
            await self.initialize()

            # 构建批量评估提示
            prompt = self._build_batch_priority_prompt(ai_findings, context)

            # 发送批量评估请求
            request = AIRequest(
                prompt=prompt,
                system_prompt=self._system_prompt,
                temperature=0.1,
                max_tokens=4096,
                model=self.config.ai.model,
            )

            response = await self._manager.generate(request)

            # 解析批量评估结果
            ai_priority_results = self._parse_batch_priority_result(response.content, ai_findings)

            # 将AI评估结果插入到正确的位置
            for i, idx in enumerate(ai_indices):
                if i < len(ai_priority_results):
                    priority_result = ai_priority_results[i]
                    priority_results.insert(idx, priority_result)
                    # 将评估结果添加到知识库
                    self._add_priority_to_knowledge(ai_findings[i], priority_result)
                else:
                    # 如果解析失败，使用默认优先级
                    default_result = PriorityResult(
                        vulnerability_id=ai_findings[i].rule_id,
                        priority=3,
                        score=0.5,
                        factors={"severity": 0.5, "exploitability": 0.5, "impact": 0.5, "context": 0.5, "asset_value": 0.5},
                        rationale="无法自动评估优先级",
                        metadata={"evaluation_method": "default"}
                    )
                    priority_results.insert(idx, default_result)

        return priority_results

    def _build_batch_priority_prompt(self, findings: List[VulnerabilityFinding], context: AnalysisContext) -> str:
        """构建批量优先级评估提示"""
        prompt_parts = ["# 批量漏洞优先级评估"]

        for i, finding in enumerate(findings):
            prompt_parts.append(f"\n## 漏洞 {i+1}")
            prompt_parts.append(f"描述: {finding.description}")
            prompt_parts.append(f"代码片段: {finding.code_snippet}")
            prompt_parts.append(f"严重程度: {finding.severity}")
            if finding.rule_name:
                prompt_parts.append(f"规则名称: {finding.rule_name}")
            if finding.explanation:
                prompt_parts.append(f"漏洞解释: {finding.explanation}")

        prompt_parts.append("\n请评估以上漏洞的优先级:")
        prompt_parts.append("1. 考虑因素: 严重程度、可利用性、影响范围、上下文、资产价值")
        prompt_parts.append("2. 优先级等级: 1-5 (1最高，5最低)")
        prompt_parts.append("3. 优先级得分: 0-1 (1最高)")
        prompt_parts.append("4. 各个因素的得分: 0-1")
        prompt_parts.append("5. 优先级评估的理由")

        prompt_parts.append("\n请以JSON格式返回结果，包含一个优先级评估结果数组:")
        prompt_parts.append("[")
        prompt_parts.append("  {")
        prompt_parts.append("    \"priority\": 1,")
        prompt_parts.append("    \"score\": 0.0,")
        prompt_parts.append("    \"factors\": {")
        prompt_parts.append("      \"severity\": 0.0,")
        prompt_parts.append("      \"exploitability\": 0.0,")
        prompt_parts.append("      \"impact\": 0.0,")
        prompt_parts.append("      \"context\": 0.0,")
        prompt_parts.append("      \"asset_value\": 0.0")
        prompt_parts.append("    },")
        prompt_parts.append("    \"rationale\": \"...\"")
        prompt_parts.append("  }")
        prompt_parts.append("]")

        return "\n".join(prompt_parts)

    def _parse_batch_priority_result(self, content: str, findings: List[VulnerabilityFinding]) -> List[PriorityResult]:
        """解析批量优先级评估结果"""
        import json
        import re

        priority_results = []

        try:
            # 提取JSON部分
            json_match = re.search(r'\[[\s\S]*\]', content)
            if json_match:
                json_str = json_match.group(0)
                data_list = json.loads(json_str)
            else:
                # 尝试直接解析
                data_list = json.loads(content)

            for i, data in enumerate(data_list):
                if i < len(findings):
                    finding = findings[i]
                    priority = data.get("priority", 3)
                    score = data.get("score", 0.5)
                    factors = data.get("factors", {})
                    rationale = data.get("rationale", "")

                    priority_result = PriorityResult(
                        vulnerability_id=finding.rule_id,
                        priority=priority,
                        score=score,
                        factors=factors,
                        rationale=rationale,
                        metadata={"evaluation_method": "ai-batch"}
                    )
                    priority_results.append(priority_result)
        except Exception as e:
            logger.error(f"批量优先级评估结果解析失败: {e}")

        # 确保返回的评估结果数量与预期一致
        while len(priority_results) < len(findings):
            i = len(priority_results)
            finding = findings[i]
            default_result = PriorityResult(
                vulnerability_id=finding.rule_id,
                priority=3,
                score=0.5,
                factors={"severity": 0.5, "exploitability": 0.5, "impact": 0.5, "context": 0.5, "asset_value": 0.5},
                rationale="无法自动评估优先级",
                metadata={"evaluation_method": "default"}
            )
            priority_results.append(default_result)

        return priority_results

    async def prioritize_findings(self, result: SecurityAnalysisResult, context: AnalysisContext) -> PriorityAnalysisResult:
        """对漏洞发现进行优先级排序

        Args:
            result: 安全分析结果
            context: 分析上下文

        Returns:
            优先级分析结果
        """
        if not result.findings:
            return PriorityAnalysisResult(
                priority_results=[],
                prioritized_findings=[],
                summary="没有漏洞需要评估优先级"
            )

        # 批量评估优先级
        priority_results = await self.evaluate_batch_priority(result.findings, context)

        # 按优先级和得分排序
        sorted_pairs = sorted(
            zip(result.findings, priority_results),
            key=lambda x: (x[1].priority, -x[1].score)
        )

        # 分离排序后的结果
        prioritized_findings = [pair[0] for pair in sorted_pairs]
        sorted_priority_results = [pair[1] for pair in sorted_pairs]

        # 生成摘要
        summary = self._generate_priority_summary(sorted_priority_results)

        return PriorityAnalysisResult(
            priority_results=sorted_priority_results,
            prioritized_findings=prioritized_findings,
            summary=summary,
            metadata={
                "total_findings": len(result.findings),
                "priority_distribution": self._get_priority_distribution(sorted_priority_results)
            }
        )

    def _generate_priority_summary(self, priority_results: List[PriorityResult]) -> str:
        """生成优先级评估摘要

        Args:
            priority_results: 优先级评估结果列表

        Returns:
            优先级评估摘要
        """
        # 统计各优先级的数量
        priority_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for result in priority_results:
            priority_counts[result.priority] += 1

        # 生成摘要
        summary_parts = [
            f"优先级评估完成，共评估 {len(priority_results)} 个漏洞",
            f"最高优先级 (1): {priority_counts[1]} 个",
            f"高优先级 (2): {priority_counts[2]} 个",
            f"中优先级 (3): {priority_counts[3]} 个",
            f"低优先级 (4): {priority_counts[4]} 个",
            f"最低优先级 (5): {priority_counts[5]} 个"
        ]

        return "\n".join(summary_parts)

    def _get_priority_distribution(self, priority_results: List[PriorityResult]) -> Dict[int, int]:
        """获取优先级分布

        Args:
            priority_results: 优先级评估结果列表

        Returns:
            优先级分布
        """
        distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for result in priority_results:
            distribution[result.priority] += 1
        return distribution


class AIPriorityEvaluator:
    """AI优先级评估器，集成到现有分析流程中"""

    def __init__(self, config: Optional[Config] = None) -> None:
        """初始化AI优先级评估器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._evaluator = VulnerabilityPriorityEvaluator(config)

    async def prioritize_findings(self, result: SecurityAnalysisResult, context: AnalysisContext) -> PriorityAnalysisResult:
        """对漏洞发现进行优先级排序

        Args:
            result: 安全分析结果
            context: 分析上下文

        Returns:
            优先级分析结果
        """
        return await self._evaluator.prioritize_findings(result, context)


# 全局优先级评估器实例
_priority_evaluator: Optional[VulnerabilityPriorityEvaluator] = None


# 全局AI优先级评估器实例
_ai_priority_evaluator: Optional[AIPriorityEvaluator] = None


def get_priority_evaluator() -> VulnerabilityPriorityEvaluator:
    """获取全局优先级评估器实例

    Returns:
        优先级评估器实例
    """
    global _priority_evaluator
    if _priority_evaluator is None:
        _priority_evaluator = VulnerabilityPriorityEvaluator()
    return _priority_evaluator


def get_ai_priority_evaluator() -> AIPriorityEvaluator:
    """获取全局AI优先级评估器实例

    Returns:
        AI优先级评估器实例
    """
    global _ai_priority_evaluator
    if _ai_priority_evaluator is None:
        _ai_priority_evaluator = AIPriorityEvaluator()
    return _ai_priority_evaluator
