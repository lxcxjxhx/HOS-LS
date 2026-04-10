"""漏洞分类器模块

提供基于AI的漏洞自动分类功能，包括级别、类型和详细描述的分类。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any

from src.ai.models import (
    AIRequest,
    AIResponse,
    SecurityAnalysisResult,
    VulnerabilityFinding,
    AnalysisContext,
)
from src.ai.prompts import get_prompt_manager
from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)


class VulnerabilitySeverity(Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """漏洞类型"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    HARDCODED_KEYS = "hardcoded_keys"
    INSECURE_RANDOM = "insecure_random"
    WEAK_CRYPTO = "weak_crypto"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_ISSUE = "authorization_issue"
    CSRF = "csrf"
    SSRF = "ssrf"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    XXE = "xxe"
    DOS = "dos"
    INFO_DISCLOSURE = "info_disclosure"
    OTHER = "other"


@dataclass
class ClassificationResult:
    """分类结果"""
    severity: str
    vulnerability_type: str
    confidence: float
    description: str
    additional_info: Dict[str, Any] = field(default_factory=dict)


class VulnerabilityClassifier:
    """漏洞分类器"""

    def __init__(self, config: Optional[Config] = None) -> None:
        from src.ai.client import AIModelManager
        self.config = config or get_config()
        self._manager: Optional[AIModelManager] = None
        self._prompt_manager = get_prompt_manager(self.config)
        self._system_prompt = self._load_system_prompt()
        from src.storage.rag_knowledge_base import get_rag_knowledge_base
        self._rag_knowledge_base = get_rag_knowledge_base()
        self._classification_rules = self._load_classification_rules()

    def _load_classification_rules(self) -> Dict[str, List[Tuple[str, str, float]]]:
        """加载分类规则

        Returns:
            分类规则字典，键为漏洞类型，值为(关键词, 严重程度, 置信度)元组列表
        """
        return {
            "sql_injection": [
                (r"select.*from.*where.*=\".*\"", "critical", 0.9),
                (r"insert.*into.*values.*\".*\"", "critical", 0.9),
                (r"update.*set.*where.*=\".*\"", "critical", 0.9),
                (r"delete.*from.*where.*=\".*\"", "critical", 0.9),
                (r"sql.*inject", "critical", 0.8),
            ],
            "command_injection": [
                (r"os\.system.*\".*\"", "critical", 0.9),
                (r"subprocess\.call.*\".*\"", "high", 0.8),
                (r"subprocess\.Popen.*\".*\"", "high", 0.8),
                (r"exec\(.*\".*\"", "high", 0.8),
                (r"eval\(.*\".*\"", "high", 0.8),
            ],
            "hardcoded_credentials": [
                (r"password.*=\".*\"", "medium", 0.8),
                (r"secret.*=\".*\"", "medium", 0.8),
                (r"api_key.*=\".*\"", "medium", 0.8),
                (r"token.*=\".*\"", "medium", 0.8),
            ],
            "weak_crypto": [
                (r"md5\(", "medium", 0.8),
                (r"sha1\(", "medium", 0.8),
                (r"DES", "medium", 0.8),
                (r"3DES", "medium", 0.8),
            ],
            "insecure_random": [
                (r"random\.rand", "low", 0.8),
                (r"random\.randint", "low", 0.8),
                (r"random\.choice", "low", 0.8),
            ],
            "sensitive_data_exposure": [
                (r"print\(.*password.*", "low", 0.7),
                (r"print\(.*secret.*", "low", 0.7),
                (r"print\(.*api_key.*", "low", 0.7),
            ],
        }

    def _load_system_prompt(self) -> str:
        """加载分类系统提示"""
        return self._prompt_manager.get_prompt("vulnerability_classification")

    async def initialize(self) -> None:
        """初始化分类器"""
        from src.ai.client import _manager, get_model_manager
        _manager = None
        self._manager = await get_model_manager(self.config)

    def _classify_by_rules(self, finding: VulnerabilityFinding, context: AnalysisContext) -> Optional[ClassificationResult]:
        """基于规则的分类

        Args:
            finding: 漏洞发现
            context: 分析上下文

        Returns:
            分类结果，如果没有匹配的规则则返回None
        """
        import re

        # 组合所有文本信息
        text = " ".join([
            finding.description or "",
            finding.code_snippet or "",
            finding.rule_name or "",
            finding.explanation or ""
        ]).lower()

        best_match = None
        highest_confidence = 0.0

        # 检查所有规则
        for vuln_type, rules in self._classification_rules.items():
            for pattern, severity, confidence in rules:
                if re.search(pattern, text):
                    if confidence > highest_confidence:
                        highest_confidence = confidence
                        best_match = (
                            vuln_type,
                            severity,
                            confidence
                        )

        # 检查RAG知识库
        knowledge_results = self._rag_knowledge_base.search_knowledge(text)
        for knowledge in knowledge_results:
            if knowledge.confidence > highest_confidence:
                highest_confidence = knowledge.confidence
                best_match = (
                    knowledge.tags[0] if knowledge.tags else "other",
                    knowledge.metadata.get("severity", "medium"),
                    knowledge.confidence
                )

        # 如果找到匹配且置信度足够高
        if best_match and highest_confidence >= 0.7:
            vuln_type, severity, confidence = best_match
            return ClassificationResult(
                severity=severity,
                vulnerability_type=vuln_type,
                confidence=confidence,
                description=finding.description or f"{vuln_type} vulnerability",
                additional_info={"classification_method": "rule-based"}
            )

        return None

    async def classify(self, finding: VulnerabilityFinding, context: AnalysisContext) -> ClassificationResult:
        """对漏洞进行分类

        Args:
            finding: 漏洞发现
            context: 分析上下文

        Returns:
            分类结果
        """
        # 首先尝试基于规则的分类
        rule_based_result = self._classify_by_rules(finding, context)
        if rule_based_result:
            return rule_based_result

        # 如果规则分类失败或置信度不足，使用AI分类
        await self.initialize()

        # 构建分类提示
        prompt = self._build_classification_prompt(finding, context)

        # 发送分类请求
        request = AIRequest(
            prompt=prompt,
            system_prompt=self._system_prompt,
            temperature=0.0,
            max_tokens=2048,
            model=self.config.ai.model,
        )

        response = await self._manager.generate(request)

        # 解析分类结果
        classification = self._parse_classification(response.content)

        # 将分类结果添加到知识库
        self._add_classification_to_knowledge(finding, classification)

        return classification

    def _add_classification_to_knowledge(self, finding: VulnerabilityFinding, classification: ClassificationResult) -> None:
        """将分类结果添加到RAG知识库

        Args:
            finding: 漏洞发现
            classification: 分类结果
        """
        from src.learning.self_learning import Knowledge, KnowledgeType

        # 创建知识对象
        knowledge = Knowledge(
            id=f"classify_{finding.rule_id}_{classification.vulnerability_type}",
            knowledge_type=KnowledgeType.ai_learning,
            content=f"{classification.vulnerability_type}: {classification.description}",
            source="auto_classification",
            confidence=classification.confidence,
            tags=[classification.vulnerability_type, classification.severity],
            metadata={
                "severity": classification.severity,
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name
            }
        )

        # 添加到RAG知识库
        self._rag_knowledge_base.add_knowledge(knowledge)

    def _build_classification_prompt(self, finding: VulnerabilityFinding, context: AnalysisContext) -> str:
        """构建分类提示"""
        prompt_parts = [
            f"漏洞描述: {finding.description}",
            f"代码片段: {finding.code_snippet}",
            f"文件路径: {context.file_path}",
            f"编程语言: {context.language}",
        ]

        if finding.rule_name:
            prompt_parts.append(f"规则名称: {finding.rule_name}")
        if finding.explanation:
            prompt_parts.append(f"漏洞解释: {finding.explanation}")

        prompt_parts.append("\n请对该漏洞进行分类:")
        prompt_parts.append("1. 严重程度: critical, high, medium, low, info")
        prompt_parts.append("2. 漏洞类型: sql_injection, xss, command_injection, hardcoded_credentials, hardcoded_keys, insecure_random, weak_crypto, sensitive_data_exposure, authentication_bypass, authorization_issue, csrf, ssrf, rce, lfi, rfi, xxe, dos, info_disclosure, other")
        prompt_parts.append("3. 详细描述: 符合规范的详细漏洞描述")
        prompt_parts.append("4. 置信度: 0-1之间的数值")
        prompt_parts.append("\n请以JSON格式返回结果，包含以下字段:")
        prompt_parts.append("{\n  \"severity\": \"...\",\n  \"vulnerability_type\": \"...\",\n  \"description\": \"...\",\n  \"confidence\": 0.0\n}")

        return "\n".join(prompt_parts)

    def _parse_classification(self, content: str) -> ClassificationResult:
        """解析分类结果"""
        import json
        
        try:
            # 提取JSON部分
            import re
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
            else:
                # 尝试直接解析
                data = json.loads(content)

            severity = data.get("severity", "medium")
            vulnerability_type = data.get("vulnerability_type", "other")
            description = data.get("description", "")
            confidence = data.get("confidence", 0.5)

            return ClassificationResult(
                severity=severity.lower(),
                vulnerability_type=vulnerability_type,
                confidence=confidence,
                description=description
            )
        except Exception as e:
            logger.error(f"分类结果解析失败: {e}")
            # 返回默认分类
            return ClassificationResult(
                severity="medium",
                vulnerability_type="other",
                confidence=0.3,
                description="无法自动分类的漏洞"
            )

    def get_severity_level(self, severity: str) -> VulnerabilitySeverity:
        """获取严重程度枚举值"""
        try:
            return VulnerabilitySeverity(severity)
        except ValueError:
            return VulnerabilitySeverity.MEDIUM

    def get_vulnerability_type(self, vuln_type: str) -> VulnerabilityType:
        """获取漏洞类型枚举值"""
        try:
            return VulnerabilityType(vuln_type)
        except ValueError:
            return VulnerabilityType.OTHER

    async def classify_batch(self, findings: List[VulnerabilityFinding], context: AnalysisContext) -> List[ClassificationResult]:
        """批量分类漏洞

        Args:
            findings: 漏洞发现列表
            context: 分析上下文

        Returns:
            分类结果列表
        """
        classifications = []
        ai_findings = []
        ai_indices = []

        # 首先尝试基于规则的分类
        for i, finding in enumerate(findings):
            rule_based_result = self._classify_by_rules(finding, context)
            if rule_based_result:
                classifications.append(rule_based_result)
            else:
                ai_findings.append(finding)
                ai_indices.append(i)

        # 对需要AI分类的漏洞进行批量处理
        if ai_findings:
            await self.initialize()

            # 构建批量分类提示
            prompt = self._build_batch_classification_prompt(ai_findings, context)

            # 发送批量分类请求
            request = AIRequest(
                prompt=prompt,
                system_prompt=self._system_prompt,
                temperature=0.0,
                max_tokens=4096,
                model=self.config.ai.model,
            )

            response = await self._manager.generate(request)

            # 解析批量分类结果
            ai_classifications = self._parse_batch_classification(response.content, len(ai_findings))

            # 将AI分类结果插入到正确的位置
            for i, idx in enumerate(ai_indices):
                if i < len(ai_classifications):
                    classification = ai_classifications[i]
                    classifications.insert(idx, classification)
                    # 将分类结果添加到知识库
                    self._add_classification_to_knowledge(ai_findings[i], classification)
                else:
                    # 如果解析失败，使用默认分类
                    default_classification = ClassificationResult(
                        severity="medium",
                        vulnerability_type="other",
                        confidence=0.3,
                        description="无法自动分类的漏洞"
                    )
                    classifications.insert(idx, default_classification)

        return classifications

    def _build_batch_classification_prompt(self, findings: List[VulnerabilityFinding], context: AnalysisContext) -> str:
        """构建批量分类提示"""
        prompt_parts = ["# 批量漏洞分类"]

        for i, finding in enumerate(findings):
            prompt_parts.append(f"\n## 漏洞 {i+1}")
            prompt_parts.append(f"描述: {finding.description}")
            prompt_parts.append(f"代码片段: {finding.code_snippet}")
            if finding.rule_name:
                prompt_parts.append(f"规则名称: {finding.rule_name}")
            if finding.explanation:
                prompt_parts.append(f"漏洞解释: {finding.explanation}")

        prompt_parts.append("\n请对以上漏洞进行分类:")
        prompt_parts.append("1. 严重程度: critical, high, medium, low, info")
        prompt_parts.append("2. 漏洞类型: sql_injection, xss, command_injection, hardcoded_credentials, hardcoded_keys, insecure_random, weak_crypto, sensitive_data_exposure, authentication_bypass, authorization_issue, csrf, ssrf, rce, lfi, rfi, xxe, dos, info_disclosure, other")
        prompt_parts.append("3. 详细描述: 符合规范的详细漏洞描述")
        prompt_parts.append("4. 置信度: 0-1之间的数值")

        prompt_parts.append("\n请以JSON格式返回结果，包含一个分类结果数组:")
        prompt_parts.append("[")
        prompt_parts.append("  {")
        prompt_parts.append("    \"severity\": \"...\",")
        prompt_parts.append("    \"vulnerability_type\": \"...\",")
        prompt_parts.append("    \"description\": \"...\",")
        prompt_parts.append("    \"confidence\": 0.0")
        prompt_parts.append("  }")
        prompt_parts.append("]")

        return "\n".join(prompt_parts)

    def _parse_batch_classification(self, content: str, expected_count: int) -> List[ClassificationResult]:
        """解析批量分类结果"""
        import json
        import re

        classifications = []

        try:
            # 提取JSON部分
            json_match = re.search(r'\[[\s\S]*\]', content)
            if json_match:
                json_str = json_match.group(0)
                data_list = json.loads(json_str)
            else:
                # 尝试直接解析
                data_list = json.loads(content)

            for data in data_list:
                severity = data.get("severity", "medium")
                vulnerability_type = data.get("vulnerability_type", "other")
                description = data.get("description", "")
                confidence = data.get("confidence", 0.5)

                classification = ClassificationResult(
                    severity=severity,
                    vulnerability_type=vulnerability_type,
                    confidence=confidence,
                    description=description,
                    additional_info={"classification_method": "ai-batch"}
                )
                classifications.append(classification)
        except Exception as e:
            logger.error(f"批量分类结果解析失败: {e}")

        # 确保返回的分类结果数量与预期一致
        while len(classifications) < expected_count:
            classifications.append(ClassificationResult(
                severity="medium",
                vulnerability_type="other",
                confidence=0.3,
                description="无法自动分类的漏洞"
            ))

        return classifications


class AutoClassifier:
    """自动分类器，集成到现有分析流程中"""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or get_config()
        self._classifier = VulnerabilityClassifier(config)

    async def enhance_findings(self, result: SecurityAnalysisResult, context: AnalysisContext) -> SecurityAnalysisResult:
        """增强漏洞发现结果，添加自动分类

        Args:
            result: 安全分析结果
            context: 分析上下文

        Returns:
            增强后的安全分析结果
        """
        if not result.findings:
            return result

        # 使用批量分类提高性能
        classifications = await self._classifier.classify_batch(result.findings, context)

        # 更新漏洞信息
        enhanced_findings = []
        for finding, classification in zip(result.findings, classifications):
            # 确保严重级别是小写的
            severity = classification.severity.lower()
            enhanced_finding = VulnerabilityFinding(
                rule_id=finding.rule_id,
                rule_name=finding.rule_name,
                description=classification.description or finding.description,
                severity=severity,
                confidence=classification.confidence,
                location=finding.location,
                code_snippet=finding.code_snippet,
                fix_suggestion=finding.fix_suggestion,
                explanation=finding.explanation,
                references=finding.references,
                exploit_scenario=finding.exploit_scenario
            )
            enhanced_findings.append(enhanced_finding)

        # 更新结果
        enhanced_result = SecurityAnalysisResult(
            findings=enhanced_findings,
            false_positives=result.false_positives,
            risk_score=result.risk_score,
            summary=result.summary,
            recommendations=result.recommendations,
            metadata={
                **result.metadata,
                "auto_classified": True,
                "classification_method": "batch"
            }
        )

        return enhanced_result
