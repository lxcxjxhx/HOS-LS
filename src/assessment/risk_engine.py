"""风险评估引擎模块

评估漏洞的综合风险，包括影响范围分析、可利用性评估和风险等级计算。
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class RiskLevel(Enum):
    """风险等级"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ImpactType(Enum):
    """影响类型"""

    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NON_REPUDIATION = "non_repudiation"


class Exploitability(Enum):
    """可利用性"""

    EASY = "easy"
    MODERATE = "moderate"
    DIFFICULT = "difficult"
    VERY_DIFFICULT = "very_difficult"


class AttackVector(Enum):
    """攻击向量"""

    NETWORK = "network"
    ADJACENT = "adjacent"
    LOCAL = "local"
    PHYSICAL = "physical"


class AttackComplexity(Enum):
    """攻击复杂度"""

    LOW = "low"
    HIGH = "high"


class PrivilegesRequired(Enum):
    """所需权限"""

    NONE = "none"
    LOW = "low"
    HIGH = "high"


class UserInteraction(Enum):
    """用户交互"""

    NONE = "none"
    REQUIRED = "required"


@dataclass
class Finding:
    """漏洞发现"""

    id: str
    rule_id: str
    name: str
    description: str
    severity: str
    confidence: float
    file_path: str
    line: int
    column: int = 0
    code_snippet: str = ""
    fix_suggestion: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
        }


@dataclass
class AssessmentContext:
    """评估上下文"""

    project_type: str = "web"
    environment: str = "production"
    data_sensitivity: str = "high"
    user_base: str = "public"
    compliance_requirements: List[str] = field(default_factory=list)
    existing_controls: List[str] = field(default_factory=list)
    asset_value: str = "high"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """风险评估结果"""

    finding_id: str
    risk_level: RiskLevel
    risk_score: float
    impact_score: float
    exploitability_score: float
    impact_types: List[ImpactType]
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    cvss_score: float
    cvss_vector: str
    business_impact: str
    remediation_priority: int
    confidence: float
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "finding_id": self.finding_id,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "impact_score": self.impact_score,
            "exploitability_score": self.exploitability_score,
            "impact_types": [it.value for it in self.impact_types],
            "attack_vector": self.attack_vector.value,
            "attack_complexity": self.attack_complexity.value,
            "privileges_required": self.privileges_required.value,
            "user_interaction": self.user_interaction.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "business_impact": self.business_impact,
            "remediation_priority": self.remediation_priority,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class RiskConfig:
    """风险配置"""

    critical_threshold: float = 0.9
    high_threshold: float = 0.7
    medium_threshold: float = 0.5
    low_threshold: float = 0.3

    impact_weight: float = 0.6
    exploitability_weight: float = 0.4

    max_risk_score: float = 10.0


CWE_IMPACT_MAP: Dict[str, Dict[str, Any]] = {
    "CWE-79": {
        "name": "XSS",
        "impact_types": [ImpactType.CONFIDENTIALITY, ImpactType.INTEGRITY],
        "default_severity": "medium",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-89": {
        "name": "SQL Injection",
        "impact_types": [
            ImpactType.CONFIDENTIALITY,
            ImpactType.INTEGRITY,
            ImpactType.AVAILABILITY,
        ],
        "default_severity": "high",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "impact_types": [
            ImpactType.CONFIDENTIALITY,
            ImpactType.INTEGRITY,
            ImpactType.AVAILABILITY,
        ],
        "default_severity": "critical",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-22": {
        "name": "Path Traversal",
        "impact_types": [ImpactType.CONFIDENTIALITY, ImpactType.INTEGRITY],
        "default_severity": "high",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-918": {
        "name": "SSRF",
        "impact_types": [ImpactType.CONFIDENTIALITY, ImpactType.INTEGRITY],
        "default_severity": "high",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-352": {
        "name": "CSRF",
        "impact_types": [ImpactType.INTEGRITY],
        "default_severity": "medium",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-306": {
        "name": "Missing Authentication",
        "impact_types": [
            ImpactType.CONFIDENTIALITY,
            ImpactType.INTEGRITY,
            ImpactType.AVAILABILITY,
        ],
        "default_severity": "critical",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "impact_types": [
            ImpactType.CONFIDENTIALITY,
            ImpactType.INTEGRITY,
            ImpactType.AVAILABILITY,
        ],
        "default_severity": "high",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "impact_types": [ImpactType.CONFIDENTIALITY, ImpactType.AUTHENTICATION],
        "default_severity": "critical",
        "attack_vector": AttackVector.LOCAL,
    },
    "CWE-200": {
        "name": "Information Exposure",
        "impact_types": [ImpactType.CONFIDENTIALITY],
        "default_severity": "medium",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-502": {
        "name": "Deserialization",
        "impact_types": [
            ImpactType.CONFIDENTIALITY,
            ImpactType.INTEGRITY,
            ImpactType.AVAILABILITY,
        ],
        "default_severity": "critical",
        "attack_vector": AttackVector.NETWORK,
    },
    "CWE-611": {
        "name": "XXE",
        "impact_types": [
            ImpactType.CONFIDENTIALITY,
            ImpactType.INTEGRITY,
            ImpactType.AVAILABILITY,
        ],
        "default_severity": "high",
        "attack_vector": AttackVector.NETWORK,
    },
}


class RiskAssessmentEngine:
    """风险评估引擎

    评估漏洞的综合风险，支持 CVSS 评分和业务影响分析。
    """

    def __init__(self, config: Optional[RiskConfig] = None):
        """初始化风险评估引擎

        Args:
            config: 风险配置
        """
        self.config = config or RiskConfig()
        self._assessments: Dict[str, RiskAssessment] = {}

    def assess_risk(
        self,
        finding: Finding,
        context: Optional[AssessmentContext] = None,
    ) -> RiskAssessment:
        """评估风险

        Args:
            finding: 漏洞发现
            context: 评估上下文

        Returns:
            风险评估结果
        """
        ctx = context or AssessmentContext()

        impact_score = self.calculate_impact_score(finding, ctx)
        exploitability_score = self.calculate_exploitability_score(finding, ctx)

        risk_score = (
            impact_score * self.config.impact_weight
            + exploitability_score * self.config.exploitability_weight
        ) * self.config.max_risk_score

        impact_types = self._determine_impact_types(finding)
        attack_vector = self._determine_attack_vector(finding)
        attack_complexity = self._determine_attack_complexity(finding)
        privileges_required = self._determine_privileges_required(finding)
        user_interaction = self._determine_user_interaction(finding)

        cvss_score, cvss_vector = self._calculate_cvss(
            finding,
            impact_score,
            exploitability_score,
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
        )

        risk_level = self.determine_risk_level(risk_score)
        business_impact = self._assess_business_impact(finding, ctx, impact_score)
        remediation_priority = self._calculate_remediation_priority(
            risk_score, business_impact, ctx
        )

        assessment = RiskAssessment(
            finding_id=finding.id,
            risk_level=risk_level,
            risk_score=risk_score,
            impact_score=impact_score,
            exploitability_score=exploitability_score,
            impact_types=impact_types,
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            business_impact=business_impact,
            remediation_priority=remediation_priority,
            confidence=finding.confidence,
        )

        self._assessments[finding.id] = assessment
        return assessment

    def calculate_impact_score(
        self,
        finding: Finding,
        context: Optional[AssessmentContext] = None,
    ) -> float:
        """计算影响评分

        Args:
            finding: 漏洞发现
            context: 评估上下文

        Returns:
            影响评分 (0.0 - 1.0)
        """
        score = 0.0
        ctx = context or AssessmentContext()

        severity_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1,
        }
        score += severity_scores.get(finding.severity.lower(), 0.5)

        if finding.cwe_id and finding.cwe_id in CWE_IMPACT_MAP:
            cwe_info = CWE_IMPACT_MAP[finding.cwe_id]
            impact_types = cwe_info.get("impact_types", [])
            score += len(impact_types) * 0.1

        if ctx.data_sensitivity == "high":
            score += 0.15
        elif ctx.data_sensitivity == "medium":
            score += 0.1

        if ctx.environment == "production":
            score += 0.1
        elif ctx.environment == "staging":
            score += 0.05

        if ctx.asset_value == "high":
            score += 0.1

        return min(score, 1.0)

    def calculate_exploitability_score(
        self,
        finding: Finding,
        context: Optional[AssessmentContext] = None,
    ) -> float:
        """计算可利用性评分

        Args:
            finding: 漏洞发现
            context: 评估上下文

        Returns:
            可利用性评分 (0.0 - 1.0)
        """
        score = 0.0
        ctx = context or AssessmentContext()

        if finding.confidence >= 0.9:
            score += 0.3
        elif finding.confidence >= 0.7:
            score += 0.2
        elif finding.confidence >= 0.5:
            score += 0.1

        if finding.cwe_id and finding.cwe_id in CWE_IMPACT_MAP:
            cwe_info = CWE_IMPACT_MAP[finding.cwe_id]
            attack_vector = cwe_info.get("attack_vector", AttackVector.NETWORK)
            if attack_vector == AttackVector.NETWORK:
                score += 0.3
            elif attack_vector == AttackVector.ADJACENT:
                score += 0.2
            elif attack_vector == AttackVector.LOCAL:
                score += 0.1

        code_snippet = finding.code_snippet.lower()
        easy_exploit_indicators = [
            "eval(",
            "exec(",
            "system(",
            "subprocess",
            "shell=true",
            "raw_input",
            "input(",
        ]
        for indicator in easy_exploit_indicators:
            if indicator in code_snippet:
                score += 0.1

        if ctx.existing_controls:
            score -= len(ctx.existing_controls) * 0.05

        return max(min(score, 1.0), 0.0)

    def determine_risk_level(self, assessment: Union[RiskAssessment, float]) -> RiskLevel:
        """确定风险等级

        Args:
            assessment: 风险评估结果或风险分数

        Returns:
            风险等级
        """
        if isinstance(assessment, RiskAssessment):
            score = assessment.risk_score / self.config.max_risk_score
        else:
            score = assessment / self.config.max_risk_score

        if score >= self.config.critical_threshold:
            return RiskLevel.CRITICAL
        elif score >= self.config.high_threshold:
            return RiskLevel.HIGH
        elif score >= self.config.medium_threshold:
            return RiskLevel.MEDIUM
        elif score >= self.config.low_threshold:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def get_assessment(self, finding_id: str) -> Optional[RiskAssessment]:
        """获取风险评估

        Args:
            finding_id: 发现ID

        Returns:
            风险评估结果
        """
        return self._assessments.get(finding_id)

    def get_all_assessments(self) -> List[RiskAssessment]:
        """获取所有风险评估

        Returns:
            所有风险评估列表
        """
        return list(self._assessments.values())

    def get_risk_statistics(self) -> Dict[str, Any]:
        """获取风险统计

        Returns:
            风险统计信息
        """
        assessments = list(self._assessments.values())

        if not assessments:
            return {
                "total": 0,
                "by_level": {},
                "avg_risk_score": 0.0,
                "avg_cvss_score": 0.0,
            }

        by_level: Dict[str, int] = {}
        for assessment in assessments:
            level = assessment.risk_level.value
            by_level[level] = by_level.get(level, 0) + 1

        avg_risk_score = sum(a.risk_score for a in assessments) / len(assessments)
        avg_cvss_score = sum(a.cvss_score for a in assessments) / len(assessments)

        return {
            "total": len(assessments),
            "by_level": by_level,
            "avg_risk_score": avg_risk_score,
            "avg_cvss_score": avg_cvss_score,
        }

    def _determine_impact_types(self, finding: Finding) -> List[ImpactType]:
        """确定影响类型

        Args:
            finding: 漏洞发现

        Returns:
            影响类型列表
        """
        if finding.cwe_id and finding.cwe_id in CWE_IMPACT_MAP:
            return CWE_IMPACT_MAP[finding.cwe_id].get("impact_types", [ImpactType.INTEGRITY])

        impact_types: List[ImpactType] = []

        code_snippet = finding.code_snippet.lower()

        if any(
            kw in code_snippet
            for kw in ["password", "secret", "key", "token", "credential"]
        ):
            impact_types.append(ImpactType.CONFIDENTIALITY)

        if any(
            kw in code_snippet
            for kw in ["update", "delete", "modify", "write", "insert"]
        ):
            impact_types.append(ImpactType.INTEGRITY)

        if any(kw in code_snippet for kw in ["dos", "crash", "hang", "block"]):
            impact_types.append(ImpactType.AVAILABILITY)

        if any(kw in code_snippet for kw in ["auth", "login", "session", "token"]):
            impact_types.append(ImpactType.AUTHENTICATION)

        if any(kw in code_snippet for kw in ["permission", "role", "access", "privilege"]):
            impact_types.append(ImpactType.AUTHORIZATION)

        if not impact_types:
            impact_types.append(ImpactType.INTEGRITY)

        return impact_types

    def _determine_attack_vector(self, finding: Finding) -> AttackVector:
        """确定攻击向量

        Args:
            finding: 漏洞发现

        Returns:
            攻击向量
        """
        if finding.cwe_id and finding.cwe_id in CWE_IMPACT_MAP:
            return CWE_IMPACT_MAP[finding.cwe_id].get(
                "attack_vector", AttackVector.NETWORK
            )

        code_snippet = finding.code_snippet.lower()

        if any(
            kw in code_snippet
            for kw in ["request", "http", "url", "param", "query", "form"]
        ):
            return AttackVector.NETWORK

        if any(kw in code_snippet for kw in ["file", "path", "read", "write"]):
            return AttackVector.LOCAL

        return AttackVector.NETWORK

    def _determine_attack_complexity(self, finding: Finding) -> AttackComplexity:
        """确定攻击复杂度

        Args:
            finding: 漏洞发现

        Returns:
            攻击复杂度
        """
        if finding.confidence >= 0.8:
            return AttackComplexity.LOW
        elif finding.confidence >= 0.5:
            return AttackComplexity.HIGH
        else:
            return AttackComplexity.HIGH

    def _determine_privileges_required(self, finding: Finding) -> PrivilegesRequired:
        """确定所需权限

        Args:
            finding: 漏洞发现

        Returns:
            所需权限
        """
        code_snippet = finding.code_snippet.lower()

        if any(
            kw in code_snippet
            for kw in ["admin", "root", "sudo", "superuser", "elevated"]
        ):
            return PrivilegesRequired.HIGH

        if any(kw in code_snippet for kw in ["user", "member", "authenticated"]):
            return PrivilegesRequired.LOW

        return PrivilegesRequired.NONE

    def _determine_user_interaction(self, finding: Finding) -> UserInteraction:
        """确定用户交互

        Args:
            finding: 漏洞发现

        Returns:
            用户交互
        """
        code_snippet = finding.code_snippet.lower()

        if any(kw in code_snippet for kw in ["click", "submit", "form", "button"]):
            return UserInteraction.REQUIRED

        return UserInteraction.NONE

    def _calculate_cvss(
        self,
        finding: Finding,
        impact_score: float,
        exploitability_score: float,
        attack_vector: AttackVector,
        attack_complexity: AttackComplexity,
        privileges_required: PrivilegesRequired,
        user_interaction: UserInteraction,
    ) -> Tuple[float, str]:
        """计算 CVSS 评分

        Args:
            finding: 漏洞发现
            impact_score: 影响评分
            exploitability_score: 可利用性评分
            attack_vector: 攻击向量
            attack_complexity: 攻击复杂度
            privileges_required: 所需权限
            user_interaction: 用户交互

        Returns:
            (CVSS 评分, CVSS 向量字符串)
        """
        av_map = {
            AttackVector.NETWORK: "N",
            AttackVector.ADJACENT: "A",
            AttackVector.LOCAL: "L",
            AttackVector.PHYSICAL: "P",
        }

        ac_map = {
            AttackComplexity.LOW: "L",
            AttackComplexity.HIGH: "H",
        }

        pr_map = {
            PrivilegesRequired.NONE: "N",
            PrivilegesRequired.LOW: "L",
            PrivilegesRequired.HIGH: "H",
        }

        ui_map = {
            UserInteraction.NONE: "N",
            UserInteraction.REQUIRED: "R",
        }

        iss = 1 - ((1 - impact_score) * (1 - impact_score) * (1 - impact_score))
        impact = 6.42 * iss

        exploitability = 8.22 * exploitability_score

        if impact <= 0:
            base_score = 0
        else:
            base_score = min((impact + exploitability), 10)

        cvss_vector = f"CVSS:3.1/AV:{av_map[attack_vector]}/AC:{ac_map[attack_complexity]}/PR:{pr_map[privileges_required]}/UI:{ui_map[user_interaction]}/C:H/I:H/A:H"

        return round(base_score, 1), cvss_vector

    def _assess_business_impact(
        self,
        finding: Finding,
        context: AssessmentContext,
        impact_score: float,
    ) -> str:
        """评估业务影响

        Args:
            finding: 漏洞发现
            context: 评估上下文
            impact_score: 影响评分

        Returns:
            业务影响描述
        """
        impacts: List[str] = []

        if impact_score >= 0.8:
            impacts.append("可能导致严重的数据泄露或系统被完全控制")
        elif impact_score >= 0.6:
            impacts.append("可能导致敏感数据泄露或系统功能受损")
        elif impact_score >= 0.4:
            impacts.append("可能导致部分数据泄露或功能异常")

        if context.data_sensitivity == "high":
            impacts.append("涉及高敏感数据")
        elif context.data_sensitivity == "medium":
            impacts.append("涉及中等敏感数据")

        if context.environment == "production":
            impacts.append("影响生产环境")

        if context.user_base == "public":
            impacts.append("影响公开用户")

        if context.compliance_requirements:
            impacts.append(f"可能违反合规要求: {', '.join(context.compliance_requirements)}")

        return "; ".join(impacts) if impacts else "影响较小"

    def _calculate_remediation_priority(
        self,
        risk_score: float,
        business_impact: str,
        context: AssessmentContext,
    ) -> int:
        """计算修复优先级

        Args:
            risk_score: 风险分数
            business_impact: 业务影响
            context: 评估上下文

        Returns:
            修复优先级 (1-5, 1最高)
        """
        priority = 5

        if risk_score >= 8:
            priority = 1
        elif risk_score >= 6:
            priority = 2
        elif risk_score >= 4:
            priority = 3
        elif risk_score >= 2:
            priority = 4

        if context.environment == "production":
            priority = max(1, priority - 1)

        if context.data_sensitivity == "high":
            priority = max(1, priority - 1)

        return priority
