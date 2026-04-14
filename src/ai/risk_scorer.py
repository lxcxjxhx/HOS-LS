"""风险评分模块

提供 Hybrid Risk Score 功能，融合传统规则评分和 AI 语义评分。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.ai.models import SecurityAnalysisResult, VulnerabilityFinding


@dataclass
class RiskScore:
    """风险评分"""

    overall_score: float = 0.0  # 0-10
    rule_score: float = 0.0  # 0-10
    ai_score: float = 0.0  # 0-10
    confidence: float = 0.0  # 0-1
    factors: Dict[str, float] = field(default_factory=dict)


class HybridRiskScorer:
    """混合风险评分器

    融合传统规则评分和 AI 语义评分。
    """

    def __init__(
        self,
        rule_weight: float = 0.4,
        ai_weight: float = 0.6,
    ) -> None:
        self.rule_weight = rule_weight
        self.ai_weight = ai_weight

    def calculate_score(
        self,
        finding: VulnerabilityFinding,
        ai_confidence: Optional[float] = None,
    ) -> RiskScore:
        """计算混合风险评分"""
        # 计算规则评分
        rule_score = self._calculate_rule_score(finding)

        # 计算 AI 评分
        ai_score = self._calculate_ai_score(finding, ai_confidence)

        # 计算综合评分
        overall_score = (
            rule_score * self.rule_weight + ai_score * self.ai_weight
        )

        # 计算置信度
        confidence = self._calculate_confidence(finding, ai_confidence)

        return RiskScore(
            overall_score=overall_score,
            rule_score=rule_score,
            ai_score=ai_score,
            confidence=confidence,
            factors={
                "severity_weight": self._get_severity_weight(finding.severity),
                "confidence_factor": finding.confidence,
                "ai_confidence": ai_confidence or finding.confidence,
            },
        )

    def calculate_project_score(
        self,
        result: SecurityAnalysisResult,
    ) -> RiskScore:
        """计算项目级风险评分"""
        if not result.findings:
            return RiskScore()

        total_score = 0.0
        total_confidence = 0.0

        for finding in result.findings:
            score = self.calculate_score(finding)
            total_score += score.overall_score
            total_confidence += score.confidence

        count = len(result.findings)
        return RiskScore(
            overall_score=total_score / count,
            confidence=total_confidence / count,
            factors={"finding_count": count},
        )

    def _calculate_rule_score(self, finding: VulnerabilityFinding) -> float:
        """计算规则评分"""
        severity_weight = self._get_severity_weight(finding.severity)
        return severity_weight * finding.confidence

    def _calculate_ai_score(
        self,
        finding: VulnerabilityFinding,
        ai_confidence: Optional[float] = None,
    ) -> float:
        """计算 AI 评分"""
        confidence = ai_confidence or finding.confidence
        severity_weight = self._get_severity_weight(finding.severity)
        return severity_weight * confidence

    def _calculate_confidence(
        self,
        finding: VulnerabilityFinding,
        ai_confidence: Optional[float] = None,
    ) -> float:
        """计算综合置信度"""
        if ai_confidence is not None:
            return (finding.confidence + ai_confidence) / 2
        return finding.confidence

    def _get_severity_weight(self, severity) -> float:
        """获取严重级别权重"""
        weights = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 1.0,
        }
        if hasattr(severity, 'value'):
            severity_str = severity.value
        else:
            severity_str = str(severity)
        return weights.get(severity_str.lower(), 5.0)
