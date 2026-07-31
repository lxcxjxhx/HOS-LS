"""复合漏洞风险量化模型

基于 CodeX-Verify 论文的风险评估方法论，实现多维度漏洞风险量化分析。
通过可利用性 (Exploitability)、影响度 (Impact)、流行度 (Prevalence)、
可检测性 (Detectability) 四个维度对漏洞发现进行综合评分，
并映射到 CVSS v3.1 标准评分体系。

核心公式:
    CompositeRisk = w_e * Exploitability + w_i * Impact + w_p * Prevalence + w_d * Detectability

其中权重默认值为: w_e=0.30, w_i=0.35, w_p=0.15, w_d=0.20
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# 枚举与常量
# ---------------------------------------------------------------------------

class RiskSeverity(Enum):
    """风险严重等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackVector(Enum):
    """攻击向量类型"""
    NETWORK = "network"        # 远程网络可达
    ADJACENT = "adjacent"      # 相邻网络
    LOCAL = "local"            # 本地访问
    PHYSICAL = "physical"      # 物理访问


class AttackComplexity(Enum):
    """攻击复杂度"""
    LOW = "low"                # 简单攻击，无需特殊条件
    MEDIUM = "medium"          # 中等复杂度
    HIGH = "high"              # 复杂攻击，需要特殊条件


class ExploitCodeAvailability(Enum):
    """漏洞利用代码可用性"""
    AVAILABLE = "available"    # 已有公开利用代码
    FUNCTIONAL = "functional"  # 存在功能性利用代码
    PROOF_OF_CONCEPT = "poc"   # 仅有概念验证代码
    UNAVAILABLE = "unavailable"  # 无已知利用代码


class CIAImpact(Enum):
    """CIA 三要素影响级别"""
    HIGH = "high"
    LOW = "low"
    NONE = "none"


# ---------------------------------------------------------------------------
# CWE 流行度统计数据 (基于 NVD/CWE Top 25 2023-2024)
# ---------------------------------------------------------------------------

CWE_PREVALENCE_MAP: Dict[str, float] = {
    # CWE Top 25 高流行度漏洞 ( prevalence >= 70 )
    "CWE-79": 92.0,     # XSS
    "CWE-78": 78.0,     # OS Command Injection
    "CWE-89": 85.0,     # SQL Injection
    "CWE-416": 76.0,    # Use After Free
    "CWE-787": 82.0,    # Out-of-bounds Write
    "CWE-125": 74.0,    # Out-of-bounds Read
    "CWE-22": 71.0,     # Path Traversal
    "CWE-352": 70.0,    # CSRF
    "CWE-798": 72.0,    # Hard-coded Credentials
    "CWE-918": 73.0,    # SSRF
    "CWE-502": 77.0,    # Deserialization of Untrusted Data
    "CWE-434": 65.0,    # Unrestricted File Upload
    "CWE-20": 68.0,     # Improper Input Validation
    "CWE-23": 60.0,     # Improper Link Resolution
    "CWE-36": 55.0,     # Absolute Path Traversal
    "CWE-426": 58.0,    # Untrusted Search Path
    "CWE-190": 62.0,    # Integer Overflow
    "CWE-287": 67.0,    # Improper Authentication
    "CWE-522": 64.0,    # Insufficiently Protected Credentials
    "CWE-611": 69.0,    # XXE
    "CWE-732": 61.0,    # Incorrect Permission Assignment
    "CWE-617": 57.0,    # Reachable Assertion
    "CWE-476": 66.0,    # NULL Pointer Dereference
    "CWE-269": 63.0,    # Improper Privilege Management
    "CWE-295": 59.0,    # Improper Certificate Validation
    "CWE-306": 56.0,    # Missing Authentication
    "CWE-862": 54.0,    # Missing Authorization
    "CWE-863": 52.0,    # Incorrect Authorization
    "CWE-276": 50.0,    # Incorrect Default Permissions
    "CWE-94": 75.0,     # Code Injection
    "CWE-91": 48.0,     # XML Injection
    "CWE-119": 70.0,    # Buffer Overflow
    "CWE-120": 65.0,    # Classic Buffer Overflow
    "CWE-400": 60.0,    # Uncontrolled Resource Consumption
    "CWE-77": 72.0,     # Command Injection
    "CWE-90": 55.0,     # LDAP Injection
    "CWE-96": 53.0,     # Reflected XSS
    "CWE-601": 51.0,    # Open Redirect
    "CWE-311": 49.0,    # Missing Encryption of Sensitive Data
    "CWE-327": 58.0,    # Use of Broken Crypto Algorithm
    "CWE-330": 47.0,    # Use of Insufficiently Random Values
    "CWE-331": 45.0,    # Insufficient Entropy
    "CWE-362": 56.0,    # Race Condition
    "CWE-693": 50.0,    # Protection Mechanism Failure
    "CWE-706": 48.0,    # Use of Incorrectly-resolved Name
    "CWE-754": 53.0,    # Improper Check for Exceptional Conditions
    "CWE-760": 46.0,    # Use of Constant Salt
    "CWE-829": 54.0,    # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-834": 44.0,    # Excessive Iteration
    "CWE-908": 42.0,    # Use of Uninitialized Resource
    "CWE-940": 40.0,    # Improper Verification of Source
    "CWE-1021": 38.0,   # Improper Restriction of Rendered UI Layers
}

# 默认流行度（未列入统计的 CWE）
DEFAULT_PREVALENCE: float = 30.0


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class RiskScore:
    """单维度风险评分

    每个维度的取值范围均为 0-100:
    - exploitability: 可利用性，衡量攻击者利用该漏洞的难易程度
    - impact:         影响度，衡量漏洞被利用后造成的损害
    - prevalence:     流行度，衡量该漏洞类型在实际中的普遍程度
    - detectability:  可检测性，衡量该漏洞被自动化工具发现的容易程度
    """
    exploitability: float = 0.0
    impact: float = 0.0
    prevalence: float = 0.0
    detectability: float = 0.0

    def __post_init__(self) -> None:
        """校验各维度分数在 0-100 范围内"""
        for dim_name in ("exploitability", "impact", "prevalence", "detectability"):
            value = getattr(self, dim_name)
            if not 0.0 <= value <= 100.0:
                logger.warning(
                    "RiskScore.%s = %.2f 超出 [0, 100] 范围，已自动裁剪",
                    dim_name, value,
                )
                setattr(self, dim_name, max(0.0, min(100.0, value)))

    def to_dict(self) -> Dict[str, float]:
        """转换为字典"""
        return {
            "exploitability": round(self.exploitability, 2),
            "impact": round(self.impact, 2),
            "prevalence": round(self.prevalence, 2),
            "detectability": round(self.detectability, 2),
        }

    @property
    def average(self) -> float:
        """四维度简单平均"""
        return (self.exploitability + self.impact + self.prevalence + self.detectability) / 4.0


@dataclass
class CompositeRisk:
    """复合风险评分

    将多个风险维度通过加权方式组合为单一综合分数，
    同时保留各维度的详细评分以便后续分析和审计。

    Attributes:
        risk_score:       各维度原始评分
        weights:          各维度权重 (和为 1.0)
        composite_score:  加权综合分数 (0-100)
        cvss_score:       映射到 CVSS v3.1 的分数 (0.0-10.0)
        severity:         风险严重等级
        finding_id:       关联的漏洞发现标识
        metadata:         附加元数据
    """
    risk_score: RiskScore
    weights: Dict[str, float] = field(default_factory=lambda: {
        "exploitability": 0.30,
        "impact": 0.35,
        "prevalence": 0.15,
        "detectability": 0.20,
    })
    composite_score: float = 0.0
    cvss_score: float = 0.0
    severity: RiskSeverity = RiskSeverity.INFO
    finding_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """计算加权综合分数"""
        self.composite_score = self._calculate_composite()
        self.cvss_score = self._map_to_cvss()
        self.severity = self._classify_severity()

    def _calculate_composite(self) -> float:
        """计算加权综合分数

        公式: sum(weight_i * score_i) for each dimension
        """
        score = (
            self.weights.get("exploitability", 0.30) * self.risk_score.exploitability
            + self.weights.get("impact", 0.35) * self.risk_score.impact
            + self.weights.get("prevalence", 0.15) * self.risk_score.prevalence
            + self.weights.get("detectability", 0.20) * self.risk_score.detectability
        )
        return round(max(0.0, min(100.0, score)), 2)

    def _map_to_cvss(self) -> float:
        """将 0-100 综合分数映射到 CVSS v3.1 的 0.0-10.0 范围

        采用分段线性映射，确保与 CVSS 严重等级区间对齐:
        - Critical: 9.0-10.0  <->  composite 80-100
        - High:     7.0-8.9   <->  composite 55-79
        - Medium:   4.0-6.9   <->  composite 25-54
        - Low:      0.1-3.9   <->  composite 1-24
        - None:     0.0       <->  composite 0
        """
        cs = self.composite_score
        if cs >= 80.0:
            # 80-100 -> 9.0-10.0
            cvss = 9.0 + (cs - 80.0) / 20.0 * 1.0
        elif cs >= 55.0:
            # 55-79 -> 7.0-8.9
            cvss = 7.0 + (cs - 55.0) / 24.0 * 1.9
        elif cs >= 25.0:
            # 25-54 -> 4.0-6.9
            cvss = 4.0 + (cs - 25.0) / 29.0 * 2.9
        elif cs >= 1.0:
            # 1-24 -> 0.1-3.9
            cvss = 0.1 + (cs - 1.0) / 23.0 * 3.8
        else:
            cvss = 0.0
        return round(max(0.0, min(10.0, cvss)), 1)

    def _classify_severity(self) -> RiskSeverity:
        """根据综合分数划分严重等级"""
        if self.composite_score >= 80.0:
            return RiskSeverity.CRITICAL
        elif self.composite_score >= 55.0:
            return RiskSeverity.HIGH
        elif self.composite_score >= 25.0:
            return RiskSeverity.MEDIUM
        elif self.composite_score >= 1.0:
            return RiskSeverity.LOW
        else:
            return RiskSeverity.INFO

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "finding_id": self.finding_id,
            "risk_score": self.risk_score.to_dict(),
            "weights": self.weights,
            "composite_score": self.composite_score,
            "cvss_score": self.cvss_score,
            "severity": self.severity.value,
            "metadata": self.metadata,
        }


@dataclass
class RiskProfile:
    """文件/项目级别的风险画像

    汇总多个漏洞发现的复合风险评分，提供整体风险视图。

    Attributes:
        composite_risks:     各漏洞发现的复合风险列表
        file_path:           文件路径
        project_name:        项目名称
        overall_score:       综合风险分数 (0-100)
        overall_cvss:        综合 CVSS 分数 (0.0-10.0)
        overall_severity:    整体严重等级
        dimension_averages:  各维度平均值
        risk_distribution:   严重等级分布统计
        top_risks:           最高风险发现列表
    """
    composite_risks: List[CompositeRisk] = field(default_factory=list)
    file_path: str = ""
    project_name: str = ""
    overall_score: float = 0.0
    overall_cvss: float = 0.0
    overall_severity: RiskSeverity = RiskSeverity.INFO
    dimension_averages: Dict[str, float] = field(default_factory=dict)
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    top_risks: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """计算汇总指标"""
        self._calculate_overall()

    def _calculate_overall(self) -> None:
        """计算整体风险指标"""
        if not self.composite_risks:
            self.overall_score = 0.0
            self.overall_cvss = 0.0
            self.overall_severity = RiskSeverity.INFO
            self.dimension_averages = {
                "exploitability": 0.0,
                "impact": 0.0,
                "prevalence": 0.0,
                "detectability": 0.0,
            }
            self.risk_distribution = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            }
            return

        count = len(self.composite_risks)

        # 整体分数: 取最高分与平均分的加权组合 (偏向最坏情况)
        scores = [cr.composite_score for cr in self.composite_risks]
        max_score = max(scores)
        avg_score = sum(scores) / count
        # 70% 最高分 + 30% 平均分，体现最坏情况主导
        self.overall_score = round(max(0.0, min(100.0, max_score * 0.7 + avg_score * 0.3)), 2)

        # 整体 CVSS: 从综合分数重新映射
        self.overall_cvss = self._score_to_cvss(self.overall_score)

        # 整体严重等级
        self.overall_severity = self._score_to_severity(self.overall_score)

        # 各维度平均值
        exp_avg = sum(cr.risk_score.exploitability for cr in self.composite_risks) / count
        imp_avg = sum(cr.risk_score.impact for cr in self.composite_risks) / count
        prev_avg = sum(cr.risk_score.prevalence for cr in self.composite_risks) / count
        det_avg = sum(cr.risk_score.detectability for cr in self.composite_risks) / count
        self.dimension_averages = {
            "exploitability": round(exp_avg, 2),
            "impact": round(imp_avg, 2),
            "prevalence": round(prev_avg, 2),
            "detectability": round(det_avg, 2),
        }

        # 严重等级分布
        self.risk_distribution = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for cr in self.composite_risks:
            self.risk_distribution[cr.severity.value] += 1

        # Top 风险 (按综合分降序，取前 10)
        sorted_risks = sorted(self.composite_risks, key=lambda c: c.composite_score, reverse=True)
        self.top_risks = [cr.to_dict() for cr in sorted_risks[:10]]

    @staticmethod
    def _score_to_cvss(score: float) -> float:
        """0-100 分数映射到 CVSS v3.1 的 0.0-10.0"""
        if score >= 80.0:
            cvss = 9.0 + (score - 80.0) / 20.0 * 1.0
        elif score >= 55.0:
            cvss = 7.0 + (score - 55.0) / 24.0 * 1.9
        elif score >= 25.0:
            cvss = 4.0 + (score - 25.0) / 29.0 * 2.9
        elif score >= 1.0:
            cvss = 0.1 + (score - 1.0) / 23.0 * 3.8
        else:
            cvss = 0.0
        return round(max(0.0, min(10.0, cvss)), 1)

    @staticmethod
    def _score_to_severity(score: float) -> RiskSeverity:
        """分数划分严重等级"""
        if score >= 80.0:
            return RiskSeverity.CRITICAL
        elif score >= 55.0:
            return RiskSeverity.HIGH
        elif score >= 25.0:
            return RiskSeverity.MEDIUM
        elif score >= 1.0:
            return RiskSeverity.LOW
        return RiskSeverity.INFO

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "file_path": self.file_path,
            "project_name": self.project_name,
            "overall_score": self.overall_score,
            "overall_cvss": self.overall_cvss,
            "overall_severity": self.overall_severity.value,
            "dimension_averages": self.dimension_averages,
            "risk_distribution": self.risk_distribution,
            "total_findings": len(self.composite_risks),
            "top_risks": self.top_risks,
        }


# ---------------------------------------------------------------------------
# 风险量化器
# ---------------------------------------------------------------------------

class RiskQuantifier:
    """复合漏洞风险量化器

    基于 CodeX-Verify 论文的多维度风险评估方法，对漏洞发现进行量化分析。
    综合考量可利用性、影响度、流行度和可检测性四个维度，
    并映射到 CVSS v3.1 标准评分体系。

    典型用法::

        quantifier = RiskQuantifier()
        composite = quantifier.quantify_finding(finding_dict, context_dict)
        profile = quantifier.quantify_file(findings_list, file_meta_dict)
    """

    # 默认维度权重
    DEFAULT_WEIGHTS: Dict[str, float] = {
        "exploitability": 0.30,
        "impact": 0.35,
        "prevalence": 0.15,
        "detectability": 0.20,
    }

    # 漏洞类型到 CWE 的默认映射
    VULN_TO_CWE: Dict[str, str] = {
        "sql_injection": "CWE-89",
        "sqli": "CWE-89",
        "command_injection": "CWE-78",
        "cmdi": "CWE-78",
        "code_injection": "CWE-94",
        "xss": "CWE-79",
        "cross_site_scripting": "CWE-79",
        "path_traversal": "CWE-22",
        "directory_traversal": "CWE-22",
        "ssrf": "CWE-918",
        "xxe": "CWE-611",
        "deserialization": "CWE-502",
        "insecure_deserialization": "CWE-502",
        "hardcoded_credentials": "CWE-798",
        "hardcoded_secrets": "CWE-798",
        "weak_crypto": "CWE-327",
        "broken_crypto": "CWE-327",
        "auth_bypass": "CWE-287",
        "improper_auth": "CWE-287",
        "privilege_escalation": "CWE-269",
        "csrf": "CWE-352",
        "open_redirect": "CWE-601",
        "buffer_overflow": "CWE-120",
        "use_after_free": "CWE-416",
        "null_dereference": "CWE-476",
        "race_condition": "CWE-362",
        "dos": "CWE-400",
        "uncontrolled_resource": "CWE-400",
        "file_upload": "CWE-434",
        "sensitive_data_exposure": "CWE-311",
        "missing_encryption": "CWE-311",
        "improper_input_validation": "CWE-20",
    }

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        """初始化风险量化器

        Args:
            weights: 自定义维度权重。若未提供则使用默认权重。
                     权重之和应约等于 1.0，否则会自动归一化。
        """
        if weights is not None:
            total = sum(weights.values())
            if total > 0 and abs(total - 1.0) > 0.01:
                logger.info("权重之和 (%.4f) 不等于 1.0，自动归一化", total)
                self._weights = {k: v / total for k, v in weights.items()}
            else:
                self._weights = dict(weights)
        else:
            self._weights = dict(self.DEFAULT_WEIGHTS)

        logger.info(
            "RiskQuantifier 初始化完成，权重: %s",
            {k: round(v, 3) for k, v in self._weights.items()},
        )

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def quantify_finding(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> CompositeRisk:
        """量化单个漏洞发现的风险

        根据漏洞发现信息和上下文，计算可利用性、影响度、流行度、
        可检测性四个维度的评分，并综合为复合风险分数。

        Args:
            finding: 漏洞发现字典，应包含以下键:
                - rule_id / vulnerability_type: 漏洞类型标识
                - cwe_id: CWE 编号 (可选)
                - severity: 严重等级 (可选)
                - confidence: 置信度 (可选)
                - metadata: 附加元数据 (可选)
            context: 上下文信息字典，可包含:
                - attack_vector: 攻击向量 (network/local/adjacent/physical)
                - auth_required: 是否需要认证 (bool)
                - user_interaction: 是否需要用户交互 (bool)
                - scope_changed: 是否影响范围改变 (bool)
                - environment: 运行环境描述
                - exposure: 暴露面描述
                - has_public_exploit: 是否有公开利用代码 (bool)
                - cia: CIA 影响字典 {"confidentiality": "high", ...}

        Returns:
            CompositeRisk: 复合风险评分结果
        """
        finding_id = finding.get("rule_id", finding.get("vulnerability_type", "unknown"))
        logger.debug("量化漏洞发现: %s", finding_id)

        # 计算四个维度
        exploitability = self.calculate_exploitability(finding, context)
        impact = self.calculate_impact(finding, context)
        prevalence = self.calculate_prevalence(finding, context)
        detectability = self.calculate_detectability(finding, context)

        risk_score = RiskScore(
            exploitability=exploitability,
            impact=impact,
            prevalence=prevalence,
            detectability=detectability,
        )

        composite = CompositeRisk(
            risk_score=risk_score,
            weights=dict(self._weights),
            finding_id=str(finding_id),
            metadata={
                "vulnerability_type": finding.get("vulnerability_type", finding.get("rule_id", "")),
                "cwe_id": finding.get("cwe_id", self._resolve_cwe(finding)),
                "confidence": finding.get("confidence", 1.0),
                "original_severity": finding.get("severity", "unknown"),
            },
        )

        logger.debug(
            "漏洞 %s 量化结果: composite=%.2f, cvss=%.1f, severity=%s",
            finding_id, composite.composite_score, composite.cvss_score,
            composite.severity.value,
        )
        return composite

    def quantify_file(
        self,
        findings: List[Dict[str, Any]],
        file_meta: Dict[str, Any],
    ) -> RiskProfile:
        """量化文件中所有漏洞发现的风险

        对文件中的每个漏洞发现分别进行量化，然后汇总为文件级别的风险画像。

        Args:
            findings: 漏洞发现列表
            file_meta: 文件元数据字典，可包含:
                - file_path: 文件路径
                - project_name: 项目名称
                - language: 编程语言
                - line_count: 代码行数
                - context: 文件级别上下文 (可选)

        Returns:
            RiskProfile: 文件级风险画像
        """
        file_path = file_meta.get("file_path", "")
        project_name = file_meta.get("project_name", "")
        file_context = file_meta.get("context", {})

        logger.info(
            "量化文件风险: %s (共 %d 个发现)",
            file_path, len(findings),
        )

        composite_risks: List[CompositeRisk] = []
        for idx, finding in enumerate(findings):
            try:
                # 合并文件级上下文和发现级上下文
                merged_context = dict(file_context)
                merged_context.update(finding.get("context", {}))

                composite = self.quantify_finding(finding, merged_context)
                composite_risks.append(composite)
            except Exception as exc:
                logger.warning(
                    "量化第 %d 个发现时出错 (%s): %s",
                    idx, finding.get("rule_id", "unknown"), exc,
                )

        profile = RiskProfile(
            composite_risks=composite_risks,
            file_path=file_path,
            project_name=project_name,
        )

        logger.info(
            "文件 %s 风险画像: overall_score=%.2f, cvss=%.1f, severity=%s, findings=%d",
            file_path, profile.overall_score, profile.overall_cvss,
            profile.overall_severity.value, len(composite_risks),
        )
        return profile

    # ------------------------------------------------------------------
    # 可利用性计算
    # ------------------------------------------------------------------

    def calculate_exploitability(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """计算漏洞可利用性评分

        综合以下因素评估漏洞被利用的难易程度:
        1. 攻击向量 (远程/本地/物理)
        2. 攻击复杂度 (简单/中等/复杂)
        3. 是否需要认证
        4. 是否需要用户交互
        5. 已知利用代码的可用性

        Args:
            finding: 漏洞发现字典
            context: 上下文信息字典

        Returns:
            float: 可利用性评分 (0-100)
        """
        score = 0.0

        # --- 因素 1: 攻击向量 (最高 30 分) ---
        attack_vector = self._parse_attack_vector(context)
        vector_scores = {
            AttackVector.NETWORK: 30.0,
            AttackVector.ADJACENT: 22.0,
            AttackVector.LOCAL: 12.0,
            AttackVector.PHYSICAL: 5.0,
        }
        score += vector_scores.get(attack_vector, 12.0)

        # --- 因素 2: 攻击复杂度 (最高 20 分) ---
        complexity = self._parse_attack_complexity(finding, context)
        complexity_scores = {
            AttackComplexity.LOW: 20.0,
            AttackComplexity.MEDIUM: 12.0,
            AttackComplexity.HIGH: 5.0,
        }
        score += complexity_scores.get(complexity, 12.0)

        # --- 因素 3: 认证要求 (最高 20 分) ---
        auth_required = context.get("auth_required", None)
        if auth_required is None:
            auth_required = self._infer_auth_required(finding)
        if not auth_required:
            score += 20.0   # 无需认证
        else:
            score += 6.0    # 需要认证

        # --- 因素 4: 用户交互 (最高 15 分) ---
        user_interaction = context.get("user_interaction", None)
        if user_interaction is None:
            user_interaction = self._infer_user_interaction(finding)
        if not user_interaction:
            score += 15.0   # 无需用户交互
        else:
            score += 5.0    # 需要用户交互

        # --- 因素 5: 利用代码可用性 (最高 15 分) ---
        exploit_avail = self._parse_exploit_availability(finding, context)
        exploit_scores = {
            ExploitCodeAvailability.AVAILABLE: 15.0,
            ExploitCodeAvailability.FUNCTIONAL: 12.0,
            ExploitCodeAvailability.PROOF_OF_CONCEPT: 7.0,
            ExploitCodeAvailability.UNAVAILABLE: 2.0,
        }
        score += exploit_scores.get(exploit_avail, 2.0)

        return round(max(0.0, min(100.0, score)), 2)

    # ------------------------------------------------------------------
    # 影响度计算
    # ------------------------------------------------------------------

    def calculate_impact(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """计算漏洞影响度评分

        基于 CIA 三要素 (机密性、完整性、可用性) 评估漏洞被利用后的影响，
        同时考虑以下扩展影响因子:
        1. 数据泄露潜力
        2. 代码执行潜力
        3. 权限提升潜力
        4. 拒绝服务潜力
        5. 横向移动潜力

        Args:
            finding: 漏洞发现字典
            context: 上下文信息字典

        Returns:
            float: 影响度评分 (0-100)
        """
        # --- CIA 三要素基础分 (最高 50 分) ---
        cia = context.get("cia", {})
        conf_impact = self._parse_cia_level(
            cia.get("confidentiality", finding.get("confidentiality_impact", None)),
            default="medium",
        )
        integ_impact = self._parse_cia_level(
            cia.get("integrity", finding.get("integrity_impact", None)),
            default="medium",
        )
        avail_impact = self._parse_cia_level(
            cia.get("availability", finding.get("availability_impact", None)),
            default="medium",
        )

        cia_map = {"high": 1.0, "medium": 0.6, "low": 0.3, "none": 0.0}
        cia_score = (
            cia_map.get(conf_impact, 0.6)
            + cia_map.get(integ_impact, 0.6)
            + cia_map.get(avail_impact, 0.6)
        ) / 3.0 * 50.0

        # --- 扩展影响因子 (最高 50 分) ---
        ext_score = 0.0

        # 数据泄露潜力 (最高 12 分)
        data_breach = self._assess_data_breach_potential(finding, context)
        ext_score += data_breach

        # 代码执行潜力 (最高 14 分)
        code_exec = self._assess_code_execution_potential(finding, context)
        ext_score += code_exec

        # 权限提升潜力 (最高 10 分)
        priv_esc = self._assess_privilege_escalation_potential(finding, context)
        ext_score += priv_esc

        # 拒绝服务潜力 (最高 6 分)
        dos_potential = self._assess_dos_potential(finding, context)
        ext_score += dos_potential

        # 横向移动潜力 (最高 8 分)
        lateral = self._assess_lateral_movement_potential(finding, context)
        ext_score += lateral

        total = cia_score + ext_score
        return round(max(0.0, min(100.0, total)), 2)

    # ------------------------------------------------------------------
    # 流行度计算
    # ------------------------------------------------------------------

    def calculate_prevalence(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """计算漏洞流行度评分

        基于 CWE 统计数据评估该漏洞类型在实际中的普遍程度。
        同时考虑:
        1. CWE 排名数据 (主要因素)
        2. 该漏洞类型在已知 CVE 数据库中的出现频率
        3. 项目技术栈中该漏洞的常见程度

        Args:
            finding: 漏洞发现字典
            context: 上下文信息字典

        Returns:
            float: 流行度评分 (0-100)
        """
        # 解析 CWE ID
        cwe_id = finding.get("cwe_id", self._resolve_cwe(finding))
        base_prevalence = DEFAULT_PREVALENCE

        if cwe_id and cwe_id in CWE_PREVALENCE_MAP:
            base_prevalence = CWE_PREVALENCE_MAP[cwe_id]
            logger.debug("CWE %s 流行度基线: %.1f", cwe_id, base_prevalence)
        elif cwe_id:
            logger.debug("CWE %s 未在流行度统计中，使用默认值 %.1f", cwe_id, base_prevalence)

        # 调整因子: 项目技术栈相关性
        tech_stack = context.get("tech_stack", [])
        vuln_type = self._get_vuln_type(finding).lower()
        stack_bonus = 0.0

        # 如果漏洞类型与项目技术栈高度相关，适当提升流行度
        stack_relevance = {
            "sql_injection": ["django", "flask", "sqlalchemy", "jdbc", "mysql", "postgres"],
            "xss": ["express", "react", "vue", "angular", "django", "flask", "jinja"],
            "command_injection": ["subprocess", "os.system", "shell", "cgi"],
            "ssrf": ["requests", "urllib", "http.client", "axios", "fetch"],
            "deserialization": ["pickle", "yaml", "java.io", "marshal", "php.unserialize"],
            "path_traversal": ["flask", "django", "express", "fastapi", "nginx", "apache"],
        }

        relevant_stacks = stack_relevance.get(vuln_type, [])
        matching_stacks = [s for s in tech_stack if s.lower() in relevant_stacks]
        if matching_stacks:
            stack_bonus = min(len(matching_stacks) * 3.0, 10.0)

        # 调整因子: 是否有已知 CVE 关联
        has_cve = finding.get("metadata", {}).get("has_cve", context.get("has_cve", False))
        cve_bonus = 5.0 if has_cve else 0.0

        total = base_prevalence + stack_bonus + cve_bonus
        return round(max(0.0, min(100.0, total)), 2)

    # ------------------------------------------------------------------
    # 可检测性计算
    # ------------------------------------------------------------------

    def calculate_detectability(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """计算漏洞可检测性评分

        评估该漏洞被自动化工具或人工审计发现的容易程度。
        考虑因素:
        1. 是否有成熟的静态分析规则 (SAST)
        2. 是否有动态检测手段 (DAST)
        3. 漏洞模式是否明确/可模式化
        4. 是否需要深层数据流分析才能发现
        5. 误报率水平

        Args:
            finding: 漏洞发现字典
            context: 上下文信息字典

        Returns:
            float: 可检测性评分 (0-100)
        """
        score = 0.0
        vuln_type = self._get_vuln_type(finding).lower()

        # --- 因素 1: SAST 检测成熟度 (最高 30 分) ---
        sast_maturity = self._get_sast_detectability(vuln_type)
        score += sast_maturity

        # --- 因素 2: DAST 检测成熟度 (最高 25 分) ---
        dast_maturity = self._get_dast_detectability(vuln_type)
        score += dast_maturity

        # --- 因素 3: 模式明确性 (最高 20 分) ---
        pattern_clarity = self._assess_pattern_clarity(vuln_type)
        score += pattern_clarity

        # --- 因素 4: 数据流深度需求 (最高 15 分) ---
        # 越浅层越容易检测
        data_flow_depth = context.get("data_flow_depth", None)
        if data_flow_depth is None:
            data_flow_depth = self._estimate_data_flow_depth(finding)
        if data_flow_depth <= 1:
            score += 15.0   # 直接调用，极易检测
        elif data_flow_depth <= 3:
            score += 11.0   # 浅层传播
        elif data_flow_depth <= 6:
            score += 7.0    # 中层传播
        else:
            score += 3.0    # 深层传播，难以检测

        # --- 因素 5: 误报率调整 (最高 10 分) ---
        false_positive_rate = finding.get("metadata", {}).get(
            "false_positive_rate",
            context.get("false_positive_rate", None),
        )
        if false_positive_rate is not None:
            # 误报率越低，可检测性评分越高
            fp_score = max(0.0, (1.0 - float(false_positive_rate)) * 10.0)
            score += fp_score
        else:
            # 无数据时给中间分
            score += 5.0

        return round(max(0.0, min(100.0, score)), 2)

    # ------------------------------------------------------------------
    # CVSS v3.1 映射
    # ------------------------------------------------------------------

    def map_to_cvss(self, composite_risk: CompositeRisk) -> Dict[str, Any]:
        """将复合风险映射为 CVSS v3.1 格式的详细评分

        提供完整的 CVSS v3.1 向量字符串和各指标分解。

        Args:
            composite_risk: 复合风险评分结果

        Returns:
            Dict: CVSS v3.1 格式的评分详情
        """
        rs = composite_risk.risk_score

        # 推导 CVSS 各基础指标
        attack_vector = self._derive_cvss_attack_vector(rs.exploitability)
        attack_complexity = self._derive_cvss_attack_complexity(rs.exploitability)
        privileges_required = self._derive_cvss_privileges_required(rs.exploitability)
        user_interaction = self._derive_cvss_user_interaction(rs.exploitability)
        scope = self._derive_cvss_scope(rs.impact)
        confidentiality = self._derive_cvss_cia_impact(rs.impact, "confidentiality")
        integrity = self._derive_cvss_cia_impact(rs.impact, "integrity")
        availability = self._derive_cvss_cia_impact(rs.impact, "availability")

        # 构建 CVSS 向量字符串
        vector = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}"
            f"/PR:{privileges_required}/UI:{user_interaction}"
            f"/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        return {
            "cvss_version": "3.1",
            "cvss_score": composite_risk.cvss_score,
            "severity": composite_risk.severity.value.upper(),
            "vector_string": vector,
            "metrics": {
                "attack_vector": attack_vector,
                "attack_complexity": attack_complexity,
                "privileges_required": privileges_required,
                "user_interaction": user_interaction,
                "scope": scope,
                "confidentiality_impact": confidentiality,
                "integrity_impact": integrity,
                "availability_impact": availability,
            },
            "composite_score": composite_risk.composite_score,
            "dimension_scores": rs.to_dict(),
        }

    # ------------------------------------------------------------------
    # 内部辅助方法 - 解析与推断
    # ------------------------------------------------------------------

    def _get_vuln_type(self, finding: Dict[str, Any]) -> str:
        """从 finding 中提取漏洞类型"""
        return (
            finding.get("vulnerability_type", "")
            or finding.get("rule_id", "")
            or finding.get("type", "")
            or "unknown"
        )

    def _resolve_cwe(self, finding: Dict[str, Any]) -> str:
        """根据漏洞类型推断 CWE 编号"""
        cwe_id = finding.get("cwe_id", "")
        if cwe_id:
            return str(cwe_id)

        vuln_type = self._get_vuln_type(finding).lower()
        # 尝试直接匹配
        if vuln_type in self.VULN_TO_CWE:
            return self.VULN_TO_CWE[vuln_type]

        # 尝试部分匹配
        for key, cwe in self.VULN_TO_CWE.items():
            if key in vuln_type or vuln_type in key:
                return cwe

        return ""

    def _parse_attack_vector(self, context: Dict[str, Any]) -> AttackVector:
        """解析攻击向量"""
        av = context.get("attack_vector", "").lower()
        if av in ("network", "remote", "n"):
            return AttackVector.NETWORK
        elif av in ("adjacent", "adjacent_network", "a"):
            return AttackVector.ADJACENT
        elif av in ("local", "l"):
            return AttackVector.LOCAL
        elif av in ("physical", "p"):
            return AttackVector.PHYSICAL

        # 从 exposure 推断
        exposure = context.get("exposure", "").lower()
        if "internet" in exposure or "public" in exposure or "remote" in exposure:
            return AttackVector.NETWORK
        elif "internal" in exposure or "lan" in exposure:
            return AttackVector.ADJACENT

        return AttackVector.NETWORK  # 默认假设网络可达（保守估计）

    def _parse_attack_complexity(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> AttackComplexity:
        """解析攻击复杂度"""
        ac = context.get("attack_complexity", finding.get("attack_complexity", "")).lower()
        if ac in ("low", "simple", "l"):
            return AttackComplexity.LOW
        elif ac in ("medium", "m"):
            return AttackComplexity.MEDIUM
        elif ac in ("high", "complex", "h"):
            return AttackComplexity.HIGH

        # 从漏洞类型推断
        vuln_type = self._get_vuln_type(finding).lower()
        simple_types = {"sql_injection", "xss", "hardcoded_credentials", "open_redirect", "csrf"}
        complex_types = {"deserialization", "race_condition", "use_after_free", "buffer_overflow"}

        if vuln_type in simple_types:
            return AttackComplexity.LOW
        elif vuln_type in complex_types:
            return AttackComplexity.HIGH

        return AttackComplexity.MEDIUM

    def _parse_exploit_availability(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> ExploitCodeAvailability:
        """解析利用代码可用性"""
        # 直接指定
        ea = context.get("exploit_availability", finding.get("exploit_availability", "")).lower()
        if ea in ("available", "public", "weaponized"):
            return ExploitCodeAvailability.AVAILABLE
        elif ea in ("functional",):
            return ExploitCodeAvailability.FUNCTIONAL
        elif ea in ("poc", "proof_of_concept"):
            return ExploitCodeAvailability.PROOF_OF_CONCEPT
        elif ea in ("unavailable", "none"):
            return ExploitCodeAvailability.UNAVAILABLE

        # 从元数据推断
        metadata = finding.get("metadata", {})
        if metadata.get("has_public_exploit", False) or context.get("has_public_exploit", False):
            return ExploitCodeAvailability.AVAILABLE
        if metadata.get("has_poc", False) or context.get("has_poc", False):
            return ExploitCodeAvailability.PROOF_OF_CONCEPT

        # 从 CVE/KEV 推断
        if metadata.get("in_kev", False):
            return ExploitCodeAvailability.AVAILABLE
        if metadata.get("has_cve", False):
            return ExploitCodeAvailability.FUNCTIONAL

        return ExploitCodeAvailability.UNAVAILABLE

    def _infer_auth_required(self, finding: Dict[str, Any]) -> bool:
        """推断是否需要认证"""
        vuln_type = self._get_vuln_type(finding).lower()
        # 通常需要认证的漏洞类型
        auth_types = {
            "privilege_escalation", "auth_bypass", "improper_auth",
            "hardcoded_credentials", "csrf",
        }
        # 通常不需要认证的漏洞类型
        no_auth_types = {
            "xss", "sql_injection", "command_injection", "ssrf",
            "open_redirect", "path_traversal", "dos",
        }
        if vuln_type in no_auth_types:
            return False
        if vuln_type in auth_types:
            return True
        return False  # 默认不需要（保守估计）

    def _infer_user_interaction(self, finding: Dict[str, Any]) -> bool:
        """推断是否需要用户交互"""
        vuln_type = self._get_vuln_type(finding).lower()
        # 需要用户交互的漏洞类型
        ui_types = {
            "xss", "csrf", "open_redirect", "file_upload",
            "sensitive_data_exposure",
        }
        if vuln_type in ui_types:
            return True
        return False

    def _parse_cia_level(self, value: Any, default: str = "medium") -> str:
        """解析 CIA 影响级别"""
        if value is None:
            return default
        v = str(value).lower().strip()
        if v in ("high", "h", "complete"):
            return "high"
        elif v in ("low", "l", "partial"):
            return "low"
        elif v in ("none", "n", "0"):
            return "none"
        elif v in ("medium", "m", "moderate"):
            return "medium"
        return default

    # ------------------------------------------------------------------
    # 内部辅助方法 - 影响度评估
    # ------------------------------------------------------------------

    def _assess_data_breach_potential(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """评估数据泄露潜力 (0-12 分)"""
        vuln_type = self._get_vuln_type(finding).lower()
        score = 0.0

        # 高数据泄露风险的漏洞类型
        high_risk = {
            "sql_injection", "sensitive_data_exposure", "path_traversal",
            "hardcoded_credentials", "missing_encryption", "xxe",
            "broken_crypto", "weak_crypto", "hardcoded_secrets",
        }
        medium_risk = {
            "xss", "ssrf", "deserialization", "auth_bypass",
            "improper_auth", "open_redirect",
        }

        if vuln_type in high_risk:
            score = 10.0
        elif vuln_type in medium_risk:
            score = 6.0
        else:
            score = 2.0

        # 如果上下文中明确涉及敏感数据，增加分数
        data_types = context.get("data_types", [])
        sensitive_keywords = {"password", "credit_card", "ssn", "token", "secret", "pii", "phi"}
        sensitive_matches = [d for d in data_types if d.lower() in sensitive_keywords]
        if sensitive_matches:
            score = min(12.0, score + len(sensitive_matches) * 1.5)

        return min(12.0, score)

    def _assess_code_execution_potential(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """评估代码执行潜力 (0-14 分)"""
        vuln_type = self._get_vuln_type(finding).lower()
        score = 0.0

        # 可直接执行代码的漏洞类型
        direct_exec = {
            "code_injection", "command_injection", "deserialization",
            "insecure_deserialization", "buffer_overflow", "use_after_free",
        }
        # 间接可能导致代码执行的漏洞类型
        indirect_exec = {
            "sql_injection", "ssrf", "path_traversal", "xxe",
            "file_upload", "race_condition",
        }

        if vuln_type in direct_exec:
            score = 14.0
        elif vuln_type in indirect_exec:
            score = 7.0
        else:
            score = 1.0

        # 如果攻击向量是远程，增加代码执行的严重性
        av = self._parse_attack_vector(context)
        if av == AttackVector.NETWORK and score >= 7.0:
            score = min(14.0, score + 2.0)

        return score

    def _assess_privilege_escalation_potential(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """评估权限提升潜力 (0-10 分)"""
        vuln_type = self._get_vuln_type(finding).lower()
        score = 0.0

        priv_esc_types = {
            "privilege_escalation", "improper_auth", "auth_bypass",
            "hardcoded_credentials", "code_injection", "command_injection",
            "deserialization", "race_condition",
        }
        if vuln_type in priv_esc_types:
            score = 8.0
        elif context.get("scope_changed", False):
            score = 7.0
        else:
            score = 2.0

        # 如果环境是高权限环境，增加分数
        environment = context.get("environment", "").lower()
        high_priv_envs = {"root", "admin", "system", "privileged", "container_host"}
        if any(env in environment for env in high_priv_envs):
            score = min(10.0, score + 2.0)

        return min(10.0, score)

    def _assess_dos_potential(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """评估拒绝服务潜力 (0-6 分)"""
        vuln_type = self._get_vuln_type(finding).lower()
        score = 0.0

        dos_types = {
            "dos", "uncontrolled_resource", "buffer_overflow",
            "race_condition", "sql_injection", "command_injection",
        }
        if vuln_type in dos_types:
            score = 5.0
        else:
            score = 1.0

        # 如果漏洞涉及资源消耗模式，增加分数
        resource_patterns = {"infinite_loop", "memory_leak", "cpu_exhaustion", "disk_fill"}
        patterns = context.get("resource_patterns", [])
        matching = [p for p in patterns if p.lower() in resource_patterns]
        if matching:
            score = min(6.0, score + len(matching) * 1.0)

        return min(6.0, score)

    def _assess_lateral_movement_potential(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """评估横向移动潜力 (0-8 分)"""
        vuln_type = self._get_vuln_type(finding).lower()
        score = 0.0

        # 可能用于横向移动的漏洞类型
        lateral_types = {
            "ssrf", "hardcoded_credentials", "auth_bypass",
            "privilege_escalation", "code_injection", "command_injection",
            "deserialization", "sensitive_data_exposure",
        }
        if vuln_type in lateral_types:
            score = 6.0
        else:
            score = 1.0

        # 如果处于网络内部，增加横向移动风险
        av = self._parse_attack_vector(context)
        if av in (AttackVector.NETWORK, AttackVector.ADJACENT):
            score = min(8.0, score + 2.0)

        # 如果上下文提到内部服务或网络
        network_context = context.get("network_context", "").lower()
        if any(kw in network_context for kw in ("internal", "intranet", "private", "vpc")):
            score = min(8.0, score + 1.0)

        return min(8.0, score)

    # ------------------------------------------------------------------
    # 内部辅助方法 - 可检测性评估
    # ------------------------------------------------------------------

    def _get_sast_detectability(self, vuln_type: str) -> float:
        """获取 SAST 工具对该漏洞类型的检测成熟度 (0-30 分)"""
        # 高成熟度: 有成熟规则，主流工具均可检测
        high_maturity = {
            "sql_injection", "xss", "command_injection", "path_traversal",
            "hardcoded_credentials", "hardcoded_secrets", "xxe",
            "weak_crypto", "broken_crypto", "open_redirect",
        }
        # 中成熟度: 有规则但误报率较高
        medium_maturity = {
            "ssrf", "csrf", "deserialization", "insecure_deserialization",
            "sensitive_data_exposure", "missing_encryption", "file_upload",
            "improper_input_validation", "null_dereference",
        }
        # 低成熟度: 难以通过静态分析检测
        low_maturity = {
            "race_condition", "use_after_free", "buffer_overflow",
            "privilege_escalation", "auth_bypass", "improper_auth",
        }

        vt = vuln_type.lower()
        if vt in high_maturity:
            return 25.0
        elif vt in medium_maturity:
            return 16.0
        elif vt in low_maturity:
            return 7.0
        return 12.0  # 默认中等偏低

    def _get_dast_detectability(self, vuln_type: str) -> float:
        """获取 DAST 工具对该漏洞类型的检测成熟度 (0-25 分)"""
        high_maturity = {
            "sql_injection", "xss", "command_injection", "ssrf",
            "path_traversal", "open_redirect", "xxe", "csrf",
        }
        medium_maturity = {
            "hardcoded_credentials", "weak_crypto", "file_upload",
            "deserialization", "sensitive_data_exposure",
        }
        low_maturity = {
            "race_condition", "use_after_free", "buffer_overflow",
            "privilege_escalation", "auth_bypass", "code_injection",
            "null_dereference", "dos",
        }

        vt = vuln_type.lower()
        if vt in high_maturity:
            return 22.0
        elif vt in medium_maturity:
            return 13.0
        elif vt in low_maturity:
            return 5.0
        return 10.0

    def _assess_pattern_clarity(self, vuln_type: str) -> float:
        """评估漏洞模式的明确性 (0-20 分)

        模式越明确、越容易通过正则或简单规则匹配，分数越高。
        """
        # 模式非常明确
        clear_patterns = {
            "hardcoded_credentials", "hardcoded_secrets", "weak_crypto",
            "broken_crypto", "open_redirect", "xxe",
        }
        # 模式较明确
        moderate_patterns = {
            "sql_injection", "xss", "command_injection", "path_traversal",
            "csrf", "missing_encryption", "sensitive_data_exposure",
        }
        # 模式模糊，需要语义分析
        vague_patterns = {
            "race_condition", "auth_bypass", "privilege_escalation",
            "deserialization", "use_after_free", "buffer_overflow",
            "improper_auth", "dos", "null_dereference",
        }

        vt = vuln_type.lower()
        if vt in clear_patterns:
            return 18.0
        elif vt in moderate_patterns:
            return 12.0
        elif vt in vague_patterns:
            return 5.0
        return 9.0

    def _estimate_data_flow_depth(self, finding: Dict[str, Any]) -> int:
        """估算漏洞的数据流传播深度"""
        metadata = finding.get("metadata", {})

        # 如果元数据中有传播步数信息
        propagation_steps = metadata.get("propagation_steps", None)
        if propagation_steps is not None:
            return int(propagation_steps)

        # 从 taint_path 长度推断
        taint_path = metadata.get("taint_path_length", None)
        if taint_path is not None:
            return int(taint_path)

        # 根据漏洞类型推断典型深度
        vuln_type = self._get_vuln_type(finding).lower()
        shallow_types = {
            "hardcoded_credentials", "weak_crypto", "hardcoded_secrets",
            "broken_crypto", "open_redirect",
        }
        deep_types = {
            "sql_injection", "command_injection", "ssrf",
            "deserialization", "race_condition",
        }

        if vuln_type in shallow_types:
            return 1
        elif vuln_type in deep_types:
            return 4
        return 2

    # ------------------------------------------------------------------
    # 内部辅助方法 - CVSS 映射
    # ------------------------------------------------------------------

    def _derive_cvss_attack_vector(self, exploitability: float) -> str:
        """从可利用性分数推导 CVSS 攻击向量"""
        if exploitability >= 75.0:
            return "N"  # Network
        elif exploitability >= 50.0:
            return "A"  # Adjacent
        elif exploitability >= 25.0:
            return "L"  # Local
        else:
            return "P"  # Physical

    def _derive_cvss_attack_complexity(self, exploitability: float) -> str:
        """从可利用性分数推导 CVSS 攻击复杂度"""
        if exploitability >= 60.0:
            return "L"  # Low
        else:
            return "H"  # High

    def _derive_cvss_privileges_required(self, exploitability: float) -> str:
        """从可利用性分数推导 CVSS 所需权限"""
        if exploitability >= 80.0:
            return "N"  # None
        elif exploitability >= 40.0:
            return "L"  # Low
        else:
            return "H"  # High

    def _derive_cvss_user_interaction(self, exploitability: float) -> str:
        """从可利用性分数推导 CVSS 用户交互"""
        if exploitability >= 65.0:
            return "N"  # None
        else:
            return "R"  # Required

    def _derive_cvss_scope(self, impact: float) -> str:
        """从影响度分数推导 CVSS 范围"""
        if impact >= 75.0:
            return "C"  # Changed
        else:
            return "U"  # Unchanged

    def _derive_cvss_cia_impact(self, impact: float, dimension: str) -> str:
        """从影响度分数推导 CIA 各维度影响

        根据 impact 总分和维度类型分配不同的 CIA 级别。
        """
        # 根据总分划分基础 CIA 级别
        if impact >= 80.0:
            return "H"  # High
        elif impact >= 50.0:
            return "L"  # Low
        elif impact >= 25.0:
            # 中间区间根据维度区分
            if dimension == "confidentiality":
                return "L"
            else:
                return "N"  # None
        else:
            return "N"  # None
