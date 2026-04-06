"""攻击链分析增强

构建漏洞间的因果关系和依赖关系，生成攻击路径。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from src.core.result_aggregator import AggregatedFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RelationshipType(Enum):
    """漏洞关系类型"""
    CAUSAL = "causal"  # 因果关系：A 导致 B
    DEPENDENCY = "dependency"  # 依赖关系：B 依赖 A
    COMPLEMENTARY = "complementary"  # 互补关系：A 和 B 配合使用
    ALTERNATIVE = "alternative"  # 替代关系：A 或 B 都可达成目标
    SAME_ROOT = "same_root"  # 同源关系：A 和 B 有相同根源


@dataclass
class VulnerabilityRelationship:
    """漏洞关系"""
    source_index: int
    target_index: int
    relationship_type: RelationshipType
    probability: float  # 0.0-1.0
    description: str
    attack_scenario: Optional[str] = None


@dataclass
class AttackStep:
    """攻击步骤"""
    finding_index: int
    finding: AggregatedFinding
    step_order: int
    description: str


@dataclass
class AttackPath:
    """攻击路径"""
    steps: List[AttackStep] = field(default_factory=list)
    total_risk_score: float = 0.0
    success_probability: float = 0.0
    description: str = ""

    @property
    def length(self) -> int:
        return len(self.steps)


@dataclass
class AttackChainAnalysisResult:
    """攻击链分析结果"""
    findings: List[AggregatedFinding] = field(default_factory=list)
    relationships: List[VulnerabilityRelationship] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    critical_chains: List[AttackPath] = field(default_factory=list)
    summary: str = ""


class AttackChainAnalyzer:
    """攻击链分析器"""

    # 漏洞类型优先级（用于排序攻击路径）
    VULN_TYPE_PRIORITY = {
        "rce": 100,
        "sql_injection": 90,
        "command_injection": 85,
        "authentication_bypass": 80,
        "authorization_issue": 75,
        "ssrf": 70,
        "xss": 65,
        "path_traversal": 60,
        "hardcoded_credentials": 55,
        "weak_crypto": 50,
        "sensitive_data_exposure": 45,
        "csrf": 40,
        "xxe": 35,
        "deserialization": 30,
        "default": 10
    }

    # 漏洞类型依赖关系规则
    DEPENDENCY_RULES = {
        ("hardcoded_credentials", "authentication_bypass"): {
            "type": RelationshipType.CAUSAL,
            "probability": 0.8,
            "description": "硬编码凭证可用于认证绕过"
        },
        ("path_traversal", "sensitive_data_exposure"): {
            "type": RelationshipType.CAUSAL,
            "probability": 0.9,
            "description": "路径遍历可导致敏感数据暴露"
        },
        ("sql_injection", "authentication_bypass"): {
            "type": RelationshipType.CAUSAL,
            "probability": 0.7,
            "description": "SQL 注入可用于认证绕过"
        },
        ("xss", "csrf"): {
            "type": RelationshipType.COMPLEMENTARY,
            "probability": 0.6,
            "description": "XSS 和 CSRF 可配合发起更复杂攻击"
        },
        ("ssrf", "rce"): {
            "type": RelationshipType.CAUSAL,
            "probability": 0.4,
            "description": "SSRF 在某些情况下可用于 RCE"
        }
    }

    def __init__(self):
        """初始化攻击链分析器"""
        pass

    def analyze(
        self,
        findings: List[AggregatedFinding]
    ) -> AttackChainAnalysisResult:
        """分析漏洞，构建攻击链

        Args:
            findings: 漏洞发现列表

        Returns:
            AttackChainAnalysisResult: 分析结果
        """
        result = AttackChainAnalysisResult(findings=findings)

        if len(findings) < 2:
            result.summary = "漏洞数量不足，无法构建攻击链"
            return result

        # 1. 识别漏洞间关系
        result.relationships = self._identify_relationships(findings)

        # 2. 构建攻击路径
        result.attack_paths = self._build_attack_paths(
            findings, result.relationships
        )

        # 3. 识别关键攻击链
        result.critical_chains = self._identify_critical_chains(result.attack_paths)

        # 4. 生成摘要
        result.summary = self._generate_summary(result)

        return result

    def _identify_relationships(
        self,
        findings: List[AggregatedFinding]
    ) -> List[VulnerabilityRelationship]:
        """识别漏洞间关系

        Args:
            findings: 漏洞发现列表

        Returns:
            List[VulnerabilityRelationship]: 漏洞关系列表
        """
        relationships = []

        for i, finding_a in enumerate(findings):
            for j, finding_b in enumerate(findings):
                if i == j:
                    continue

                # 检查基于规则的依赖
                rule_key = (finding_a.rule_id.lower(), finding_b.rule_id.lower())
                if rule_key in self.DEPENDENCY_RULES:
                    rule = self.DEPENDENCY_RULES[rule_key]
                    rel = VulnerabilityRelationship(
                        source_index=i,
                        target_index=j,
                        relationship_type=rule["type"],
                        probability=rule["probability"],
                        description=rule["description"],
                        attack_scenario=self._generate_attack_scenario(
                            finding_a, finding_b, rule["type"]
                        )
                    )
                    relationships.append(rel)
                    continue

                # 检查位置关系（同一文件）
                if finding_a.location.file == finding_b.location.file:
                    # 检查时序关系（行号顺序）
                    if finding_a.location.line < finding_b.location.line:
                        # 检查是否为同源问题（类似规则 ID）
                        if self._is_same_root(finding_a, finding_b):
                            rel = VulnerabilityRelationship(
                                source_index=i,
                                target_index=j,
                                relationship_type=RelationshipType.SAME_ROOT,
                                probability=0.7,
                                description=f"两个漏洞可能有相同根源（同一文件：{finding_a.location.file}）"
                            )
                            relationships.append(rel)

                # 检查严重性互补
                if (finding_a.severity in ["critical", "high"] and
                    finding_b.severity in ["critical", "high"]):
                    # 高风险漏洞可能互补
                    pass

        return relationships

    def _is_same_root(
        self,
        finding_a: AggregatedFinding,
        finding_b: AggregatedFinding
    ) -> bool:
        """判断两个漏洞是否有相同根源

        Args:
            finding_a: 漏洞 A
            finding_b: 漏洞 B

        Returns:
            bool: 是否有相同根源
        """
        # 规则 ID 前缀相同
        prefix_a = finding_a.rule_id.split('_')[0]
        prefix_b = finding_b.rule_id.split('_')[0]
        if prefix_a == prefix_b:
            return True

        # 描述中有相似关键词
        keywords_a = set(finding_a.description.lower().split())
        keywords_b = set(finding_b.description.lower().split())
        common_keywords = keywords_a & keywords_b
        if len(common_keywords) >= 3:
            return True

        return False

    def _generate_attack_scenario(
        self,
        finding_a: AggregatedFinding,
        finding_b: AggregatedFinding,
        rel_type: RelationshipType
    ) -> str:
        """生成攻击场景描述

        Args:
            finding_a: 漏洞 A
            finding_b: 漏洞 B
            rel_type: 关系类型

        Returns:
            str: 攻击场景描述
        """
        if rel_type == RelationshipType.CAUSAL:
            return f"攻击者先利用 {finding_a.rule_name}（{finding_a.location.file}:{finding_a.location.line}），" \
                   f"然后通过该漏洞进一步利用 {finding_b.rule_name}（{finding_b.location.file}:{finding_b.location.line}）"
        elif rel_type == RelationshipType.COMPLEMENTARY:
            return f"攻击者配合使用 {finding_a.rule_name} 和 {finding_b.rule_name}，" \
                   f"发起更复杂的组合攻击"
        else:
            return f"{finding_a.rule_name} 和 {finding_b.rule_name} 存在关联关系"

    def _build_attack_paths(
        self,
        findings: List[AggregatedFinding],
        relationships: List[VulnerabilityRelationship]
    ) -> List[AttackPath]:
        """构建攻击路径

        Args:
            findings: 漏洞发现列表
            relationships: 漏洞关系列表

        Returns:
            List[AttackPath]: 攻击路径列表
        """
        attack_paths = []

        # 构建图
        graph = defaultdict(list)
        for rel in relationships:
            if rel.relationship_type in [RelationshipType.CAUSAL, RelationshipType.DEPENDENCY]:
                graph[rel.source_index].append((rel.target_index, rel))

        # 从每个节点开始 DFS 寻找路径
        for start_idx in range(len(findings)):
            paths = self._dfs_paths(graph, start_idx, set(), [])
            for path_indices in paths:
                if len(path_indices) >= 2:
                    attack_path = self._build_attack_path_from_indices(
                        path_indices, findings, relationships
                    )
                    attack_paths.append(attack_path)

        # 排序攻击路径（按风险得分）
        attack_paths.sort(key=lambda p: p.total_risk_score, reverse=True)

        return attack_paths

    def _dfs_paths(
        self,
        graph: Dict[int, List[Tuple[int, VulnerabilityRelationship]]],
        current: int,
        visited: Set[int],
        path: List[int]
    ) -> List[List[int]]:
        """DFS 寻找所有路径

        Args:
            graph: 图
            current: 当前节点
            visited: 已访问节点
            path: 当前路径

        Returns:
            List[List[int]]: 所有路径
        """
        visited.add(current)
        path.append(current)

        paths = [path.copy()]

        if current in graph:
            for neighbor, _ in graph[current]:
                if neighbor not in visited:
                    paths.extend(self._dfs_paths(graph, neighbor, visited.copy(), path.copy()))

        return paths

    def _build_attack_path_from_indices(
        self,
        path_indices: List[int],
        findings: List[AggregatedFinding],
        relationships: List[VulnerabilityRelationship]
    ) -> AttackPath:
        """从索引列表构建攻击路径

        Args:
            path_indices: 路径索引
            findings: 漏洞发现列表
            relationships: 漏洞关系列表

        Returns:
            AttackPath: 攻击路径
        """
        attack_path = AttackPath()

        for step_order, idx in enumerate(path_indices):
            finding = findings[idx]
            step = AttackStep(
                finding_index=idx,
                finding=finding,
                step_order=step_order + 1,
                description=f"步骤 {step_order + 1}: 利用 {finding.rule_name}"
            )
            attack_path.steps.append(step)

        # 计算风险得分
        attack_path.total_risk_score = sum(
            self._get_vuln_score(step.finding) for step in attack_path.steps
        )

        # 计算成功概率（取路径中最小概率）
        min_prob = 1.0
        for i in range(len(path_indices) - 1):
            source_idx = path_indices[i]
            target_idx = path_indices[i + 1]
            for rel in relationships:
                if rel.source_index == source_idx and rel.target_index == target_idx:
                    min_prob = min(min_prob, rel.probability)
                    break
        attack_path.success_probability = min_prob

        # 生成描述
        attack_path.description = " → ".join(
            step.finding.rule_name for step in attack_path.steps
        )

        return attack_path

    def _get_vuln_score(self, finding: AggregatedFinding) -> float:
        """获取漏洞风险得分

        Args:
            finding: 漏洞发现

        Returns:
            float: 风险得分
        """
        severity_scores = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 2.0,
            "info": 0.5
        }

        severity_score = severity_scores.get(finding.severity, 1.0)
        confidence_score = finding.confidence

        # 类型优先级得分
        type_priority = self.VULN_TYPE_PRIORITY.get(
            finding.rule_id.lower(),
            self.VULN_TYPE_PRIORITY["default"]
        )
        type_score = type_priority / 10.0

        return severity_score * confidence_score * type_score

    def _identify_critical_chains(
        self,
        attack_paths: List[AttackPath],
        top_n: int = 5
    ) -> List[AttackPath]:
        """识别关键攻击链

        Args:
            attack_paths: 攻击路径列表
            top_n: 返回前 N 个

        Returns:
            List[AttackPath]: 关键攻击链
        """
        # 过滤掉成功率过低的路径
        filtered = [p for p in attack_paths if p.success_probability >= 0.3]

        # 按综合得分排序（风险 * 成功率）
        filtered.sort(
            key=lambda p: p.total_risk_score * p.success_probability,
            reverse=True
        )

        return filtered[:top_n]

    def _generate_summary(self, result: AttackChainAnalysisResult) -> str:
        """生成分析摘要

        Args:
            result: 分析结果

        Returns:
            str: 摘要
        """
        parts = []

        parts.append(f"发现 {len(result.findings)} 个漏洞")
        parts.append(f"识别出 {len(result.relationships)} 个漏洞关系")
        parts.append(f"构建出 {len(result.attack_paths)} 条潜在攻击路径")

        if result.critical_chains:
            parts.append(f"发现 {len(result.critical_chains)} 条关键攻击链")
            top_chain = result.critical_chains[0]
            parts.append(f"最危险攻击链: {top_chain.description}")
            parts.append(f"风险得分: {top_chain.total_risk_score:.1f}")
            parts.append(f"成功概率: {top_chain.success_probability:.0%}")

        return " | ".join(parts)
