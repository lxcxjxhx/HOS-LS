"""攻击链分析增强

构建漏洞间的因果关系和依赖关系，生成攻击路径。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

from src.core.result_aggregator import AggregatedFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


class NodeType(Enum):
    """节点类型"""
    INPUT = "input"  # 输入节点：prompt / API
    PROCESS = "process"  # 处理节点：LLM / Agent
    ACTION = "action"  # 动作节点：tool / shell
    SINK = "sink"  # 目标节点：file / db / response


class VulnType(Enum):
    """漏洞类型"""
    PROMPT_INJECTION = "prompt_injection"
    RCE = "rce"
    LEAK = "leak"
    AUTH_BYPASS = "authentication_bypass"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    SSRF = "ssrf"
    CSRF = "csrf"
    WEAK_CRYPTO = "weak_crypto"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"


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
    status: str = "possible"  # possible, confirmed, exploited
    risk_level: str = "low"  # low, medium, high

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
    metadata: Dict[str, Any] = field(default_factory=dict)


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
        "prompt_injection": 95,
        "agent_abuse": 85,
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
        },
        ("prompt_injection", "agent_abuse"): {
            "type": RelationshipType.CAUSAL,
            "probability": 0.9,
            "description": "Prompt注入可导致Agent滥用"
        },
        ("agent_abuse", "command_injection"): {
            "type": RelationshipType.CAUSAL,
            "probability": 0.8,
            "description": "Agent滥用可导致命令注入"
        },
        ("agent_abuse", "path_traversal"): {
            "type": RelationshipType.CAUSAL,
            "probability": 0.75,
            "description": "Agent滥用可导致路径遍历"
        }
    }

    # 节点类型映射规则
    NODE_TYPE_MAPPING = {
        "prompt": NodeType.INPUT,
        "api": NodeType.INPUT,
        "llm": NodeType.PROCESS,
        "agent": NodeType.PROCESS,
        "tool": NodeType.ACTION,
        "shell": NodeType.ACTION,
        "file": NodeType.SINK,
        "db": NodeType.SINK,
        "response": NodeType.SINK
    }

    def __init__(self):
        """初始化攻击链分析器"""
        pass

    def _classify_node_type(self, finding: AggregatedFinding) -> NodeType:
        """分类节点类型

        Args:
            finding: 漏洞发现

        Returns:
            NodeType: 节点类型
        """
        rule_name_lower = finding.rule_name.lower()
        
        # 基于规则名称分类
        if any(keyword in rule_name_lower for keyword in ["prompt", "input"]):
            return NodeType.INPUT
        elif any(keyword in rule_name_lower for keyword in ["llm", "agent", "process"]):
            return NodeType.PROCESS
        elif any(keyword in rule_name_lower for keyword in ["tool", "shell", "command", "execute"]):
            return NodeType.ACTION
        elif any(keyword in rule_name_lower for keyword in ["file", "db", "database", "response", "output"]):
            return NodeType.SINK
        else:
            # 默认根据漏洞类型分类
            vuln_type = self._get_vuln_type(finding)
            if vuln_type in [VulnType.PROMPT_INJECTION]:
                return NodeType.INPUT
            elif vuln_type in [VulnType.RCE, VulnType.COMMAND_INJECTION]:
                return NodeType.ACTION
            elif vuln_type in [VulnType.SENSITIVE_DATA_EXPOSURE, VulnType.LEAK]:
                return NodeType.SINK
            else:
                return NodeType.PROCESS

    def _get_vuln_type(self, finding: AggregatedFinding) -> VulnType:
        """获取漏洞类型

        Args:
            finding: 漏洞发现

        Returns:
            VulnType: 漏洞类型
        """
        rule_name_lower = finding.rule_name.lower()
        rule_id_lower = finding.rule_id.lower()
        
        if any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["prompt", "injection"]):
            return VulnType.PROMPT_INJECTION
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["rce", "remote code"]):
            return VulnType.RCE
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["leak", "exposure"]):
            return VulnType.LEAK
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["auth", "bypass"]):
            return VulnType.AUTH_BYPASS
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["command", "inject"]):
            return VulnType.COMMAND_INJECTION
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["path", "traversal"]):
            return VulnType.PATH_TRAVERSAL
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["xss"]):
            return VulnType.XSS
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["sql", "injection"]):
            return VulnType.SQL_INJECTION
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["ssrf"]):
            return VulnType.SSRF
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["csrf"]):
            return VulnType.CSRF
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["crypto", "weak"]):
            return VulnType.WEAK_CRYPTO
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["hardcode", "credential"]):
            return VulnType.HARDCODED_CREDENTIALS
        elif any(keyword in rule_name_lower or keyword in rule_id_lower for keyword in ["sensitive", "data"]):
            return VulnType.SENSITIVE_DATA_EXPOSURE
        else:
            return VulnType.LEAK

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

        # 按节点类型分类
        node_types = [self._classify_node_type(finding) for finding in findings]

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

                # 基于节点类型的自动连接规则
                type_a = node_types[i]
                type_b = node_types[j]

                # 规则1: INPUT → PROCESS
                if type_a == NodeType.INPUT and type_b == NodeType.PROCESS:
                    rel = VulnerabilityRelationship(
                        source_index=i,
                        target_index=j,
                        relationship_type=RelationshipType.CAUSAL,
                        probability=0.85,
                        description="输入节点可影响处理节点",
                        attack_scenario=f"攻击者通过 {finding_a.rule_name} 影响 {finding_b.rule_name}"
                    )
                    relationships.append(rel)
                # 规则2: PROCESS → ACTION
                elif type_a == NodeType.PROCESS and type_b == NodeType.ACTION:
                    rel = VulnerabilityRelationship(
                        source_index=i,
                        target_index=j,
                        relationship_type=RelationshipType.CAUSAL,
                        probability=0.8,
                        description="处理节点可导致动作节点执行",
                        attack_scenario=f"攻击者通过 {finding_a.rule_name} 触发 {finding_b.rule_name}"
                    )
                    relationships.append(rel)
                # 规则3: ACTION → SINK
                elif type_a == NodeType.ACTION and type_b == NodeType.SINK:
                    rel = VulnerabilityRelationship(
                        source_index=i,
                        target_index=j,
                        relationship_type=RelationshipType.CAUSAL,
                        probability=0.9,
                        description="动作节点可影响目标节点",
                        attack_scenario=f"攻击者通过 {finding_a.rule_name} 访问 {finding_b.rule_name}"
                    )
                    relationships.append(rel)

                # 检查位置关系（同一文件）
                if finding_a.file_path == finding_b.file_path:
                    # 检查时序关系（行号顺序）
                    if finding_a.line < finding_b.line:
                        # 检查是否为同源问题（类似规则 ID）
                        if self._is_same_root(finding_a, finding_b):
                            rel = VulnerabilityRelationship(
                                source_index=i,
                                target_index=j,
                                relationship_type=RelationshipType.SAME_ROOT,
                                probability=0.7,
                                description=f"两个漏洞可能有相同根源（同一文件：{finding_a.file_path}）"
                            )
                            relationships.append(rel)

                # 检查严重性互补
                if (finding_a.severity in ["critical", "high"] and
                    finding_b.severity in ["critical", "high"]):
                    # 高风险漏洞可能互补
                    rel = VulnerabilityRelationship(
                        source_index=i,
                        target_index=j,
                        relationship_type=RelationshipType.COMPLEMENTARY,
                        probability=0.6,
                        description="两个高风险漏洞可配合使用",
                        attack_scenario=f"攻击者配合使用 {finding_a.rule_name} 和 {finding_b.rule_name}"
                    )
                    relationships.append(rel)

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
            return f"攻击者先利用 {finding_a.rule_name}（{finding_a.file_path}:{finding_a.line}），" \
                   f"然后通过该漏洞进一步利用 {finding_b.rule_name}（{finding_b.file_path}:{finding_b.line}）"
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

        # 计算可利用性评分
        exploitability_score = self._calculate_exploitability_score(attack_path, findings)
        
        # 确定风险等级
        attack_path.risk_level = self._get_risk_level(exploitability_score)

        # 生成描述
        attack_path.description = " → ".join(
            step.finding.rule_name for step in attack_path.steps
        )

        return attack_path

    def _calculate_exploitability_score(self, attack_path: AttackPath, findings: List[AggregatedFinding]) -> float:
        """计算攻击链可利用性评分

        Args:
            attack_path: 攻击路径
            findings: 漏洞发现列表

        Returns:
            float: 可利用性评分
        """
        # 评分维度
        controllable_score = 0.0
        exploited_score = 0.0
        sensitive_sink_score = 0.0

        # 检查输入是否可控
        first_step = attack_path.steps[0]
        first_finding = first_step.finding
        if any(keyword in first_finding.rule_name.lower() for keyword in ["input", "prompt"]):
            controllable_score = 3.0

        # 检查是否已验证
        for step in attack_path.steps:
            finding = step.finding
            if hasattr(finding, 'exploit_status') and finding.exploit_status in ['confirmed', 'exploited']:
                exploited_score = 5.0
                break

        # 检查是否影响敏感数据
        last_step = attack_path.steps[-1]
        last_finding = last_step.finding
        if any(keyword in last_finding.rule_name.lower() for keyword in ["file", "data", "exposure", "leak"]):
            sensitive_sink_score = 4.0

        # 计算总评分
        total_score = controllable_score + exploited_score + sensitive_sink_score
        return total_score

    def _get_risk_level(self, score: float) -> str:
        """根据评分确定风险等级

        Args:
            score: 可利用性评分

        Returns:
            str: 风险等级
        """
        if score >= 8:
            return "high"
        elif score >= 4:
            return "medium"
        else:
            return "low"

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
