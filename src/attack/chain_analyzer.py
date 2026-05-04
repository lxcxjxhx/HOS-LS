"""攻击链路分析模块

利用AI识别漏洞之间的关联关系，构建攻击路径，评估风险，并生成可视化的攻击链路图。
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any

from src.ai.client import AIModelManager, get_model_manager
from src.ai.models import AIRequest, SecurityAnalysisResult, VulnerabilityFinding
from src.ai.prompts import get_prompt_manager
from src.storage.rag_knowledge_base import get_rag_knowledge_base
from src.utils.logger import get_logger
from src.core.config import Config, get_config

logger = get_logger(__name__)


@dataclass
class AttackNode:
    """攻击节点"""
    id: str
    vulnerability: VulnerabilityFinding
    risk_score: float
    reachable: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackEdge:
    """攻击边"""
    id: str
    source: str
    target: str
    relationship: str
    probability: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """攻击路径"""
    id: str
    nodes: List[str]
    edges: List[str]
    risk_score: float
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChainResult:
    """攻击链路分析结果"""
    nodes: List[AttackNode]
    edges: List[AttackEdge]
    paths: List[AttackPath]
    risk_score: float
    summary: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttackChainAnalyzer:
    """攻击链路分析器

    利用AI识别漏洞之间的关联关系，构建攻击路径，评估风险。
    """

    def __init__(self, config: Optional[Config] = None):
        """初始化攻击链路分析器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._manager: Optional[AIModelManager] = None
        self._prompt_manager = get_prompt_manager(self.config)
        self._system_prompt = self._load_system_prompt()
        # 纯AI模式下跳过RAG知识库初始化
        if hasattr(self.config, 'pure_ai') and self.config.pure_ai:
            self._rag_knowledge_base = None
        else:
            self._rag_knowledge_base = get_rag_knowledge_base()

    def _load_system_prompt(self) -> str:
        """加载攻击链路分析系统提示"""
        return self._prompt_manager.get_prompt("attack_chain_analysis")

    async def initialize(self) -> None:
        """初始化攻击链路分析器"""
        from src.ai.client import _manager
        _manager = None
        self._manager = await get_model_manager(self.config)

    async def analyze(self, findings: List[VulnerabilityFinding]) -> AttackChainResult:
        """分析攻击链路

        Args:
            findings: 漏洞发现列表

        Returns:
            攻击链路分析结果
        """
        await self.initialize()

        # 构建攻击节点
        nodes = self._build_nodes(findings)

        # 分析漏洞之间的关联关系
        edges = await self._analyze_relationships(nodes, findings)

        # 构建攻击路径
        paths = self._build_attack_paths(nodes, edges)

        # 计算总体风险评分
        risk_score = self._calculate_overall_risk(paths)

        # 生成摘要
        summary = self._generate_summary(nodes, edges, paths, risk_score)

        return AttackChainResult(
            nodes=nodes,
            edges=edges,
            paths=paths,
            risk_score=risk_score,
            summary=summary
        )

    def _build_nodes(self, findings: List[VulnerabilityFinding]) -> List[AttackNode]:
        """构建攻击节点

        Args:
            findings: 漏洞发现列表

        Returns:
            攻击节点列表
        """
        nodes = []

        for finding in findings:
            # 计算节点风险评分
            risk_score = self._calculate_node_risk(finding)

            node = AttackNode(
                id=hashlib.sha256(finding.code_snippet.encode()).hexdigest()[:16],
                vulnerability=finding,
                risk_score=risk_score,
                metadata={
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "location": finding.location
                }
            )
            nodes.append(node)

        return nodes

    async def _analyze_relationships(self, nodes: List[AttackNode], findings: List[VulnerabilityFinding]) -> List[AttackEdge]:
        """分析漏洞之间的关联关系

        Args:
            nodes: 攻击节点列表
            findings: 漏洞发现列表

        Returns:
            攻击边列表
        """
        edges = []

        # 构建漏洞描述
        vulnerability_descriptions = []
        for i, finding in enumerate(findings):
            description = f"漏洞 {i+1}: {finding.rule_name} - {finding.description}\n"
            description += f"严重程度: {finding.severity}\n"
            description += f"代码片段: {finding.code_snippet[:100]}..."
            vulnerability_descriptions.append(description)

        # 构建分析提示
        prompt = self._build_relationship_prompt(vulnerability_descriptions)

        # 发送AI请求
        request = AIRequest(
            prompt=prompt,
            system_prompt=self._system_prompt,
            temperature=0.1,
            max_tokens=4096,
            model=self.config.ai.model
        )

        response = await self._manager.generate(request)

        # 解析AI响应
        relationships = self._parse_relationships(response.content, nodes)

        # 构建攻击边
        for source_idx, target_idx, relationship, probability in relationships:
            if 0 <= source_idx < len(nodes) and 0 <= target_idx < len(nodes):
                source_node = nodes[source_idx]
                target_node = nodes[target_idx]

                edge = AttackEdge(
                    id=hashlib.sha256(f"{source_node.id}_{target_node.id}".encode()).hexdigest()[:16],
                    source=source_node.id,
                    target=target_node.id,
                    relationship=relationship,
                    probability=probability,
                    metadata={
                        "source_vulnerability": source_node.vulnerability.rule_name,
                        "target_vulnerability": target_node.vulnerability.rule_name
                    }
                )
                edges.append(edge)

        return edges

    def _build_relationship_prompt(self, vulnerability_descriptions: List[str]) -> str:
        """构建关系分析提示"""
        prompt_parts = [
            "# 漏洞关联关系分析",
            "\n请分析以下漏洞之间的潜在关联关系:",
        ]

        for i, description in enumerate(vulnerability_descriptions):
            prompt_parts.append(f"\n## 漏洞 {i+1}")
            prompt_parts.append(description)

        prompt_parts.append("\n## 分析要求:")
        prompt_parts.append("1. 识别漏洞之间的因果关系和依赖关系")
        prompt_parts.append("2. 评估漏洞之间的攻击路径可能性")
        prompt_parts.append("3. 为每对漏洞之间的关系提供概率评分 (0-1)")
        prompt_parts.append("4. 描述关系的类型和可能的攻击场景")

        prompt_parts.append("\n请以JSON格式返回分析结果，包含以下字段:")
        prompt_parts.append("{")
        prompt_parts.append("  \"relationships\": [")
        prompt_parts.append("    {")
        prompt_parts.append("      \"source\": 0,  # 源漏洞索引")
        prompt_parts.append("      \"target\": 1,  # 目标漏洞索引")
        prompt_parts.append("      \"relationship\": \"...\",  # 关系类型")
        prompt_parts.append("      \"probability\": 0.8,  # 概率评分")
        prompt_parts.append("      \"description\": \"...\"  # 关系描述")
        prompt_parts.append("    }")
        prompt_parts.append("  ]")
        prompt_parts.append("}")

        return "\n".join(prompt_parts)

    def _parse_relationships(self, content: str, nodes: List[AttackNode]) -> List[Tuple[int, int, str, float]]:
        """解析AI响应中的关系信息"""
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

            relationships = []
            for rel in data.get("relationships", []):
                source = rel.get("source", 0)
                target = rel.get("target", 0)
                relationship = rel.get("relationship", "related")
                probability = rel.get("probability", 0.5)
                relationships.append((source, target, relationship, probability))

            return relationships
        except Exception as e:
            logger.error(f"解析关系信息失败: {e}")
            return []

    def _build_attack_paths(self, nodes: List[AttackNode], edges: List[AttackEdge]) -> List[AttackPath]:
        """构建攻击路径

        Args:
            nodes: 攻击节点列表
            edges: 攻击边列表

        Returns:
            攻击路径列表
        """
        paths = []

        # 构建节点映射
        node_map = {node.id: node for node in nodes}

        # 构建邻接表
        adjacency = {node.id: [] for node in nodes}
        for edge in edges:
            adjacency[edge.source].append((edge.target, edge.probability, edge.id))

        # 寻找所有可能的路径
        for start_node in nodes:
            visited = set()
            path_nodes = []
            path_edges = []
            self._dfs(start_node.id, visited, path_nodes, path_edges, adjacency, node_map, paths)

        # 过滤和排序路径
        filtered_paths = self._filter_paths(paths)
        sorted_paths = sorted(filtered_paths, key=lambda p: p.risk_score, reverse=True)[:10]  # 只保留前10个最高风险路径

        return sorted_paths

    def _dfs(self, current: str, visited: Set[str], path_nodes: List[str], path_edges: List[str], adjacency: Dict[str, List[Tuple[str, float, str]]], node_map: Dict[str, AttackNode], paths: List[AttackPath]):
        """深度优先搜索寻找攻击路径"""
        if current in visited:
            # 检测循环
            if current in path_nodes:
                return
            return

        visited.add(current)
        path_nodes.append(current)

        # 检查是否形成有效路径
        if len(path_nodes) >= 2:
            path = self._create_path(path_nodes, path_edges, node_map)
            if path:
                paths.append(path)

        # 继续搜索
        for neighbor, probability, edge_id in adjacency.get(current, []):
            path_edges.append(edge_id)
            self._dfs(neighbor, visited.copy(), path_nodes.copy(), path_edges.copy(), adjacency, node_map, paths)
            path_edges.pop()

        path_nodes.pop()

    def _create_path(self, node_ids: List[str], edge_ids: List[str], node_map: Dict[str, AttackNode]) -> Optional[AttackPath]:
        """创建攻击路径"""
        if len(node_ids) < 2:
            return None

        # 计算路径风险评分
        risk_score = 0.0
        for node_id in node_ids:
            node = node_map.get(node_id)
            if node:
                risk_score += node.risk_score
        risk_score /= len(node_ids)

        # 生成路径描述
        descriptions = []
        for node_id in node_ids:
            node = node_map.get(node_id)
            if node:
                descriptions.append(f"{node.vulnerability.rule_name} ({node.vulnerability.severity})")
        description = " → ".join(descriptions)

        path_id = hashlib.sha256("-".join(node_ids).encode()).hexdigest()[:16]

        return AttackPath(
            id=path_id,
            nodes=node_ids,
            edges=edge_ids,
            risk_score=risk_score,
            description=description,
            metadata={"length": len(node_ids)}
        )

    def _filter_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """过滤攻击路径"""
        # 移除重复路径
        unique_paths = []
        seen = set()

        for path in paths:
            path_key = "-".join(path.nodes)
            if path_key not in seen:
                seen.add(path_key)
                unique_paths.append(path)

        # 移除风险评分过低的路径
        filtered = [p for p in unique_paths if p.risk_score >= 0.3]

        return filtered

    def _calculate_node_risk(self, finding: VulnerabilityFinding) -> float:
        """计算节点风险评分

        Args:
            finding: 漏洞发现

        Returns:
            风险评分 (0-1)
        """
        severity_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "info": 0.1
        }

        severity_score = severity_scores.get(finding.severity, 0.5)
        confidence = finding.confidence

        return severity_score * confidence

    def _calculate_overall_risk(self, paths: List[AttackPath]) -> float:
        """计算总体风险评分

        Args:
            paths: 攻击路径列表

        Returns:
            总体风险评分 (0-1)
        """
        if not paths:
            return 0.0

        # 取最高风险路径的评分
        max_risk = max(path.risk_score for path in paths)
        return min(max_risk, 1.0)

    def _generate_summary(self, nodes: List[AttackNode], edges: List[AttackEdge], paths: List[AttackPath], risk_score: float) -> str:
        """生成分析摘要

        Args:
            nodes: 攻击节点列表
            edges: 攻击边列表
            paths: 攻击路径列表
            risk_score: 总体风险评分

        Returns:
            分析摘要
        """
        parts = [
            f"攻击链路分析完成，共发现 {len(nodes)} 个漏洞节点和 {len(edges)} 个关联关系",
            f"识别出 {len(paths)} 条可能的攻击路径",
            f"总体风险评分: {risk_score:.2f}"
        ]

        if paths:
            parts.append("\n高风险攻击路径:")
            for i, path in enumerate(paths[:3]):
                parts.append(f"{i+1}. {path.description} (风险: {path.risk_score:.2f})")

        return "\n".join(parts)

    def generate_visualization_data(self, result: AttackChainResult) -> Dict[str, Any]:
        """生成可视化数据

        Args:
            result: 攻击链路分析结果

        Returns:
            可视化数据
        """
        nodes = []
        for node in result.nodes:
            nodes.append({
                "id": node.id,
                "label": node.vulnerability.rule_name,
                "severity": node.vulnerability.severity,
                "risk": node.risk_score,
                "description": node.vulnerability.description,
                "code": node.vulnerability.code_snippet
            })

        edges = []
        for edge in result.edges:
            edges.append({
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "label": edge.relationship,
                "probability": edge.probability
            })

        paths = []
        for path in result.paths:
            paths.append({
                "id": path.id,
                "nodes": path.nodes,
                "edges": path.edges,
                "risk": path.risk_score,
                "description": path.description
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "paths": paths,
            "risk_score": result.risk_score,
            "summary": result.summary
        }


class AIAttackChainBuilder:
    """AI攻击链路构建器

    集成到现有系统中，提供攻击链路分析功能。
    """

    def __init__(self, config: Optional[Config] = None):
        """初始化AI攻击链路构建器

        Args:
            config: 配置对象
        """
        self.config = config or get_config()
        self._analyzer = AttackChainAnalyzer(config)

    async def build_attack_chains(self, result: SecurityAnalysisResult) -> AttackChainResult:
        """构建攻击链路

        Args:
            result: 安全分析结果

        Returns:
            攻击链路分析结果
        """
        return await self._analyzer.analyze(result.findings)

    def get_visualization_data(self, result: AttackChainResult) -> Dict[str, Any]:
        """获取可视化数据

        Args:
            result: 攻击链路分析结果

        Returns:
            可视化数据
        """
        return self._analyzer.generate_visualization_data(result)


# 全局攻击链路分析器实例
_attack_chain_analyzer: Optional[AttackChainAnalyzer] = None


# 全局AI攻击链路构建器实例
_ai_attack_chain_builder: Optional[AIAttackChainBuilder] = None


def get_attack_chain_analyzer() -> AttackChainAnalyzer:
    """获取全局攻击链路分析器实例

    Returns:
        攻击链路分析器实例
    """
    global _attack_chain_analyzer
    if _attack_chain_analyzer is None:
        _attack_chain_analyzer = AttackChainAnalyzer()
    return _attack_chain_analyzer


def get_ai_attack_chain_builder() -> AIAttackChainBuilder:
    """获取全局AI攻击链路构建器实例

    Returns:
        AI攻击链路构建器实例
    """
    global _ai_attack_chain_builder
    if _ai_attack_chain_builder is None:
        _ai_attack_chain_builder = AIAttackChainBuilder()
    return _ai_attack_chain_builder


class CrossFileAttackChainBuilder:
    """跨文件攻击链路构建器

    专门处理跨多个文件的攻击链路分析，增强 AttackChainAnalyzer 的多文件支持。
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._analyzer = AttackChainAnalyzer(config)

    async def analyze_cross_file(
        self,
        findings: List["VulnerabilityFinding"],
        dependency_graph: Optional["FileDependencyGraph"] = None,
    ) -> AttackChainResult:
        """分析跨文件攻击链路

        Args:
            findings: 漏洞发现列表
            dependency_graph: 文件依赖图

        Returns:
            攻击链路分析结果
        """
        if not dependency_graph:
            return await self._analyzer.analyze(findings)

        cross_file_findings = self._identify_cross_file_findings(findings, dependency_graph)

        if not cross_file_findings:
            return await self._analyzer.analyze(findings)

        all_findings = findings + cross_file_findings

        result = await self._analyzer.analyze(all_findings)

        result.metadata["cross_file_analyzed"] = True
        result.metadata["cross_file_count"] = len(cross_file_findings)

        return result

    def _identify_cross_file_findings(
        self,
        findings: List["VulnerabilityFinding"],
        dependency_graph: "FileDependencyGraph",
    ) -> List["VulnerabilityFinding"]:
        """识别跨文件漏洞

        Args:
            findings: 漏洞发现列表
            dependency_graph: 文件依赖图

        Returns:
            跨文件漏洞列表
        """
        cross_file_findings = []

        finding_by_file: Dict[str, List["VulnerabilityFinding"]] = {}
        for finding in findings:
            if hasattr(finding, 'location') and isinstance(finding.location, dict):
                file_path = finding.location.get('file', '')
            else:
                file_path = getattr(finding, 'file_path', '')

            if file_path not in finding_by_file:
                finding_by_file[file_path] = []
            finding_by_file[file_path].append(finding)

        for file_path, file_findings in finding_by_file.items():
            related_files = dependency_graph.get_related_files(file_path, depth=2)

            for related_file in related_files:
                if related_file in finding_by_file:
                    for main_finding in file_findings:
                        for related_finding in finding_by_file[related_file]:
                            if self._can_form_attack_chain(main_finding, related_finding):
                                cross_file_node = self._create_cross_file_finding(
                                    main_finding,
                                    related_finding,
                                )
                                cross_file_findings.append(cross_file_node)

        return cross_file_findings

    def _can_form_attack_chain(
        self,
        finding1: "VulnerabilityFinding",
        finding2: "VulnerabilityFinding",
    ) -> bool:
        """判断两个漏洞是否能形成攻击链

        Args:
            finding1: 漏洞1
            finding2: 漏洞2

        Returns:
            是否能形成攻击链
        """
        rule_types = {
            "input_validation": ["xss", "sql_injection", "command_injection"],
            "authentication": ["auth_bypass", "session_hijack"],
            "authorization": ["access_control", "privilege_escalation"],
        }

        type1 = self._get_finding_type(finding1)
        type2 = self._get_finding_type(finding2)

        for category, types in rule_types.items():
            if type1 in types and type2 in types:
                return True

        return False

    def _get_finding_type(self, finding: "VulnerabilityFinding") -> str:
        """获取漏洞类型"""
        rule_name = getattr(finding, 'rule_name', '').lower()
        rule_id = getattr(finding, 'rule_id', '').lower()

        for vuln_type in ["xss", "sql_injection", "command_injection", "auth_bypass", "ssrf", "csrf"]:
            if vuln_type in rule_name or vuln_type in rule_id:
                return vuln_type

        return "unknown"

    def _create_cross_file_finding(
        self,
        main_finding: "VulnerabilityFinding",
        related_finding: "VulnerabilityFinding",
    ) -> "VulnerabilityFinding":
        """创建跨文件漏洞

        Args:
            main_finding: 主漏洞
            related_finding: 关联漏洞

        Returns:
            跨文件漏洞
        """
        from src.ai.models import VulnerabilityFinding

        main_location = main_finding.location if hasattr(main_finding, 'location') else {}
        related_location = related_finding.location if hasattr(related_finding, 'location') else {}

        main_file = main_location.get('file', 'unknown') if isinstance(main_location, dict) else str(main_location)
        related_file = related_location.get('file', 'unknown') if isinstance(related_location, dict) else str(related_location)

        combined_description = f"[跨文件] {main_finding.description} -> {related_finding.description}"

        metadata = {
            "is_cross_file": True,
            "main_file": main_file,
            "related_file": related_file,
            "main_rule_id": main_finding.rule_id,
            "related_rule_id": related_finding.rule_id,
        }

        return VulnerabilityFinding(
            rule_id=f"cross_file_{main_finding.rule_id}",
            rule_name=f"跨文件: {main_finding.rule_name}",
            description=combined_description,
            severity=max(
                self._severity_to_score(main_finding.severity),
                self._severity_to_score(related_finding.severity),
            ),
            severity_value=max(
                self._severity_to_score(main_finding.severity),
                self._severity_to_score(related_finding.severity),
            ),
            confidence=max(main_finding.confidence, related_finding.confidence),
            location={"file": main_file, "line": main_finding.line if hasattr(main_finding, 'line') else 0},
            code_snippet=f"{main_finding.code_snippet}\n...\n{related_finding.code_snippet}",
            metadata=metadata,
        )

    def _severity_to_score(self, severity: str) -> str:
        """将严重级别转换为分数"""
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return severity_map.get(severity.lower(), "medium")
