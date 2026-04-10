"""攻击图引擎

使用 networkx 构建攻击图，识别攻击路径。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx


@dataclass
class AttackNode:
    """攻击节点"""

    id: str
    node_type: str  # entry_point, vulnerability, sink, etc.
    file_path: str
    line: int
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackEdge:
    """攻击边"""

    source: str
    target: str
    edge_type: str  # data_flow, control_flow, call, etc.
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """攻击路径"""

    nodes: List[AttackNode] = field(default_factory=list)
    edges: List[AttackEdge] = field(default_factory=list)
    risk_score: float = 0.0
    description: str = ""


class AttackGraphEngine:
    """攻击图引擎

    使用 networkx 构建和分析攻击图。
    """

    def __init__(self) -> None:
        self._graph: Optional[nx.DiGraph] = None
        self._nodes: Dict[str, AttackNode] = {}
        self._edges: List[AttackEdge] = []

    def initialize(self) -> None:
        """初始化引擎"""
        self._graph = nx.DiGraph()
        self._nodes = {}
        self._edges = []

    def add_node(self, node: AttackNode) -> None:
        """添加节点

        Args:
            node: 攻击节点
        """
        if self._graph is None:
            self.initialize()

        self._nodes[node.id] = node
        self._graph.add_node(
            node.id,
            node_type=node.node_type,
            file_path=node.file_path,
            line=node.line,
            description=node.description,
            **node.metadata,
        )

    def add_edge(self, edge: AttackEdge) -> None:
        """添加边

        Args:
            edge: 攻击边
        """
        if self._graph is None:
            self.initialize()

        self._edges.append(edge)
        self._graph.add_edge(
            edge.source,
            edge.target,
            edge_type=edge.edge_type,
            description=edge.description,
            **edge.metadata,
        )

    def find_attack_paths(
        self,
        entry_points: Optional[List[str]] = None,
        sinks: Optional[List[str]] = None,
    ) -> List[AttackPath]:
        """查找攻击路径

        Args:
            entry_points: 入口点节点 ID 列表
            sinks: 危险点节点 ID 列表

        Returns:
            攻击路径列表
        """
        if self._graph is None or not self._nodes:
            return []

        paths = []

        # 如果没有指定入口点，使用所有 entry_point 类型的节点
        if entry_points is None:
            entry_points = [
                node_id
                for node_id, node in self._nodes.items()
                if node.node_type == "entry_point"
            ]

        # 如果没有指定危险点，使用所有 sink 类型的节点
        if sinks is None:
            sinks = [
                node_id
                for node_id, node in self._nodes.items()
                if node.node_type == "sink"
            ]

        # 查找从入口点到危险点的所有路径
        for entry in entry_points:
            for sink in sinks:
                try:
                    # 使用所有简单路径
                    for path_nodes in nx.all_simple_paths(
                        self._graph, entry, sink, cutoff=10
                    ):
                        path = self._build_attack_path(path_nodes)
                        if path:
                            paths.append(path)
                except nx.NetworkXNoPath:
                    continue

        # 按风险评分排序
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        return paths

    def _build_attack_path(self, node_ids: List[str]) -> Optional[AttackPath]:
        """构建攻击路径

        Args:
            node_ids: 节点 ID 列表

        Returns:
            攻击路径
        """
        if not node_ids:
            return None

        nodes = []
        edges = []

        for i, node_id in enumerate(node_ids):
            node = self._nodes.get(node_id)
            if node:
                nodes.append(node)

            # 添加边
            if i < len(node_ids) - 1:
                next_id = node_ids[i + 1]
                edge_data = self._graph.get_edge_data(node_id, next_id)
                if edge_data:
                    edges.append(
                        AttackEdge(
                            source=node_id,
                            target=next_id,
                            edge_type=edge_data.get("edge_type", "unknown"),
                            description=edge_data.get("description", ""),
                        )
                    )

        # 计算风险评分
        risk_score = self._calculate_path_risk(nodes)

        # 生成描述
        description = self._generate_path_description(nodes)

        return AttackPath(
            nodes=nodes,
            edges=edges,
            risk_score=risk_score,
            description=description,
        )

    def _calculate_path_risk(self, nodes: List[AttackNode]) -> float:
        """计算路径风险评分"""
        if not nodes:
            return 0.0

        # 基于节点类型和数量计算风险
        risk_weights = {
            "entry_point": 1.0,
            "vulnerability": 5.0,
            "sink": 10.0,
        }

        total_risk = 0.0
        for node in nodes:
            weight = risk_weights.get(node.node_type, 1.0)
            total_risk += weight

        return min(total_risk / len(nodes), 10.0)

    def _generate_path_description(self, nodes: List[AttackNode]) -> str:
        """生成路径描述"""
        if not nodes:
            return ""

        parts = []
        for i, node in enumerate(nodes):
            if i == 0:
                parts.append(f"从 {node.description} 开始")
            elif i == len(nodes) - 1:
                parts.append(f"到达 {node.description}")
            else:
                parts.append(f"经过 {node.description}")

        return " -> ".join(parts)

    def get_node_predecessors(self, node_id: str) -> List[str]:
        """获取节点的前驱节点

        Args:
            node_id: 节点 ID

        Returns:
            前驱节点 ID 列表
        """
        if self._graph is None:
            return []
        return list(self._graph.predecessors(node_id))

    def get_node_successors(self, node_id: str) -> List[str]:
        """获取节点的后继节点

        Args:
            node_id: 节点 ID

        Returns:
            后继节点 ID 列表
        """
        if self._graph is None:
            return []
        return list(self._graph.successors(node_id))

    def analyze_node_criticality(self) -> Dict[str, float]:
        """分析节点关键性

        Returns:
            节点 ID 到关键性评分的映射
        """
        if self._graph is None:
            return {}

        # 使用介数中心性作为关键性指标
        centrality = nx.betweenness_centrality(self._graph)
        return centrality

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "nodes": [
                {
                    "id": node.id,
                    "type": node.node_type,
                    "file_path": node.file_path,
                    "line": node.line,
                    "description": node.description,
                }
                for node in self._nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.edge_type,
                    "description": edge.description,
                }
                for edge in self._edges
            ],
        }

    def clear(self) -> None:
        """清空图"""
        self.initialize()
