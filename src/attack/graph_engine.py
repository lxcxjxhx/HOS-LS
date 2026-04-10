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

    def find_privilege_escalation_paths(self) -> List[AttackPath]:
        """查找特权提升路径

        Returns:
            特权提升路径列表
        """
        if self._graph is None or not self._nodes:
            return []

        # 识别特权提升相关节点
        privilege_nodes = [
            node_id
            for node_id, node in self._nodes.items()
            if self._is_privilege_related(node)
        ]

        paths = []

        # 查找包含特权提升节点的路径
        for entry in [node_id for node_id, node in self._nodes.items() if node.node_type == "entry_point"]:
            for sink in [node_id for node_id, node in self._nodes.items() if node.node_type == "sink"]:
                try:
                    for path_nodes in nx.all_simple_paths(
                        self._graph, entry, sink, cutoff=10
                    ):
                        # 检查路径是否包含特权提升节点
                        if any(node_id in privilege_nodes for node_id in path_nodes):
                            path = self._build_attack_path(path_nodes)
                            if path:
                                # 标记为特权提升路径
                                path.description = f"特权提升: {path.description}"
                                # 提高风险评分
                                path.risk_score *= 1.5
                                paths.append(path)
                except nx.NetworkXNoPath:
                    continue

        # 按风险评分排序
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        return paths

    def find_lateral_movement_paths(self) -> List[AttackPath]:
        """查找横向移动路径

        Returns:
            横向移动路径列表
        """
        if self._graph is None or not self._nodes:
            return []

        # 识别横向移动相关节点
        lateral_movement_nodes = [
            node_id
            for node_id, node in self._nodes.items()
            if self._is_lateral_movement_related(node)
        ]

        paths = []

        # 查找包含横向移动节点的路径
        for entry in [node_id for node_id, node in self._nodes.items() if node.node_type == "entry_point"]:
            for sink in [node_id for node_id, node in self._nodes.items() if node.node_type == "sink"]:
                try:
                    for path_nodes in nx.all_simple_paths(
                        self._graph, entry, sink, cutoff=10
                    ):
                        # 检查路径是否包含横向移动节点
                        if any(node_id in lateral_movement_nodes for node_id in path_nodes):
                            path = self._build_attack_path(path_nodes)
                            if path:
                                # 标记为横向移动路径
                                path.description = f"横向移动: {path.description}"
                                # 提高风险评分
                                path.risk_score *= 1.3
                                paths.append(path)
                except nx.NetworkXNoPath:
                    continue

        # 按风险评分排序
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        return paths

    def find_rce_chains(self) -> List[AttackPath]:
        """查找远程代码执行(RCE)链

        Returns:
            RCE链列表
        """
        if self._graph is None or not self._nodes:
            return []

        # 识别RCE相关节点
        rce_nodes = [
            node_id
            for node_id, node in self._nodes.items()
            if self._is_rce_related(node)
        ]

        paths = []

        # 查找包含RCE节点的路径
        for entry in [node_id for node_id, node in self._nodes.items() if node.node_type == "entry_point"]:
            for sink in [node_id for node_id, node in self._nodes.items() if node.node_type == "sink"]:
                try:
                    for path_nodes in nx.all_simple_paths(
                        self._graph, entry, sink, cutoff=10
                    ):
                        # 检查路径是否包含RCE节点
                        if any(node_id in rce_nodes for node_id in path_nodes):
                            path = self._build_attack_path(path_nodes)
                            if path:
                                # 标记为RCE链
                                path.description = f"RCE链: {path.description}"
                                # 提高风险评分
                                path.risk_score *= 1.8
                                paths.append(path)
                except nx.NetworkXNoPath:
                    continue

        # 按风险评分排序
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        return paths

    def _is_lateral_movement_related(self, node: AttackNode) -> bool:
        """检查节点是否与横向移动相关

        Args:
            node: 攻击节点

        Returns:
            是否与横向移动相关
        """
        lateral_keywords = [
            'lateral', 'movement', 'network', 'remote', 'access', 'connect',
            'ssh', 'rdp', 'smb', 'ftp', 'telnet', 'connection'
        ]

        description = node.description.lower()
        for keyword in lateral_keywords:
            if keyword in description:
                return True

        # 检查元数据
        metadata = node.metadata
        if 'lateral' in metadata or 'network' in metadata:
            return True

        return False

    def _is_rce_related(self, node: AttackNode) -> bool:
        """检查节点是否与远程代码执行相关

        Args:
            node: 攻击节点

        Returns:
            是否与远程代码执行相关
        """
        rce_keywords = [
            'rce', 'remote code', 'code execution', 'execute', 'eval', 'exec',
            'system', 'shell', 'command', 'injection', 'payload'
        ]

        description = node.description.lower()
        for keyword in rce_keywords:
            if keyword in description:
                return True

        # 检查元数据
        metadata = node.metadata
        if 'rce' in metadata or 'code_execution' in metadata:
            return True

        return False

    def _is_privilege_related(self, node: AttackNode) -> bool:
        """检查节点是否与特权提升相关

        Args:
            node: 攻击节点

        Returns:
            是否与特权提升相关
        """
        privilege_keywords = [
            'privilege', 'escalation', 'admin', 'root', 'sudo', 'permission',
            'auth', 'authentication', 'authorization', 'access', 'user', 'role'
        ]

        description = node.description.lower()
        for keyword in privilege_keywords:
            if keyword in description:
                return True

        # 检查元数据
        metadata = node.metadata
        if 'privilege' in metadata or 'auth' in metadata:
            return True

        return False

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

        # 基于节点类型计算风险
        risk_weights = {
            "entry_point": 1.0,
            "vulnerability": 5.0,
            "sink": 10.0,
            "privilege_escalation": 15.0,
            "lateral_movement": 12.0,
            "rce": 20.0
        }

        # 计算基础风险
        total_risk = 0.0
        for node in nodes:
            # 检查节点类型
            node_type = node.node_type
            # 检查节点描述中的关键词
            description = node.description.lower()
            
            # 确定节点权重
            weight = risk_weights.get(node_type, 1.0)
            
            # 检查是否包含特权提升关键词
            if any(keyword in description for keyword in ['privilege', 'escalation', 'admin', 'root']):
                weight = risk_weights.get('privilege_escalation', 15.0)
            # 检查是否包含横向移动关键词
            elif any(keyword in description for keyword in ['lateral', 'movement', 'network', 'remote']):
                weight = risk_weights.get('lateral_movement', 12.0)
            # 检查是否包含RCE关键词
            elif any(keyword in description for keyword in ['rce', 'remote code', 'code execution', 'execute']):
                weight = risk_weights.get('rce', 20.0)
            
            total_risk += weight

        # 路径长度调整
        path_length = len(nodes)
        if path_length > 5:
            # 长路径风险更高
            total_risk *= 1.2
        elif path_length == 1:
            # 单节点风险较低
            total_risk *= 0.5

        # 平均风险
        average_risk = total_risk / path_length

        return min(average_risk, 10.0)

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
