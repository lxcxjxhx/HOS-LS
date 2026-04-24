"""图谱构建模块

负责从 AST、污点分析和 CVE 数据构建知识图谱。
"""

from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass

from tree_sitter import Node, Tree

from src.analyzers.ast_analyzer import ASTAnalyzer
from src.taint.analyzer import TaintAnalyzer, TaintPath, TaintSource, TaintSink
from src.analyzers.base import AnalysisContext


@dataclass
class GraphNode:
    """图节点"""
    id: str
    label: str
    properties: Dict[str, Any]


@dataclass
class GraphEdge:
    """图边"""
    source: str
    target: str
    type: str
    properties: Dict[str, Any]


class GraphBuilder:
    """图谱构建器

    从 AST、污点分析和 CVE 数据构建知识图谱。
    """

    def __init__(self):
        self._ast_analyzer = ASTAnalyzer()
        self._taint_analyzer = TaintAnalyzer()
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []

    def build_from_ast(self, context: AnalysisContext) -> None:
        """从 AST 构建图谱

        Args:
            context: 分析上下文
        """
        # 解析 AST
        tree = self._ast_analyzer.get_tree(context.file_content, context.language)
        if not tree:
            return

        # 遍历 AST 构建节点和边
        self._traverse_ast(tree, context)

    def build_from_taint(self, context: AnalysisContext) -> None:
        """从污点分析构建图谱

        Args:
            context: 分析上下文
        """
        # 执行污点分析
        taint_paths = self._taint_analyzer.analyze(context)

        # 构建污点流边
        for path in taint_paths:
            self._add_taint_path(path)

    def build_from_cve(self, cve_data: List[Dict[str, Any]]) -> None:
        """从 CVE 数据构建图谱

        Args:
            cve_data: CVE 数据列表
        """
        for cve in cve_data:
            self._add_cve_node(cve)

    def get_nodes(self) -> List[GraphNode]:
        """获取所有节点

        Returns:
            节点列表
        """
        return list(self._nodes.values())

    def get_edges(self) -> List[GraphEdge]:
        """获取所有边

        Returns:
            边列表
        """
        return self._edges

    def clear(self) -> None:
        """清空图谱"""
        self._nodes = {}
        self._edges = []

    def _traverse_ast(self, tree: Tree, context: AnalysisContext) -> None:
        """遍历 AST 构建图谱

        Args:
            tree: AST 树
            context: 分析上下文
        """
        root_node = tree.root_node
        self._traverse_node(root_node, context, None)

    def _traverse_node(self, node: Node, context: AnalysisContext, parent_id: Optional[str]) -> None:
        """遍历节点

        Args:
            node: 当前节点
            context: 分析上下文
            parent_id: 父节点 ID
        """
        node_id = self._get_node_id(node, context)
        node_type = node.type

        # 处理不同类型的节点
        if node_type == "function_definition":
            self._process_function_definition(node, context, node_id, parent_id)
        elif node_type == "class_definition":
            self._process_class_definition(node, context, node_id, parent_id)
        elif node_type == "call":
            self._process_function_call(node, context, node_id, parent_id)
        elif node_type == "import_statement" or node_type == "import_from_statement":
            self._process_import(node, context, node_id, parent_id)

        # 递归遍历子节点
        for child in node.children:
            self._traverse_node(child, context, node_id)

    def _process_function_definition(self, node: Node, context: AnalysisContext, node_id: str, parent_id: Optional[str]) -> None:
        """处理函数定义

        Args:
            node: 函数定义节点
            context: 分析上下文
            node_id: 节点 ID
            parent_id: 父节点 ID
        """
        function_name = self._get_function_name(node)
        if not function_name:
            return

        # 创建函数节点
        properties = {
            "name": function_name,
            "file_path": context.file_path,
            "line": node.start_point[0] + 1,
            "language": context.language
        }
        self._add_node(node_id, "Function", properties)

        # 添加与父节点的关系
        if parent_id:
            self._add_edge(parent_id, node_id, "CONTAINS", {})

    def _process_class_definition(self, node: Node, context: AnalysisContext, node_id: str, parent_id: Optional[str]) -> None:
        """处理类定义

        Args:
            node: 类定义节点
            context: 分析上下文
            node_id: 节点 ID
            parent_id: 父节点 ID
        """
        class_name = self._get_class_name(node)
        if not class_name:
            return

        # 创建类节点
        properties = {
            "name": class_name,
            "file_path": context.file_path,
            "line": node.start_point[0] + 1,
            "language": context.language
        }
        self._add_node(node_id, "Class", properties)

        # 添加与父节点的关系
        if parent_id:
            self._add_edge(parent_id, node_id, "CONTAINS", {})

    def _process_function_call(self, node: Node, context: AnalysisContext, node_id: str, parent_id: Optional[str]) -> None:
        """处理函数调用

        Args:
            node: 函数调用节点
            context: 分析上下文
            node_id: 节点 ID
            parent_id: 父节点 ID
        """
        function_name = self._get_function_name(node)
        if not function_name:
            return

        # 创建函数调用节点
        properties = {
            "name": function_name,
            "file_path": context.file_path,
            "line": node.start_point[0] + 1,
            "language": context.language
        }
        self._add_node(node_id, "FunctionCall", properties)

        # 添加与父节点的关系
        if parent_id:
            self._add_edge(parent_id, node_id, "CALLS", {})

        # 检查是否为危险函数
        sink_info = self._taint_analyzer._is_dangerous_function(function_name, context.language)
        if sink_info:
            # 创建 Sink 节点
            sink_id = f"sink_{function_name}_{context.file_path}_{node.start_point[0]}"
            sink_properties = {
                "name": function_name,
                "type": sink_info["type"],
                "file_path": context.file_path,
                "line": node.start_point[0] + 1
            }
            self._add_node(sink_id, "Sink", sink_properties)
            self._add_edge(node_id, sink_id, "TRIGGERS", {})

    def _process_import(self, node: Node, context: AnalysisContext, node_id: str, parent_id: Optional[str]) -> None:
        """处理导入语句

        Args:
            node: 导入语句节点
            context: 分析上下文
            node_id: 节点 ID
            parent_id: 父节点 ID
        """
        import_text = self._get_node_text(node)

        # 创建导入节点
        properties = {
            "text": import_text,
            "file_path": context.file_path,
            "line": node.start_point[0] + 1,
            "language": context.language
        }
        self._add_node(node_id, "Import", properties)

        # 添加与父节点的关系
        if parent_id:
            self._add_edge(parent_id, node_id, "IMPORTS", {})

    def _add_taint_path(self, path: TaintPath) -> None:
        """添加污点路径

        Args:
            path: 污点传播路径
        """
        # 创建 Source 节点
        source_id = f"source_{path.source.name}_{path.source.file_path}_{path.source.line}"
        source_properties = {
            "name": path.source.name,
            "description": path.source.description,
            "file_path": path.source.file_path,
            "line": path.source.line
        }
        self._add_node(source_id, "Source", source_properties)

        # 创建 Sink 节点
        sink_id = f"sink_{path.sink.name}_{path.sink.file_path}_{path.sink.line}"
        sink_properties = {
            "name": path.sink.name,
            "description": path.sink.description,
            "vulnerability_type": path.sink.vulnerability_type,
            "file_path": path.sink.file_path,
            "line": path.sink.line
        }
        self._add_node(sink_id, "Sink", sink_properties)

        # 添加污点流边
        self._add_edge(source_id, sink_id, "TAINT_FLOW", {
            "confidence": path.confidence,
            "severity": path.severity,
            "path": path.path
        })

        # 创建 Vulnerability 节点
        vuln_id = f"vuln_{path.sink.vulnerability_type}_{path.sink.file_path}_{path.sink.line}"
        vuln_properties = {
            "type": path.sink.vulnerability_type,
            "severity": path.severity,
            "file_path": path.sink.file_path,
            "line": path.sink.line
        }
        self._add_node(vuln_id, "Vulnerability", vuln_properties)

        # 添加漏洞关系
        self._add_edge(sink_id, vuln_id, "CAUSES", {})

    def _add_cve_node(self, cve: Dict[str, Any]) -> None:
        """添加 CVE 节点

        Args:
            cve: CVE 数据
        """
        cve_id = cve.get("cve_id")
        if not cve_id:
            return

        # 创建 CVE 节点
        cve_properties = {
            "id": cve_id,
            "title": cve.get("title", ""),
            "description": cve.get("description", ""),
            "cvss": cve.get("cvss", 0.0),
            "source": cve.get("source", ""),
            "published_date": cve.get("published_date", "")
        }
        self._add_node(cve_id, "CVE", cve_properties)

        # 处理 CWE
        cwe = cve.get("cwe")
        if cwe:
            cwe_id = f"cwe_{cwe}"
            cwe_properties = {
                "id": cwe,
                "name": cwe
            }
            self._add_node(cwe_id, "Weakness", cwe_properties)
            self._add_edge(cve_id, cwe_id, "BELONGS_TO", {})

        # 处理受影响产品
        affected_products = cve.get("affected_products", [])
        for product in affected_products:
            product_id = f"product_{product}"
            product_properties = {
                "name": product
            }
            self._add_node(product_id, "Product", product_properties)
            self._add_edge(cve_id, product_id, "AFFECTS", {})

        # 处理 Sink
        sinks = cve.get("sinks", [])
        for sink in sinks:
            sink_id = f"sink_{sink}"
            sink_properties = {
                "type": sink
            }
            self._add_node(sink_id, "Sink", sink_properties)
            self._add_edge(cve_id, sink_id, "HAS_SINK", {})

        # 处理 Source
        sources = cve.get("sources", [])
        for source in sources:
            source_id = f"source_{source}"
            source_properties = {
                "type": source
            }
            self._add_node(source_id, "Source", source_properties)
            self._add_edge(source_id, sink_id, "TRIGGERS", {})

    def _add_node(self, node_id: str, label: str, properties: Dict[str, Any]) -> None:
        """添加节点

        Args:
            node_id: 节点 ID
            label: 节点标签
            properties: 节点属性
        """
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                label=label,
                properties=properties
            )

    def _add_edge(self, source: str, target: str, type: str, properties: Dict[str, Any]) -> None:
        """添加边

        Args:
            source: 源节点 ID
            target: 目标节点 ID
            type: 边类型
            properties: 边属性
        """
        # 检查源节点和目标节点是否存在
        if source not in self._nodes or target not in self._nodes:
            return

        # 检查边是否已存在
        for edge in self._edges:
            if edge.source == source and edge.target == target and edge.type == type:
                return

        self._edges.append(GraphEdge(
            source=source,
            target=target,
            type=type,
            properties=properties
        ))

    def _get_node_id(self, node: Node, context: AnalysisContext) -> str:
        """获取节点 ID

        Args:
            node: AST 节点
            context: 分析上下文

        Returns:
            节点 ID
        """
        node_type = node.type
        line = node.start_point[0] + 1
        column = node.start_point[1]
        return f"{node_type}_{context.file_path}_{line}_{column}"

    def _get_function_name(self, node: Node) -> Optional[str]:
        """获取函数名

        Args:
            node: 函数定义或调用节点

        Returns:
            函数名
        """
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child)
        return None

    def _get_class_name(self, node: Node) -> Optional[str]:
        """获取类名

        Args:
            node: 类定义节点

        Returns:
            类名
        """
        for child in node.children:
            if child.type == "identifier":
                return self._get_node_text(child)
        return None

    def _get_node_text(self, node: Node) -> str:
        """获取节点文本

        Args:
            node: AST 节点

        Returns:
            节点文本
        """
        if node.text:
            return node.text.decode()
        return ""

    def get_statistics(self) -> Dict[str, Any]:
        """获取图谱统计信息

        Returns:
            统计信息
        """
        # 统计节点类型
        node_counts = {}
        for node in self._nodes.values():
            if node.label not in node_counts:
                node_counts[node.label] = 0
            node_counts[node.label] += 1

        # 统计边类型
        edge_counts = {}
        for edge in self._edges:
            if edge.type not in edge_counts:
                edge_counts[edge.type] = 0
            edge_counts[edge.type] += 1

        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "node_counts": node_counts,
            "edge_counts": edge_counts
        }
