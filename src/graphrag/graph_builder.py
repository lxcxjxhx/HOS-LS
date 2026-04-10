"""图谱构建模块

负责从 AST、污点分析和 CVE 数据构建知识图谱。
"""

import time
import hashlib
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

    从 AST、污点分析和 CVE 数据构建知识图谱，支持多种图结构。
    """

    def __init__(self):
        self._ast_analyzer = ASTAnalyzer()
        self._taint_analyzer = TaintAnalyzer()
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._function_calls: Dict[str, List[str]] = {}  # 函数调用关系
        self._file_hashes: Dict[str, str] = {}  # 用于增量更新的文件哈希
        self._node_cache: Dict[str, GraphNode] = {}  # 节点缓存
        self._edge_cache: Dict[str, GraphEdge] = {}  # 边缓存
        self._ast_cache: Dict[str, Tree] = {}  # AST缓存

    def build_ast_graph(self, context: AnalysisContext) -> None:
        """构建 AST 图谱

        Args:
            context: 分析上下文
        """
        # 检查 AST 缓存
        cache_key = f"{context.file_path}_{self._calculate_file_hash(context.file_content)}"
        if cache_key in self._ast_cache:
            tree = self._ast_cache[cache_key]
        else:
            # 解析 AST
            tree = self._ast_analyzer.get_tree(context.file_content, context.language)
            if not tree:
                return
            # 缓存 AST
            self._ast_cache[cache_key] = tree

        # 遍历 AST 构建节点和边
        self._traverse_ast(tree, context)

    def build_call_graph(self, context: AnalysisContext) -> None:
        """构建调用图谱

        Args:
            context: 分析上下文
        """
        # 首先构建 AST 图谱以获取函数调用信息
        self.build_ast_graph(context)

        # 处理函数调用关系
        for caller, callees in self._function_calls.items():
            for callee in callees:
                # 检查节点是否存在
                if caller in self._nodes and callee in self._nodes:
                    self._add_edge(caller, callee, "CALLS", {})

    def build_data_flow_graph(self, context: AnalysisContext) -> None:
        """构建数据流图谱

        Args:
            context: 分析上下文
        """
        # 执行污点分析
        taint_paths = self._taint_analyzer.analyze(context)

        # 构建污点流边
        for path in taint_paths:
            self._add_taint_path(path)

    def build_vuln_pattern_graph(self, cve_data: List[Dict[str, Any]]) -> None:
        """构建漏洞模式图谱

        Args:
            cve_data: CVE 数据列表
        """
        for cve in cve_data:
            self._add_cve_node(cve)

    def build_complete_graph(self, context: AnalysisContext, cve_data: List[Dict[str, Any]] = None) -> None:
        """构建完整的知识图谱

        Args:
            context: 分析上下文
            cve_data: CVE 数据列表
        """
        self.build_ast_graph(context)
        self.build_call_graph(context)
        self.build_data_flow_graph(context)
        if cve_data:
            self.build_vuln_pattern_graph(cve_data)
        # 增强图结构之间的关联分析
        self._enhance_cross_graph_connections(context)

    def build_from_ast(self, context: AnalysisContext) -> None:
        """从 AST 构建图谱（兼容旧接口）

        Args:
            context: 分析上下文
        """
        self.build_ast_graph(context)

    def build_from_taint(self, context: AnalysisContext) -> None:
        """从污点分析构建图谱（兼容旧接口）

        Args:
            context: 分析上下文
        """
        self.build_data_flow_graph(context)

    def build_from_cve(self, cve_data: List[Dict[str, Any]]) -> None:
        """从 CVE 数据构建图谱（兼容旧接口）

        Args:
            cve_data: CVE 数据列表
        """
        self.build_vuln_pattern_graph(cve_data)

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
        self._function_calls = {}
        self._file_hashes = {}
        self._node_cache = {}
        self._edge_cache = {}
        self._ast_cache = {}

    def _calculate_file_hash(self, content: str) -> str:
        """计算文件内容的哈希值

        Args:
            content: 文件内容

        Returns:
            文件哈希值
        """
        return hashlib.md5(content.encode()).hexdigest()

    def build_incremental_graph(self, context: AnalysisContext, cve_data: List[Dict[str, Any]] = None) -> bool:
        """增量构建知识图谱

        Args:
            context: 分析上下文
            cve_data: CVE 数据列表

        Returns:
            是否进行了增量更新
        """
        # 计算当前文件的哈希值
        current_hash = self._calculate_file_hash(context.file_content)
        file_path = context.file_path
        
        # 检查文件是否有变化
        if file_path in self._file_hashes and self._file_hashes[file_path] == current_hash:
            return False  # 文件未变化，不需要更新
        
        # 文件有变化，进行增量更新
        # 1. 移除与该文件相关的节点和边
        self._remove_file_nodes_edges(file_path)
        
        # 2. 重新构建该文件的图谱
        self.build_complete_graph(context, cve_data)
        
        # 3. 更新文件哈希
        self._file_hashes[file_path] = current_hash
        
        return True

    def _remove_file_nodes_edges(self, file_path: str) -> None:
        """移除与指定文件相关的节点和边

        Args:
            file_path: 文件路径
        """
        # 找出与该文件相关的节点
        file_nodes = [node_id for node_id, node in self._nodes.items() 
                     if node.properties.get("file_path") == file_path]
        
        # 移除相关的边
        self._edges = [edge for edge in self._edges 
                      if edge.source not in file_nodes and edge.target not in file_nodes]
        
        # 移除相关的节点
        for node_id in file_nodes:
            if node_id in self._nodes:
                del self._nodes[node_id]
        
        # 清理函数调用关系
        for caller in list(self._function_calls.keys()):
            if caller in file_nodes:
                del self._function_calls[caller]

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
        elif node_type == "assignment":
            self._process_assignment(node, context, node_id, parent_id)

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
            self._add_edge(parent_id, node_id, "CONTAINS", {})

            # 记录函数调用关系
            if parent_id not in self._function_calls:
                self._function_calls[parent_id] = []
            # 创建被调用函数的节点
            callee_id = f"function_{function_name}_{context.file_path}"
            callee_properties = {
                "name": function_name,
                "file_path": context.file_path,
                "language": context.language
            }
            self._add_node(callee_id, "Function", callee_properties)
            self._function_calls[parent_id].append(callee_id)

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

    def _process_assignment(self, node: Node, context: AnalysisContext, node_id: str, parent_id: Optional[str]) -> None:
        """处理赋值语句

        Args:
            node: 赋值语句节点
            context: 分析上下文
            node_id: 节点 ID
            parent_id: 父节点 ID
        """
        # 创建赋值节点
        properties = {
            "file_path": context.file_path,
            "line": node.start_point[0] + 1,
            "language": context.language
        }
        self._add_node(node_id, "Assignment", properties)

        # 添加与父节点的关系
        if parent_id:
            self._add_edge(parent_id, node_id, "CONTAINS", {})

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
            # 为每个 source 连接到每个 sink
            for sink in sinks:
                sink_id = f"sink_{sink}"
                if sink_id in self._nodes:
                    self._add_edge(source_id, sink_id, "TRIGGERS", {})

    def _add_node(self, node_id: str, label: str, properties: Dict[str, Any]) -> None:
        """添加节点

        Args:
            node_id: 节点 ID
            label: 节点标签
            properties: 节点属性
        """
        if node_id not in self._nodes:
            # 检查节点缓存
            if node_id in self._node_cache:
                node = self._node_cache[node_id]
            else:
                node = GraphNode(
                    id=node_id,
                    label=label,
                    properties=properties
                )
                # 缓存节点
                self._node_cache[node_id] = node
            self._nodes[node_id] = node

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

        # 生成边的唯一标识
        edge_key = f"{source}_{target}_{type}"
        
        # 检查边是否已存在
        if edge_key in self._edge_cache:
            return
        
        # 检查边列表
        for edge in self._edges:
            if edge.source == source and edge.target == target and edge.type == type:
                self._edge_cache[edge_key] = edge
                return

        # 创建新边
        edge = GraphEdge(
            source=source,
            target=target,
            type=type,
            properties=properties
        )
        self._edges.append(edge)
        self._edge_cache[edge_key] = edge

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
            elif child.type == "member_expression":
                # 处理对象方法调用，如 obj.method()
                for grandchild in child.children:
                    if grandchild.type == "identifier":
                        return self._get_node_text(grandchild)
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

    def _enhance_cross_graph_connections(self, context: AnalysisContext) -> None:
        """增强图结构之间的关联分析

        Args:
            context: 分析上下文
        """
        # 1. 连接 AST 节点与漏洞节点
        self._connect_ast_to_vulnerabilities()
        
        # 2. 连接调用图节点与数据流节点
        self._connect_call_to_data_flow()
        
        # 3. 连接 CVE 节点与相关代码节点
        self._connect_cve_to_code(context)
        
        # 4. 创建高级关系
        self._create_higher_level_relationships()

    def _connect_ast_to_vulnerabilities(self) -> None:
        """连接 AST 节点与漏洞节点"""
        # 找出所有的漏洞节点
        vuln_nodes = [node for node in self._nodes.values() if node.label == "Vulnerability"]
        
        # 找出所有的函数和类节点
        code_nodes = [node for node in self._nodes.values() if node.label in ["Function", "Class"]]
        
        # 为每个漏洞节点找到相关的代码节点
        for vuln_node in vuln_nodes:
            vuln_file = vuln_node.properties.get("file_path")
            if not vuln_file:
                continue
            
            # 查找同一文件中的代码节点
            for code_node in code_nodes:
                code_file = code_node.properties.get("file_path")
                if code_file == vuln_file:
                    # 添加关联边
                    self._add_edge(code_node.id, vuln_node.id, "HAS_VULNERABILITY", {})

    def _connect_call_to_data_flow(self) -> None:
        """连接调用图节点与数据流节点"""
        # 找出所有的函数调用节点
        call_nodes = [node for node in self._nodes.values() if node.label == "FunctionCall"]
        
        # 找出所有的污点流边
        taint_edges = [edge for edge in self._edges if edge.type == "TAINT_FLOW"]
        
        # 为每个函数调用节点查找相关的污点流
        for call_node in call_nodes:
            call_file = call_node.properties.get("file_path")
            call_line = call_node.properties.get("line")
            if not call_file or not call_line:
                continue
            
            # 查找相关的污点流
            for taint_edge in taint_edges:
                source_node = self._nodes.get(taint_edge.source)
                sink_node = self._nodes.get(taint_edge.target)
                if source_node and sink_node:
                    source_file = source_node.properties.get("file_path")
                    sink_file = sink_node.properties.get("file_path")
                    if source_file == call_file or sink_file == call_file:
                        # 添加关联边
                        self._add_edge(call_node.id, taint_edge.source, "RELATED_TO", {})
                        self._add_edge(call_node.id, taint_edge.target, "RELATED_TO", {})

    def _connect_cve_to_code(self, context: AnalysisContext) -> None:
        """连接 CVE 节点与相关代码节点"""
        # 找出所有的 CVE 节点
        cve_nodes = [node for node in self._nodes.values() if node.label == "CVE"]
        
        # 找出所有的代码节点
        code_nodes = [node for node in self._nodes.values() if node.label in ["Function", "Class", "FunctionCall"]]
        
        # 为每个 CVE 节点找到相关的代码节点
        for cve_node in cve_nodes:
            cve_description = cve_node.properties.get("description", "")
            
            # 简单的基于关键词的匹配
            for code_node in code_nodes:
                code_name = code_node.properties.get("name", "")
                if code_name and code_name.lower() in cve_description.lower():
                    # 添加关联边
                    self._add_edge(cve_node.id, code_node.id, "AFFECTS_CODE", {})

    def _create_higher_level_relationships(self) -> None:
        """创建高级关系"""
        # 1. 识别攻击路径
        self._identify_attack_paths()
        
        # 2. 识别安全边界
        self._identify_security_boundaries()

    def _identify_attack_paths(self) -> None:
        """识别攻击路径"""
        # 找出所有的 Source -> Sink 路径
        sources = [node for node in self._nodes.values() if node.label == "Source"]
        sinks = [node for node in self._nodes.values() if node.label == "Sink"]
        
        for source in sources:
            for sink in sinks:
                # 检查是否存在从 Source 到 Sink 的路径
                if self._has_path(source.id, sink.id):
                    # 创建攻击路径节点
                    attack_path_id = f"attack_path_{source.id}_{sink.id}"
                    attack_path_properties = {
                        "source": source.properties.get("name"),
                        "sink": sink.properties.get("name"),
                        "vulnerability_type": sink.properties.get("vulnerability_type")
                    }
                    self._add_node(attack_path_id, "AttackPath", attack_path_properties)
                    
                    # 添加关联边
                    self._add_edge(attack_path_id, source.id, "STARTS_AT", {})
                    self._add_edge(attack_path_id, sink.id, "ENDS_AT", {})

    def _identify_security_boundaries(self) -> None:
        """识别安全边界"""
        # 找出所有的导入节点
        import_nodes = [node for node in self._nodes.values() if node.label == "Import"]
        
        for import_node in import_nodes:
            import_text = import_node.properties.get("text", "")
            # 识别安全相关的导入
            security_keywords = ["crypto", "security", "auth", "login", "password", "token", "jwt"]
            for keyword in security_keywords:
                if keyword in import_text.lower():
                    # 创建安全边界节点
                    boundary_id = f"security_boundary_{import_node.id}"
                    boundary_properties = {
                        "import": import_text,
                        "type": "security"
                    }
                    self._add_node(boundary_id, "SecurityBoundary", boundary_properties)
                    
                    # 添加关联边
                    self._add_edge(import_node.id, boundary_id, "DEFINES", {})

    def _has_path(self, source_id: str, target_id: str) -> bool:
        """检查是否存在从源节点到目标节点的路径

        Args:
            source_id: 源节点 ID
            target_id: 目标节点 ID

        Returns:
            是否存在路径
        """
        # 简单的深度优先搜索
        visited = set()
        
        def dfs(node_id):
            if node_id == target_id:
                return True
            if node_id in visited:
                return False
            visited.add(node_id)
            
            # 查找所有从当前节点出发的边
            for edge in self._edges:
                if edge.source == node_id:
                    if dfs(edge.target):
                        return True
            return False
        
        return dfs(source_id)

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
