from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass
import libcst

@dataclass
class SemanticNode:
    """语义节点"""
    node_id: str
    node_type: str  # function, variable, class, call, etc.
    name: Optional[str] = None
    value: Optional[Any] = None
    line: Optional[int] = None
    column: Optional[int] = None
    file_path: Optional[str] = None
    dependencies: Set[str] = None
    properties: Dict[str, Any] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = set()
        if self.properties is None:
            self.properties = {}

@dataclass
class SemanticEdge:
    """语义边"""
    source: str
    target: str
    edge_type: str  # calls, defines, uses, etc.
    properties: Dict[str, Any] = None

    def __post_init__(self):
        if self.properties is None:
            self.properties = {}

class SemanticGraph:
    """语义图"""
    
    def __init__(self):
        self.nodes: Dict[str, SemanticNode] = {}
        self.edges: List[SemanticEdge] = []
        self.file_nodes: Dict[str, List[str]] = {}  # 文件到节点的映射
    
    def add_node(self, node: SemanticNode):
        """添加节点"""
        self.nodes[node.node_id] = node
        if node.file_path:
            if node.file_path not in self.file_nodes:
                self.file_nodes[node.file_path] = []
            self.file_nodes[node.file_path].append(node.node_id)
    
    def add_edge(self, edge: SemanticEdge):
        """添加边"""
        self.edges.append(edge)
    
    def get_node(self, node_id: str) -> Optional[SemanticNode]:
        """获取节点"""
        return self.nodes.get(node_id)
    
    def get_nodes_by_file(self, file_path: str) -> List[SemanticNode]:
        """获取文件中的所有节点"""
        node_ids = self.file_nodes.get(file_path, [])
        return [self.nodes[node_id] for node_id in node_ids if node_id in self.nodes]
    
    def get_nodes_by_type(self, node_type: str) -> List[SemanticNode]:
        """获取指定类型的节点"""
        return [node for node in self.nodes.values() if node.node_type == node_type]
    
    def get_edges_from(self, node_id: str) -> List[SemanticEdge]:
        """获取从指定节点出发的边"""
        return [edge for edge in self.edges if edge.source == node_id]
    
    def get_edges_to(self, node_id: str) -> List[SemanticEdge]:
        """获取指向指定节点的边"""
        return [edge for edge in self.edges if edge.target == node_id]
    
    def get_dependencies(self, node_id: str) -> List[SemanticNode]:
        """获取节点的依赖节点"""
        dependencies = []
        for edge in self.get_edges_to(node_id):
            if edge.source in self.nodes:
                dependencies.append(self.nodes[edge.source])
        return dependencies
    
    def get_dependents(self, node_id: str) -> List[SemanticNode]:
        """获取依赖于指定节点的节点"""
        dependents = []
        for edge in self.get_edges_from(node_id):
            if edge.target in self.nodes:
                dependents.append(self.nodes[edge.target])
        return dependents
    
    def merge(self, other: 'SemanticGraph'):
        """合并另一个语义图"""
        # 合并节点
        for node_id, node in other.nodes.items():
            if node_id not in self.nodes:
                self.add_node(node)
        
        # 合并边
        for edge in other.edges:
            self.add_edge(edge)
        
        # 合并文件节点映射
        for file_path, node_ids in other.file_nodes.items():
            if file_path not in self.file_nodes:
                self.file_nodes[file_path] = []
            for node_id in node_ids:
                if node_id not in self.file_nodes[file_path]:
                    self.file_nodes[file_path].append(node_id)
    
    def clear(self):
        """清空语义图"""
        self.nodes.clear()
        self.edges.clear()
        self.file_nodes.clear()

class SemanticGraphBuilder:
    """语义图构建器"""
    
    def __init__(self):
        self.graph = SemanticGraph()
        self.node_counter = 0
    
    def generate_node_id(self) -> str:
        """生成唯一节点 ID"""
        self.node_counter += 1
        return f"node_{self.node_counter}"
    
    def build_from_file(self, file_path: str) -> SemanticGraph:
        """从文件构建语义图"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 使用 libcst 解析代码
            tree = libcst.parse_module(content)
            
            # 遍历 AST 构建语义图
            self._visit_tree(tree, file_path)
            
            return self.graph
        except Exception as e:
            print(f"构建语义图失败: {e}")
            return self.graph
    
    def _visit_tree(self, node, file_path: str, parent_id: Optional[str] = None):
        """遍历 AST 节点"""
        if isinstance(node, libcst.Module):
            module_id = self.generate_node_id()
            module_node = SemanticNode(
                node_id=module_id,
                node_type="module",
                name=file_path,
                file_path=file_path
            )
            self.graph.add_node(module_node)
            
            for statement in node.body:
                self._visit_tree(statement, file_path, module_id)
        
        elif isinstance(node, libcst.FunctionDef):
            function_id = self.generate_node_id()
            function_name = node.name.value
            # 获取行号
            line = None
            if hasattr(node, 'start') and hasattr(node.start, 'location'):
                line = node.start.location.line
            
            function_node = SemanticNode(
                node_id=function_id,
                node_type="function",
                name=function_name,
                line=line,
                file_path=file_path
            )
            self.graph.add_node(function_node)
            
            if parent_id:
                edge = SemanticEdge(
                    source=parent_id,
                    target=function_id,
                    edge_type="contains"
                )
                self.graph.add_edge(edge)
            
            # 处理函数参数
            for param in node.params.params:
                if isinstance(param, libcst.Param):
                    param_id = self.generate_node_id()
                    param_name = param.name.value
                    # 获取行号
                    param_line = None
                    if hasattr(param, 'start') and hasattr(param.start, 'location'):
                        param_line = param.start.location.line
                    
                    param_node = SemanticNode(
                        node_id=param_id,
                        node_type="parameter",
                        name=param_name,
                        line=param_line,
                        file_path=file_path
                    )
                    self.graph.add_node(param_node)
                    edge = SemanticEdge(
                        source=function_id,
                        target=param_id,
                        edge_type="parameter"
                    )
                    self.graph.add_edge(edge)
            
            # 处理函数体
            for statement in node.body.body:
                self._visit_tree(statement, file_path, function_id)
        
        elif isinstance(node, libcst.Call):
            call_id = self.generate_node_id()
            # 尝试获取调用的函数名
            function_name = "unknown"
            if isinstance(node.func, libcst.Name):
                function_name = node.func.value
            elif isinstance(node.func, libcst.Attribute):
                function_name = f"{node.func.value.value}.{node.func.attr.value}"
            
            # 获取行号
            line = None
            if hasattr(node, 'start') and hasattr(node.start, 'location'):
                line = node.start.location.line
            
            call_node = SemanticNode(
                node_id=call_id,
                node_type="call",
                name=function_name,
                line=line,
                file_path=file_path
            )
            self.graph.add_node(call_node)
            
            if parent_id:
                edge = SemanticEdge(
                    source=parent_id,
                    target=call_id,
                    edge_type="calls"
                )
                self.graph.add_edge(edge)
            
            # 处理参数
            for arg in node.args:
                if isinstance(arg, libcst.Arg):
                    self._visit_tree(arg.value, file_path, call_id)
        
        elif isinstance(node, libcst.Name):
            name_id = self.generate_node_id()
            # 获取行号
            line = None
            if hasattr(node, 'start') and hasattr(node.start, 'location'):
                line = node.start.location.line
            
            name_node = SemanticNode(
                node_id=name_id,
                node_type="name",
                name=node.value,
                line=line,
                file_path=file_path
            )
            self.graph.add_node(name_node)
            
            if parent_id:
                edge = SemanticEdge(
                    source=parent_id,
                    target=name_id,
                    edge_type="uses"
                )
                self.graph.add_edge(edge)
        
        # 添加 AgentFlow 框架专用语义节点
        self._handle_agentflow_nodes(node, file_path, parent_id)
    
    def _handle_agentflow_nodes(self, node, file_path: str, parent_id: Optional[str] = None):
        """处理 AgentFlow 框架专用语义节点"""
        if isinstance(node, libcst.Call):
            # 检测 tool.call
            if isinstance(node.func, libcst.Attribute):
                if (isinstance(node.func.value, libcst.Name) and 
                    node.func.value.value == "tool" and 
                    node.func.attr.value == "call"):
                    tool_call_id = self.generate_node_id()
                    # 获取行号
                    line = None
                    if hasattr(node, 'start') and hasattr(node.start, 'location'):
                        line = node.start.location.line
                    
                    tool_call_node = SemanticNode(
                        node_id=tool_call_id,
                        node_type="agentflow_tool_call",
                        name="tool.call",
                        line=line,
                        file_path=file_path
                    )
                    self.graph.add_node(tool_call_node)
                    
                    if parent_id:
                        edge = SemanticEdge(
                            source=parent_id,
                            target=tool_call_id,
                            edge_type="agentflow_tool_call"
                        )
                        self.graph.add_edge(edge)
            
            # 检测 agent.execute
            if isinstance(node.func, libcst.Attribute):
                if (isinstance(node.func.value, libcst.Name) and 
                    node.func.value.value == "agent" and 
                    node.func.attr.value == "execute"):
                    agent_execute_id = self.generate_node_id()
                    # 获取行号
                    line = None
                    if hasattr(node, 'start') and hasattr(node.start, 'location'):
                        line = node.start.location.line
                    
                    agent_execute_node = SemanticNode(
                        node_id=agent_execute_id,
                        node_type="agentflow_agent_execute",
                        name="agent.execute",
                        line=line,
                        file_path=file_path
                    )
                    self.graph.add_node(agent_execute_node)
                    
                    if parent_id:
                        edge = SemanticEdge(
                            source=parent_id,
                            target=agent_execute_id,
                            edge_type="agentflow_agent_execute"
                        )
                        self.graph.add_edge(edge)
        
        # 检测 prompt.template
        if isinstance(node, libcst.Attribute):
            if (isinstance(node.value, libcst.Name) and 
                node.value.value == "prompt" and 
                node.attr.value == "template"):
                prompt_template_id = self.generate_node_id()
                # 获取行号
                line = None
                if hasattr(node, 'start') and hasattr(node.start, 'location'):
                    line = node.start.location.line
                
                prompt_template_node = SemanticNode(
                    node_id=prompt_template_id,
                    node_type="agentflow_prompt_template",
                    name="prompt.template",
                    line=line,
                    file_path=file_path
                )
                self.graph.add_node(prompt_template_node)
                
                if parent_id:
                    edge = SemanticEdge(
                        source=parent_id,
                        target=prompt_template_id,
                        edge_type="agentflow_prompt_template"
                    )
                    self.graph.add_edge(edge)

semantic_graph_builder = SemanticGraphBuilder()