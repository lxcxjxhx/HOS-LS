"""SAL路径探索器

从Modified_Funcs出发，探索到Sink的路径。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from src.sal.sink_registry import SinkRegistry, SinkDefinition, SinkCategory


@dataclass
class CallGraphNode:
    """调用图节点"""
    func_name: str
    file_path: str
    line_number: int = 0
    language: str = "python"
    is_entry_point: bool = False
    is_sink: bool = False
    sink_category: Optional[SinkCategory] = None


@dataclass
class CallGraphEdge:
    """调用图边"""
    caller: str  # 调用者函数名
    callee: str  # 被调用函数名
    caller_file: str
    callee_file: str
    line_number: int = 0


@dataclass
class CallGraph:
    """调用图"""
    nodes: Dict[str, CallGraphNode] = field(default_factory=dict)
    edges: List[CallGraphEdge] = field(default_factory=list)
    adjacency: Dict[str, List[str]] = field(default_factory=dict)  # caller -> [callees]
    reverse_adjacency: Dict[str, List[str]] = field(default_factory=dict)  # callee -> [callers]
    
    def add_node(self, node: CallGraphNode):
        """添加节点"""
        key = f"{node.file_path}:{node.func_name}"
        self.nodes[key] = node
        if key not in self.adjacency:
            self.adjacency[key] = []
        if key not in self.reverse_adjacency:
            self.reverse_adjacency[key] = []
    
    def add_edge(self, edge: CallGraphEdge):
        """添加边"""
        self.edges.append(edge)
        
        caller_key = f"{edge.caller_file}:{edge.caller}"
        callee_key = f"{edge.callee_file}:{edge.callee}"
        
        if caller_key not in self.adjacency:
            self.adjacency[caller_key] = []
        self.adjacency[caller_key].append(callee_key)
        
        if callee_key not in self.reverse_adjacency:
            self.reverse_adjacency[callee_key] = []
        self.reverse_adjacency[callee_key].append(caller_key)
    
    def get_callees(self, func_key: str) -> List[str]:
        """获取被调用函数列表"""
        return self.adjacency.get(func_key, [])
    
    def get_callers(self, func_key: str) -> List[str]:
        """获取调用者列表"""
        return self.reverse_adjacency.get(func_key, [])


@dataclass
class CandidatePath:
    """候选漏洞路径"""
    entry_point: str  # 入口点
    sink: str  # Sink点
    call_chain: List[str]  # 调用链
    modified_functions: List[str]  # 涉及的修改函数
    files_involved: List[str]  # 涉及的文件
    sink_category: SinkCategory = SinkCategory.OTHER
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_point": self.entry_point,
            "sink": self.sink,
            "call_chain": self.call_chain,
            "modified_functions": self.modified_functions,
            "files_involved": self.files_involved,
            "sink_category": self.sink_category.value,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class SALExplorer:
    """SAL路径探索器
    
    从Modified_Funcs出发，正向/反向遍历调用图，找到从入口点到Sink的路径。
    """
    
    def __init__(self, sink_registry: Optional[SinkRegistry] = None):
        self.sink_registry = sink_registry or SinkRegistry()
        self._visited: Set[str] = set()
    
    def explore_paths(
        self,
        modified_funcs: List[str],
        call_graph: CallGraph,
        entry_points: Optional[List[str]] = None,
        max_depth: int = 10,
    ) -> List[CandidatePath]:
        """探索从Modified_Funcs到Sink的路径
        
        Args:
            modified_funcs: 修改过的函数列表 (格式: "file:func_name")
            call_graph: 调用图
            entry_points: 入口点列表（如HTTP Handler），如果为None则自动检测
            max_depth: 最大探索深度
            
        Returns:
            候选漏洞路径列表
        """
        candidates = []
        
        # 如果没有指定入口点，自动检测
        if entry_points is None:
            entry_points = self._detect_entry_points(call_graph)
        
        # 找到所有Sink节点
        sink_nodes = self._find_sink_nodes(call_graph)
        
        # 对每个Modified_Func，探索到Sink的路径
        for mod_func in modified_funcs:
            # 正向探索：从Modified_Func到Sink
            forward_paths = self._explore_forward(
                mod_func, sink_nodes, call_graph, max_depth
            )
            candidates.extend(forward_paths)
            
            # 反向探索：从Sink到Modified_Func（找入口点）
            backward_paths = self._explore_backward(
                mod_func, sink_nodes, entry_points, call_graph, max_depth
            )
            candidates.extend(backward_paths)
        
        # 去重和排序
        candidates = self._deduplicate_paths(candidates)
        candidates.sort(key=lambda p: p.confidence, reverse=True)
        
        return candidates
    
    def _detect_entry_points(self, call_graph: CallGraph) -> List[str]:
        """自动检测入口点
        
        入口点通常是：
        - HTTP Handler（如Flask/Django路由）
        - main函数
        - 公共API函数
        """
        entry_points = []
        
        for key, node in call_graph.nodes.items():
            # 检查是否是入口点
            if node.is_entry_point:
                entry_points.append(key)
                continue
            
            # 启发式检测
            func_lower = node.func_name.lower()
            if any(pattern in func_lower for pattern in [
                "main", "app", "handler", "controller", "route", "api",
                "endpoint", "index", "start", "init", "setup"
            ]):
                entry_points.append(key)
                node.is_entry_point = True
        
        return entry_points
    
    def _find_sink_nodes(self, call_graph: CallGraph) -> List[Tuple[str, SinkDefinition]]:
        """找到所有Sink节点"""
        sink_nodes = []
        
        for key, node in call_graph.nodes.items():
            matching_sinks = self.sink_registry.find_matching_sinks(
                node.func_name, node.language
            )
            if matching_sinks:
                node.is_sink = True
                for sink in matching_sinks:
                    sink_nodes.append((key, sink))
                    node.sink_category = sink.category
        
        return sink_nodes
    
    def _explore_forward(
        self,
        start: str,
        sink_nodes: List[Tuple[str, SinkDefinition]],
        call_graph: CallGraph,
        max_depth: int,
    ) -> List[CandidatePath]:
        """正向探索：从start到Sink"""
        candidates = []
        sink_keys = {key for key, _ in sink_nodes}
        
        # BFS探索
        queue = [(start, [start], set())]
        
        while queue:
            current, path, visited = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            # 检查是否到达Sink
            if current in sink_keys:
                sink_def = next(s for k, s in sink_nodes if k == current)
                candidates.append(CandidatePath(
                    entry_point=path[0],
                    sink=current,
                    call_chain=path.copy(),
                    modified_functions=[start],
                    files_involved=list(set(p.split(":")[0] for p in path)),
                    sink_category=sink_def.category,
                    confidence=self._calculate_confidence(path, sink_def),
                ))
                continue
            
            # 继续探索
            for callee in call_graph.get_callees(current):
                if callee not in visited:
                    new_visited = visited.copy()
                    new_visited.add(callee)
                    queue.append((callee, path + [callee], new_visited))
        
        return candidates
    
    def _explore_backward(
        self,
        target: str,
        sink_nodes: List[Tuple[str, SinkDefinition]],
        entry_points: List[str],
        call_graph: CallGraph,
        max_depth: int,
    ) -> List[CandidatePath]:
        """反向探索：从Sink到target（找入口点）"""
        candidates = []
        
        # 对每个Sink，反向探索到entry_points
        for sink_key, sink_def in sink_nodes:
            paths = self._find_paths_to_entry(
                sink_key, target, entry_points, call_graph, max_depth
            )
            
            for path in paths:
                candidates.append(CandidatePath(
                    entry_point=path[0],
                    sink=sink_key,
                    call_chain=path.copy(),
                    modified_functions=[target],
                    files_involved=list(set(p.split(":")[0] for p in path)),
                    sink_category=sink_def.category,
                    confidence=self._calculate_confidence(path, sink_def),
                ))
        
        return candidates
    
    def _find_paths_to_entry(
        self,
        start: str,
        must_include: str,
        entry_points: List[str],
        call_graph: CallGraph,
        max_depth: int,
    ) -> List[List[str]]:
        """找到从start到entry_points的路径，且必须包含must_include"""
        paths = []
        entry_set = set(entry_points)
        
        # BFS探索
        queue = [(start, [start], set())]
        
        while queue:
            current, path, visited = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            # 检查是否到达入口点
            if current in entry_set and must_include in path:
                paths.append(path.copy())
                continue
            
            # 继续反向探索
            for caller in call_graph.get_callers(current):
                if caller not in visited:
                    new_visited = visited.copy()
                    new_visited.add(caller)
                    queue.append((caller, path + [caller], new_visited))
        
        return paths
    
    def _calculate_confidence(self, path: List[str], sink_def: SinkDefinition) -> float:
        """计算路径置信度"""
        # 基础置信度
        base_confidence = 0.5
        
        # 路径长度惩罚（越长越不可信）
        length_penalty = max(0, (len(path) - 3) * 0.05)
        
        # Sink严重性加成
        severity_bonus = {
            "CRITICAL": 0.3,
            "HIGH": 0.2,
            "MEDIUM": 0.1,
            "LOW": 0.0,
        }.get(sink_def.severity, 0.0)
        
        confidence = base_confidence - length_penalty + severity_bonus
        return max(0.0, min(1.0, confidence))
    
    def _deduplicate_paths(self, paths: List[CandidatePath]) -> List[CandidatePath]:
        """去重路径"""
        seen = set()
        unique_paths = []
        
        for path in paths:
            # 使用调用链作为去重key
            key = tuple(path.call_chain)
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)
        
        return unique_paths
    
    def explore_from_modified_functions(
        self,
        modified_funcs: List[str],
        repo_path: str,
        language: str = "python",
    ) -> List[CandidatePath]:
        """便捷方法：从修改的函数出发探索路径
        
        自动构建调用图并探索路径。
        
        Args:
            modified_funcs: 修改的函数列表
            repo_path: 仓库路径
            language: 编程语言
            
        Returns:
            候选漏洞路径列表
        """
        # 这里需要集成tree-sitter来构建调用图
        # 暂时返回空列表，实际实现需要调用CFGBuilder
        # TODO: 集成tree-sitter调用图构建
        return []
