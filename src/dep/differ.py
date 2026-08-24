"""路径差异对比器

对比改前改后的路径图，标记只在改后存在的路径为Suspicious。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum

from src.sal.path_explorer import CandidatePath, CallGraph


class DiffReason(str, Enum):
    """差异原因枚举"""
    NEW_PATH = "new_path"  # 改后新增的路径
    MODIFIED_PATH = "modified_path"  # 改后修改的路径
    REMOVED_PATH = "removed_path"  # 改后移除的路径
    NEW_SINK_REACHED = "new_sink_reached"  # 新增到达Sink的路径
    EXISTING_PATH_WEAKENED = "existing_path_weakened"  # 现有路径的安全检查被削弱


@dataclass
class SuspiciousPath:
    """可疑路径"""
    path: CandidatePath
    reason: DiffReason
    description: str = ""
    confidence: float = 0.0
    before_path: Optional[CandidatePath] = None  # 改前对应路径（如果存在）
    after_path: Optional[CandidatePath] = None  # 改后路径
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path.to_dict(),
            "reason": self.reason.value,
            "description": self.description,
            "confidence": self.confidence,
            "before_path": self.before_path.to_dict() if self.before_path else None,
            "after_path": self.after_path.to_dict() if self.after_path else None,
            "metadata": self.metadata,
        }


class PathDiffer:
    """路径差异对比器
    
    对比改前改后的路径图，标记Suspicious路径。
    """
    
    def diff_paths(
        self,
        paths_before: List[CandidatePath],
        paths_after: List[CandidatePath],
        modified_funcs: List[str],
    ) -> List[SuspiciousPath]:
        """对比前后路径，标记Suspicious
        
        Args:
            paths_before: 改前路径列表
            paths_after: 改后路径列表
            modified_funcs: 修改过的函数列表
            
        Returns:
            可疑路径列表
        """
        suspicious = []
        
        # 构建路径索引
        before_index = self._build_path_index(paths_before)
        after_index = self._build_path_index(paths_after)
        
        # 1. 找出改后新增的路径（改前不存在）
        for after_key, after_path in after_index.items():
            if after_key not in before_index:
                # 检查是否涉及修改的函数
                if self._involves_modified_functions(after_path, modified_funcs):
                    suspicious.append(SuspiciousPath(
                        path=after_path,
                        reason=DiffReason.NEW_PATH,
                        description=f"AI补丁新增了从 {after_path.entry_point} 到 {after_path.sink} 的路径",
                        confidence=0.8,
                        after_path=after_path,
                    ))
        
        # 2. 找出改后到达新Sink的路径
        before_sinks = {p.sink for p in paths_before}
        for after_path in paths_after:
            if after_path.sink not in before_sinks:
                if self._involves_modified_functions(after_path, modified_funcs):
                    suspicious.append(SuspiciousPath(
                        path=after_path,
                        reason=DiffReason.NEW_SINK_REACHED,
                        description=f"AI补丁新增了到达Sink {after_path.sink} 的路径",
                        confidence=0.9,
                        after_path=after_path,
                    ))
        
        # 3. 找出改后被削弱的路径（安全检查被移除/修改）
        weakened_paths = self._find_weakened_paths(
            paths_before, paths_after, modified_funcs
        )
        suspicious.extend(weakened_paths)
        
        # 去重
        suspicious = self._deduplicate_suspicious(suspicious)
        
        # 按置信度排序
        suspicious.sort(key=lambda s: s.confidence, reverse=True)
        
        return suspicious
    
    def _build_path_index(self, paths: List[CandidatePath]) -> Dict[str, CandidatePath]:
        """构建路径索引"""
        index = {}
        for path in paths:
            # 使用调用链作为key
            key = self._path_key(path)
            index[key] = path
        return index
    
    def _path_key(self, path: CandidatePath) -> str:
        """生成路径的唯一key"""
        return f"{path.entry_point}->{'->'.join(path.call_chain)}->{path.sink}"
    
    def _involves_modified_functions(
        self, path: CandidatePath, modified_funcs: List[str]
    ) -> bool:
        """检查路径是否涉及修改的函数"""
        # 检查路径中的函数是否在修改列表中
        for func in path.call_chain:
            func_name = func.split(":")[-1] if ":" in func else func
            for mod_func in modified_funcs:
                mod_name = mod_func.split(":")[-1] if ":" in mod_func else mod_func
                if func_name == mod_name:
                    return True
        
        # 检查修改函数列表
        for mod_func in path.modified_functions:
            if mod_func in modified_funcs:
                return True
        
        return False
    
    def _find_weakened_paths(
        self,
        paths_before: List[CandidatePath],
        paths_after: List[CandidatePath],
        modified_funcs: List[str],
    ) -> List[SuspiciousPath]:
        """找出被削弱的路径
        
        检查改前存在的安全检查是否在改后被移除或修改。
        """
        weakened = []
        
        # 构建改前路径的Sink索引
        before_by_sink: Dict[str, List[CandidatePath]] = {}
        for path in paths_before:
            if path.sink not in before_by_sink:
                before_by_sink[path.sink] = []
            before_by_sink[path.sink].append(path)
        
        # 检查改后路径
        for after_path in paths_after:
            if after_path.sink in before_by_sink:
                # 找到改前到达同一Sink的路径
                before_paths = before_by_sink[after_path.sink]
                
                for before_path in before_paths:
                    # 检查路径是否被削弱
                    if self._is_path_weakened(before_path, after_path, modified_funcs):
                        weakened.append(SuspiciousPath(
                            path=after_path,
                            reason=DiffReason.EXISTING_PATH_WEAKENED,
                            description=f"AI补丁削弱了到达 {after_path.sink} 的安全检查",
                            confidence=0.7,
                            before_path=before_path,
                            after_path=after_path,
                        ))
        
        return weakened
    
    def _is_path_weakened(
        self,
        before_path: CandidatePath,
        after_path: CandidatePath,
        modified_funcs: List[str],
    ) -> bool:
        """检查路径是否被削弱
        
        启发式规则：
        1. 改后路径更短（可能移除了安全检查）
        2. 改后路径涉及修改的函数
        3. 改后路径的置信度更高（更容易到达Sink）
        """
        # 规则1：改后路径更短
        if len(after_path.call_chain) < len(before_path.call_chain):
            # 检查是否涉及修改的函数
            if self._involves_modified_functions(after_path, modified_funcs):
                return True
        
        # 规则2：改后置信度更高
        if after_path.confidence > before_path.confidence + 0.2:
            if self._involves_modified_functions(after_path, modified_funcs):
                return True
        
        return False
    
    def _deduplicate_suspicious(
        self, suspicious: List[SuspiciousPath]
    ) -> List[SuspiciousPath]:
        """去重可疑路径"""
        seen = set()
        unique = []
        
        for s in suspicious:
            key = (s.reason, self._path_key(s.path))
            if key not in seen:
                seen.add(key)
                unique.append(s)
        
        return unique
    
    def diff_call_graphs(
        self,
        graph_before: CallGraph,
        graph_after: CallGraph,
        modified_funcs: List[str],
    ) -> Dict[str, Any]:
        """对比两个调用图
        
        Args:
            graph_before: 改前调用图
            graph_after: 改后调用图
            modified_funcs: 修改的函数列表
            
        Returns:
            差异报告
        """
        # 节点差异
        nodes_before = set(graph_before.nodes.keys())
        nodes_after = set(graph_after.nodes.keys())
        
        new_nodes = nodes_after - nodes_before
        removed_nodes = nodes_before - nodes_after
        common_nodes = nodes_before & nodes_after
        
        # 边差异
        edges_before = {(e.caller, e.callee) for e in graph_before.edges}
        edges_after = {(e.caller, e.callee) for e in graph_after.edges}
        
        new_edges = edges_after - edges_before
        removed_edges = edges_before - edges_after
        
        return {
            "new_nodes": list(new_nodes),
            "removed_nodes": list(removed_nodes),
            "new_edges": list(new_edges),
            "removed_edges": list(removed_edges),
            "modified_functions": modified_funcs,
        }
