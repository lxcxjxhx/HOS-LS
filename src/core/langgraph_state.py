from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, TypedDict
from pathlib import Path

from src.core.engine import ScanResult, Finding


class AgentState(TypedDict):
    """Agent状态
    
    管理LangGraph流程中的所有状态数据
    """
    input_code: str  # 用户输入的代码
    cve_candidates: List[dict]  # FAISS Top-K结果
    graph_subgraph: dict  # Neo4j局部攻击链
    analysis_result: str  # 分析结果
    final_report: dict  # 最终报告
    iteration: int  # 用于Critic循环


@dataclass
class ScanState:
    """扫描状态
    
    管理LangGraph流程中的所有状态数据
    """
    # 输入信息
    target: str  # 扫描目标
    config: Any  # 扫描配置
    
    # 中间结果
    code_analysis_result: Optional[Dict[str, Any]] = None  # 代码分析结果
    rag_results: Optional[List[Dict[str, Any]]] = None  # RAG检索结果
    graph_query_results: Optional[List[Dict[str, Any]]] = None  # 图谱查询结果
    
    # 最终结果
    scan_result: Optional[ScanResult] = None  # 扫描结果
    
    # 决策标记
    needs_rag: bool = False  # 是否需要RAG检索
    needs_graph: bool = False  # 是否需要图谱查询
    is_simple: bool = False  # 是否为简单场景
    
    def update(self, **kwargs) -> 'ScanState':
        """更新状态
        
        Args:
            **kwargs: 要更新的状态字段
            
        Returns:
            ScanState: 更新后的状态
        """
        return self.__class__(
            target=self.target,
            config=self.config,
            code_analysis_result=kwargs.get('code_analysis_result', self.code_analysis_result),
            rag_results=kwargs.get('rag_results', self.rag_results),
            graph_query_results=kwargs.get('graph_query_results', self.graph_query_results),
            scan_result=kwargs.get('scan_result', self.scan_result),
            needs_rag=kwargs.get('needs_rag', self.needs_rag),
            needs_graph=kwargs.get('needs_graph', self.needs_graph),
            is_simple=kwargs.get('is_simple', self.is_simple)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典
        
        Returns:
            Dict[str, Any]: 状态字典
        """
        return {
            'target': self.target,
            'config': self.config,
            'code_analysis_result': self.code_analysis_result,
            'rag_results': self.rag_results,
            'graph_query_results': self.graph_query_results,
            'scan_result': self.scan_result.to_dict() if self.scan_result else None,
            'needs_rag': self.needs_rag,
            'needs_graph': self.needs_graph,
            'is_simple': self.is_simple
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanState':
        """从字典创建状态
        
        Args:
            data: 状态数据字典
            
        Returns:
            ScanState: 状态对象
        """
        return cls(
            target=data.get('target'),
            config=data.get('config'),
            code_analysis_result=data.get('code_analysis_result'),
            rag_results=data.get('rag_results'),
            graph_query_results=data.get('graph_query_results'),
            scan_result=data.get('scan_result'),
            needs_rag=data.get('needs_rag', False),
            needs_graph=data.get('needs_graph', False),
            is_simple=data.get('is_simple', False)
        )


def create_initial_state(target: str, config: Any) -> ScanState:
    """创建初始状态
    
    Args:
        target: 扫描目标
        config: 扫描配置
        
    Returns:
        ScanState: 初始状态
    """
    return ScanState(
        target=target,
        config=config
    )


def evaluate_complexity(code: str) -> bool:
    """评估代码复杂度
    
    Args:
        code: 代码内容
        
    Returns:
        bool: 是否为简单代码
    """
    # 基于代码长度、复杂度指标等评估
    lines = code.split('\n')
    code_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
    
    # 简单代码判断标准
    if len(code_lines) < 50:
        # 检查是否包含高风险模式
        high_risk_patterns = [
            'eval(', 'exec(', 'execfile(', 'compile(',
            'pickle.loads', 'unpickle', 'yaml.load',
            'os.system', 'subprocess', 'socket',
            'SQL', 'database', 'connection'
        ]
        
        for pattern in high_risk_patterns:
            if pattern.lower() in code.lower():
                return False
        
        return True
    
    # 超过50行的代码认为是复杂代码
    return False


def identify_vulnerability_types(code_analysis: Dict[str, Any]) -> List[str]:
    """识别漏洞类型
    
    Args:
        code_analysis: 代码分析结果
        
    Returns:
        List[str]: 漏洞类型列表
    """
    vulnerability_types = []
    
    # 基于代码分析结果识别漏洞类型
    if code_analysis.get('has_eval'):
        vulnerability_types.append('RCE')
    if code_analysis.get('has_sql'):
        vulnerability_types.append('SQLi')
    if code_analysis.get('has_xss'):
        vulnerability_types.append('XSS')
    if code_analysis.get('has_deserialization'):
        vulnerability_types.append('Deserialization')
    
    return vulnerability_types


def should_use_rag(code_analysis: Dict[str, Any]) -> bool:
    """判断是否需要RAG检索
    
    Args:
        code_analysis: 代码分析结果
        
    Returns:
        bool: 是否需要RAG
    """
    # 基于代码分析结果判断
    if code_analysis.get('complexity') == 'high':
        return True
    if code_analysis.get('vulnerability_count', 0) > 0:
        return True
    return False


def should_use_graph(rag_results: List[Dict[str, Any]]) -> bool:
    """判断是否需要图谱查询
    
    Args:
        rag_results: RAG检索结果
        
    Returns:
        bool: 是否需要图谱查询
    """
    # 基于RAG结果判断
    if not rag_results:
        return False
    
    # 检查是否存在可能的攻击链
    for result in rag_results:
        if 'CVE' in result.get('title', ''):
            return True
    
    return False