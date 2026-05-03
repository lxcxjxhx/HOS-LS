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
    
    # 多Agent输出
    cst: List[Dict[str, Any]] = field(default_factory=list)  # CST分析结果
    ast: List[Dict[str, Any]] = field(default_factory=list)  # AST分析结果
    taint: List[Dict[str, Any]] = field(default_factory=list)  # 污点分析结果
    rag: List[Dict[str, Any]] = field(default_factory=list)  # RAG检索结果
    semantic: List[Dict[str, Any]] = field(default_factory=list)  # 语义分析结果
    
    # 融合证据
    evidence: List[Dict[str, Any]] = field(default_factory=list)  # 统一证据格式
    
    # 推理结果
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)  # 攻击链路径
    
    # 分析结果
    code_analysis_result: Optional[Dict[str, Any]] = None  # 代码分析结果
    
    # 最终结果
    scan_result: Optional[ScanResult] = None  # 扫描结果
    
    # 控制信息
    confidence: float = 0.0  # 整体置信度
    iteration: int = 0  # 迭代次数
    flags: Dict[str, Any] = field(default_factory=dict)  # 控制标志
    
    # 分块信息
    chunks: List[Dict[str, Any]] = field(default_factory=list)  # 分块列表
    
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
            cst=kwargs.get('cst', self.cst),
            ast=kwargs.get('ast', self.ast),
            taint=kwargs.get('taint', self.taint),
            rag=kwargs.get('rag', self.rag),
            semantic=kwargs.get('semantic', self.semantic),
            evidence=kwargs.get('evidence', self.evidence),
            attack_paths=kwargs.get('attack_paths', self.attack_paths),
            code_analysis_result=kwargs.get('code_analysis_result', self.code_analysis_result),
            scan_result=kwargs.get('scan_result', self.scan_result),
            confidence=kwargs.get('confidence', self.confidence),
            iteration=kwargs.get('iteration', self.iteration),
            flags=kwargs.get('flags', self.flags),
            needs_rag=kwargs.get('needs_rag', self.needs_rag),
            needs_graph=kwargs.get('needs_graph', self.needs_graph),
            is_simple=kwargs.get('is_simple', self.is_simple),
            chunks=kwargs.get('chunks', self.chunks)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典
        
        Returns:
            Dict[str, Any]: 状态字典
        """
        return {
            'target': self.target,
            'config': self.config,
            'cst': self.cst,
            'ast': self.ast,
            'taint': self.taint,
            'rag': self.rag,
            'semantic': self.semantic,
            'evidence': self.evidence,
            'attack_paths': self.attack_paths,
            'code_analysis_result': self.code_analysis_result,
            'scan_result': self.scan_result.to_dict() if self.scan_result else None,
            'confidence': self.confidence,
            'iteration': self.iteration,
            'flags': self.flags,
            'needs_rag': self.needs_rag,
            'needs_graph': self.needs_graph,
            'is_simple': self.is_simple,
            'chunks': self.chunks
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
            cst=data.get('cst', []),
            ast=data.get('ast', []),
            taint=data.get('taint', []),
            rag=data.get('rag', []),
            semantic=data.get('semantic', []),
            evidence=data.get('evidence', []),
            attack_paths=data.get('attack_paths', []),
            code_analysis_result=data.get('code_analysis_result'),
            scan_result=data.get('scan_result'),
            confidence=data.get('confidence', 0.0),
            iteration=data.get('iteration', 0),
            flags=data.get('flags', {}),
            needs_rag=data.get('needs_rag', False),
            needs_graph=data.get('needs_graph', False),
            is_simple=data.get('is_simple', False),
            chunks=data.get('chunks', [])
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
        config=config,
        cst=[],
        ast=[],
        taint=[],
        rag=[],
        semantic=[],
        evidence=[],
        attack_paths=[],
        code_analysis_result=None,
        confidence=0.0,
        iteration=0,
        flags={},
        needs_rag=False,
        needs_graph=False,
        is_simple=False,
        chunks=[]
    )


def evaluate_complexity(code: str) -> float:
    """评估代码复杂度
    
    Args:
        code: 代码内容
        
    Returns:
        float: 复杂度分数 (0.0-1.0)
    """
    # 基于代码长度、复杂度指标等评估
    lines = code.split('\n')
    code_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
    
    # 计算复杂度分数
    base_complexity = min(len(code_lines) / 200, 1.0)  # 基于代码行数
    
    # 检查高风险模式，增加复杂度
    high_risk_patterns = [
        'eval(', 'exec(', 'execfile(', 'compile(',
        'pickle.loads', 'unpickle', 'yaml.load',
        'os.system', 'subprocess', 'socket',
        'SQL', 'database', 'connection'
    ]
    
    risk_factor = 0.0
    for pattern in high_risk_patterns:
        if pattern.lower() in code.lower():
            risk_factor += 0.1
    
    # 综合复杂度分数
    complexity = min(base_complexity + risk_factor, 1.0)
    
    return complexity


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