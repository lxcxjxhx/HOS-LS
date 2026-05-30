# LangGraph 核心流程设计

## 1. 状态图结构

### 1.1 状态定义

```python
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path

from src.core.engine import ScanResult, Finding

@dataclass
class ScanState:
    """扫描状态"""
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
```

### 1.2 节点定义

| 节点名称 | 功能描述 | 输入状态 | 输出状态 |
|---------|---------|---------|---------|
| `analyze_code` | 代码分析，评估复杂度和风险 | target, config | code_analysis_result, is_simple, needs_rag |
| `retrieve_cve` | RAG检索CVE漏洞信息 | code_analysis_result | rag_results |
| `query_graph` | 查询Neo4j攻击链图谱 | rag_results | graph_query_results |
| `generate_report` | 生成最终扫描报告 | rag_results, graph_query_results | scan_result |
| `fast_path` | 快速路径，直接规则扫描 | target, config | scan_result |

### 1.3 边定义

```python
# 条件边
graph.add_conditional_edges(
    "analyze_code",
    condition_func=lambda state: "fast_path" if state.is_simple else "retrieve_cve",
    {"fast_path": "fast_path", "retrieve_cve": "retrieve_cve"}
)

# 条件边
graph.add_conditional_edges(
    "retrieve_cve",
    condition_func=lambda state: "query_graph" if state.needs_graph else "generate_report",
    {"query_graph": "query_graph", "generate_report": "generate_report"}
)

# 普通边
graph.add_edge("query_graph", "generate_report")
graph.add_edge("fast_path", "generate_report")
```

## 2. 条件分支逻辑

### 2.1 代码复杂度评估

```python
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
        return True
    
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
```

### 2.2 漏洞类型识别

```python
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
```

### 2.3 路径选择逻辑

```python
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
```

## 3. 流程示例

### 3.1 简单代码流程

```
[输入代码] → analyze_code → [判断为简单] → fast_path → generate_report → [输出结果]
```

### 3.2 复杂代码流程

```
[输入代码] → analyze_code → [判断为复杂] → retrieve_cve → [需要攻击链] → query_graph → generate_report → [输出结果]
```

### 3.3 中等复杂度代码流程

```
[输入代码] → analyze_code → [判断为复杂] → retrieve_cve → [不需要攻击链] → generate_report → [输出结果]
```

## 4. 实现要点

1. **状态管理**：使用 `ScanState` 类管理整个扫描过程的状态
2. **节点实现**：每个节点都是一个独立的函数，接收状态并返回更新后的状态
3. **条件分支**：使用 `add_conditional_edges` 实现基于状态的条件分支
4. **错误处理**：每个节点都应该包含错误处理逻辑
5. **性能优化**：使用缓存机制减少重复计算

## 5. 集成要点

1. **与现有系统集成**：保持与现有扫描器的兼容性
2. **CLI接口**：提供新的命令行选项启动LangGraph流程
3. **配置管理**：支持通过配置文件调整LangGraph行为
4. **日志记录**：记录LangGraph流程的执行情况

## 6. 测试策略

1. **单元测试**：测试每个节点的独立功能
2. **集成测试**：测试整个流程的执行
3. **性能测试**：测试不同复杂度代码的处理时间
4. **边界测试**：测试边界情况的处理

## 7. 预期收益

1. **性能提升**：简单代码扫描速度提升80%以上
2. **资源节省**：减少不必要的计算和API调用
3. **可扩展性**：易于添加新的节点和流程
4. **可维护性**：流程清晰，易于理解和修改

---

**设计文档版本**: 1.0
**创建日期**: 2026-04-06