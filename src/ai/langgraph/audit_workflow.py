"""LangGraph 安全审计工作流

替代所有硬编码规则的 AI 动态编排流水线。
通过 LangGraph 状态图实现多 Agent 协作审计。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, TypedDict, Annotated
from operator import add

from langgraph.graph import StateGraph, END

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 工作流状态定义
# ---------------------------------------------------------------------------

class AuditGraphState(TypedDict):
    """LangGraph 安全审计状态"""
    code: str                          # 待分析代码
    language: str                      # 编程语言
    finding: Dict                      # 已有发现信息
    taint_result: Dict                 # 污点分析结果
    cwe_result: Dict                   # CWE 分类结果
    confidence_result: Dict            # 置信度评估结果
    attack_chain: Dict                 # 攻击链
    final_result: Dict                 # 最终审计结果
    errors: Annotated[list, add]       # 错误日志
    analysis_complete: bool            # 分析是否完成


# ---------------------------------------------------------------------------
# 节点实现
# ---------------------------------------------------------------------------

def _taint_analysis_node(state: AuditGraphState, analyzer) -> Dict:
    """污点分析节点（替代 SOURCE_PATTERNS/SINK_PATTERNS/SANITIZER_PATTERNS）"""
    try:
        code = state.get('code', '')
        language = state.get('language', 'python')

        if not code:
            return {'errors': ['无代码可分析'], 'taint_result': {}}

        result = analyzer.taint_analyzer.analyze(code, language)

        return {
            'taint_result': {
                'sources': result.sources,
                'sinks': result.sinks,
                'sanitizers': result.sanitizers,
                'taint_paths': result.taint_paths,
                'vulnerability_type': result.vulnerability_type,
                'confidence': result.confidence,
            }
        }
    except Exception as e:
        logger.error(f"污点分析失败: {e}")
        return {'errors': [f"污点分析异常: {str(e)}"], 'taint_result': {}}


def _cwe_classification_node(state: AuditGraphState, analyzer) -> Dict:
    """CWE 分类节点（替代硬编码 CWE_PATTERNS）"""
    try:
        code = state.get('code', '')
        finding = state.get('finding', {})

        result = analyzer.cwe_classifier.classify(
            code_context=code,
            rule_name=finding.get('rule_name', ''),
            description=finding.get('description', ''),
        )

        return {
            'cwe_result': {
                'cwe_id': result.cwe_id,
                'cwe_name': result.cwe_name,
                'cwe_description': result.cwe_description,
                'confidence': result.confidence,
                'reasoning': result.reasoning,
                'matched_evidence': result.matched_evidence,
            }
        }
    except Exception as e:
        logger.error(f"CWE 分类失败: {e}")
        return {'errors': [f"CWE 分类异常: {str(e)}"], 'cwe_result': {}}


def _confidence_evaluation_node(state: AuditGraphState, analyzer) -> Dict:
    """置信度评估节点（替代硬编码置信度公式）"""
    try:
        finding = state.get('finding', {})
        cwe_result = state.get('cwe_result', {})

        verification = {
            'path_valid': finding.get('path_valid', True),
            'code_valid': finding.get('code_valid', True),
            'cwe_match': {
                'cwe_id': cwe_result.get('cwe_id', ''),
                'confidence': cwe_result.get('confidence', 0.0),
            },
            'agent_confirmed': finding.get('agent_confirmed', False),
        }

        result = analyzer.confidence_evaluator.evaluate(finding, verification)

        return {
            'confidence_result': {
                'score': result.score,
                'verification_level': result.verification_level,
                'reasoning': result.reasoning,
                'factors': result.factors,
            }
        }
    except Exception as e:
        logger.error(f"置信度评估失败: {e}")
        return {'errors': [f"置信度评估异常: {str(e)}"], 'confidence_result': {}}


def _attack_chain_node(state: AuditGraphState, analyzer) -> Dict:
    """攻击链构建节点"""
    try:
        code = state.get('code', '')
        taint_result = state.get('taint_result', {})

        if not taint_result.get('taint_paths'):
            return {'attack_chain': {}}

        # Convert dict to TaintAnalysisResult for the agent
        from src.ai.agents.ai_security_agents import TaintAnalysisResult
        taint_obj = TaintAnalysisResult(
            sources=taint_result.get('sources', []),
            sinks=taint_result.get('sinks', []),
            sanitizers=taint_result.get('sanitizers', []),
            taint_paths=taint_result.get('taint_paths', []),
            vulnerability_type=taint_result.get('vulnerability_type', ''),
            confidence=taint_result.get('confidence', 0.0),
        )

        chain = analyzer.attack_chain_builder.build_attack_chain(taint_obj, code)
        return {'attack_chain': chain}
    except Exception as e:
        logger.error(f"攻击链构建失败: {e}")
        return {'errors': [f"攻击链构建异常: {str(e)}"], 'attack_chain': {}}


def _finalize_node(state: AuditGraphState) -> Dict:
    """结果整合节点"""
    taint = state.get('taint_result', {})
    cwe = state.get('cwe_result', {})
    confidence = state.get('confidence_result', {})
    attack_chain = state.get('attack_chain', {})

    final = {
        'vulnerability_type': taint.get('vulnerability_type', ''),
        'cwe': {
            'id': cwe.get('cwe_id', ''),
            'name': cwe.get('cwe_name', ''),
            'description': cwe.get('cwe_description', ''),
            'confidence': cwe.get('confidence', 0.0),
            'reasoning': cwe.get('reasoning', ''),
        },
        'taint': {
            'sources': taint.get('sources', []),
            'sinks': taint.get('sinks', []),
            'sanitizers': taint.get('sanitizers', []),
            'paths': taint.get('taint_paths', []),
        },
        'confidence': {
            'score': confidence.get('score', 0.0),
            'verification_level': confidence.get('verification_level', 'none'),
            'reasoning': confidence.get('reasoning', ''),
        },
        'attack_chain': attack_chain,
        'errors': state.get('errors', []),
    }

    return {
        'final_result': final,
        'analysis_complete': True,
    }


# ---------------------------------------------------------------------------
# 条件边
# ---------------------------------------------------------------------------

def _should_build_attack_chain(state: AuditGraphState) -> str:
    """条件边：是否有污点路径需要构建攻击链"""
    taint = state.get('taint_result', {})
    if taint.get('taint_paths'):
        return "build_chain"
    return "finalize"


# ---------------------------------------------------------------------------
# 工作流构建
# ---------------------------------------------------------------------------

def build_audit_workflow(analyzer) -> StateGraph:
    """构建安全审计 LangGraph 工作流

    Args:
        analyzer: AISecurityAnalyzer 实例

    Returns:
        完整的 LangGraph StateGraph
    """
    workflow = StateGraph(AuditGraphState)

    # 添加节点
    workflow.add_node("taint_analysis", lambda s: _taint_analysis_node(s, analyzer))
    workflow.add_node("cwe_classification", lambda s: _cwe_classification_node(s, analyzer))
    workflow.add_node("confidence_evaluation", lambda s: _confidence_evaluation_node(s, analyzer))
    workflow.add_node("attack_chain_build", lambda s: _attack_chain_node(s, analyzer))
    workflow.add_node("finalize", _finalize_node)

    # 设置入口
    workflow.set_entry_point("taint_analysis")

    # 添加边：污点分析完成后并行执行 CWE 分类
    workflow.add_edge("taint_analysis", "cwe_classification")
    workflow.add_edge("cwe_classification", "confidence_evaluation")

    # 条件边：是否需要构建攻击链
    workflow.add_conditional_edges(
        "confidence_evaluation",
        _should_build_attack_chain,
        {
            "build_chain": "attack_chain_build",
            "finalize": "finalize",
        },
    )

    workflow.add_edge("attack_chain_build", "finalize")
    workflow.add_edge("finalize", END)

    return workflow


# ---------------------------------------------------------------------------
# 工作流执行
# ---------------------------------------------------------------------------

async def run_audit_workflow(
    workflow: StateGraph,
    code: str,
    language: str = "python",
    finding: Dict = None,
) -> Dict[str, Any]:
    """编译并运行安全审计工作流

    Args:
        workflow: StateGraph 实例
        code: 待分析代码
        language: 编程语言
        finding: 已有发现信息

    Returns:
        最终审计结果
    """
    graph = workflow.compile()

    initial_state: AuditGraphState = {
        'code': code,
        'language': language,
        'finding': finding or {},
        'taint_result': {},
        'cwe_result': {},
        'confidence_result': {},
        'attack_chain': {},
        'final_result': {},
        'errors': [],
        'analysis_complete': False,
    }

    logger.info(f"[AuditWorkflow] 开始审计: language={language}")

    final_state = await graph.ainvoke(initial_state)

    logger.info(f"[AuditWorkflow] 审计完成: complete={final_state.get('analysis_complete')}")

    return final_state.get('final_result', {})


def run_audit_workflow_sync(
    workflow: StateGraph,
    code: str,
    language: str = "python",
    finding: Dict = None,
) -> Dict[str, Any]:
    """同步运行安全审计工作流（用于无 async 环境）"""
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already in async context, need different approach
            return run_audit_workflow_sync_fallback(workflow, code, language, finding)
        return loop.run_until_complete(
            run_audit_workflow(workflow, code, language, finding)
        )
    except RuntimeError:
        return asyncio.run(run_audit_workflow(workflow, code, language, finding))


def run_audit_workflow_sync_fallback(
    workflow: StateGraph,
    code: str,
    language: str = "python",
    finding: Dict = None,
) -> Dict[str, Any]:
    """回退方案：不使用 LangGraph 的同步执行"""
    # 如果 LangGraph 不可用，直接调用 analyzer
    from src.ai.agents.ai_security_agents import AISecurityAnalyzer

    # Extract analyzer from workflow nodes (fallback)
    analyzer = None
    for node_name, node_func in workflow.nodes.items():
        # Try to extract analyzer from closure
        pass

    # Simple direct analysis without LangGraph
    from src.ai.agents.ai_security_agents import AISecurityAnalyzer
    # This requires the analyzer to be passed separately
    return {
        'error': 'LangGraph async workflow requires async context',
        'final_result': {},
    }
