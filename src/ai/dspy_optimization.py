import dspy
from typing import List, Dict, Any


class VulnerabilityAnalysis(dspy.Signature):
    """输入代码片段，输出结构化漏洞报告"""
    code: str = dspy.InputField()
    cve_context: str = dspy.InputField()
    attack_chain: str = dspy.InputField()
    vulnerabilities: str = dspy.OutputField()
    exploitation: str = dspy.OutputField()
    fix_suggestions: str = dspy.OutputField()


class RetrievalAnalysis(dspy.Signature):
    """输入代码，输出相关的CVE候选列表"""
    code: str = dspy.InputField()
    cve_candidates: List[Dict[str, Any]] = dspy.OutputField()


class GraphAnalysis(dspy.Signature):
    """输入CVE列表，输出攻击链分析"""
    cve_candidates: List[Dict[str, Any]] = dspy.InputField()
    attack_chain: Dict[str, Any] = dspy.OutputField()


class CriticEvaluation(dspy.Signature):
    """输入分析结果，输出质量评估"""
    analysis_result: str = dspy.InputField()
    quality: str = dspy.OutputField()
    improvements: str = dspy.OutputField()


class RepairSuggestion(dspy.Signature):
    """输入漏洞详情，输出修复建议"""
    vulnerability_details: str = dspy.InputField()
    fix_suggestions: str = dspy.OutputField()


def create_dspy_program(signature, trainset=None):
    """创建并优化DSPy程序
    
    Args:
        signature: DSPy Signature
        trainset: 训练集
        
    Returns:
        dspy.Program: 优化后的程序
    """
    if trainset:
        # 使用BootstrapFewShotWithRandomSearch自动优化
        optimizer = dspy.BootstrapFewShotWithRandomSearch(
            metric=lambda pred, gold: 1 if pred == gold else 0,  # 简单的准确率 metric
            max_bootstrapped_demos=8
        )
        compiled_program = optimizer.compile(signature, trainset=trainset)
    else:
        # 使用默认程序
        compiled_program = dspy.Predict(signature)
    
    return compiled_program


def get_dspy_programs():
    """获取所有DSPy程序
    
    Returns:
        Dict[str, dspy.Program]: 程序字典
    """
    return {
        'vulnerability_analysis': create_dspy_program(VulnerabilityAnalysis()),
        'retrieval_analysis': create_dspy_program(RetrievalAnalysis()),
        'graph_analysis': create_dspy_program(GraphAnalysis()),
        'critic_evaluation': create_dspy_program(CriticEvaluation()),
        'repair_suggestion': create_dspy_program(RepairSuggestion())
    }
