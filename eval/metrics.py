"""评测指标计算

实现Pair-Correct等评测指标。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from data.schema import (
    EvaluationResult, PairResult, EvaluationMetrics,
    SampleData
)


def calculate_pair_correct(
    vuln_results: List[EvaluationResult],
    patched_results: List[EvaluationResult],
) -> Tuple[List[PairResult], float]:
    """计算Pair-Correct指标
    
    Pair-Correct要求：
    - 漏洞样本预测为有漏洞 (True)
    - 修复样本预测为无漏洞 (False)
    
    Args:
        vuln_results: 漏洞样本评测结果
        patched_results: 修复样本评测结果
        
    Returns:
        (成对结果列表, Pair-Correct率)
    """
    pairs = []
    
    # 假设vuln_results和patched_results是配对的
    # 按sample_id排序确保配对正确
    vuln_sorted = sorted(vuln_results, key=lambda r: r.sample_id)
    patched_sorted = sorted(patched_results, key=lambda r: r.sample_id)
    
    # 配对
    for vuln_r, patched_r in zip(vuln_sorted, patched_sorted):
        pair = PairResult(
            pair_id=f"{vuln_r.sample_id}_vs_{patched_r.sample_id}",
            vuln_sample_id=vuln_r.sample_id,
            patched_sample_id=patched_r.sample_id,
            vuln_prediction=vuln_r.prediction,
            patched_prediction=patched_r.prediction,
        )
        pairs.append(pair)
    
    # 计算Pair-Correct率
    if pairs:
        pair_correct_count = sum(1 for p in pairs if p.pair_correct)
        pair_correct_rate = pair_correct_count / len(pairs)
    else:
        pair_correct_rate = 0.0
    
    return pairs, pair_correct_rate


def calculate_metrics(
    results: List[EvaluationResult],
    pairs: Optional[List[PairResult]] = None,
) -> EvaluationMetrics:
    """计算评测指标
    
    Args:
        results: 评测结果列表
        pairs: 成对结果列表（可选）
        
    Returns:
        评测指标
    """
    metrics = EvaluationMetrics()
    metrics.calculate(results, pairs or [])
    return metrics


def calculate_ablation_metrics(
    results_locator_only: List[EvaluationResult],
    results_differ_only: List[EvaluationResult],
    results_full: List[EvaluationResult],
    pairs_locator_only: Optional[List[PairResult]] = None,
    pairs_differ_only: Optional[List[PairResult]] = None,
    pairs_full: Optional[List[PairResult]] = None,
) -> Dict[str, EvaluationMetrics]:
    """计算消融实验指标
    
    Args:
        results_locator_only: 只运行定位员的结果
        results_differ_only: 只运行差分员的结果
        results_full: 运行完整系统的结果
        
    Returns:
        各配置的评测指标
    """
    return {
        "locator_only": calculate_metrics(results_locator_only, pairs_locator_only),
        "differ_only": calculate_metrics(results_differ_only, pairs_differ_only),
        "full": calculate_metrics(results_full, pairs_full),
    }


def format_metrics_report(metrics: EvaluationMetrics, title: str = "") -> str:
    """格式化评测指标报告"""
    lines = []
    
    if title:
        lines.append(f"=== {title} ===")
        lines.append("")
    
    lines.append(f"总样本数: {metrics.total_samples}")
    lines.append(f"正确预测: {metrics.correct_predictions}")
    lines.append(f"准确率: {metrics.accuracy:.2%}")
    lines.append("")
    
    lines.append("漏洞样本:")
    lines.append(f"  总数: {metrics.vuln_total}")
    lines.append(f"  正确: {metrics.vuln_correct}")
    lines.append(f"  召回率: {metrics.vuln_recall:.2%}")
    lines.append("")
    
    lines.append("修复样本:")
    lines.append(f"  总数: {metrics.patched_total}")
    lines.append(f"  正确: {metrics.patched_correct}")
    lines.append(f"  特异性: {metrics.patched_specificity:.2%}")
    lines.append("")
    
    lines.append("成对指标:")
    lines.append(f"  总对数: {metrics.total_pairs}")
    lines.append(f"  成对正确: {metrics.pair_correct_count}")
    lines.append(f"  Pair-Correct率: {metrics.pair_correct_rate:.2%}")
    lines.append("")
    
    lines.append("其他指标:")
    lines.append(f"  误报数: {metrics.false_positives}")
    lines.append(f"  漏报数: {metrics.false_negatives}")
    lines.append(f"  精确率: {metrics.precision:.2%}")
    lines.append(f"  F1分数: {metrics.f1_score:.2%}")
    
    return "\n".join(lines)


def format_ablation_report(
    ablation_metrics: Dict[str, EvaluationMetrics]
) -> str:
    """格式化消融实验报告"""
    lines = ["=== 消融实验报告 ===", ""]
    
    for config, metrics in ablation_metrics.items():
        lines.append(f"--- {config} ---")
        lines.append(f"  Pair-Correct率: {metrics.pair_correct_rate:.2%}")
        lines.append(f"  召回率: {metrics.vuln_recall:.2%}")
        lines.append(f"  误报率: {metrics.false_positives / metrics.total_samples:.2%}" if metrics.total_samples > 0 else "  误报率: N/A")
        lines.append("")
    
    # 比较分析
    lines.append("=== 比较分析 ===")
    
    if "full" in ablation_metrics and "locator_only" in ablation_metrics:
        full = ablation_metrics["full"]
        locator = ablation_metrics["locator_only"]
        
        if locator.pair_correct_rate > 0:
            improvement = (full.pair_correct_rate - locator.pair_correct_rate) / locator.pair_correct_rate
            lines.append(f"完整系统 vs 只用定位员:")
            lines.append(f"  Pair-Correct提升: {improvement:.2%}")
    
    if "full" in ablation_metrics and "differ_only" in ablation_metrics:
        full = ablation_metrics["full"]
        differ = ablation_metrics["differ_only"]
        
        if differ.pair_correct_rate > 0:
            improvement = (full.pair_correct_rate - differ.pair_correct_rate) / differ.pair_correct_rate
            lines.append(f"完整系统 vs 只用差分员:")
            lines.append(f"  Pair-Correct提升: {improvement:.2%}")
    
    return "\n".join(lines)


def prepare_evaluation_samples(
    samples: List[SampleData],
) -> Tuple[List[SampleData], List[SampleData]]:
    """准备评测样本
    
    将样本分为漏洞样本和修复样本。
    
    Args:
        samples: 样本列表
        
    Returns:
        (漏洞样本列表, 修复样本列表)
    """
    vuln_samples = [s for s in samples if s.metadata.is_vulnerable]
    patched_samples = [s for s in samples if not s.metadata.is_vulnerable]
    
    return vuln_samples, patched_samples


def create_evaluation_result(
    sample: SampleData,
    prediction: bool,
    confidence: float = 0.0,
    evidence: Optional[Dict[str, Any]] = None,
) -> EvaluationResult:
    """创建评测结果
    
    Args:
        sample: 样本数据
        prediction: 预测结果
        confidence: 置信度
        evidence: 证据
        
    Returns:
        评测结果
    """
    # Handle both enum and string vulnerability types
    vuln_type = sample.metadata.vulnerability_type
    if hasattr(vuln_type, 'value'):
        vuln_type_str = vuln_type.value
    else:
        vuln_type_str = str(vuln_type)
    
    return EvaluationResult(
        sample_id=sample.metadata.sample_id,
        prediction=prediction,
        ground_truth=sample.metadata.is_vulnerable,
        confidence=confidence,
        evidence=evidence,
        metadata={
            "project_name": sample.metadata.project_name,
            "vulnerability_type": vuln_type_str,
            "cve_ids": sample.metadata.cve_ids,
            "cwe_ids": sample.metadata.cwe_ids,
        }
    )
