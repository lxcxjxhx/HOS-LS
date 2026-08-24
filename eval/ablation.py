"""消融实验框架

支持SAL-only、DEP-only、Full三种配置的消融实验。
"""

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from data.schema import (
    SampleData, EvaluationResult, PairResult, EvaluationMetrics
)
from eval.metrics import (
    calculate_pair_correct, calculate_metrics,
    calculate_ablation_metrics, format_ablation_report,
    prepare_evaluation_samples, create_evaluation_result
)
from src.orchestrator import Orchestrator, PatchTriplet, AnalysisMode


class AblationConfig(str, Enum):
    """消融实验配置枚举"""
    LOCATOR_ONLY = "locator_only"  # 只运行定位员
    DIFFER_ONLY = "differ_only"  # 只运行差分员
    FULL = "full"  # 运行完整系统


@dataclass
class AblationResult:
    """消融实验结果"""
    config: AblationConfig
    metrics: EvaluationMetrics
    results: List[EvaluationResult] = field(default_factory=list)
    pairs: List[PairResult] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class AblationRunner:
    """消融实验运行器
    
    运行不同配置的消融实验，比较SAL、DEP模块的贡献。
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
    
    async def run_ablation(
        self,
        samples: List[SampleData],
        configs: Optional[List[AblationConfig]] = None,
    ) -> Dict[str, AblationResult]:
        """运行消融实验
        
        Args:
            samples: 样本列表
            configs: 要运行的配置列表（默认全部）
            
        Returns:
            各配置的实验结果
        """
        if configs is None:
            configs = list(AblationConfig)
        
        results = {}
        
        for config in configs:
            print(f"Running ablation: {config.value}")
            result = await self.run_single_config(samples, config)
            results[config.value] = result
        
        return results
    
    async def run_single_config(
        self,
        samples: List[SampleData],
        config: AblationConfig,
    ) -> AblationResult:
        """运行单个配置
        
        Args:
            samples: 样本列表
            config: 配置
            
        Returns:
            实验结果
        """
        start_time = time.time()
        
        # 根据配置创建Orchestrator
        mode = self._config_to_mode(config)
        orchestrator = Orchestrator(
            llm_client=self.llm_client,
            mode=mode,
        )
        
        # 运行评测
        eval_results = []
        for sample in samples:
            result = await self._evaluate_sample(orchestrator, sample)
            eval_results.append(result)
        
        # 分离漏洞和修复样本
        vuln_samples, patched_samples = prepare_evaluation_samples(samples)
        vuln_results = [r for r in eval_results if r.ground_truth]
        patched_results = [r for r in eval_results if not r.ground_truth]
        
        # 计算成对指标
        pairs, pair_correct_rate = calculate_pair_correct(vuln_results, patched_results)
        
        # 计算指标
        metrics = calculate_metrics(eval_results, pairs)
        
        elapsed = time.time() - start_time
        
        return AblationResult(
            config=config,
            metrics=metrics,
            results=eval_results,
            pairs=pairs,
            elapsed_seconds=elapsed,
            metadata={
                "total_samples": len(samples),
                "vuln_samples": len(vuln_samples),
                "patched_samples": len(patched_samples),
            }
        )
    
    def _config_to_mode(self, config: AblationConfig) -> AnalysisMode:
        """将配置转换为分析模式"""
        mapping = {
            AblationConfig.LOCATOR_ONLY: AnalysisMode.LOCATOR_ONLY,
            AblationConfig.DIFFER_ONLY: AnalysisMode.DIFFER_ONLY,
            AblationConfig.FULL: AnalysisMode.FULL,
        }
        return mapping.get(config, AnalysisMode.FULL)
    
    async def _evaluate_sample(
        self,
        orchestrator: Orchestrator,
        sample: SampleData,
    ) -> EvaluationResult:
        """评测单个样本"""
        try:
            # 构建PatchTriplet
            triplet = PatchTriplet(
                r_before=sample.r_before,
                task_desc=sample.task_desc,
                delta_ai=sample.delta_ai,
                sample_id=sample.metadata.sample_id,
                cve_ids=sample.metadata.cve_ids,
                cwe_ids=sample.metadata.cwe_ids,
                language=sample.metadata.language,
            )
            
            # 运行分析
            report = await orchestrator.analyze(
                triplet=triplet,
                modified_funcs=sample.modified_functions,
            )
            
            # 创建评测结果
            return create_evaluation_result(
                sample=sample,
                prediction=report.vulnerability_found,
                confidence=report.confidence,
                evidence=report.verification_evidence,
            )
        
        except Exception as e:
            # 出错时返回错误结果
            return EvaluationResult(
                sample_id=sample.metadata.sample_id,
                prediction=False,
                ground_truth=sample.metadata.is_vulnerable,
                confidence=0.0,
                metadata={"error": str(e)},
            )
    
    def generate_report(
        self,
        ablation_results: Dict[str, AblationResult]
    ) -> str:
        """生成消融实验报告"""
        # 转换为指标字典
        metrics_dict = {
            config: result.metrics
            for config, result in ablation_results.items()
        }
        
        # 生成报告
        report = format_ablation_report(metrics_dict)
        
        # 添加详细信息
        lines = [report, "", "=== 详细结果 ==="]
        
        for config, result in ablation_results.items():
            lines.append(f"\n--- {config} ---")
            lines.append(f"  运行时间: {result.elapsed_seconds:.2f}秒")
            lines.append(f"  样本数: {result.metrics.total_samples}")
            lines.append(f"  Pair-Correct率: {result.metrics.pair_correct_rate:.2%}")
            lines.append(f"  召回率: {result.metrics.vuln_recall:.2%}")
            lines.append(f"  误报数: {result.metrics.false_positives}")
        
        return "\n".join(lines)
    
    def save_results(
        self,
        ablation_results: Dict[str, AblationResult],
        output_path: str,
    ):
        """保存实验结果"""
        output = {}
        
        for config, result in ablation_results.items():
            output[config] = {
                "config": config,
                "metrics": {
                    "total_samples": result.metrics.total_samples,
                    "accuracy": result.metrics.accuracy,
                    "vuln_recall": result.metrics.vuln_recall,
                    "patched_specificity": result.metrics.patched_specificity,
                    "pair_correct_rate": result.metrics.pair_correct_rate,
                    "precision": result.metrics.precision,
                    "f1_score": result.metrics.f1_score,
                    "false_positives": result.metrics.false_positives,
                    "false_negatives": result.metrics.false_negatives,
                },
                "elapsed_seconds": result.elapsed_seconds,
                "metadata": result.metadata,
            }
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
