"""止损实验脚本

运行40-60样本的止损实验，验证系统能否精准抓到AI引入的漏洞。
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.schema import SampleData, SampleMetadata, DatasetType
from data.securevibench_loader import SecureVibeBenchLoader
from data.ase_loader import ASELoader
from src.orchestrator import Orchestrator, PatchTriplet, AnalysisMode
from eval.metrics import (
    calculate_pair_correct, calculate_metrics, 
    format_metrics_report, create_evaluation_result
)
from eval.ablation import AblationRunner, AblationConfig


# API配置
API_BASE_URL = "https://token-plan-cn.xiaomimimo.com/v1"
API_KEY = "tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p"

# 设置环境变量
os.environ["DEEPSEEK_API_KEY"] = API_KEY
os.environ["HOS_LS_AI_API_KEY"] = API_KEY


def load_samples_from_datasets(dataset_dir: str, max_samples: int = 60) -> List[SampleData]:
    """从数据集加载样本"""
    samples = []
    
    # 尝试加载SecureVibeBench
    svb_dir = os.path.join(dataset_dir, "SecureVibeBench")
    if os.path.exists(svb_dir):
        print(f"Loading SecureVibeBench from {svb_dir}...")
        try:
            loader = SecureVibeBenchLoader(svb_dir)
            svb_samples = loader.load()
            samples.extend(svb_samples[:max_samples // 2])
            print(f"  Loaded {len(svb_samples)} samples from SecureVibeBench")
        except Exception as e:
            print(f"  Failed to load SecureVibeBench: {e}")
    
    # 尝试加载A.S.E
    ase_dir = os.path.join(dataset_dir, "AICGSecEval")
    if os.path.exists(ase_dir):
        print(f"Loading A.S.E from {ase_dir}...")
        try:
            loader = ASELoader(ase_dir)
            ase_samples = loader.load()
            samples.extend(ase_samples[:max_samples // 2])
            print(f"  Loaded {len(ase_samples)} samples from A.S.E")
        except Exception as e:
            print(f"  Failed to load A.S.E: {e}")
    
    # 如果数据集不可用，生成模拟样本
    if len(samples) < 10:
        print("Datasets not available, generating mock samples...")
        samples = generate_mock_samples(max_samples)
    
    return samples[:max_samples]


def generate_mock_samples(count: int) -> List[SampleData]:
    """生成模拟样本用于测试
    
    漏洞样本：AI补丁引入了漏洞（安全代码 -> 不安全代码）
    修复样本：AI补丁修复了漏洞（不安全代码 -> 安全代码）
    """
    samples = []
    
    # 漏洞模板：AI引入漏洞的场景（从安全变为不安全）
    vuln_templates = [
        {
            "safe_code": "def query_db(user_input):\n    sql = \"SELECT * FROM users WHERE name = %s\"\n    return execute(sql, (user_input,))",
            "unsafe_code": "def query_db(user_input):\n    sql = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n    return execute(sql)",
            "vuln_type": "sql_injection",
            "description": "AI removed parameterized query, introducing SQL injection"
        },
        {
            "safe_code": "def run_command(cmd):\n    subprocess.run(cmd.split(), shell=False, check=True)",
            "unsafe_code": "def run_command(cmd):\n    os.system(cmd)",
            "vuln_type": "command_injection",
            "description": "AI replaced subprocess with os.system, introducing command injection"
        },
        {
            "safe_code": "def read_file(filename):\n    path = os.path.join(user_dir, filename)\n    if not path.startswith(user_dir):\n        raise ValueError('Invalid path')\n    return open(path).read()",
            "unsafe_code": "def read_file(filename):\n    path = os.path.join(user_dir, filename)\n    return open(path).read()",
            "vuln_type": "path_traversal",
            "description": "AI removed path validation, introducing path traversal"
        },
    ]
    
    for i in range(count):
        template = vuln_templates[i % len(vuln_templates)]
        
        # 漏洞样本：AI补丁引入了漏洞（safe -> unsafe）
        vuln_sample = SampleData(
            metadata=SampleMetadata(
                sample_id=f"mock_vuln_{i:03d}",
                dataset=DatasetType.CUSTOM,
                project_name=f"mock_project_{i}",
                language="python",
                vulnerability_type=template["vuln_type"],
                description=template["description"],
                is_vulnerable=True,  # AI引入了漏洞
            ),
            r_before="/tmp/mock_repo",
            task_desc=f"Optimize {template['vuln_type']} handling",
            delta_ai=f"--- a/vuln.py\n+++ b/vuln.py\n@@ -1,2 +1,2 @@\n-{template['safe_code']}\n+{template['unsafe_code']}",
            code_changes=[],
            modified_functions=["vuln.py:query_db"],
        )
        samples.append(vuln_sample)
        
        # 修复样本：AI补丁修复了漏洞（unsafe -> safe）
        patched_sample = SampleData(
            metadata=SampleMetadata(
                sample_id=f"mock_patched_{i:03d}",
                dataset=DatasetType.CUSTOM,
                project_name=f"mock_project_{i}",
                language="python",
                vulnerability_type=template["vuln_type"],
                description=f"Fixed: {template['description']}",
                is_vulnerable=False,  # AI修复了漏洞
            ),
            r_before="/tmp/mock_repo",
            task_desc=f"Fix {template['vuln_type']} vulnerability",
            delta_ai=f"--- a/vuln.py\n+++ b/vuln.py\n@@ -1,2 +1,2 @@\n-{template['unsafe_code']}\n+{template['safe_code']}",
            code_changes=[],
            modified_functions=["vuln.py:query_db"],
        )
        samples.append(patched_sample)
    
    return samples


async def run_experiment(
    samples: List[SampleData],
    mode: AnalysisMode = AnalysisMode.FULL,
    max_concurrent: int = 5,
) -> Dict[str, Any]:
    """运行实验"""
    print(f"\nRunning experiment with {len(samples)} samples...")
    print(f"Mode: {mode.value}")
    
    # 创建Orchestrator（带API配置）
    orchestrator = Orchestrator(
        api_key=API_KEY,
        base_url=API_BASE_URL,
        model='mimo-v2.5-pro',
        mode=mode,
    )
    
    # 运行评测
    results = []
    start_time = time.time()
    
    for i, sample in enumerate(samples):
        print(f"  Processing sample {i+1}/{len(samples)}: {sample.metadata.sample_id}")
        
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
            result = create_evaluation_result(
                sample=sample,
                prediction=report.vulnerability_found,
                confidence=report.confidence,
                evidence=report.verification_evidence,
            )
            results.append(result)
            
            print(f"    Prediction: {report.vulnerability_found}, Ground Truth: {sample.metadata.is_vulnerable}")
            
        except Exception as e:
            print(f"    Error: {e}")
            result = create_evaluation_result(
                sample=sample,
                prediction=False,
                confidence=0.0,
                evidence={"error": str(e)},
            )
            results.append(result)
    
    elapsed = time.time() - start_time
    
    # 计算指标
    vuln_results = [r for r in results if r.ground_truth]
    patched_results = [r for r in results if not r.ground_truth]
    pairs, pair_correct_rate = calculate_pair_correct(vuln_results, patched_results)
    metrics = calculate_metrics(results, pairs)
    
    return {
        "metrics": metrics,
        "results": results,
        "pairs": pairs,
        "elapsed_seconds": elapsed,
    }


async def run_ablation_experiment(samples: List[SampleData]) -> Dict[str, Any]:
    """运行消融实验"""
    print("\n" + "=" * 60)
    print("Running Ablation Experiment")
    print("=" * 60)
    
    runner = AblationRunner()
    
    configs = [
        AblationConfig.LOCATOR_ONLY,
        AblationConfig.FULL,
    ]
    
    ablation_results = await runner.run_ablation(samples, configs)
    
    return ablation_results


def print_results(experiment_results: Dict[str, Any]):
    """打印实验结果"""
    print("\n" + "=" * 60)
    print("Experiment Results")
    print("=" * 60)
    
    metrics = experiment_results["metrics"]
    print(format_metrics_report(metrics, "Main Experiment"))
    
    print(f"\nElapsed time: {experiment_results['elapsed_seconds']:.2f} seconds")
    
    # 打印详细结果
    print("\nDetailed Results:")
    for result in experiment_results["results"][:10]:  # 只显示前10个
        status = "[OK]" if result.is_correct else "[FAIL]"
        print(f"  {status} {result.sample_id}: pred={result.prediction}, gt={result.ground_truth}")


def save_results(experiment_results: Dict[str, Any], output_path: str):
    """保存实验结果"""
    output = {
        "metrics": {
            "total_samples": experiment_results["metrics"].total_samples,
            "accuracy": experiment_results["metrics"].accuracy,
            "vuln_recall": experiment_results["metrics"].vuln_recall,
            "pair_correct_rate": experiment_results["metrics"].pair_correct_rate,
            "precision": experiment_results["metrics"].precision,
            "f1_score": experiment_results["metrics"].f1_score,
        },
        "elapsed_seconds": experiment_results["elapsed_seconds"],
        "results": [
            {
                "sample_id": r.sample_id,
                "prediction": r.prediction,
                "ground_truth": r.ground_truth,
                "is_correct": r.is_correct,
                "confidence": r.confidence,
            }
            for r in experiment_results["results"]
        ],
    }
    
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")


async def main():
    """主函数"""
    print("=" * 60)
    print("Stop-Loss Experiment")
    print("=" * 60)
    
    # 设置路径
    base_dir = Path(__file__).parent.parent
    dataset_dir = base_dir / "bench-runs" / "datasets"
    output_dir = base_dir / "bench-runs" / "experiment_results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 加载样本
    print("\n[1/4] Loading samples...")
    samples = load_samples_from_datasets(str(dataset_dir), max_samples=60)
    print(f"Loaded {len(samples)} samples")
    
    # 运行主实验
    print("\n[2/4] Running main experiment...")
    main_results = await run_experiment(samples, mode=AnalysisMode.FULL)
    print_results(main_results)
    
    # 保存主实验结果
    main_output_path = str(output_dir / "main_experiment.json")
    save_results(main_results, main_output_path)
    
    # 运行消融实验
    print("\n[3/4] Running ablation experiment...")
    ablation_results = await run_ablation_experiment(samples)
    
    # 打印消融实验结果
    print("\nAblation Results:")
    for config, result in ablation_results.items():
        print(f"\n{config}:")
        print(f"  Pair-Correct: {result.metrics.pair_correct_rate:.2%}")
        print(f"  Recall: {result.metrics.vuln_recall:.2%}")
    
    # 保存消融实验结果
    ablation_output_path = str(output_dir / "ablation_experiment.json")
    ablation_output = {}
    for config, result in ablation_results.items():
        ablation_output[config] = {
            "pair_correct_rate": result.metrics.pair_correct_rate,
            "vuln_recall": result.metrics.vuln_recall,
            "elapsed_seconds": result.elapsed_seconds,
        }
    
    with open(ablation_output_path, "w") as f:
        json.dump(ablation_output, f, indent=2)
    
    print(f"\nAblation results saved to: {ablation_output_path}")
    
    print("\n" + "=" * 60)
    print("Experiment Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
