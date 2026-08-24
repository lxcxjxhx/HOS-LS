"""真实数据集止损实验

使用SecureVibeBench和A.S.E真实数据集运行实验。
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from data.schema import SampleData, SampleMetadata, DatasetType, VulnerabilityType
from src.orchestrator import Orchestrator, PatchTriplet, AnalysisMode
from eval.metrics import calculate_pair_correct, calculate_metrics, format_metrics_report


# API配置
API_BASE_URL = "https://token-plan-cn.xiaomimimo.com/v1"
API_KEY = "tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p"
MODEL = "mimo-v2.5-pro"

# 代理配置
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
os.environ["DEEPSEEK_API_KEY"] = API_KEY


def load_ase_samples(max_samples: int = 40) -> List[SampleData]:
    """加载A.S.E数据集"""
    samples = []
    data_path = Path(__file__).parent.parent / "bench-runs" / "datasets" / "AICGSecEval_hf" / "data" / "static_eval.jsonl"
    
    if not data_path.exists():
        print(f"[ERROR] A.S.E dataset not found at {data_path}")
        return samples
    
    with open(data_path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if i >= max_samples:
                break
            item = json.loads(line)
            
            # 提取漏洞类型
            vuln_type_map = {
                "Command Injection": VulnerabilityType.COMMAND_INJECTION,
                "SQL Injection": VulnerabilityType.SQL_INJECTION,
                "Path Traversal": VulnerabilityType.PATH_TRAVERSAL,
                "XSS": VulnerabilityType.XSS,
                "SSRF": VulnerabilityType.SSRF,
            }
            vuln_type = vuln_type_map.get(item.get("vuln_type", ""), VulnerabilityType.OTHER)
            
            # 构建样本
            sample = SampleData(
                metadata=SampleMetadata(
                    sample_id=item["instance_id"],
                    dataset=DatasetType.ASE,
                    project_name=item.get("repo", ""),
                    repo_url=f"https://github.com/{item.get('repo', '')}",
                    commit_hash=item.get("base_commit", ""),
                    language=item.get("language", "unknown"),
                    cwe_ids=[item.get("cwe_id", "")] if item.get("cwe_id") else [],
                    vulnerability_type=vuln_type,
                    description=item.get("vuln_type", ""),
                    is_vulnerable=True,  # A.S.E都是漏洞样本
                ),
                r_before="",  # 需要从仓库重建
                task_desc=f"Fix {item.get('vuln_type', 'vulnerability')} in {item.get('vuln_file', 'unknown')}",
                delta_ai="",  # 需要从仓库获取diff
                modified_functions=[f"{item.get('vuln_file', '')}:{line}" for line in item.get("vuln_lines", [])],
            )
            samples.append(sample)
    
    return samples


def load_securevibench_samples(max_samples: int = 40) -> List[SampleData]:
    """加载SecureVibeBench数据集"""
    samples = []
    data_path = Path(__file__).parent.parent / "bench-runs" / "datasets" / "SecureVibeBench_hf" / "data" / "train-00000-of-00001.parquet"
    
    if not data_path.exists():
        print(f"[ERROR] SecureVibeBench dataset not found at {data_path}")
        return samples
    
    df = pd.read_parquet(data_path)
    
    for i, row in df.head(max_samples).iterrows():
        sample = SampleData(
            metadata=SampleMetadata(
                sample_id=str(row["localid"]),
                dataset=DatasetType.SECUREVIBEBENCH,
                project_name=row.get("repo_url", "").split("/")[-1].replace(".git", ""),
                repo_url=row.get("repo_url", ""),
                commit_hash=row.get("vic", ""),
                language="c",  # SecureVibeBench是C/C++
                vulnerability_type=VulnerabilityType.OTHER,
                description=row.get("description", "")[:200],
                is_vulnerable=True,
            ),
            r_before="",
            task_desc=row.get("description", "")[:500],
            delta_ai="",
            modified_functions=[],
        )
        samples.append(sample)
    
    return samples


async def run_experiment_with_real_data(
    samples: List[SampleData],
    max_samples: int = 20,
) -> Dict[str, Any]:
    """使用真实数据运行实验"""
    print(f"\n{'='*60}")
    print(f"Running experiment with {min(len(samples), max_samples)} real samples")
    print(f"{'='*60}")
    
    orchestrator = Orchestrator(
        api_key=API_KEY,
        base_url=API_BASE_URL,
        model=MODEL,
        mode=AnalysisMode.FULL,
    )
    
    results = []
    start_time = time.time()
    
    for i, sample in enumerate(samples[:max_samples]):
        print(f"\n[{i+1}/{min(len(samples), max_samples)}] {sample.metadata.sample_id}")
        print(f"  Project: {sample.metadata.project_name}")
        print(f"  Task: {sample.task_desc[:80]}...")
        
        try:
            # 对于真实数据，我们用任务描述作为diff的替代
            # 因为真实数据需要从仓库获取实际diff
            triplet = PatchTriplet(
                r_before=sample.r_before or "/tmp/repo",
                task_desc=sample.task_desc,
                delta_ai=sample.delta_ai or f"[Task] {sample.task_desc}",
                sample_id=sample.metadata.sample_id,
                cve_ids=sample.metadata.cve_ids,
                cwe_ids=sample.metadata.cwe_ids,
                language=sample.metadata.language,
            )
            
            report = await orchestrator.analyze(triplet)
            
            from eval.metrics import create_evaluation_result
            result = create_evaluation_result(
                sample=sample,
                prediction=report.vulnerability_found,
                confidence=report.confidence,
            )
            results.append(result)
            
            print(f"  -> Prediction: {report.vulnerability_found}, Confidence: {report.confidence:.2f}")
            print(f"  -> Summary: {report.summary[:100]}")
            
        except Exception as e:
            print(f"  -> Error: {e}")
            from eval.metrics import create_evaluation_result
            result = create_evaluation_result(
                sample=sample,
                prediction=False,
                confidence=0.0,
            )
            results.append(result)
    
    elapsed = time.time() - start_time
    
    # 计算指标
    metrics = calculate_metrics(results)
    
    return {
        "metrics": metrics,
        "results": results,
        "elapsed_seconds": elapsed,
    }


async def main():
    """主函数"""
    print("=" * 60)
    print("Real Dataset Experiment")
    print("=" * 60)
    
    # 加载A.S.E数据集
    print("\n[1] Loading A.S.E dataset...")
    ase_samples = load_ase_samples(max_samples=10)
    print(f"  Loaded {len(ase_samples)} samples from A.S.E")
    
    # 加载SecureVibeBench数据集
    print("\n[2] Loading SecureVibeBench dataset...")
    svb_samples = load_securevibench_samples(max_samples=10)
    print(f"  Loaded {len(svb_samples)} samples from SecureVibeBench")
    
    # 合并样本
    all_samples = ase_samples + svb_samples
    print(f"\n[3] Total samples: {len(all_samples)}")
    
    if not all_samples:
        print("[ERROR] No samples loaded. Check dataset paths.")
        return
    
    # 运行实验（减少样本数）
    print("\n[4] Running experiment...")
    results = await run_experiment_with_real_data(all_samples, max_samples=10)
    
    # 输出结果
    print("\n" + "=" * 60)
    print("Results")
    print("=" * 60)
    print(format_metrics_report(results["metrics"], "Real Dataset Experiment"))
    print(f"\nElapsed time: {results['elapsed_seconds']:.2f} seconds")
    
    # 保存结果
    output_dir = Path(__file__).parent.parent / "bench-runs" / "experiment_results"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "real_experiment_results.json"
    
    output = {
        "metrics": {
            "total_samples": results["metrics"].total_samples,
            "accuracy": results["metrics"].accuracy,
            "vuln_recall": results["metrics"].vuln_recall,
            "pair_correct_rate": results["metrics"].pair_correct_rate,
        },
        "elapsed_seconds": results["elapsed_seconds"],
        "samples": [
            {
                "sample_id": r.sample_id,
                "prediction": r.prediction,
                "ground_truth": r.ground_truth,
                "is_correct": r.is_correct,
                "confidence": r.confidence,
            }
            for r in results["results"]
        ],
    }
    
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
