"""最终实验 - 使用DirectLLM"""

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"

from src.direct_llm import DirectLLM
from src.data_adapter import DREAAdapter, VulnSample


def main():
    base_dir = Path(__file__).parent.parent
    
    # 初始化LLM
    llm = DirectLLM(
        api_key="tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p",
        base_url="https://token-plan-cn.xiaomimimo.com/v1",
        model="mimo-v2.5-pro",
    )
    
    # 加载DREA数据集
    print("Loading DREA dataset...")
    drea_adapter = DREAAdapter(str(base_dir.parent / "drea" / "data" / "repopairbench_100.jsonl"))
    samples = drea_adapter.load_samples(max_samples=30)
    print(f"Loaded {len(samples)} samples")
    
    # 运行实验
    results = []
    start_time = time.time()
    
    for i, sample in enumerate(samples):
        print(f"[{i+1}/{len(samples)}] {sample.sample_id} ({sample.vuln_type})", end=" -> ")
        
        result = llm.analyze_vulnerability(
            code=sample.code_before,
            vuln_type=sample.vuln_type,
            cwe_id=sample.cwe_id,
            code_after=sample.code_after,
        )
        
        prediction = result.get("vulnerable", False)
        results.append({
            "sample_id": sample.sample_id,
            "vuln_type": sample.vuln_type,
            "cwe_id": sample.cwe_id,
            "prediction": prediction,
            "confidence": result.get("confidence", 0.0),
            "reason": result.get("reason", "")[:100],
            "ground_truth": True,
        })
        
        print(f"{prediction} ({result.get('confidence', 0):.2f})")
    
    elapsed = time.time() - start_time
    correct = sum(1 for r in results if r['prediction'])
    
    # 按类型统计
    type_stats = {}
    for r in results:
        t = r['vuln_type']
        if t not in type_stats:
            type_stats[t] = {"total": 0, "detected": 0}
        type_stats[t]["total"] += 1
        if r['prediction']:
            type_stats[t]["detected"] += 1
    
    print(f"\n{'='*60}")
    print(f"Results: {correct}/{len(samples)} ({correct/len(samples):.1%})")
    print(f"Time: {elapsed:.0f}s ({elapsed/len(samples):.1f}s/sample)")
    print(f"\nBy Type:")
    for t, s in type_stats.items():
        print(f"  {t}: {s['detected']}/{s['total']} ({s['detected']/s['total']:.0%})")
    
    # 保存结果
    output_path = base_dir / "bench-runs" / "experiment_results" / "final_experiment_v2.json"
    with open(output_path, 'w') as f:
        json.dump({
            "metrics": {"total": len(samples), "correct": correct, "accuracy": correct/len(samples), "by_type": type_stats},
            "elapsed_seconds": elapsed,
            "results": results,
        }, f, indent=2)
    print(f"\nSaved to {output_path}")


if __name__ == "__main__":
    main()
