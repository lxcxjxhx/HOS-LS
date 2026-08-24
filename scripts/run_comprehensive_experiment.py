"""综合实验 - 使用数据适配器和直接LLM调用"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
os.environ["DEEPSEEK_API_KEY"] = "tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p"

from src.data_adapter import ASEAdapter, DREAAdapter, VulnSample
from src.orchestrator import LLMClient


async def analyze_sample(client: LLMClient, sample: VulnSample) -> Dict:
    """分析单个样本"""
    
    # 构建prompt
    if sample.code_after:
        # DREA格式：有before/after
        prompt = f"""You are a security researcher. A CVE vulnerability was fixed in this code.

## Vulnerability: {sample.vuln_type} ({sample.cwe_id})

## Code BEFORE (vulnerable):
```
{sample.code_before[:2500]}
```

## Code AFTER (fixed):
```
{sample.code_after[:2500]}
```

## Task
Confirm the "before" code has a real {sample.vuln_type} vulnerability that is fixed in the "after" code.

Reply JSON: {{"vulnerable": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}}"""
    else:
        # A.S.E格式：只有漏洞代码
        prompt = f"""You are a security researcher. Analyze this code for {sample.vuln_type} vulnerability.

## File: {sample.vuln_file}
## Vulnerability Type: {sample.vuln_type} ({sample.cwe_id})
## Lines: {sample.vuln_lines}

## Code:
```
{sample.code_before[:3000]}
```

## Task
Is this code vulnerable to {sample.vuln_type}?

Reply JSON: {{"vulnerable": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}}"""

    try:
        response = await client.generate(prompt)
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            result = json.loads(response[start:end])
            return result
        return {"vulnerable": False, "confidence": 0.0, "reason": response[:200]}
    except Exception as e:
        return {"vulnerable": False, "confidence": 0.0, "error": str(e)}


async def run_experiment(samples: List[VulnSample], dataset_name: str) -> Dict:
    """运行实验"""
    print(f"\n{'='*60}")
    print(f"Running experiment: {dataset_name}")
    print(f"{'='*60}")
    
    client = LLMClient(
        api_key=os.getenv('DEEPSEEK_API_KEY'),
        base_url='https://token-plan-cn.xiaomimimo.com/v1',
        model='mimo-v2.5-pro',
    )
    
    results = []
    start_time = time.time()
    
    for i, sample in enumerate(samples):
        print(f"[{i+1}/{len(samples)}] {sample.sample_id} ({sample.vuln_type})", end=" -> ")
        
        result = await analyze_sample(client, sample)
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
    
    return {
        "dataset": dataset_name,
        "metrics": {
            "total": len(results),
            "correct": correct,
            "accuracy": correct / len(results) if results else 0,
            "by_type": type_stats,
        },
        "elapsed_seconds": elapsed,
        "results": results,
    }


async def main():
    """主函数"""
    base_dir = Path(__file__).parent.parent
    
    # 加载A.S.E数据集
    print("Loading A.S.E dataset...")
    ase_adapter = ASEAdapter(
        str(base_dir / "bench-runs" / "datasets" / "AICGSecEval_hf" / "data" / "static_eval.jsonl"),
        str(base_dir / "bench-runs" / "datasets" / "ase_repos"),
    )
    ase_samples = ase_adapter.load_samples(max_samples=10)
    print(f"Loaded {len(ase_samples)} A.S.E samples")
    
    # 加载DREA数据集
    print("\nLoading DREA dataset...")
    drea_adapter = DREAAdapter(
        str(base_dir.parent / "drea" / "data" / "repopairbench_100.jsonl"),
    )
    drea_samples = drea_adapter.load_samples(max_samples=10)
    print(f"Loaded {len(drea_samples)} DREA samples")
    
    # 运行实验
    ase_results = await run_experiment(ase_samples, "A.S.E")
    drea_results = await run_experiment(drea_samples, "DREA")
    
    # 输出结果
    print(f"\n{'='*60}")
    print("Experiment Results Summary")
    print(f"{'='*60}")
    
    for result in [ase_results, drea_results]:
        print(f"\n{result['dataset']}:")
        print(f"  Total: {result['metrics']['total']}")
        print(f"  Correct: {result['metrics']['correct']}")
        print(f"  Accuracy: {result['metrics']['accuracy']:.1%}")
        print(f"  Time: {result['elapsed_seconds']:.0f}s")
        
        print(f"  By Type:")
        for t, s in result['metrics']['by_type'].items():
            print(f"    {t}: {s['detected']}/{s['total']} ({s['detected']/s['total']:.0%})")
    
    # 保存结果
    output_dir = base_dir / "bench-runs" / "experiment_results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / "comprehensive_experiment_results.json", 'w') as f:
        json.dump({
            "ase": ase_results,
            "drea": drea_results,
        }, f, indent=2)
    
    print(f"\nResults saved to: {output_dir / 'comprehensive_experiment_results.json'}")


if __name__ == "__main__":
    asyncio.run(main())
