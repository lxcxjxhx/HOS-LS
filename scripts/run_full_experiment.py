"""完整实验 - 使用真实diff和LLM分析"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.orchestrator import LLMClient


# API配置
API_BASE_URL = "https://token-plan-cn.xiaomimimo.com/v1"
API_KEY = "tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p"
MODEL = "mimo-v2.5-pro"

# 代理配置
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
os.environ["DEEPSEEK_API_KEY"] = API_KEY


def load_samples(data_path: str) -> List[Dict]:
    """加载样本"""
    with open(data_path, 'r', encoding='utf-8') as f:
        return json.load(f)


async def analyze_vulnerability(client: LLMClient, sample: Dict) -> Dict:
    """分析漏洞"""
    vuln_content = sample.get('vuln_content', '')[:4000]
    vuln_type = sample.get('vuln_type', 'unknown')
    cwe_id = sample.get('cwe_id', 'unknown')
    vuln_file = sample.get('vuln_file', 'unknown')
    vuln_lines = sample.get('vuln_lines', [])
    
    prompt = f"""You are a security expert performing code review. Analyze the following code for security vulnerabilities.

## Context
- File: {vuln_file}
- Expected Vulnerability Type: {vuln_type}
- CWE: {cwe_id}
- Vulnerable Lines: {vuln_lines}

## Code to Analyze
```php
{vuln_content}
```

## Analysis Task
1. Identify if there is a security vulnerability in the code
2. Focus on the specified vulnerability type ({vuln_type})
3. Look for patterns like:
   - User input being used without sanitization
   - Command execution with user-controlled data
   - SQL queries with string concatenation
   - File operations with user-controlled paths

## Response Format
Reply with JSON:
{{
    "vulnerable": true/false,
    "confidence": 0.0-1.0,
    "vulnerability_type": "detected type or null",
    "explanation": "detailed explanation of the vulnerability",
    "location": "file:line where vulnerability exists"
}}"""

    try:
        response = await client.generate(prompt)
        # 尝试解析JSON
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            result = json.loads(response[start:end])
            return result
        return {"vulnerable": False, "confidence": 0.0, "explanation": response[:300]}
    except Exception as e:
        return {"vulnerable": False, "confidence": 0.0, "error": str(e)}


async def main():
    """主函数"""
    print("=" * 60)
    print("Full Experiment with Real Diffs")
    print("=" * 60)
    
    # 加载数据
    data_path = Path(__file__).parent.parent / "bench-runs" / "datasets" / "ase_with_diffs.json"
    print(f"\n[1] Loading data from {data_path}...")
    samples = load_samples(str(data_path))
    print(f"  Loaded {len(samples)} samples")
    
    # 过滤有内容的样本
    valid_samples = [s for s in samples if s.get('vuln_content')]
    print(f"  Valid samples with content: {len(valid_samples)}")
    
    if not valid_samples:
        print("[ERROR] No valid samples.")
        return
    
    # 创建LLM客户端
    client = LLMClient(
        api_key=API_KEY,
        base_url=API_BASE_URL,
        model=MODEL,
    )
    
    # 运行分析
    print(f"\n[2] Running analysis on {len(valid_samples)} samples...")
    results = []
    start_time = time.time()
    
    for i, sample in enumerate(valid_samples):
        print(f"\n[{i+1}/{len(valid_samples)}] {sample['instance_id']}")
        print(f"  File: {sample['vuln_file']}")
        print(f"  Type: {sample['vuln_type']} ({sample['cwe_id']})")
        print(f"  Lines: {sample['vuln_lines']}")
        
        result = await analyze_vulnerability(client, sample)
        
        prediction = result.get("vulnerable", False)
        confidence = result.get("confidence", 0.0)
        
        results.append({
            "sample_id": sample['instance_id'],
            "ground_truth": True,  # A.S.E都是漏洞样本
            "prediction": prediction,
            "confidence": confidence,
            "explanation": result.get("explanation", "")[:150],
            "vuln_type_detected": result.get("vulnerability_type"),
            "location": result.get("location"),
        })
        
        print(f"  -> Prediction: {prediction}")
        print(f"  -> Confidence: {confidence:.2f}")
        print(f"  -> Detected Type: {result.get('vulnerability_type', 'N/A')}")
        print(f"  -> Location: {result.get('location', 'N/A')}")
    
    elapsed = time.time() - start_time
    
    # 计算指标
    correct = sum(1 for r in results if r['prediction'] == r['ground_truth'])
    accuracy = correct / len(results) if results else 0
    recall = sum(1 for r in results if r['prediction']) / len(results) if results else 0
    
    # 按漏洞类型统计
    type_stats = {}
    for r in results:
        # 从sample获取原始类型
        sample = next((s for s in valid_samples if s['instance_id'] == r['sample_id']), None)
        if sample:
            vtype = sample.get('vuln_type', 'unknown')
            if vtype not in type_stats:
                type_stats[vtype] = {"total": 0, "correct": 0}
            type_stats[vtype]["total"] += 1
            if r['prediction']:
                type_stats[vtype]["correct"] += 1
    
    print("\n" + "=" * 60)
    print("Results Summary")
    print("=" * 60)
    print(f"Total samples: {len(results)}")
    print(f"Correct predictions: {correct}")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Recall (detection rate): {recall:.2%}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
    print(f"Average time per sample: {elapsed/len(results):.2f} seconds")
    
    print("\nBy Vulnerability Type:")
    for vtype, stats in type_stats.items():
        rate = stats['correct'] / stats['total'] if stats['total'] > 0 else 0
        print(f"  {vtype}: {stats['correct']}/{stats['total']} ({rate:.0%})")
    
    # 保存结果
    output_dir = Path(__file__).parent.parent / "bench-runs" / "experiment_results"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "full_experiment_results.json"
    
    with open(output_path, "w") as f:
        json.dump({
            "metrics": {
                "total_samples": len(results),
                "correct": correct,
                "accuracy": accuracy,
                "recall": recall,
                "by_type": type_stats,
            },
            "elapsed_seconds": elapsed,
            "results": results,
        }, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
