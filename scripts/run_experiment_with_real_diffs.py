"""使用真实diff运行实验"""

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


def load_samples_with_diffs(data_path: str) -> List[Dict]:
    """加载带diff的样本"""
    with open(data_path, 'r', encoding='utf-8') as f:
        return json.load(f)


async def analyze_with_llm(client: LLMClient, sample: Dict) -> Dict:
    """使用LLM分析真实diff"""
    vuln_content = sample.get('vuln_content', '')[:3000]  # 限制长度
    vuln_type = sample.get('vuln_type', 'unknown')
    cwe_id = sample.get('cwe_id', 'unknown')
    vuln_file = sample.get('vuln_file', 'unknown')
    vuln_lines = sample.get('vuln_lines', [])
    
    prompt = f"""You are a security expert. Analyze this vulnerable code for security issues.

File: {vuln_file}
Vulnerability Type: {vuln_type}
CWE: {cwe_id}
Vulnerable Lines: {vuln_lines}

Code:
```
{vuln_content}
```

Is this code vulnerable to {vuln_type}? Analyze the code and determine if there is a real security vulnerability.

Reply with JSON:
{{"vulnerable": true/false, "confidence": 0.0-1.0, "explanation": "brief explanation of the vulnerability"}}"""

    try:
        response = await client.generate(prompt)
        # 尝试解析JSON
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            return json.loads(response[start:end])
        return {"vulnerable": False, "confidence": 0.0, "explanation": response[:200]}
    except Exception as e:
        return {"vulnerable": False, "confidence": 0.0, "error": str(e)}


async def main():
    """主函数"""
    print("=" * 60)
    print("Experiment with Real Diffs")
    print("=" * 60)
    
    # 加载数据
    data_path = Path(__file__).parent.parent / "bench-runs" / "datasets" / "ase_with_diffs.json"
    print(f"\n[1] Loading data from {data_path}...")
    samples = load_samples_with_diffs(str(data_path))
    print(f"  Loaded {len(samples)} samples")
    
    if not samples:
        print("[ERROR] No samples loaded.")
        return
    
    # 创建LLM客户端
    client = LLMClient(
        api_key=API_KEY,
        base_url=API_BASE_URL,
        model=MODEL,
    )
    
    # 运行分析
    print("\n[2] Running analysis...")
    results = []
    start_time = time.time()
    
    for i, sample in enumerate(samples):
        print(f"\n[{i+1}/{len(samples)}] {sample['instance_id']}")
        print(f"  File: {sample['vuln_file']}")
        print(f"  Type: {sample['vuln_type']} ({sample['cwe_id']})")
        print(f"  Lines: {sample['vuln_lines']}")
        
        result = await analyze_with_llm(client, sample)
        results.append({
            "sample_id": sample['instance_id'],
            "ground_truth": True,  # A.S.E都是漏洞样本
            "prediction": result.get("vulnerable", False),
            "confidence": result.get("confidence", 0.0),
            "explanation": result.get("explanation", "")[:100],
        })
        
        print(f"  -> Prediction: {result.get('vulnerable', False)}")
        print(f"  -> Confidence: {result.get('confidence', 0.0):.2f}")
        print(f"  -> Explanation: {result.get('explanation', '')[:80]}")
    
    elapsed = time.time() - start_time
    
    # 计算指标
    correct = sum(1 for r in results if r['prediction'] == r['ground_truth'])
    accuracy = correct / len(results) if results else 0
    recall = sum(1 for r in results if r['prediction']) / len(results) if results else 0
    
    print("\n" + "=" * 60)
    print("Results")
    print("=" * 60)
    print(f"Total samples: {len(results)}")
    print(f"Correct predictions: {correct}")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Recall (vulnerability detection rate): {recall:.2%}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
    print(f"Average time per sample: {elapsed/len(results):.2f} seconds")
    
    # 保存结果
    output_dir = Path(__file__).parent.parent / "bench-runs" / "experiment_results"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "real_diff_experiment_results.json"
    
    with open(output_path, "w") as f:
        json.dump({
            "metrics": {
                "total_samples": len(results),
                "correct": correct,
                "accuracy": accuracy,
                "recall": recall,
            },
            "elapsed_seconds": elapsed,
            "results": results,
        }, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
