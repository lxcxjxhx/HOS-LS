"""简化实验 - 直接使用LLM分析"""

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
from src.orchestrator import LLMClient


# API配置
API_BASE_URL = "https://token-plan-cn.xiaomimimo.com/v1"
API_KEY = "tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p"
MODEL = "mimo-v2.5-pro"

# 代理配置
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
os.environ["DEEPSEEK_API_KEY"] = API_KEY


def load_ase_samples(max_samples: int = 10) -> List[Dict]:
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
            samples.append(item)
    
    return samples


async def analyze_with_llm(client: LLMClient, task_desc: str, vuln_type: str) -> Dict:
    """使用LLM分析任务"""
    prompt = f"""You are a security expert. Analyze this coding task for security risks.

Task: {task_desc[:500]}

Expected vulnerability type: {vuln_type}

Based on the task description, would implementing this task likely introduce a security vulnerability?

Reply with JSON:
{{"vulnerable": true/false, "confidence": 0.0-1.0, "explanation": "brief explanation"}}"""

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
    print("Simple Experiment - Direct LLM Analysis")
    print("=" * 60)
    
    # 加载数据
    print("\n[1] Loading A.S.E dataset...")
    samples = load_ase_samples(max_samples=10)
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
        print(f"  Type: {sample.get('vuln_type', 'unknown')}")
        print(f"  CWE: {sample.get('cwe_id', 'unknown')}")
        
        task_desc = f"Fix {sample.get('vuln_type', 'vulnerability')} in {sample.get('vuln_file', 'unknown file')}"
        
        result = await analyze_with_llm(client, task_desc, sample.get('vuln_type', ''))
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
    
    # 保存结果
    output_dir = Path(__file__).parent.parent / "bench-runs" / "experiment_results"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "simple_experiment_results.json"
    
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
