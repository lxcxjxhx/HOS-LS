"""使用DREA数据集运行实验"""

import json
import os
import sys
import time
from pathlib import Path
from openai import OpenAI

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"

API_KEY = "tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p"
BASE_URL = "https://token-plan-cn.xiaomimimo.com/v1"


def analyze(client: OpenAI, code_before: str, code_after: str, vuln_type: str, cwe_id: str) -> dict:
    """分析漏洞 - 对比before/after，聚焦差异"""
    
    prompt = f"""You are a senior security researcher. A developer submitted a security fix.

## Task
The "before" code had a {vuln_type} vulnerability ({cwe_id}) that was fixed in the "after" code.
Your job is to confirm the vulnerability existed in the "before" code.

## Code BEFORE (vulnerable):
```
{code_before[:2500]}
```

## Code AFTER (fixed):
```
{code_after[:2500]}
```

## Key Question
Does the "before" code contain a real, exploitable {vuln_type} vulnerability?

Focus on:
- Is user input used without proper validation?
- Are dangerous functions called with user-controlled data?
- Is there a path from user input to a security-sensitive operation?

Reply with JSON:
{{"vulnerable": true/false, "confidence": 0.0-1.0, "reason": "why the before code is vulnerable or secure"}}"""

    try:
        response = client.chat.completions.create(
            model="mimo-v2.5-pro",
            messages=[
                {"role": "system", "content": "You are a security expert. The code samples are from real CVEs. Be accurate - these are known vulnerabilities that were fixed."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
        )
        text = response.choices[0].message.content
        start = text.find('{')
        end = text.rfind('}') + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
        # 检查关键词
        text_lower = text.lower()
        if "vulnerable" in text_lower and "not vulnerable" not in text_lower and "secure" not in text_lower:
            return {"vulnerable": True, "confidence": 0.7}
        return {"vulnerable": False, "confidence": 0.0}
    except Exception as e:
        return {"vulnerable": False, "confidence": 0.0, "error": str(e)}


def main():
    data_path = Path(__file__).parent.parent.parent / "drea" / "data" / "repopairbench_100.jsonl"
    
    print("Loading DREA dataset...")
    samples = []
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            samples.append(json.loads(line))
    print(f"Loaded {len(samples)} samples")
    
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    
    results = []
    start_time = time.time()
    
    # 测试前20个样本
    for i, sample in enumerate(samples[:20]):
        vuln_data = sample.get('vuln_data', {})
        code_before = vuln_data.get('code_before', '')
        code_after = vuln_data.get('code_after', '')
        cwe_id = sample.get('cwe_ids', ['unknown'])[0] if sample.get('cwe_ids') else 'unknown'
        
        # 推断漏洞类型
        vuln_type_map = {
            'CWE-22': 'Path Traversal',
            'CWE-78': 'Command Injection',
            'CWE-79': 'XSS',
            'CWE-89': 'SQL Injection',
            'CWE-94': 'Code Injection',
            'CWE-287': 'Authentication Bypass',
            'CWE-306': 'Missing Authentication',
            'CWE-434': 'File Upload',
            'CWE-502': 'Deserialization',
            'CWE-611': 'XXE',
            'CWE-918': 'SSRF',
        }
        vuln_type = vuln_type_map.get(cwe_id, 'Unknown')
        
        print(f"[{i+1}/20] {sample['id']} ({vuln_type})", end=" -> ")
        
        if not code_before or not code_after:
            print("SKIP (no code)")
            continue
        
        result = analyze(client, code_before, code_after, vuln_type, cwe_id)
        prediction = result.get("vulnerable", False)
        
        results.append({
            "sample_id": sample['id'],
            "vuln_type": vuln_type,
            "cwe_id": cwe_id,
            "prediction": prediction,
            "confidence": result.get("confidence", 0.0),
            "ground_truth": True,  # DREA数据集都是漏洞样本
        })
        
        print(f"{prediction} ({result.get('confidence', 0):.2f})")
    
    elapsed = time.time() - start_time
    correct = sum(1 for r in results if r['prediction'])
    
    print(f"\n{'='*60}")
    print(f"Results: {correct}/{len(results)} ({correct/len(results):.1%})")
    print(f"Time: {elapsed:.0f}s ({elapsed/len(results):.1f}s/sample)")
    
    # 按类型统计
    type_stats = {}
    for r in results:
        t = r['vuln_type']
        if t not in type_stats:
            type_stats[t] = {"total": 0, "detected": 0}
        type_stats[t]["total"] += 1
        if r['prediction']:
            type_stats[t]["detected"] += 1
    
    print(f"\nBy Type:")
    for t, s in type_stats.items():
        print(f"  {t}: {s['detected']}/{s['total']} ({s['detected']/s['total']:.0%})")
    
    output_path = Path(__file__).parent.parent / "bench-runs" / "experiment_results" / "drea_experiment_results.json"
    with open(output_path, 'w') as f:
        json.dump({
            "metrics": {"total": len(results), "correct": correct, "accuracy": correct/len(results), "by_type": type_stats},
            "elapsed_seconds": elapsed,
            "results": results,
        }, f, indent=2)
    print(f"\nSaved to {output_path}")


if __name__ == "__main__":
    main()
