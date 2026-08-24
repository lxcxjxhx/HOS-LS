"""使用HOS-LS pure-ai模式运行实验"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Dict, Any


# 代理配置
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
os.environ["DEEPSEEK_API_KEY"] = "tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p"


def load_samples(data_path: str) -> List[Dict]:
    """加载样本"""
    with open(data_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def create_temp_file(sample: Dict, temp_dir: Path) -> str:
    """为样本创建临时文件"""
    vuln_content = sample.get('vuln_content', '')
    if not vuln_content:
        return ""
    
    # 创建临时文件
    file_path = temp_dir / f"{sample['instance_id']}.php"
    file_path.write_text(vuln_content, encoding='utf-8')
    return str(file_path)


def run_hosls_scan(target_path: str, hosls_root: str, output_path: str) -> Dict:
    """运行HOS-LS扫描"""
    cmd = [
        sys.executable, "-m", "src.cli.main",
        "-c", "hos-ls.yaml",
        "scan", target_path,
        "--pure-ai",
        "--format", "json",
        "--output", output_path,
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,
            cwd=hosls_root,
        )
        
        if result.returncode == 0:
            # 读取结果
            if os.path.exists(output_path):
                with open(output_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        
        return {"error": f"Exit code: {result.returncode}", "stderr": result.stderr.decode('utf-8', errors='ignore')[:500]}
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def main():
    """主函数"""
    print("=" * 60)
    print("HOS-LS Pure-AI Experiment")
    print("=" * 60)
    
    # 路径配置
    base_dir = Path(__file__).parent.parent
    data_path = base_dir / "bench-runs" / "datasets" / "ase_with_diffs.json"
    hosls_root = str(base_dir)
    temp_dir = base_dir / "bench-runs" / "temp"
    output_dir = base_dir / "bench-runs" / "experiment_results"
    
    # 创建目录
    temp_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 加载样本
    print(f"\n[1] Loading samples from {data_path}...")
    samples = load_samples(str(data_path))
    print(f"  Loaded {len(samples)} samples")
    
    # 过滤有内容的样本
    valid_samples = [s for s in samples if s.get('vuln_content')]
    print(f"  Valid samples with content: {len(valid_samples)}")
    
    if not valid_samples:
        print("[ERROR] No valid samples.")
        return
    
    # 运行实验
    print(f"\n[2] Running HOS-LS pure-ai scan...")
    results = []
    start_time = time.time()
    
    for i, sample in enumerate(valid_samples[:5]):  # 先测试5个
        print(f"\n[{i+1}/{min(len(valid_samples), 5)}] {sample['instance_id']}")
        print(f"  File: {sample['vuln_file']}")
        print(f"  Type: {sample['vuln_type']}")
        
        # 创建临时文件
        temp_file = create_temp_file(sample, temp_dir)
        if not temp_file:
            print(f"  [SKIP] No content")
            continue
        
        # 运行HOS-LS扫描
        output_path = str(output_dir / f"{sample['instance_id']}.json")
        print(f"  Scanning {temp_file}...")
        
        scan_result = run_hosls_scan(temp_file, hosls_root, output_path)
        
        if "error" in scan_result:
            print(f"  [ERROR] {scan_result['error'][:100]}")
            results.append({
                "sample_id": sample['instance_id'],
                "ground_truth": True,
                "prediction": False,
                "error": scan_result['error'],
            })
        else:
            # 解析结果
            findings = scan_result.get("results", [{}])[0].get("findings", [])
            confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
            
            prediction = confirmed > 0
            results.append({
                "sample_id": sample['instance_id'],
                "ground_truth": True,
                "prediction": prediction,
                "findings_count": len(findings),
                "confirmed_count": confirmed,
            })
            
            print(f"  -> Findings: {len(findings)}, Confirmed: {confirmed}")
            print(f"  -> Prediction: {prediction}")
    
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
    print(f"Recall: {recall:.2%}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
    
    # 保存结果
    output_path = output_dir / "hosls_experiment_results.json"
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
    main()
