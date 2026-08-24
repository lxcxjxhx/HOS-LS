"""调试LLM响应"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"

from src.direct_llm import DirectLLM
from src.data_adapter import DREAAdapter


def main():
    base_dir = Path(__file__).parent.parent
    
    llm = DirectLLM(
        api_key="tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p",
        base_url="https://token-plan-cn.xiaomimimo.com/v1",
        model="mimo-v2.5-pro",
    )
    
    # 加载一个样本
    drea_adapter = DREAAdapter(str(base_dir.parent / "drea" / "data" / "repopairbench_100.jsonl"))
    samples = drea_adapter.load_samples(max_samples=1)
    
    if not samples:
        print("No samples loaded")
        return
    
    sample = samples[0]
    print(f"Sample: {sample.sample_id}")
    print(f"Type: {sample.vuln_type}")
    print(f"CWE: {sample.cwe_id}")
    print()
    
    # 测试分析
    result = llm.analyze_vulnerability(
        code=sample.code_before,
        vuln_type=sample.vuln_type,
        cwe_id=sample.cwe_id,
        code_after=sample.code_after,
    )
    
    print("Result:")
    print(result)


if __name__ == "__main__":
    main()
