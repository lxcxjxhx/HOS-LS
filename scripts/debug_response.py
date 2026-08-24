"""调试LLM响应"""

import json
import os
from pathlib import Path
from openai import OpenAI

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"

API_KEY = "tp-ctl20tpyggqekyerc4lel07djw5uqs0eibwb6a7sujnjmc8p"
BASE_URL = "https://token-plan-cn.xiaomimimo.com/v1"


def main():
    data_path = Path(__file__).parent.parent.parent / "drea" / "data" / "repopairbench_100.jsonl"
    
    with open(data_path, 'r', encoding='utf-8') as f:
        samples = [json.loads(line) for line in f]
    
    # 测试第一个样本
    s = samples[0]
    vuln_data = s.get('vuln_data', {})
    code_before = vuln_data.get('code_before', '')[:1500]
    code_after = vuln_data.get('code_after', '')[:1500]
    
    print(f"Sample: {s['id']}")
    print(f"CWE: {s.get('cwe_ids', [])}")
    print()
    
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    
    prompt = f"""Is the "before" code vulnerable to path traversal?

Before:
```
{code_before}
```

After (fixed):
```
{code_after}
```

Reply: vulnerable or secure?"""
    
    response = client.chat.completions.create(
        model="mimo-v2.5-pro",
        messages=[
            {"role": "system", "content": "You are a security expert."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=300,
    )
    
    print("Response:")
    print(response.choices[0].message.content)


if __name__ == "__main__":
    main()
