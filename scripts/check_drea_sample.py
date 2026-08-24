"""检查DREA样本"""

import json
from pathlib import Path

data_path = Path(__file__).parent.parent.parent / "drea" / "data" / "repopairbench_100.jsonl"

with open(data_path, 'r', encoding='utf-8') as f:
    samples = [json.loads(line) for line in f]

# 检查第一个样本
s = samples[0]
print(f"ID: {s['id']}")
print(f"Project: {s['project_name']}")
print(f"CWE: {s.get('cwe_ids', [])}")
print()

vuln_data = s.get('vuln_data', {})
print("Code BEFORE (vulnerable):")
print(vuln_data.get('code_before', '')[:500])
print()
print("Code AFTER (fixed):")
print(vuln_data.get('code_after', '')[:500])
