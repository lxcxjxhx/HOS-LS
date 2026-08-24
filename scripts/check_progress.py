"""检查下载进度"""

import json
from pathlib import Path

data_path = Path(__file__).parent.parent / "bench-runs" / "datasets" / "ase_with_diffs.json"

if data_path.exists():
    with open(data_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"Total samples: {len(data)}")
    print(f"Samples with diff: {sum(1 for d in data if d.get('diff'))}")
    print(f"Samples with vuln_content: {sum(1 for d in data if d.get('vuln_content'))}")
    print(f"Unique repos: {len(set(d['repo'] for d in data))}")
    
    # 按仓库统计
    repo_counts = {}
    for d in data:
        repo = d['repo']
        repo_counts[repo] = repo_counts.get(repo, 0) + 1
    
    print(f"\nTop 10 repos:")
    for repo, count in sorted(repo_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {repo}: {count} samples")
else:
    print("No data file found")
