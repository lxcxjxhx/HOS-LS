"""克隆A.S.E数据集中的仓库并获取真实diff"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

# 代理配置
os.environ["HTTP_PROXY"] = "http://127.0.0.1:7897"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
os.environ["GIT_SSL_BACKEND"] = "openssl"
os.environ["GIT_CONFIG_NOSYSTEM"] = "1"

# 创建临时gitconfig文件
GITCONFIG_PATH = Path(__file__).parent.parent / ".gitconfig_proxy"
GITCONFIG_PATH.write_text("""[http]
    proxy = http://127.0.0.1:7897
[https]
    proxy = http://127.0.0.1:7897
[http]
    sslBackend = openssl
""")
os.environ["GIT_CONFIG_GLOBAL"] = str(GITCONFIG_PATH)

# Git代理配置
GIT_PROXY_ARGS = [
    "-c", "http.proxy=http://127.0.0.1:7897",
    "-c", "https.proxy=http://127.0.0.1:7897",
    "-c", "http.sslBackend=openssl",
]


def load_ase_samples(data_path: str, max_samples: int = 20) -> List[Dict]:
    """加载A.S.E数据集"""
    samples = []
    with open(data_path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if i >= max_samples:
                break
            samples.append(json.loads(line))
    return samples


def clone_repo(repo_url: str, target_dir: str, depth: int = 1) -> bool:
    """克隆Git仓库"""
    # 如果目录已存在，跳过克隆
    if os.path.exists(target_dir):
        print(f"  Repo already exists, skipping clone")
        return True
    
    cmd = ["git"] + GIT_PROXY_ARGS + ["clone", "--depth", str(depth), repo_url, target_dir]
    print(f"  Cloning: {repo_url}")
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(f"  [ERROR] Clone failed: {result.stderr[:200]}")
        return False
    return True


def fetch_commit(repo_dir: str, commit_hash: str) -> bool:
    """获取特定commit"""
    try:
        # 先检查commit是否存在
        cmd = ["git", "cat-file", "-t", commit_hash]
        result = subprocess.run(cmd, capture_output=True, cwd=repo_dir, timeout=10)
        if result.returncode == 0:
            return True
        
        # 如果不存在，尝试fetch
        cmd = ["git"] + GIT_PROXY_ARGS + ["fetch", "origin", commit_hash]
        result = subprocess.run(cmd, capture_output=True, cwd=repo_dir, timeout=60)
        return result.returncode == 0
    except Exception as e:
        print(f"  [WARN] Failed to fetch commit: {e}")
        return False


def get_diff_for_file(repo_dir: str, commit_hash: str, file_path: str) -> Optional[str]:
    """获取指定文件在commit的diff"""
    try:
        # 确保commit存在
        if not fetch_commit(repo_dir, commit_hash):
            print(f"  [WARN] Commit not found: {commit_hash[:8]}")
            return None
        
        # 只获取指定文件的diff
        cmd = ["git", "show", "--format=%H", commit_hash, "--", file_path]
        result = subprocess.run(cmd, capture_output=True, cwd=repo_dir, timeout=30)
        if result.returncode == 0 and result.stdout:
            diff = result.stdout.decode('utf-8', errors='ignore')
            # 限制diff长度
            if len(diff) > 50000:
                diff = diff[:50000] + "\n... [truncated]"
            return diff
        
        # 如果文件不存在于该commit，尝试获取文件内容
        cmd = ["git", "show", f"{commit_hash}:{file_path}"]
        result = subprocess.run(cmd, capture_output=True, cwd=repo_dir, timeout=30)
        if result.returncode == 0 and result.stdout:
            content = result.stdout.decode('utf-8', errors='ignore')
            return f"[File Content at {commit_hash}]\n{content[:10000]}"
    except Exception as e:
        print(f"  [ERROR] Failed to get diff: {e}")
    return None


def get_file_content_at_commit(repo_dir: str, commit_hash: str, file_path: str) -> Optional[str]:
    """获取指定commit的文件内容"""
    try:
        cmd = ["git", "show", f"{commit_hash}:{file_path}"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_dir, timeout=30)
        if result.returncode == 0:
            return result.stdout
    except Exception as e:
        print(f"  [ERROR] Failed to get file content: {e}")
    return None


def process_ase_samples(
    data_path: str,
    repos_dir: str,
    max_samples: int = 10,
    max_repos: int = 5,
) -> List[Dict]:
    """处理A.S.E样本，克隆仓库并获取diff"""
    samples = load_ase_samples(data_path, max_samples)
    results = []
    cloned_repos = set()
    
    for i, sample in enumerate(samples):
        print(f"\n[{i+1}/{len(samples)}] {sample['instance_id']}")
        
        repo = sample['repo']
        base_commit = sample['base_commit']
        vuln_file = sample['vuln_file']
        
        # 克隆仓库（如果还没克隆）
        repo_dir = os.path.join(repos_dir, repo.replace("/", "_"))
        
        if repo not in cloned_repos:
            if len(cloned_repos) >= max_repos:
                print(f"  [SKIP] Max repos reached ({max_repos})")
                continue
            
            repo_url = f"https://github.com/{repo}.git"
            if clone_repo(repo_url, repo_dir):
                cloned_repos.add(repo)
            else:
                continue
        
        # 获取diff（只针对漏洞文件）
        diff = get_diff_for_file(repo_dir, base_commit, vuln_file)
        
        # 获取漏洞文件内容
        vuln_content = get_file_content_at_commit(repo_dir, base_commit, vuln_file)
        
        results.append({
            "instance_id": sample['instance_id'],
            "repo": repo,
            "base_commit": base_commit,
            "vuln_file": vuln_file,
            "vuln_lines": sample['vuln_lines'],
            "language": sample['language'],
            "vuln_type": sample['vuln_type'],
            "cwe_id": sample['cwe_id'],
            "diff": diff[:2000] if diff else "",  # 限制diff长度
            "vuln_content": vuln_content[:1000] if vuln_content else "",
            "task_desc": f"Fix {sample['vuln_type']} in {vuln_file}",
        })
        
        print(f"  -> Diff length: {len(diff) if diff else 0}")
        print(f"  -> Vuln content length: {len(vuln_content) if vuln_content else 0}")
    
    return results


def main():
    """主函数"""
    print("=" * 60)
    print("Clone A.S.E Repos and Get Real Diffs")
    print("=" * 60)
    
    # 路径配置
    base_dir = Path(__file__).parent.parent
    data_path = base_dir / "bench-runs" / "datasets" / "AICGSecEval_hf" / "data" / "static_eval.jsonl"
    repos_dir = base_dir / "bench-runs" / "datasets" / "ase_repos"
    output_path = base_dir / "bench-runs" / "datasets" / "ase_with_diffs.json"
    
    # 创建仓库目录
    repos_dir.mkdir(parents=True, exist_ok=True)
    
    # 处理样本
    print(f"\nData path: {data_path}")
    print(f"Repos dir: {repos_dir}")
    
    results = process_ase_samples(
        str(data_path),
        str(repos_dir),
        max_samples=10,
        max_repos=3,  # 只克隆3个仓库
    )
    
    # 保存结果
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*60}")
    print(f"Results saved to: {output_path}")
    print(f"Total samples with diffs: {len(results)}")
    print(f"Repos cloned: {len(set(r['repo'] for r in results))}")


if __name__ == "__main__":
    main()
