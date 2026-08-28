#!/usr/bin/env python3
"""dataset_manager.py — 基准数据集统一管理（不污染源码）

管理的数据集：
- SecureVibeBench（105 大仓库、多文件编辑、静态+动态 oracle）
- A.S.E（120 仓库级安全实例，4 类 Web 漏洞）
- VulnGym（408 entries、184 advisories、23 repos）
- AI patch 数据（多 agent 生成的 vulnerable/secure patches）

所有仓库数据通过 .gitignore 排除，只跟踪 manifest 和描述文件。
"""

import json
import os
from pathlib import Path

BASE = Path(r"C:\1AAA-PROJECT\BOS\BOS-GIT")  # 项目根目录
DATASETS = BASE / "HOS-LS-paper" / "bench-runs" / "hos-ls" / "bench-runs" / "datasets"
EVAL = BASE / "HOS-LS-paper" / "bench-runs" / "hosls-eval"
REPORTS = EVAL / "reports"

# ---- SecureVibeBench ----

SVB_MANIFEST = EVAL / "svb_manifest.json"


def svb_inventory():
    """SVB 数据清单"""
    repos_dir = DATASETS / "svb_repos"
    if not repos_dir.exists():
        return {"error": "SVB repos not found", "path": str(repos_dir)}
    repos = [d.name for d in repos_dir.iterdir() if d.is_dir()]
    # 尝试从评测目录找 manifest
    eval_manifests = list((DATASETS / "SecureVibeBench").rglob("manifest*.json"))
    return {
        "repos": len(repos),
        "repo_list": sorted(repos)[:20],
        "eval_manifests": len(eval_manifests),
        "eval_manifest_paths": [str(p.relative_to(DATASETS)) for p in eval_manifests[:5]],
    }


# ---- A.S.E ----

ASE_MANIFEST = EVAL / "ase100-manifest.json"
ASE_SAMPLES = EVAL / "vuln"
ASE_PATCHED = EVAL / "patched"


def ase_inventory():
    """ASE 数据清单"""
    man = json.load(open(ASE_MANIFEST, encoding="utf-8-sig"))
    pairs = man.get("pairs", man)
    # 从文件名推断 CWE/语言
    vuln_files = [f for f in os.listdir(ASE_SAMPLES) if f.endswith(".py")]
    patched_files = [f for f in os.listdir(ASE_PATCHED) if f.endswith(".py")]
    return {
        "pairs": len(pairs),
        "vuln_files": len(vuln_files),
        "patched_files": len(patched_files),
        "sample_ids": [p["id"] if isinstance(p, dict) else p for p in pairs[:10]],
    }


# ---- 分层样本生成（40-60 个止损实验）----

def stratified_samples(n=50):
    """从 ASE 生成 n 个分层样本（按 CWE + 语言），用于止损实验。

    返回 list of {"id", "vuln", "patched", "cwe", "language"}
    """
    man = json.load(open(ASE_MANIFEST, encoding="utf-8-sig"))
    pairs = man["pairs"]

    # 推断 CWE 和语言
    def classify(pid):
        pid_lower = pid.lower()
        if "sqli" in pid_lower or "sql" in pid_lower:
            cwe, lang = "CWE-89", "php"
        elif "command" in pid_lower or "cmd" in pid_lower:
            cwe, lang = "CWE-78", "python"
        elif "xss" in pid_lower:
            cwe, lang = "CWE-79", "javascript"
        elif "path" in pid_lower or "traversal" in pid_lower:
            cwe, lang = "CWE-22", "python"
        elif "open" in pid_lower or "redirect" in pid_lower:
            cwe, lang = "CWE-601", "python"
        elif "xxe" in pid_lower:
            cwe, lang = "CWE-611", "python"
        elif "deser" in pid_lower:
            cwe, lang = "CWE-502", "java"
        elif "ssrf" in pid_lower:
            cwe, lang = "CWE-918", "python"
        elif "rce" in pid_lower:
            cwe, lang = "CWE-94", "python"
        elif ".php" in pid_lower:
            cwe, lang = "CWE-89", "php"
        elif ".go" in pid_lower:
            cwe, lang = "CWE-78", "go"
        elif ".java" in pid_lower:
            cwe, lang = "CWE-502", "java"
        elif ".js" in pid_lower:
            cwe, lang = "CWE-79", "javascript"
        else:
            cwe, lang = "CWE-unknown", "unknown"
        return cwe, lang

    # 按 CWE 分层
    from collections import defaultdict
    buckets = defaultdict(list)
    for p in pairs:
        pid = p["id"] if isinstance(p, dict) else p
        cwe, lang = classify(pid)
        buckets[(cwe, lang)].append(p)

    # 每层取 ceil(n / 层数)
    n_buckets = len(buckets)
    per_bucket = max(1, n // n_buckets)

    result = []
    for (cwe, lang), items in sorted(buckets.items()):
        for p in items[:per_bucket]:
            if isinstance(p, dict):
                result.append({
                    "id": p["id"],
                    "vuln": p["vuln"],
                    "patched": p["patched"],
                    "cwe": cwe,
                    "language": lang,
                })
            else:
                result.append({"id": p, "cwe": cwe, "language": lang})
        if len(result) >= n:
            break

    return result


def save_stratified_samples(n=50):
    """生成分层样本并保存到 reports/"""
    samples = stratified_samples(n)
    out = REPORTS / f"_stratified_{n}_samples.json"
    json.dump(samples, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    # 生成 vuln 和 patched 文件列表，供 ai_patch_eval.py scan 使用
    vuln_list = [s["vuln"] for s in samples if "vuln" in s]
    patched_list = [s["patched"] for s in samples if "patched" in s]
    json.dump(vuln_list, open(REPORTS / f"_stratified_{n}_vuln_list.json", "w"), indent=1)
    json.dump(patched_list, open(REPORTS / f"_stratified_{n}_patched_list.json", "w"), indent=1)
    # 打印统计
    from collections import Counter
    cwe_count = Counter(s["cwe"] for s in samples)
    lang_count = Counter(s.get("language", "?") for s in samples)
    print(f"Stratified samples: {len(samples)}")
    print(f"  CWE: {dict(cwe_count)}")
    print(f"  Lang: {dict(lang_count)}")
    print(f"  Output: {out}")
    return samples


def vulngym_inventory():
    """VulnGym 数据清单"""
    vg_dir = DATASETS / "VulnGym"
    if not vg_dir.exists():
        return {"error": "VulnGym not found"}
    entries_file = vg_dir / "data" / "entries.jsonl"
    reports_file = vg_dir / "data" / "reports.jsonl"
    entries, reports = [], []
    if entries_file.exists():
        for line in open(entries_file, encoding="utf-8").readlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    if reports_file.exists():
        for line in open(reports_file, encoding="utf-8").readlines():
            line = line.strip()
            if line:
                reports.append(json.loads(line))
    repos = set(e.get("repo_url", "") for e in entries)
    projects = set(e.get("project", "") for e in entries if e.get("project"))
    cwe_types = set()
    for e in entries:
        vc = e.get("vuln_category_l2") or e.get("vuln_category_l1") or ""
        if vc:
            cwe_types.add(vc)
    return {
        "entries": len(entries),
        "reports": len(reports),
        "repos": len(repos),
        "projects": len(projects),
        "cwe_types": sorted(cwe_types)[:20],
        "sample_entry": {k: entries[0][k] for k in ("entry_id", "repo_url", "project", "vuln_category_l1", "vuln_category_l2")} if entries else {},
    }


def full_inventory():
    """输出完整数据集报告"""
    svb = svb_inventory()
    ase = ase_inventory()
    vg = vulngym_inventory()
    print("=" * 60)
    print("  数据集完整清单")
    print("=" * 60)
    print(f"\n📦 SecureVibeBench: {svb.get('repos', '?')} 仓库")
    print(f"📦 A.S.E: {ase.get('pairs', '?')} 对 (vuln, patched)")
    print(f"📦 VulnGym: {vg.get('entries', '?')} entries, "
          f"{vg.get('reports', '?')} advisories, "
          f"{vg.get('repos', '?')} repos, "
          f"{vg.get('projects', '?')} projects")
    print(f"\n{"=" * 60}")
    return {"svb": svb, "ase": ase, "vulngym": vg}


# ---- CLI ----

def main():
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "inventory"

    if cmd == "inventory":
        full_inventory()

    elif cmd == "stratified":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        save_stratified_samples(n)

    else:
        print(__doc__)


if __name__ == "__main__":
    main()
