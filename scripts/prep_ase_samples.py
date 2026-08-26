"""prep_ase_samples.py — A.S.E 27 实例清洗（行号剥离 + base_commit 完整文件拉取）。

输入：bench-runs/datasets/ase_with_vuln_code.json（27 条）、ase_with_diffs.json（6 条，含 base_commit）
输出：bench-runs/datasets/ase_samples/{instance_id}.{ext} + manifest.json
用法：python scripts/prep_ase_samples.py [--github-token <token>]
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS = os.path.join(BASE, "bench-runs", "datasets")
OUT = os.path.join(DATASETS, "ase_samples")

EXT = {"php": ".php", "python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java", "go": ".go"}
LINE_PREFIX = re.compile(r"^\s*\d{1,5}\s+(?=\S)", re.M)
GITHUB_TOKEN = ""


def fetch_full_file(repo, path, commit):
    if not GITHUB_TOKEN:
        return None
    import requests
    import urllib3
    urllib3.disable_warnings()
    r = requests.get(f"https://api.github.com/repos/{repo}/contents/{path}",
                     params={"ref": commit},
                     headers={"Authorization": f"Bearer {GITHUB_TOKEN}",
                              "Accept": "application/vnd.github.raw",
                              "User-Agent": "hos-ls-eval"},
                     verify=False, timeout=90)
    return r.text if r.status_code == 200 else None


def strip_line_numbers(code):
    return LINE_PREFIX.sub("", code)


def main():
    global GITHUB_TOKEN
    if "--github-token" in sys.argv:
        GITHUB_TOKEN = sys.argv[sys.argv.index("--github-token") + 1]
    os.makedirs(OUT, exist_ok=True)
    vuln = json.load(open(os.path.join(DATASETS, "ase_with_vuln_code.json"), encoding="utf-8-sig"))
    diffs = {x["instance_id"]: x for x in
             json.load(open(os.path.join(DATASETS, "ase_with_diffs.json"), encoding="utf-8-sig"))}
    manifest = []
    for x in vuln:
        iid = x["instance_id"]
        ext = EXT.get(x.get("language", "php"), ".php")
        code, src = None, ""
        if iid in diffs and diffs[iid].get("base_commit"):
            full = fetch_full_file(x.get("repo", ""), x.get("vuln_file", ""), diffs[iid]["base_commit"])
            if full and len(full) > 200:
                code, src = full, "full@commit"
        if code is None:
            code = strip_line_numbers(x.get("vuln_code", ""))
            src = "excerpt"
        code = code.strip()
        with open(os.path.join(OUT, iid + ext), "w", encoding="utf-8") as f:
            f.write(code)
        manifest.append({
            "instance_id": iid, "repo": x.get("repo", ""), "vuln_file": x.get("vuln_file", ""),
            "vuln_lines": x.get("vuln_lines", []), "language": x.get("language", "php"),
            "vuln_type": x.get("vuln_type", ""), "cwe_id": x.get("cwe_id", ""),
            "source": src, "code_file": iid + ext, "lines": code.count("\n") + 1,
            "task_desc": diffs[iid].get("task_desc", "") if iid in diffs else "",
            "base_commit": diffs[iid].get("base_commit", "") if iid in diffs else "",
        })
    json.dump(manifest, open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(f"[prep] {len(manifest)} samples -> {OUT}")


if __name__ == "__main__":
    main()
