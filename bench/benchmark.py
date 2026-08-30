"""HOS-LS 评测分数卡工具

在标准评测集（bench-runs/hosls-eval/{vuln,patched}）上以 pure-AI 模式扫描，
产出可复现的分数卡 JSON：文件级 CONFIRMED 召回、any-finding、patched 误报率、
总耗时、总输入/输出 token（来自报告 token_records）。

用法:
    python -m bench.benchmark --groups vuln,patched --limit 20 --workers 3 --tag my-run
    python -m bench.benchmark --vuln-dir <绝对路径> --patched-dir <绝对路径> --limit 100

输出:
    bench/artifacts/<tag>/{vuln,patched}-results.json   每个文件的原始指标
    bench/artifacts/<tag>/scorecard.json                汇总分数卡

实现说明（Windows 沙箱兼容）：
- 使用 ThreadPoolExecutor 而非 ProcessPoolExecutor（后者依赖 multiprocessing 命名管道）。
- 子进程 stdout/stderr 重定向到文件句柄，stdin 用 DEVNULL，全程不创建管道。
"""

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVAL_BASE = REPO_ROOT.parent / "hosls-eval"  # bench-runs/hosls-eval


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def summarize_report(report):
    """从单文件扫描报告提取指标。"""
    rec = {
        "ok": False,
        "findings": 0,
        "confirmed": 0,
        "severities_confirmed": [],
        "statuses": {},
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "duration": 0.0,
        "err": "",
    }
    if not report:
        rec["err"] = "no report"
        return rec

    results = report.get("results") or []
    if not results:
        rec["err"] = "no results in report"
        return rec

    for fr in results:
        rec["duration"] = float(fr.get("duration", 0.0))
        token_records = fr.get("token_records") or []
        for t in token_records:
            if not isinstance(t, dict):
                continue
            rec["prompt_tokens"] += int(t.get("prompt_tokens", 0) or 0)
            rec["completion_tokens"] += int(t.get("completion_tokens", 0) or 0)
            rec["total_tokens"] += int(t.get("total_tokens", 0) or 0)
        for f in fr.get("findings", []):
            rec["findings"] += 1
            status = str(f.get("status", "") or "").upper()
            rec["statuses"][status] = rec["statuses"].get(status, 0) + 1
            if status == "CONFIRMED":
                rec["confirmed"] += 1
                sev = str(f.get("severity", ""))
                if sev:
                    rec["severities_confirmed"].append(sev)

    rec["ok"] = True
    return rec


def scan_one(args):
    """扫描单个文件（独立子进程 + 文件句柄重定向，避免管道与命名管道）。"""
    hosls_root, target, out, timeout = args
    log_file = out + ".run.log"
    try:
        with open(log_file, "w", encoding="utf-8", errors="replace") as logf:
            r = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.cli.main",
                    "-c",
                    "hos-ls.yaml",
                    "scan",
                    target,
                    "--pure-ai",
                    "--output",
                    out,
                ],
                stdin=subprocess.DEVNULL,
                stdout=logf,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                cwd=hosls_root,
            )
        report = _read_json(out)
        rec = summarize_report(report)
        if not rec["ok"] and r.returncode != 0:
            try:
                rec["err"] = open(log_file, encoding="utf-8", errors="replace").read()[-200:]
            except Exception:
                rec["err"] = f"exit={r.returncode}"
        return rec
    except subprocess.TimeoutExpired:
        return {"ok": False, "findings": 0, "confirmed": 0, "severities_confirmed": [],
                "statuses": {}, "prompt_tokens": 0, "completion_tokens": 0,
                "total_tokens": 0, "duration": 0.0, "err": "timeout"}
    except Exception as e:
        return {"ok": False, "findings": 0, "confirmed": 0, "severities_confirmed": [],
                "statuses": {}, "prompt_tokens": 0, "completion_tokens": 0,
                "total_tokens": 0, "duration": 0.0, "err": str(e)[:120]}


def run_group(hosls_root, files, tag, group, workers, out_root):
    outdir = out_root / tag
    outdir.mkdir(parents=True, exist_ok=True)
    jobs = [
        (str(hosls_root), os.path.abspath(f), str(outdir / f"{os.path.basename(f)}.json"), 400)
        for f in files
    ]
    results = {}
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_one, j): os.path.basename(j[1]) for j in jobs}
        for i, fut in enumerate(as_completed(futs), 1):
            name = futs[fut]
            results[name] = fut.result()
            if not results[name].get("ok") and results[name].get("err"):
                print(f"  [{group}] {name}: ERR {results[name]['err'][:60]}", flush=True)
            if (i % 5 == 0) or i == len(files):
                print(
                    f"  [{group}] {i}/{len(files)} 累计 confirmed-hit "
                    f"{sum(1 for v in results.values() if v.get('confirmed', 0) > 0)} "
                    f"({time.time() - t0:.0f}s)",
                    flush=True,
                )

    n = len(files) or 1
    hits = sum(1 for v in results.values() if v.get("confirmed", 0) > 0)
    anyf = sum(1 for v in results.values() if v.get("findings", 0) > 0)
    total_prompt = sum(v.get("prompt_tokens", 0) for v in results.values())
    total_completion = sum(v.get("completion_tokens", 0) for v in results.values())
    total_tokens = sum(v.get("total_tokens", 0) for v in results.values())
    total_findings = sum(v.get("findings", 0) for v in results.values())
    total_confirmed = sum(v.get("confirmed", 0) for v in results.values())
    wall = time.time() - t0
    duration_sum = sum(v.get("duration", 0.0) for v in results.values())

    group_result = {
        "group": group,
        "files": n,
        "confirmed_hit_files": hits,
        "confirmed_hit_rate": round(hits / n * 100, 1),
        "any_finding_files": anyf,
        "any_finding_rate": round(anyf / n * 100, 1),
        "total_findings": total_findings,
        "total_confirmed": total_confirmed,
        "wall_time_s": round(wall, 1),
        "sum_report_duration_s": round(duration_sum, 1),
        "prompt_tokens": total_prompt,
        "completion_tokens": total_completion,
        "total_tokens": total_tokens,
        "avg_prompt_tokens_per_file": round(total_prompt / n, 1) if n else 0,
        "avg_total_tokens_per_file": round(total_tokens / n, 1) if n else 0,
        "avg_wall_s_per_file": round(wall / n, 1) if n else 0,
        "errors": sum(1 for v in results.values() if not v.get("ok")),
    }
    with open(outdir / f"{group}-results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    return group_result, results


def main():
    ap = argparse.ArgumentParser(description="HOS-LS 评测分数卡")
    ap.add_argument("--vuln-dir", default=str(DEFAULT_EVAL_BASE / "vuln"))
    ap.add_argument("--patched-dir", default=str(DEFAULT_EVAL_BASE / "patched"))
    ap.add_argument("--groups", default="vuln", help="逗号分隔: vuln,patched")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--tag", default=time.strftime("run-%m%d-%H%M"))
    ap.add_argument("--timeout", type=int, default=400)
    args = ap.parse_args()

    groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    out_root = REPO_ROOT / "bench" / "artifacts"
    (out_root / args.tag).mkdir(parents=True, exist_ok=True)

    scorecard = {"tag": args.tag, "groups": {}, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    for group in groups:
        base = args.vuln_dir if group == "vuln" else args.patched_dir
        files = sorted(glob.glob(os.path.join(base, "*.py")))[: args.limit]
        if not files:
            print(f"[{group}] 未找到文件: {base}")
            continue
        print(f"[{group}] 开始扫描 {len(files)} 个文件 (workers={args.workers})...", flush=True)
        group_result, _ = run_group(REPO_ROOT, files, args.tag, group, args.workers, out_root)
        scorecard["groups"][group] = group_result
        print(
            f"[{group}] {len(files)} 文件: CONFIRMED 检出 {group_result['confirmed_hit_files']} "
            f"({group_result['confirmed_hit_rate']}%) | any-finding {group_result['any_finding_files']} "
            f"| token {group_result['total_tokens']:,} | 耗时 {group_result['wall_time_s']}s",
            flush=True,
        )

    # 误报率 = patched 中被 CONFIRMED 的文件占比（若扫描了 patched 组）
    if "vuln" in scorecard["groups"] and "patched" in scorecard["groups"]:
        v = scorecard["groups"]["vuln"]
        p = scorecard["groups"]["patched"]
        scorecard["summary"] = {
            "vuln_recall": v["confirmed_hit_rate"],
            "patched_fp_rate": p["confirmed_hit_rate"],
            "delta_recall_vs_baseline": round(v["confirmed_hit_rate"] - 35.0, 1),
        }

    score_path = out_root / args.tag / "scorecard.json"
    with open(score_path, "w", encoding="utf-8") as f:
        json.dump(scorecard, f, ensure_ascii=False, indent=1)
    print(f"分数卡已写入: {score_path}")


if __name__ == "__main__":
    main()
