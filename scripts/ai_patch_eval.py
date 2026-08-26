"""ai_patch_eval.py — 面向 AI 生成代码变更的可归因、可证伪漏洞验证评测。

协议输入：(R_before, task, Δ_AI, R_after)
- R_before  = 漏洞快照（A.S.E 漏洞代码摘录 / VulnGym commit 快照）
- task      = 修复任务描述（如 "Fix Command Injection in lib/rrd.php"）
- Δ_AI      = AI 生成的补丁（本脚本用 mimo-v2.5-pro 生成修复 → 完整文件）
- R_after   = 应用 Δ_AI 后的快照

子命令：
  gen-patch <manifest> [outdir] [workers]  生成 Δ_AI（修复版文件）+ patches meta
  scan <list.json> [outdir] [workers]      对文件列表跑 HOS-LS pure-ai 扫描（付费）
  vulngym <manifest> [n] [workers] [--top K] [--baseline M]  仓库级 SAL top-K AI 扫描 + baseline 对照
  dep-ase <manifest> <vuln.json> <patched.json>  DEP 判定 + Pair-Correct 指标
  report-ase <manifest> <vuln.json> <patched.json> [patch-meta.json]  汇总
  report-vulngym <ai.json>                   汇总

依赖：HOS_LS_AI_API_KEY / DEEPSEEK_API_KEY（环境变量），HTTP(S)_PROXY 走代理。
"""
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # hos-ls repo root
HOSLS = BASE
EVAL = os.path.join(BASE, "scripts")
REPOS = os.path.join(BASE, "..", "framework-audit", "repos")
REPORTS = os.path.join(BASE, "bench-runs", "ase_eval_reports")
ASE = os.path.join(BASE, "bench-runs", "datasets", "ase_samples")

API_URL = "https://token-plan-cn.xiaomimimo.com/v1/chat/completions"
API_MODEL = "mimo-v2.5-pro"
SCAN_TIMEOUT = int(os.environ.get("HOSLS_SCAN_TIMEOUT", "260"))
GIT_TIMEOUT = 300

# Windows git + 本地代理：schannel 后端握手失败，强制 openssl（与 .gitconfig_proxy 一致）
os.environ.setdefault("GIT_SSL_BACKEND", "openssl")

def load_sal_sinks():
    p = os.path.join(EVAL, "sal_sinks.json")
    return json.load(open(p, encoding="utf-8-sig")) if os.path.exists(p) else {}


def sal_candidates(repo_dir, lang, cwes, description="", max_files=20):
    """Sink 锚定候选生成（跳过 vendored/打包产物与 >1.5MB 文件）。"""
    sinks = load_sal_sinks()
    lang_table = sinks.get(lang, {})
    pats = []
    for cwe in cwes or []:
        pats.extend(lang_table.get(cwe, []) or [])
    if not pats:
        return []
    kws = []
    if description:
        for w in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", description.lower()):
            if w not in ("the", "and", "via", "for", "with", "that", "this", "from",
                         "into", "through", "using", "when", "after", "before", "during"):
                kws.append(w)
    exts = {"java": (".java",), "python": (".py",), "javascript": (".js", ".jsx", ".svelte"),
            "typescript": (".ts", ".tsx", ".vue"), "go": (".go",)}
    exts_ok = exts.get(lang, (".py",))
    skip_parts = ("node_modules", "/dist/", "/build/", "/vendor/", "/static/", "/public/",
                  "site-packages", ".next", ".nuxt", "venv", "/min/")
    cand = {}
    for root, _, files in os.walk(repo_dir):
        if ".git" in root:
            continue
        rel_root = os.path.relpath(root, repo_dir).replace("\\", "/")
        if any(s in rel_root for s in skip_parts):
            continue
        for f in files:
            if not f.endswith(exts_ok):
                continue
            if ".min." in f or "bundle" in f.lower() or f.endswith(".d.ts"):
                continue
            fp = os.path.join(root, f)
            try:
                text = open(fp, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            if len(text) > 1_500_000:
                continue
            hits = []
            for pat in pats:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    hits.append({"pattern": pat, "line": text[:m.start()].count("\n") + 1})
            if hits:
                rel = os.path.relpath(fp, repo_dir).replace("\\", "/")
                score = len(hits) * 2
                if kws:
                    low = text.lower()
                    score += sum(1 for kw in kws if kw in low)
                cand[rel] = {"hits": hits[:5], "score": score}
    ranked = sorted(cand.items(), key=lambda kv: -kv[1]["score"])[:max_files]
    return [{"file": f, "hits": h["hits"], "score": h["score"]} for f, h in ranked]


def kw_candidates(repo_dir, lang, description="", max_files=3):
    """Baseline 定位：CVE 描述关键词频次（无 sink 信号）。"""
    kws = []
    if description:
        for w in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", description.lower()):
            if w not in ("the", "and", "via", "for", "with", "that", "this", "from",
                         "into", "through", "using", "when", "after", "before", "during"):
                kws.append(w)
    exts = {"java": (".java",), "python": (".py",), "javascript": (".js", ".jsx", ".svelte"),
            "typescript": (".ts", ".tsx", ".vue"), "go": (".go",)}
    exts_ok = exts.get(lang, (".py",))
    cand = {}
    for root, _, files in os.walk(repo_dir):
        if ".git" in root:
            continue
        for f in files:
            if not f.endswith(exts_ok):
                continue
            fp = os.path.join(root, f)
            try:
                low = open(fp, encoding="utf-8", errors="replace").read().lower()
            except Exception:
                continue
            score = sum(1 for kw in kws if kw in low)
            if score > 0:
                rel = os.path.relpath(fp, repo_dir).replace("\\", "/")
                cand[rel] = score
    ranked = sorted(cand.items(), key=lambda kv: -kv[1])[:max_files]
    return [{"file": f, "score": s} for f, s in ranked]



# ---------- LLM ----------

def llm_chat(messages, max_tokens=2048, temperature=0.2, timeout=180):
    """直连 token-plan chat/completions（经代理）。返回 (content, usage_dict) 或 (None, None)。"""
    import requests
    import urllib3
    urllib3.disable_warnings()
    key = os.environ.get("HOS_LS_AI_API_KEY") or os.environ.get("DEEPSEEK_API_KEY") or ""
    if not key:
        print("[llm] ERROR: no HOS_LS_AI_API_KEY/DEEPSEEK_API_KEY in env")
        return None, None
    r = requests.post(API_URL,
                      headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                      json={"model": API_MODEL, "messages": messages, "max_tokens": max_tokens,
                            "temperature": temperature},
                      verify=False, timeout=timeout)
    if r.status_code != 200:
        print(f"[llm] HTTP {r.status_code}: {r.text[:200]}")
        return None, None
    d = r.json()
    try:
        content = d["choices"][0]["message"]["content"]
    except Exception:
        content = ""
    return content, d.get("usage", {})


def strip_fence(text):
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z0-9]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t.strip()


def apply_unified_diff(original_text, diff_text, workdir):
    """用 git apply 把 unified diff 应用到 original_text（经临时 git 仓库）。失败返回 None。"""
    os.makedirs(workdir, exist_ok=True)
    src = os.path.join(workdir, "target.txt")
    with open(src, "w", encoding="utf-8") as f:
        f.write(original_text)
    r = subprocess.run(["git", "init", "-q"], cwd=workdir, capture_output=True)
    if r.returncode != 0:
        return None
    r = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"],
                       input=diff_text, cwd=workdir, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    if r.returncode != 0:
        return None
    try:
        return open(src, encoding="utf-8").read()
    except Exception:
        return None


def gen_patch(manifest_path, outdir=None, workers=2):
    """为每个样本生成 Δ_AI（unified diff 形式）：'修复以下代码中的安全漏洞' →
    模型输出最小 diff → git apply 得到 R_after。meta 记录 diff 文本与 usage。"""
    outdir = outdir or os.path.join(ASE, "patched")
    os.makedirs(outdir, exist_ok=True)
    man = json.load(open(manifest_path, encoding="utf-8-sig"))
    meta = {}

    def work(m):
        iid = m["instance_id"]
        src = os.path.join(ASE, m["code_file"])
        code = open(src, encoding="utf-8").read()
        task = m.get("task_desc") or f"Fix {m.get('vuln_type', 'the vulnerability')} in {m.get('vuln_file', 'this file')}"
        prompt = (
            f"You are a security engineer. Below is a code file containing a security vulnerability "
            f"({m.get('vuln_type','')}, {m.get('cwe_id','')}).\n"
            f"Task: {task}\n\n"
            "Fix the vulnerability. Output ONLY a minimal unified diff (standard `git diff` format, "
            "starting with `--- a/...` / `+++ b/...` and `@@` hunks) that changes exactly what is needed. "
            "Do NOT output the full file. Do NOT add explanations.\n\n"
            f"```\n{code}\n```"
        )
        content, usage = llm_chat([{"role": "user", "content": prompt}], max_tokens=8192)
        diff = strip_fence(content or "")
        fixed = None
        if diff:
            fixed = apply_unified_diff(code, diff, os.path.join(outdir, "_gitapply", iid))
        dst = os.path.join(outdir, m["code_file"])
        ok = bool(fixed and len(fixed) > 0)
        if ok:
            with open(dst, "w", encoding="utf-8") as f:
                f.write(fixed)
        return iid, {
            "ok": ok, "out_file": m["code_file"] if ok else None,
            "src_lines": m.get("lines"), "out_lines": fixed.count("\n") + 1 if ok else 0,
            "diff_head": diff[:200] if diff else "", "diff_len": len(diff),
            "usage": usage, "prompt_tokens": len(prompt) // 4,
            "task_desc": task, "cwe_id": m.get("cwe_id"),
        }

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(work, m) for m in man]):
            iid, m = fut.result()
            meta[iid] = m
            print(f"[gen-patch] {iid:35s} ok={m['ok']} diff={m['diff_len']}B "
                  f"lines={m.get('src_lines')}->{m.get('out_lines')}", flush=True)

    dst = os.path.join(outdir, "_patch_meta.json")
    json.dump(meta, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[gen-patch] {sum(1 for m in meta.values() if m['ok'])}/{len(meta)} -> {dst}")
    return meta


# ---------- HOS-LS 扫描 ----------

def parse_scan_report(out_json):
    """从 HOS-LS 扫描报告 JSON 解析 findings。"""
    findings = []
    status = "error"
    tokens = {}
    duration = 0
    try:
        d = json.load(open(out_json, encoding="utf-8"))
        for res in d.get("results", []):
            status = res.get("status", "unknown")
            duration = res.get("duration", 0)
            tokens = res.get("token_records", {}) or {}
            for f in res.get("findings", []):
                loc = f.get("location", {})
                findings.append({
                    "status": f.get("status", "unknown"),
                    "file": loc.get("file", ""),
                    "line": loc.get("line"),
                    "end_line": loc.get("end_line"),
                    "rule": f.get("rule_name", "") or f.get("rule_id", ""),
                    "desc": (f.get("description") or f.get("message") or "")[:300],
                    "severity": f.get("severity", ""),
                })
    except Exception as e:
        status = f"parse_error:{e}"
    return status, duration, tokens, findings


def run_scan_file(filepath, out_json, timeout=SCAN_TIMEOUT):
    """对单个文件跑 HOS-LS pure-ai 扫描。返回解析结果 dict（超时返回 timeout 记录，不抛异常）。"""
    cmd = [sys.executable, "-m", "src.cli.main", "-c", "hos-ls.yaml", "scan", filepath,
           "--pure-ai", "--test", "1", "--format", "json", "--output", out_json, "--skip-data-update"]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, cwd=HOSLS)
    except subprocess.TimeoutExpired:
        print(f"[scan] {os.path.basename(filepath)} TIMEOUT after {timeout}s", flush=True)
        return {"file": filepath, "out": out_json, "status": "timeout",
                "duration": timeout, "scan_duration": 0, "tokens": {}, "findings": []}
    secs = round(time.time() - t0, 1)
    status, duration, tokens, findings = parse_scan_report(out_json)
    return {"file": filepath, "out": out_json, "status": status, "duration": secs,
            "scan_duration": duration, "tokens": tokens, "findings": findings}


def scan_batch(files, outdir, workers=3, tag="batch"):
    """并行扫描文件列表。返回 {file: result}。outdir 强制绝对路径（CLI cwd 在 hos-ls）。"""
    outdir = os.path.abspath(outdir)
    os.makedirs(outdir, exist_ok=True)
    results = {}

    def work(fp):
        base = os.path.splitext(os.path.basename(fp))[0]
        out = os.path.join(outdir, f"{base}.scan.json")
        # 断点续跑：已存在的有效报告直接复用，避免重复付费
        if os.path.exists(out):
            try:
                old = json.load(open(out, encoding="utf-8"))
                if old.get("results"):
                    status, duration, tokens, findings = parse_scan_report(out)
                    return {"file": fp, "out": out, "status": status, "duration": 0,
                            "scan_duration": duration, "tokens": tokens, "findings": findings}
            except Exception:
                pass
        return run_scan_file(fp, out)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(work, fp): fp for fp in files}
        for fut in as_completed(futs):
            fp = futs[fut]
            try:
                res = fut.result()
            except subprocess.TimeoutExpired:
                res = {"file": fp, "status": "timeout", "duration": SCAN_TIMEOUT, "findings": []}
            results[fp] = res
            n_conf = sum(1 for f in res.get("findings", []) if f["status"] == "CONFIRMED")
            print(f"[scan] {os.path.basename(fp):40s} {res.get('status','?'):12s} "
                  f"{len(res.get('findings',[]))} findings ({n_conf} CONFIRMED) {res.get('duration',0)}s", flush=True)
    dst = os.path.join(REPORTS, f"{tag}-scan-results.json")
    json.dump(results, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[scan] {len(results)} files -> {dst}")
    return results


# ---------- CWE 匹配 ----------

CWE_RE = re.compile(r"CWE-(\d{1,3})")

# 语义关键词表（HOS-LS 的 finding rule/desc 多为中文规则名，无 CWE 编号）
CWE_KEYWORDS = {
    "78": ["command", "命令", "exec", "shell", "inject", "subprocess", "popen", "system(", "eval", "rce"],
    "77": ["command", "命令", "exec", "shell", "inject", "subprocess", "popen", "system(", "eval", "rce"],
    "22": ["path", "路径", "traversal", "directory", "穿越", "目录", "文件", "upload", "上传", "realpath"],
    "89": ["sql", "注入", "query", "injection", "sqli"],
    "79": ["xss", "dom", "innerhtml", "script", "跨站", "html"],
    "94": ["code injection", "代码注入", "eval", "动态执行", "rce"],
    "918": ["ssrf", "request", "url", "服务端请求伪造", "fetch"],
    "502": ["deserial", "反序列化", "pickle", "unserialize"],
    "601": ["redirect", "跳转", "open redirect"],
}


def finding_cwes(f):
    text = " ".join(str(f.get(k, "")) for k in ("rule", "desc"))
    return set(CWE_RE.findall(text.upper()))


def cwe_hit(finding, target_cwes):
    """finding 是否命中目标 CWE：先匹配 CWE 编号，再用语义关键词兜底。"""
    fc = finding_cwes(finding)
    if fc and target_cwes:
        return bool(fc & target_cwes)
    text = (finding.get("rule", "") + " " + finding.get("desc", "")).lower()
    for cwe in target_cwes:
        for kw in CWE_KEYWORDS.get(cwe, []):
            if kw in text:
                return True
    # 无 CWE 文本时兜底：vuln_type 关键词
    for kw in ("command", "inject", "exec", "shell", "subprocess", "popen",
               "traversal", "path", "directory", "sql", "query", "eval", "rce", "ssrf"):
        if kw in text:
            return True
    return False


# ---------- DEP ----------

def dep_ase(manifest_path, vuln_json, patched_json):
    """DEP 消失性判定：vuln CONFIRMED ∧ patched 无同 CWE finding → Pair-Correct(DEP)。"""
    man = json.load(open(manifest_path, encoding="utf-8-sig"))
    vuln = json.load(open(vuln_json, encoding="utf-8"))
    patched = json.load(open(patched_json, encoding="utf-8"))
    out = []
    for m in man:
        iid = m["instance_id"]
        vres = vuln.get("file", {}).get("status") if isinstance(vuln, dict) else None
        vfile = os.path.join(ASE, m["code_file"])
        vfinds = vuln.get(vfile, {}).get("findings", []) if vfile in vuln else []
        pfile = os.path.join(ASE, "patched", m["code_file"])
        pfinds = patched.get(pfile, {}).get("findings", []) if pfile in patched else []
        confirmed = [f for f in vfinds if f["status"] == "CONFIRMED"]
        tgt = {m.get("cwe_id", "").replace("CWE-", "")} if m.get("cwe_id") else set()
        v_hit = any(cwe_hit(f, tgt) for f in confirmed) or bool(confirmed)
        # patched 端：与 vuln 端同 CWE 语义的 finding（含 CONFIRMED 或任意 finding）
        p_same_cwe = [f for f in pfinds if (tgt and cwe_hit(f, tgt)) or (not tgt and f.get("status") != "unknown")]
        p_confirmed = [f for f in pfinds if f["status"] == "CONFIRMED"]
        pair_ok_nodep = v_hit and not p_confirmed
        pair_ok_dep = v_hit and not p_same_cwe
        out.append({
            "instance_id": iid, "cwe": m.get("cwe_id"),
            "vuln_confirmed": [f["rule"] for f in confirmed],
            "vuln_hit": v_hit,
            "patched_findings": len(pfinds),
            "patched_same_cwe": len(p_same_cwe),
            "patched_confirmed": len(p_confirmed),
            "pair_ok_nodep": pair_ok_nodep,
            "pair_ok_dep": pair_ok_dep,
        })
    n = len(out)
    v = sum(1 for o in out if o["vuln_hit"])
    nd = sum(1 for o in out if o["pair_ok_nodep"])
    dd = sum(1 for o in out if o["pair_ok_dep"])
    print(f"[dep-ase] n={n} vuln_hit={v} ({v/n*100:.1f}%) Pair-Correct(no-DEP)={nd} "
          f"({nd/n*100:.1f}%) Pair-Correct(DEP)={dd} ({dd/n*100:.1f}%)")
    return {"samples": out, "metrics": {"n": n, "vuln_hit": v, "vuln_hit_rate": round(v/n, 3),
                                        "pair_nodep": nd, "pair_dep": dd,
                                        "pair_nodep_rate": round(nd/n, 3), "pair_dep_rate": round(dd/n, 3)}}


# ---------- 工具 ----------

def worktree_checkout(repo, commit, wt):
    """创建（或重建）commit 处的 worktree。绝对路径；先清理残留注册，避免
    'already checked out' 失败导致条目被跳过。"""
    wt = os.path.abspath(wt)
    # 1) 若已注册（残留/并发），先强制移除
    subprocess.run(["git", "-C", repo, "worktree", "remove", "--force", wt],
                   capture_output=True, text=True, encoding="utf-8", errors="replace",
                   timeout=GIT_TIMEOUT)
    if os.path.isdir(wt):
        try:
            import shutil
            shutil.rmtree(wt, ignore_errors=True)
        except Exception:
            pass
    # 2) 重新 add
    r = subprocess.run(["git", "-C", repo, "worktree", "add", "--detach", wt, commit],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=GIT_TIMEOUT)
    ok = r.returncode == 0 and os.path.exists(os.path.join(wt, ".git"))
    return ok, r.stderr.strip()[:200]


def kw_candidates(repo_dir, lang, description="", max_files=3):
    """Baseline 定位：按 CVE 描述关键词频次排序（无 sink 信号）。"""
    import re as _re
    kws = []
    if description:
        for w in _re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", description.lower()):
            if w not in ("the", "and", "via", "for", "with", "that", "this", "from",
                         "into", "through", "using", "when", "after", "before", "during"):
                kws.append(w)
    exts = {"java": (".java",), "python": (".py",), "javascript": (".js", ".jsx", ".svelte"),
            "typescript": (".ts", ".tsx", ".vue"), "go": (".go",)}
    exts_ok = exts.get(lang, (".py",))
    cand = {}
    for root, _, files in os.walk(repo_dir):
        if ".git" in root:
            continue
        for f in files:
            if not f.endswith(exts_ok):
                continue
            fp = os.path.join(root, f)
            try:
                low = open(fp, encoding="utf-8", errors="replace").read().lower()
            except Exception:
                continue
            score = sum(1 for kw in kws if kw in low)
            if score > 0:
                rel = os.path.relpath(fp, repo_dir).replace("\\", "/")
                cand[rel] = score
    ranked = sorted(cand.items(), key=lambda kv: -kv[1])[:max_files]
    return [{"file": f, "score": s} for f, s in ranked]


def gen_patch_full(manifest_path, outdir=None, workers=2):
    """完整输出式补丁生成（适用于小摘录）：'输出完整修复后的文件内容'。
    max_tokens=16384 + 截断校验（输出行数 < 源 50% 视为截断，重试一次）。"""
    outdir = outdir or os.path.join(ASE, "patched")
    os.makedirs(outdir, exist_ok=True)
    man = json.load(open(manifest_path, encoding="utf-8-sig"))
    meta = {}

    def work(m):
        iid = m["instance_id"]
        src = os.path.join(ASE, m["code_file"])
        code = open(src, encoding="utf-8").read()
        task = m.get("task_desc") or f"Fix {m.get('vuln_type', 'the vulnerability')} in {m.get('vuln_file', 'this file')}"
        prompt = (
            f"You are a security engineer. Below is a code excerpt containing a security vulnerability "
            f"({m.get('vuln_type','')}, {m.get('cwe_id','')}).\n"
            f"Task: {task}\n\n"
            "Fix the vulnerability. Output the COMPLETE fixed version of this exact code excerpt "
            "(same language and structure; keep all unchanged code identical; only modify what is necessary). "
            "Do NOT add explanations outside the code.\n\n"
            f"```\n{code}\n```"
        )
        fixed, usage = "", None
        for attempt in (16384, 32768):
            content, usage = llm_chat([{"role": "user", "content": prompt}], max_tokens=attempt)
            fixed = strip_fence(content or "")
            if fixed and fixed.count("\n") + 1 >= max(5, m.get("lines", 0) * 0.5):
                break
            fixed = ""
        dst = os.path.join(outdir, m["code_file"])
        ok = bool(fixed)
        if ok:
            with open(dst, "w", encoding="utf-8") as f:
                f.write(fixed)
        return iid, {
            "ok": ok, "out_file": m["code_file"] if ok else None,
            "src_lines": m.get("lines"), "out_lines": fixed.count("\n") + 1 if ok else 0,
            "usage": usage, "prompt_tokens": len(prompt) // 4,
            "task_desc": task, "cwe_id": m.get("cwe_id"),
        }

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(work, m) for m in man]):
            iid, m = fut.result()
            meta[iid] = m
            print(f"[gen-patch-full] {iid:35s} ok={m['ok']} lines={m.get('src_lines')}->{m.get('out_lines')}", flush=True)

    dst = os.path.join(outdir, "_patch_meta_full.json")
    json.dump(meta, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[gen-patch-full] {sum(1 for m in meta.values() if m['ok'])}/{len(meta)} -> {dst}")
    return meta


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "gen-patch":
        man = sys.argv[2]
        outdir = sys.argv[3] if len(sys.argv) > 3 else None
        workers = int(sys.argv[4]) if len(sys.argv) > 4 else 2
        gen_patch(man, outdir, workers)
    elif cmd == "gen-patch-full":
        man = sys.argv[2]
        outdir = sys.argv[3] if len(sys.argv) > 3 else None
        workers = int(sys.argv[4]) if len(sys.argv) > 4 else 2
        gen_patch_full(man, outdir, workers)
    elif cmd == "scan":
        list_json = sys.argv[2]
        outdir = sys.argv[3] if len(sys.argv) > 3 else os.path.join(REPORTS, "scans")
        workers = int(sys.argv[4]) if len(sys.argv) > 4 else 3
        tag = sys.argv[5] if len(sys.argv) > 5 else "batch"
        files = json.load(open(list_json, encoding="utf-8-sig"))
        scan_batch(files, outdir, workers, tag)
    elif cmd == "vulngym":
        man_path = sys.argv[2]
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        workers = int(sys.argv[4]) if len(sys.argv) > 4 else 2
        topk = int(sys.argv[5]) if len(sys.argv) > 5 else 3
        baseline_n = int(sys.argv[6]) if len(sys.argv) > 6 else 3  # 做 baseline 对照的条目数
        man = json.load(open(man_path, encoding="utf-8-sig"))[:n]
        sal_results, baseline_results, scans = {}, {}, {}
        for i, p in enumerate(man):
            do_baseline = i < baseline_n
            pid = p["item_id"]
            repo = os.path.abspath(os.path.join(REPOS, p["repo_url"].rstrip("/").split("/")[-1].replace(".git", "")))
            wt = os.path.abspath(os.path.join(REPOS, f"_wt-{pid}-vuln"))
            if not os.path.isdir(os.path.join(repo, ".git")):
                print(f"[vulngym] {pid}: repo missing {repo}")
                continue
            ok, err = worktree_checkout(repo, p.get("fix_commit") or p.get("commit", ""), wt)
            if not ok:
                print(f"[vulngym] {pid}: worktree fail {err[:120]}")
                continue
            try:
                lang = p.get("language", "python")
                sal = sal_candidates(wt, lang, p.get("cwe_ids", []), p.get("description", ""), max_files=topk)
                base = kw_candidates(wt, lang, p.get("description", ""), max_files=topk) if do_baseline else []
                gt = set(p.get("file_paths", []))
                sal_files = [os.path.join(wt, c["file"]) for c in sal]
                base_files = [os.path.join(wt, c["file"]) for c in base]
                sal_results[pid] = {"gt": sorted(gt), "sal": sal, "sal_hit": [c["file"] for c in sal if c["file"] in gt]}
                baseline_results[pid] = {"base": base, "base_hit": [c["file"] for c in base if c["file"] in gt]}
                print(f"[vulngym] {pid} {p['framework']}: SAL {len(sal)} cands hit={sal_results[pid]['sal_hit']} "
                      f"| baseline {len(base)} cands hit={baseline_results[pid]['base_hit']}", flush=True)
                scans[pid] = {"sal": [], "baseline": []}
                # 并行扫描本条目候选文件（已存在的报告直接复用）
                def scan_one(fp, side, pid):
                    out = os.path.join(REPORTS, "vulngym-ai", f"{pid}__{side}__{os.path.basename(fp)}.scan.json")
                    if os.path.exists(out):
                        try:
                            old = json.load(open(out, encoding="utf-8"))
                            if old.get("results"):
                                status, duration, tokens, findings = parse_scan_report(out)
                                return {"file": fp, "out": out, "status": status, "duration": 0,
                                        "scan_duration": duration, "tokens": tokens, "findings": findings}
                        except Exception:
                            pass
                    return run_scan_file(fp, out)

                scan_targets = [(os.path.join(wt, c["file"]), "sal") for c in sal] + \
                               [(os.path.join(wt, c["file"]), "baseline") for c in base[:topk]]
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    futs = {ex.submit(scan_one, fp, side, pid): (fp, side)
                            for fp, side in scan_targets}
                    for fut in as_completed(futs):
                        fp, side = futs[fut]
                        res = fut.result()
                        scans[pid][side].append(res)
                        n_conf = sum(1 for f in res.get("findings", []) if f["status"] == "CONFIRMED")
                        print(f"[vulngym-scan] {pid} {side} {os.path.basename(fp):40s} "
                              f"finds={len(res.get('findings', []))} conf={n_conf} {res.get('duration', 0)}s", flush=True)
            finally:
                if os.path.isdir(wt):
                    subprocess.run(["git", "-C", repo, "worktree", "remove", "--force", wt],
                                   capture_output=True, timeout=GIT_TIMEOUT)
        dst = os.path.join(REPORTS, "vulngym-ai-results.json")
        json.dump({"localization": {"sal": sal_results, "baseline": baseline_results}, "scans": scans},
                  open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"[vulngym] -> {dst}")
    elif cmd == "dep-ase":
        print(json.dumps(dep_ase(sys.argv[2], sys.argv[3], sys.argv[4]), ensure_ascii=False, indent=1))
    elif cmd == "report-ase":
        man = json.load(open(sys.argv[2], encoding="utf-8-sig"))
        vuln = json.load(open(sys.argv[3], encoding="utf-8"))
        patched = json.load(open(sys.argv[4], encoding="utf-8"))
        patch_meta = json.load(open(sys.argv[5], encoding="utf-8")) if len(sys.argv) > 5 else {}
        rows = []
        for m in man:
            vf = os.path.join(ASE, m["code_file"])
            pf = os.path.join(ASE, "patched", m["code_file"])
            vfinds = vuln.get(vf, {}).get("findings", [])
            pfinds = patched.get(pf, {}).get("findings", [])
            confirmed = [f for f in vfinds if f["status"] == "CONFIRMED"]
            rows.append({
                "instance_id": m["instance_id"], "cwe": m["cwe_id"], "language": m["language"],
                "vuln_confirmed": [f["rule"] for f in confirmed],
                "vuln_detected": len(confirmed) > 0,
                "patched_confirmed": sum(1 for f in pfinds if f["status"] == "CONFIRMED"),
                "patch_ok": patch_meta.get(m["instance_id"], {}).get("ok", False),
            })
        n = len(rows)
        det = sum(1 for r in rows if r["vuln_detected"])
        print(f"[report-ase] n={n} detected={det} ({det/n*100:.1f}%)")
        print(f"[report-ase] patch_ok={sum(1 for r in rows if r['patch_ok'])}/{n}")
        json.dump(rows, open(os.path.join(REPORTS, "ase-report-rows.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
