"""对比测试脚本 — 在 VulnGym 样本上运行 Semgrep + CodeQL + HOS-LS

模式：
  snippet (default) : 从 entries.jsonl 提取代码片段到临时文件后扫描
  repo              : 在克隆的完整仓库上扫描对应文件

支持使用预定义分层样本：
    python bench/run_comparison.py --stratified --tool semgrep          # 在 45 个分层样本上跑 Semgrep
    python bench/run_comparison.py --stratified --tool hosls --ai-provider deepseek  # 在分层样本上跑 HOS-LS

快速验证：
    python bench/run_comparison.py --limit 10             # 前 10 条 VulnGym 条目
    python bench/run_comparison.py --tool semgrep          # 只跑 Semgrep
    python bench/run_comparison.py --tool hosls            # 只跑 HOS-LS（默认 DeepInfra）
    python bench/run_comparison.py --mode repo --tool hosls  # 仓库级 HOS-LS 扫描
    python bench/run_comparison.py --ai-provider deepseek  # 指定其他 AI provider
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
VULNGYM_DIR = REPO_ROOT / "bench" / "datasets" / "VulnGym"
REPOS_DIR = REPO_ROOT / "bench" / "datasets" / "repos"
EXPERIMENTS_DIR = REPO_ROOT / "bench" / "experiments"

# ── 语言映射 ──
EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
    ".rb": "ruby", ".php": "php", ".rs": "rust",
    ".svelte": "javascript", ".vue": "javascript",
}
SEMGREP_CONFIG_MAP = {
    "python": "p/python", "javascript": "p/javascript", "typescript": "p/typescript",
    "java": "p/java", "go": "p/golang", "c": "p/c", "cpp": "p/cpp",
    "ruby": "p/ruby", "rust": "p/rust",
}

# ── VulnGym repo 映射 ──
REPO_DIR_MAP = {
    "openclaw": "openclaw", "OpenClaw": "openclaw", "OpenClaw Gateway": "openclaw",
    "@openclaw/nextcloud-talk": "openclaw", "openclaw/openclaw": "openclaw",
    "n8n": "n8n",
    "FlowiseAI/Flowise": "Flowise", "Flowise": "Flowise",
    "Flowise (FlowiseAI/Flowise)": "Flowise", "flowise": "Flowise",
    "NVIDIA/NeMo": "NeMo", "NVIDIA NeMo": "NeMo", "NVIDIA NeMo Framework": "NeMo",
    "paperclip": "paperclip", "paperclipai/paperclip": "paperclip",
    "langflow": "langflow", "langflow-ai/langflow": "langflow", "Langflow": "langflow",
    "mlflow": "mlflow", "MLflow": "mlflow",
    "WeKnora": "WeKnora", "Tencent/WeKnora": "WeKnora",
    "ollama": "ollama",
    "google/adk-python": "adk-python",
    "milvus": "milvus", "milvus-io/milvus": "milvus",
    "apache/airflow": "airflow", "Apache Airflow": "airflow",
    "open-webui": "open-webui",
    "fastmcp": "fastmcp",
    "langchain-core": "langchain", "langchain-ai/langchain": "langchain",
    "aquasecurity/trivy": "trivy",
    "n8n-mcp": "n8n-mcp",
    "AutoGPT": "AutoGPT", "Significant-Gravitas/AutoGPT": "AutoGPT",
    "typescript-sdk": "typescript-sdk", "modelcontextprotocol/typescript-sdk": "typescript-sdk",
    "onnx": "onnx", "nltk": "nltk", "litellm": "litellm", "BerriAI/litellm": "litellm",
}


# ═══════════════════════════════════════════════════════════════════════
#  数据加载
# ═══════════════════════════════════════════════════════════════════════

def load_vulngym_entries(limit: Optional[int] = None) -> List[dict]:
    """从 VulnGym JSONL 加载所有含代码样本的条目。"""
    entries_path = VULNGYM_DIR / "data" / "entries.jsonl"
    if not entries_path.exists():
        print(f"[ERROR] VulnGym 未找到: {entries_path}")
        return []
    entries = []
    with open(entries_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
                co = entry.get("critical_operation", {})
                if co and co.get("code"):
                    entries.append(entry)
                if limit and len(entries) >= limit:
                    break
            except json.JSONDecodeError:
                continue
    print(f"[INFO] 加载 {len(entries)} 条 VulnGym 条目（含代码样本）")
    return entries


def load_stratified_samples() -> List[dict]:
    """加载预定义的分层样本。"""
    path = EXPERIMENTS_DIR / "stratified_samples.json"
    if not path.exists():
        print(f"[ERROR] 分层样本未找到: {path}")
        print("       请先运行: python bench/prepare_benchmark_data.py --sample-size 50")
        return []
    with open(path, "r", encoding="utf-8") as f:
        samples = json.load(f)
    print(f"[INFO] 加载 {len(samples)} 个分层样本")
    return samples


# ═══════════════════════════════════════════════════════════════════════
#  工具函数
# ═══════════════════════════════════════════════════════════════════════

def detect_language_from_path(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return EXT_TO_LANG.get(ext, "unknown")


def infer_entry_language(entry: dict) -> str:
    """从 entry 的 critical_operation 或 entry_point 文件路径推断语言。"""
    for key in ("critical_operation", "entry_point"):
        node = entry.get(key, {})
        if node and isinstance(node, dict):
            fp = node.get("file", "")
            if fp:
                lang = detect_language_from_path(fp)
                if lang != "unknown":
                    return lang
    return "unknown"


def get_semgrep_config(lang: str) -> str:
    """根据语言返回 Semgrep 规则包。"""
    return SEMGREP_CONFIG_MAP.get(lang, "p/python")


# ═══════════════════════════════════════════════════════════════════════
#  Semgrep 运行器
# ═══════════════════════════════════════════════════════════════════════

def run_semgrep_on_code(code: str, lang: str = "python") -> dict:
    """在代码片段上运行 Semgrep，返回命中结果。"""
    import tempfile

    ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts",
               "java": ".java", "go": ".go", "c": ".c", "cpp": ".cpp"}
    ext = ext_map.get(lang, ".py")

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp_path = f.name

    try:
        cfg = get_semgrep_config(lang)
        result = subprocess.run(
            ["semgrep", "scan", "--config", cfg, "--json", tmp_path],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        )
        data = json.loads(result.stdout or "{}")
        hits = data.get("results", [])
        os.unlink(tmp_path)
        return {
            "total_hits": len(hits),
            "rules": list(set(h.get("check_id", "") for h in hits)),
            "severities": Counter(h.get("extra", {}).get("severity", "unknown") for h in hits),
        }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return {"total_hits": 0, "rules": [], "severities": {}, "error": str(e)[:100]}


def run_semgrep_on_repo_file(file_path: Path) -> dict:
    """在仓库里的真实文件上运行 Semgrep。"""
    lang = detect_language_from_path(str(file_path))
    cfg = get_semgrep_config(lang)
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", cfg, "--json", str(file_path)],
            capture_output=True, text=True, timeout=120,
            encoding="utf-8", errors="replace",
        )
        data = json.loads(result.stdout or "{}")
        hits = data.get("results", [])
        return {
            "total_hits": len(hits),
            "rules": list(set(h.get("check_id", "") for h in hits)),
            "severities": dict(Counter(h.get("extra", {}).get("severity", "unknown") for h in hits)),
        }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        return {"total_hits": 0, "rules": [], "severities": {}, "error": str(e)[:100]}


# ═══════════════════════════════════════════════════════════════════════
#  CodeQL 运行器
# ═══════════════════════════════════════════════════════════════════════

def _codeql_jar() -> Optional[Path]:
    """找到 CodeQL JAR 路径。"""
    jar = REPO_ROOT / "envs" / "codeql" / "codeql" / "tools" / "codeql.jar"
    return jar if jar.exists() else None


def run_codeql_on_code(code: str, lang: str = "python") -> dict:
    """在代码片段上运行 CodeQL 查询。"""
    import tempfile

    jar = _codeql_jar()
    if not jar:
        return {"total_hits": 0, "error": "CodeQL JAR not found"}

    ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts",
               "java": ".java", "go": ".go", "c": ".c", "cpp": ".cpp"}
    ext = ext_map.get(lang, ".py")

    with tempfile.TemporaryDirectory(prefix="codeql-bench-") as tmpdir:
        tmpdir_p = Path(tmpdir)
        src_file = tmpdir_p / f"src{ext}"
        src_file.write_text(code, encoding="utf-8")

        db_dir = tmpdir_p / "db"
        result_dir = tmpdir_p / "results"

        try:
            # 1. 创建数据库
            r1 = subprocess.run(
                ["java", "-jar", str(jar), "database", "create", str(db_dir),
                 "--language=" + lang, "--source-root=" + str(tmpdir_p),
                 "--overwrite"],
                capture_output=True, text=True, timeout=120,
                encoding="utf-8", errors="replace",
            )
            if r1.returncode != 0:
                return {"total_hits": 0, "error": f"CodeQL DB create failed: {r1.stderr[:200]}"}

            # 2. 运行查询
            qlpack_dir = REPO_ROOT / "envs" / "codeql-packs"
            qlpack = qlpack_dir / "codeql" / f"{lang}-queries"
            if not qlpack.exists():
                qlpack = qlpack_dir / f"codeql/{lang}-all"
            if not qlpack.exists():
                return {"total_hits": 0, "error": f"QL pack not found for {lang}"}

            r2 = subprocess.run(
                ["java", "-jar", str(jar), "database", "analyze", str(db_dir),
                 str(qlpack), "--format=sarif-latest", f"--output={result_dir}.sarif",
                 "--no-rerun"],
                capture_output=True, text=True, timeout=300,
                encoding="utf-8", errors="replace",
            )

            # 3. 解析结果
            if (result_dir.with_suffix(".sarif")).exists():
                with open(result_dir.with_suffix(".sarif"), "r", encoding="utf-8") as f:
                    sarif = json.load(f)
                runs = sarif.get("runs", [])
                hits = []
                for run in runs:
                    for result in run.get("results", []):
                        hits.append({
                            "rule_id": result.get("ruleId", ""),
                            "message": result.get("message", {}).get("text", ""),
                        })
                return {"total_hits": len(hits), "rules": list(set(h["rule_id"] for h in hits))}
            else:
                return {"total_hits": 0, "error": "CodeQL no SARIF output"}

        except (subprocess.TimeoutExpired, OSError) as e:
            return {"total_hits": 0, "error": str(e)[:100]}


# ═══════════════════════════════════════════════════════════════════════
#  HOS-LS 运行器
# ═══════════════════════════════════════════════════════════════════════

def _hosls_cmd_args(file_path: str, ai_provider: str = "deepseek") -> list:
    norm_path = file_path.replace("\\", "/")
    return [sys.executable, "-u",
            str(REPO_ROOT / "bench" / "run_hosls_scan.py"),
            norm_path, "--ai-provider", ai_provider]


def run_hosls_on_code(code: str, ext: str = ".py", ai_provider: str = "deepseek") -> dict:
    """在代码片段上运行 HOS-LS。"""
    import tempfile
    import shutil

    temp_dir = Path(tempfile.mkdtemp(prefix="hosls-snippet-"))
    try:
        tmp_file = temp_dir / f"src{ext}"
        tmp_file.write_text(code, encoding="utf-8")

        result = subprocess.run(
            _hosls_cmd_args(str(tmp_file), ai_provider),
            capture_output=True, text=True, timeout=300,
            encoding="utf-8", errors="replace", cwd=str(REPO_ROOT),
        )
        report = {}
        try:
            report = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            pass

        findings = report.get("results", [{}])[0].get("findings", []) if report.get("results") else []
        return {
            "hosls_findings": len(findings),
            "hosls_confirmed": sum(1 for f in findings if f.get("status") == "CONFIRMED"),
            "hosls_error": result.stderr[:200] if result.returncode != 0 else "",
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def run_hosls_on_repo_file(file_path: Path, ai_provider: str = "deepseek") -> dict:
    """在仓库里的真实文件上运行 HOS-LS。"""
    result = subprocess.run(
        _hosls_cmd_args(str(file_path), ai_provider),
        capture_output=True, text=True, timeout=300,
        encoding="utf-8", errors="replace", cwd=str(REPO_ROOT),
    )
    report = {}
    try:
        report = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        pass
    findings = report.get("results", [{}])[0].get("findings", []) if report.get("results") else []
    return {
        "hosls_findings": len(findings),
        "hosls_confirmed": sum(1 for f in findings if f.get("status") == "CONFIRMED"),
        "hosls_error": result.stderr[:200] if result.returncode != 0 else "",
    }


# ═══════════════════════════════════════════════════════════════════════
#  Benchmark 运行器
# ═══════════════════════════════════════════════════════════════════════

def run_semgrep_benchmark(entries: List[dict], limit: int = 50) -> dict:
    """在 entries 上运行 Semgrep 基准测试。"""
    results = []
    start = time.time()
    total = min(len(entries), limit)

    for i, entry in enumerate(entries[:limit]):
        co = entry.get("critical_operation", {})
        code = co.get("code", "")
        if not code:
            continue
        lang = infer_entry_language(entry) or "python"

        semgrep_result = run_semgrep_on_code(code, lang)
        results.append({
            "entry_id": entry.get("entry_id", f"entry-{i}"),
            "project": entry.get("project", "unknown"),
            "vuln_type": entry.get("vuln_category_l1", "unknown"),
            "l2_type": entry.get("vuln_category_l2", ""),
            "language": lang,
            "trace_len": len(entry.get("trace", [])),
            "cross_file_complexity": len(set(
                n.get("file", "") for n in
                [entry.get("entry_point", {}), entry.get("critical_operation", {})]
                + entry.get("trace", []) if isinstance(n, dict) and n.get("file")
            )),
            "verify": entry.get("verify", 0),
            "semgrep_hits": semgrep_result["total_hits"],
            "semgrep_rules": semgrep_result["rules"],
            "semgrep_error": semgrep_result.get("error", ""),
        })
        if (i + 1) % 10 == 0:
            elapsed = time.time() - start
            print(f"  Semgrep: {i+1}/{total} ({elapsed:.0f}s)")

    elapsed = time.time() - start
    total_hits = sum(r["semgrep_hits"] for r in results)
    hit_entries = sum(1 for r in results if r["semgrep_hits"] > 0)

    return {
        "tool": "semgrep",
        "total_entries": len(results),
        "entries_with_hits": hit_entries,
        "detection_rate": round(hit_entries / len(results) * 100, 1) if results else 0,
        "total_hits": total_hits,
        "avg_hits_per_entry": round(total_hits / len(results), 2) if results else 0,
        "business_logic_hits": sum(1 for r in results if r["vuln_type"] in ("business_logic", "业务逻辑") and r["semgrep_hits"] > 0),
        "traditional_hits": sum(1 for r in results if r["vuln_type"] not in ("business_logic", "业务逻辑") and r["semgrep_hits"] > 0),
        "verified_hits": sum(1 for r in results if r.get("verify") == 1 and r["semgrep_hits"] > 0),
        "wall_time_s": round(elapsed, 1),
        "details": results,
    }


def run_codeql_benchmark(entries: List[dict], limit: int = 20) -> dict:
    """在 entries 上运行 CodeQL 基准测试（慢，建议小批量）。"""
    results = []
    start = time.time()
    total = min(len(entries), limit)

    for i, entry in enumerate(entries[:limit]):
        co = entry.get("critical_operation", {})
        code = co.get("code", "")
        if not code:
            continue
        lang = infer_entry_language(entry) or "python"

        codeql_result = run_codeql_on_code(code, lang)
        results.append({
            "entry_id": entry.get("entry_id", f"entry-{i}"),
            "project": entry.get("project", "unknown"),
            "vuln_type": entry.get("vuln_category_l1", "unknown"),
            "language": lang,
            "verify": entry.get("verify", 0),
            "codeql_hits": codeql_result["total_hits"],
            "codeql_rules": codeql_result.get("rules", []),
            "codeql_error": codeql_result.get("error", ""),
        })
        elapsed = time.time() - start
        print(f"  CodeQL: {i+1}/{total} ({elapsed:.0f}s)")

    elapsed = time.time() - start
    hit_entries = sum(1 for r in results if r["codeql_hits"] > 0)
    return {
        "tool": "codeql",
        "total_entries": len(results),
        "entries_with_hits": hit_entries,
        "detection_rate": round(hit_entries / len(results) * 100, 1) if results else 0,
        "total_hits": sum(r["codeql_hits"] for r in results),
        "wall_time_s": round(elapsed, 1),
        "details": results,
    }


def run_hosls_benchmark(entries: List[dict], limit: int = 20, ai_provider: str = "deepseek") -> dict:
    """在 entries 上运行 HOS-LS 扫描。"""
    results = []
    start = time.time()
    total = min(len(entries), limit)

    for i, entry in enumerate(entries[:limit]):
        co = entry.get("critical_operation", {})
        code = co.get("code", "")
        if not code:
            continue

        ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts",
                   "java": ".java", "go": ".go", "c": ".c", "cpp": ".cpp"}
        lang = infer_entry_language(entry) or "python"
        ext = ext_map.get(lang, ".py")

        hosls_result = run_hosls_on_code(code, ext, ai_provider)
        results.append({
            "entry_id": entry.get("entry_id", f"entry-{i}"),
            "project": entry.get("project", "unknown"),
            "vuln_type": entry.get("vuln_category_l1", "unknown"),
            "l2_type": entry.get("vuln_category_l2", ""),
            "language": lang,
            "trace_len": len(entry.get("trace", [])),
            "cross_file_complexity": len(set(
                n.get("file", "") for n in
                [entry.get("entry_point", {}), entry.get("critical_operation", {})]
                + entry.get("trace", []) if isinstance(n, dict) and n.get("file")
            )),
            "verify": entry.get("verify", 0),
            "hosls_findings": hosls_result["hosls_findings"],
            "hosls_confirmed": hosls_result["hosls_confirmed"],
            "hosls_error": hosls_result.get("hosls_error", ""),
        })
        if (i + 1) % 5 == 0:
            elapsed = time.time() - start
            print(f"  HOS-LS: {i+1}/{total} ({elapsed:.0f}s)")

    elapsed = time.time() - start
    hit_entries = sum(1 for r in results if r["hosls_findings"] > 0)
    confirmed_entries = sum(1 for r in results if r["hosls_confirmed"] > 0)
    biz_hits = sum(1 for r in results if r["vuln_type"] in ("business_logic", "业务逻辑") and r["hosls_confirmed"] > 0)
    trad_hits = sum(1 for r in results if r["vuln_type"] not in ("business_logic", "业务逻辑") and r["hosls_confirmed"] > 0)
    verified_hits = sum(1 for r in results if r.get("verify") == 1 and r["hosls_confirmed"] > 0)

    return {
        "tool": "hosls",
        "total_entries": len(results),
        "entries_with_findings": hit_entries,
        "entries_with_confirmed": confirmed_entries,
        "detection_rate": round(hit_entries / len(results) * 100, 1) if results else 0,
        "confirmed_rate": round(confirmed_entries / len(results) * 100, 1) if results else 0,
        "total_findings": sum(r["hosls_findings"] for r in results),
        "total_confirmed": sum(r["hosls_confirmed"] for r in results),
        "business_logic_confirmed": biz_hits,
        "traditional_confirmed": trad_hits,
        "verified_confirmed": verified_hits,
        "wall_time_s": round(elapsed, 1),
        "details": results,
    }


# ═══════════════════════════════════════════════════════════════════════
#  仓库级扫描
# ═══════════════════════════════════════════════════════════════════════

def resolve_entry_repo_path(entry: dict) -> Optional[Path]:
    """将 VulnGym 条目解析为本地仓库中的真实文件路径。"""
    project = entry.get("project", "")
    file_rel = entry.get("critical_operation", {}).get("file", "")
    if not file_rel:
        return None

    local_dir = REPO_DIR_MAP.get(project)
    if not local_dir:
        proj_lower = project.lower().replace("/", "-").replace(" ", "-")
        for key, val in REPO_DIR_MAP.items():
            if key.lower().replace("/", "-").replace(" ", "-") == proj_lower:
                local_dir = val
                break
        if not local_dir:
            print(f"  [WARN] 未知项目 '{project}'，跳过")
            return None

    repo_path = REPOS_DIR / local_dir
    if not repo_path.exists():
        print(f"  [WARN] 仓库未下载: {repo_path}")
        return None

    full_path = repo_path / file_rel
    if not full_path.exists():
        filename = Path(file_rel).name
        matches = list(repo_path.rglob(filename))
        if matches:
            full_path = matches[0]
            print(f"  [INFO] 通过文件名 '{filename}' 找到: {full_path.relative_to(repo_path)}")
        else:
            print(f"  [WARN] 文件未找到: {file_rel} (在 {repo_path})")
            return None

    return full_path


def run_repo_benchmark(entries: List[dict], tool: str, limit: int = 50,
                       ai_provider: str = "deepseek") -> dict:
    """仓库级扫描基准测试。"""
    results = []
    start = time.time()
    resolved = 0
    skipped = 0

    for i, entry in enumerate(entries[:limit]):
        entry_id = entry.get("entry_id", f"entry-{i}")
        project = entry.get("project", "unknown")
        vuln_type = entry.get("vuln_category_l1", "unknown")
        lang = infer_entry_language(entry) or "unknown"

        file_path = resolve_entry_repo_path(entry)
        if file_path is None:
            results.append({
                "entry_id": entry_id, "project": project,
                "vuln_type": vuln_type, "status": "skipped", "reason": "file_not_found",
            })
            skipped += 1
            continue

        resolved += 1
        base = {
            "entry_id": entry_id, "project": project,
            "vuln_type": vuln_type, "language": lang,
            "status": "scanned", "file": str(file_path),
        }

        if tool == "semgrep":
            sg = run_semgrep_on_repo_file(file_path)
            base.update({
                "semgrep_hits": sg["total_hits"],
                "semgrep_rules": sg["rules"],
                "semgrep_error": sg.get("error", ""),
            })
        elif tool == "codeql":
            cq = run_codeql_on_code(entry.get("critical_operation", {}).get("code", ""), lang)
            base.update({
                "codeql_hits": cq["total_hits"],
                "codeql_rules": cq.get("rules", []),
                "codeql_error": cq.get("error", ""),
            })
        else:  # hosls
            hl = run_hosls_on_repo_file(file_path, ai_provider)
            base.update({
                "hosls_findings": hl["hosls_findings"],
                "hosls_confirmed": hl["hosls_confirmed"],
                "hosls_error": hl.get("hosls_error", ""),
            })

        results.append(base)
        if (i + 1) % 10 == 0:
            elapsed = time.time() - start
            print(f"  {tool}: {i+1}/{min(limit, len(entries))} ({elapsed:.0f}s, resolved={resolved}, skipped={skipped})")

    elapsed = time.time() - start
    scanned = [r for r in results if r["status"] == "scanned"]
    hit_key = {"semgrep": "semgrep_hits", "codeql": "codeql_hits", "hosls": "hosls_findings"}
    hit_entries = sum(1 for r in scanned if r.get(hit_key[tool], 0) > 0)

    return {
        "tool": tool, "mode": "repo",
        "total_entries": len(results), "resolved": resolved, "skipped": skipped,
        "entries_with_hits": hit_entries,
        "detection_rate": round(hit_entries / len(scanned) * 100, 1) if scanned else 0,
        "total_hits": sum(r.get(hit_key[tool], 0) for r in scanned),
        "wall_time_s": round(elapsed, 1),
        "details": results,
    }


# ═══════════════════════════════════════════════════════════════════════
#  报告打印
# ═══════════════════════════════════════════════════════════════════════

def print_report(report: dict):
    print(f"\n{'='*60}")
    tool_name = report.get("tool", "?").upper()
    mode = report.get("mode", "snippet")
    print(f"  工具: {tool_name} ({mode})")
    print(f"  条目数: {report['total_entries']}")
    print(f"  检出条目: {report.get('entries_with_hits', report.get('entries_with_findings', 0))}")
    print(f"  检出率: {report.get('detection_rate', 0)}%")

    if report.get("confirmed_rate") is not None:
        print(f"  CONFIRMED 率: {report['confirmed_rate']}%")
        print(f"  总 CONFIRMED: {report['total_confirmed']}")
        print(f"  BL检出: {report.get('business_logic_confirmed', 'N/A')} / 传统检出: {report.get('traditional_confirmed', 'N/A')} / 已验证: {report.get('verified_confirmed', 'N/A')}")

    if report.get("total_hits") is not None:
        print(f"  总命中数: {report['total_hits']}")
    if report.get("total_findings") is not None:
        print(f"  总发现: {report['total_findings']}")

    print(f"  耗时: {report['wall_time_s']}s")
    print(f"{'='*60}")


def print_repo_report(report: dict):
    print(f"\n{'='*60}")
    print(f"  工具: {report['tool'].upper()} (仓库级)")
    print(f"  总条目: {report['total_entries']}")
    print(f"  已解析文件: {report['resolved']}")
    print(f"  跳过: {report['skipped']}")
    print(f"  检出条目: {report['entries_with_hits']}")
    print(f"  检出率: {report['detection_rate']}%")
    print(f"  总命中数: {report['total_hits']}")
    print(f"  耗时: {report['wall_time_s']}s")
    print(f"{'='*60}")


def check_available_repos() -> dict:
    available = {}
    for repo_dir in sorted(REPOS_DIR.iterdir()):
        if repo_dir.is_dir() and (repo_dir / ".git").exists():
            git_size = sum(f.stat().st_size for f in repo_dir.rglob("*") if f.is_file())
            available[repo_dir.name] = {"path": str(repo_dir), "size_mb": round(git_size / (1024 * 1024), 1)}
    return available


# ═══════════════════════════════════════════════════════════════════════
#  主入口
# ═══════════════════════════════════════════════════════════════════════

def main():
    # 强制 UTF-8 输出
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    ap = argparse.ArgumentParser(description="对比测试: Semgrep / CodeQL / HOS-LS on VulnGym")
    ap.add_argument("--tool", choices=["semgrep", "codeql", "hosls", "all"], default="all",
                    help="要运行的工具")
    ap.add_argument("--limit", type=int, default=20, help="测试条目数（非分层模式）")
    ap.add_argument("--output", default="bench/artifacts/comparison-result.json")
    ap.add_argument("--mode", choices=["snippet", "repo"], default="snippet",
                    help="snippet: 代码片段级; repo: 仓库级文件扫描")
    ap.add_argument("--ai-provider", default="deepinfra",
                    help="HOS-LS AI provider (deepinfra, deepseek, aliyun)")
    ap.add_argument("--stratified", action="store_true",
                    help="使用预定义分层样本 (bench/experiments/stratified_samples.json)")
    args = ap.parse_args()

    if args.mode == "repo" and args.tool == "all":
        print("[INFO] 仓库模式不支持同时跑所有工具，请用 --tool 单独指定")
        return

    # ── 决定条目来源 ──
    if args.stratified:
        entries = load_stratified_samples()
        if not entries:
            return
        limit = len(entries)
    else:
        entries = load_vulngym_entries(args.limit)
        if not entries:
            return
        limit = min(len(entries), args.limit)

    if args.mode == "repo":
        available = check_available_repos()
        if not available:
            print("[ERROR] 无可用仓库")
            return
        print(f"[INFO] 已下载 {len(available)} 个仓库")

        report = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "mode": "repo",
                  "config": {"tool": args.tool, "limit": limit, "ai_provider": args.ai_provider,
                             "stratified": args.stratified},
                  "tools": {}}
        print(f"\n[仓库扫描] 工具={args.tool}, AI={args.ai_provider}, 条目={limit}")
        repo_report = run_repo_benchmark(entries, args.tool, limit, ai_provider=args.ai_provider)
        print_repo_report(repo_report)
        report["tools"][args.tool] = repo_report
    else:
        report = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "config": {"ai_provider": args.ai_provider, "stratified": args.stratified},
                  "tools": {}}

        tools_to_run = []
        if args.tool in ("semgrep", "all"):
            tools_to_run.append(("semgrep", run_semgrep_benchmark, limit))
        if args.tool in ("codeql", "all"):
            # CodeQL 慢，小批量
            cq_limit = min(limit, 10)
            tools_to_run.append(("codeql", run_codeql_benchmark, cq_limit))
        if args.tool in ("hosls", "all"):
            tools_to_run.append(("hosls", run_hosls_benchmark, limit))

        for tool_name, runner, tl in tools_to_run:
            kwargs = {}
            if tool_name == "hosls":
                kwargs["ai_provider"] = args.ai_provider
            print(f"\n[{tool_name.upper()}] 测试 {tl} 条...")
            tool_report = runner(entries, tl, **kwargs)
            print_report(tool_report)
            report["tools"][tool_name] = tool_report

    # ── 保存 ──
    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = REPO_ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[INFO] 结果已保存: {out_path}")


if __name__ == "__main__":
    main()
