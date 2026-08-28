"""对比测试脚本 — 在 VulnGym 样本上运行 Semgrep + HOS-LS

模式：
  snippet (default) : 从 entries.jsonl 提取代码片段到临时文件后扫描
  repo              : 在克隆的完整仓库上扫描对应文件

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
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VULNGYM_DIR = REPO_ROOT / "bench" / "datasets" / "VulnGym"
REPOS_DIR = REPO_ROOT / "bench" / "datasets" / "repos"

# VulnGym 项目名 -> 本地仓库目录名的映射
# 依据 entries.jsonl 中的 project 字段 -> repos/ 下的目录
REPO_DIR_MAP = {
    "openclaw": "openclaw",
    "OpenClaw": "openclaw",
    "OpenClaw Gateway": "openclaw",
    "@openclaw/nextcloud-talk": "openclaw",
    "openclaw/openclaw": "openclaw",
    "n8n": "n8n",
    "FlowiseAI/Flowise": "Flowise",
    "Flowise": "Flowise",
    "Flowise (FlowiseAI/Flowise)": "Flowise",
    "flowise": "Flowise",
    "NVIDIA/NeMo": "NeMo",
    "NVIDIA NeMo": "NeMo",
    "NVIDIA NeMo Framework": "NeMo",
    "paperclip": "paperclip",
    "paperclipai/paperclip": "paperclip",
    "langflow": "langflow",
    "langflow-ai/langflow": "langflow",
    "Langflow": "langflow",
    "mlflow": "mlflow",
    "MLflow": "mlflow",
    "WeKnora": "WeKnora",
    "Tencent/WeKnora": "WeKnora",
    "ollama": "ollama",
    "google/adk-python": "adk-python",
    "milvus": "milvus",
    "milvus-io/milvus": "milvus",
    "apache/airflow": "airflow",
    "Apache Airflow": "airflow",
    "open-webui": "open-webui",
    "fastmcp": "fastmcp",
    "langchain-core": "langchain",
    "langchain-ai/langchain": "langchain",
    "aquasecurity/trivy": "trivy",
    "n8n-mcp": "n8n-mcp",
    "AutoGPT": "AutoGPT",
    "Significant-Gravitas/AutoGPT": "AutoGPT",
    "typescript-sdk": "typescript-sdk",
    "modelcontextprotocol/typescript-sdk": "typescript-sdk",
    "onnx": "onnx",
    "nltk": "nltk",
    "litellm": "litellm",
    "BerriAI/litellm": "litellm",
}


def load_vulngym_entries(limit: int = None):
    """从 VulnGym 加载所有或前 N 条含有效代码样本的条目"""
    entries_path = VULNGYM_DIR / "data" / "entries.jsonl"
    if not entries_path.exists():
        print(f"[ERROR] VulnGym 未找到: {entries_path}")
        return []

    entries = []
    with open(entries_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
                # 检查是否有代码样本（critical_operation 中有代码）
                co = entry.get("critical_operation", {})
                if co and co.get("code"):
                    entries.append(entry)
                if limit and len(entries) >= limit:
                    break
            except json.JSONDecodeError:
                continue

    print(f"[INFO] 加载 {len(entries)} 条 VulnGym 条目（含代码样本）")
    return entries


def detect_language_from_path(file_path: str) -> str:
    """从文件路径推断编程语言"""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".rb": "ruby",
        ".php": "php",
        ".rs": "rust",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".vue": "javascript",
        ".svelte": "javascript",
    }
    ext = Path(file_path).suffix.lower()
    return ext_map.get(ext, "python")


def run_semgrep_on_code(code: str, lang: str = "python") -> dict:
    """在代码片段上运行 Semgrep，返回命中结果"""
    import tempfile

    # 根据语言确定文件后缀
    ext_map = {
        "python": ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "java": ".java",
        "go": ".go",
        "c": ".c",
        "cpp": ".cpp",
    }
    ext = ext_map.get(lang, ".py")

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", "p/default", "--config", "p/security-audit",
             "--json", "-q", tmp_path],
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


def run_semgrep_benchmark(entries: list, limit: int = 50) -> dict:
    """在 entries 上运行 Semgrep 基准测试"""
    total = len(entries)
    results = []
    start = time.time()

    for i, entry in enumerate(entries[:limit]):
        co = entry.get("critical_operation", {})
        code = co.get("code", "")
        lang = entry.get("language", "python")
        if not code:
            continue

        semgrep_result = run_semgrep_on_code(code, lang)
        results.append({
            "entry_id": entry.get("entry_id", f"entry-{i}"),
            "project": entry.get("project", "unknown"),
            "vuln_type": entry.get("vuln_category_l1", "unknown"),
            "cwe": entry.get("cwe", ""),
            "semgrep_hits": semgrep_result["total_hits"],
            "semgrep_rules": semgrep_result["rules"],
        })

        if (i + 1) % 10 == 0:
            elapsed = time.time() - start
            print(f"  Semgrep: {i+1}/{limit} ({elapsed:.0f}s)")

    elapsed = time.time() - start

    # 汇总
    total_hits = sum(r["semgrep_hits"] for r in results)
    hit_entries = sum(1 for r in results if r["semgrep_hits"] > 0)

    return {
        "tool": "semgrep",
        "total_entries": len(results),
        "entries_with_hits": hit_entries,
        "detection_rate": round(hit_entries / len(results) * 100, 1) if results else 0,
        "total_hits": total_hits,
        "avg_hits_per_entry": round(total_hits / len(results), 2) if results else 0,
        "wall_time_s": round(elapsed, 1),
        "details": results,
    }


def _hosls_cmd_args(file_path: str, ai_provider: str = "deepseek") -> list:
    """构造 HOS-LS scan 命令行参数

    注意: HOS-LS 的 scan 命令通过 @cli.command() 装饰器在模块 import 时注册。
    python -m src.cli.main 不会自动触发 scan_cmd 的 import，所以 scan 命令不可用。
    这里生成调用 bench/run_hosls_scan.py 的命令——一个独立的入口脚本。
    """
    norm_path = file_path.replace("\\", "/")
    cmd = [sys.executable, "-u",
           str(REPO_ROOT / "bench" / "run_hosls_scan.py"),
           norm_path, "--ai-provider", ai_provider]
    return cmd


def run_hosls_benchmark(entries: list, limit: int = 20, ai_provider: str = "deepseek") -> dict:
    """在 entries 上运行 HOS-LS 扫描"""
    # 将 VulnGym 条目转换为临时文件并扫描
    import tempfile
    import shutil

    temp_dir = Path(tempfile.mkdtemp(prefix="hosls-bench-"))
    results = []
    start = time.time()

    try:
        for i, entry in enumerate(entries[:limit]):
            co = entry.get("critical_operation", {})
            code = co.get("code", "")
            if not code:
                continue

            ext_map = {"python": ".py", "javascript": ".js", "go": ".go", "java": ".java"}
            ext = ext_map.get(entry.get("language", "python"), ".py")

            tmp_file = temp_dir / f"entry_{i:04d}{ext}"
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
            results.append({
                "entry_id": entry.get("entry_id", f"entry-{i}"),
                "project": entry.get("project", "unknown"),
                "vuln_type": entry.get("vuln_category_l1", "unknown"),
                "hosls_findings": len(findings),
                "hosls_confirmed": sum(1 for f in findings if f.get("status") == "CONFIRMED"),
                "hosls_error": result.stderr[:200] if result.returncode != 0 else "",
            })

            if (i + 1) % 5 == 0:
                elapsed = time.time() - start
                print(f"  HOS-LS: {i+1}/{limit} ({elapsed:.0f}s)")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    elapsed = time.time() - start
    hit_entries = sum(1 for r in results if r["hosls_findings"] > 0)

    return {
        "tool": "hosls",
        "total_entries": len(results),
        "entries_with_findings": hit_entries,
        "detection_rate": round(hit_entries / len(results) * 100, 1) if results else 0,
        "total_findings": sum(r["hosls_findings"] for r in results),
        "total_confirmed": sum(r["hosls_confirmed"] for r in results),
        "wall_time_s": round(elapsed, 1),
        "details": results,
    }


def print_report(report: dict):
    """打印汇总报告"""
    print(f"\n{'='*60}")
    print(f"  工具: {report['tool'].upper()}")
    print(f"  条目数: {report['total_entries']}")
    print(f"  检出条目: {report.get('entries_with_hits', report.get('entries_with_findings', 0))}")
    print(f"  检出率: {report.get('detection_rate', 0)}%")
    print(f"  耗时: {report['wall_time_s']}s")

    if report.get("total_hits") is not None:
        print(f"  总命中数: {report['total_hits']}")
        print(f"  平均命中/条目: {report['avg_hits_per_entry']}")
    if report.get("total_confirmed") is not None:
        print(f"  总发现: {report['total_findings']}")
        print(f"  已确认: {report['total_confirmed']}")
    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# 仓库级扫描模式 (--mode repo)
# ---------------------------------------------------------------------------

def resolve_entry_repo_path(entry: dict) -> Path | None:
    """将 VulnGym 条目解析为本地仓库中的真实文件路径"""
    project = entry.get("project", "")
    file_rel = entry.get("critical_operation", {}).get("file", "")
    if not file_rel:
        return None

    # 通过 REPO_DIR_MAP 找本地目录
    local_dir = REPO_DIR_MAP.get(project)
    if not local_dir:
        # 尝试模糊匹配
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
        # 尝试在 repo 内搜索文件名
        filename = Path(file_rel).name
        matches = list(repo_path.rglob(filename))
        if matches:
            full_path = matches[0]
            print(f"  [INFO] 通过文件名 '{filename}' 找到: {full_path.relative_to(repo_path)}")
        else:
            print(f"  [WARN] 文件未找到: {file_rel} (在 {repo_path})")
            return None

    return full_path


def run_semgrep_on_repo_file(file_path: Path, entry: dict) -> dict:
    """在仓库里的真实文件上运行 Semgrep"""
    lang = detect_language_from_path(str(file_path))

    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", "p/default", "--config", "p/security-audit",
             "--json", "-q", str(file_path)],
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


def run_hosls_on_repo_file(file_path: Path, entry: dict, ai_provider: str = "deepinfra") -> dict:
    """在仓库里的真实文件上运行 HOS-LS"""
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


def run_repo_benchmark(entries: list, tool: str, limit: int = 50, ai_provider: str = "deepinfra") -> dict:
    """仓库级扫描基准测试"""
    results = []
    start = time.time()
    resolved = 0
    skipped = 0

    for i, entry in enumerate(entries[:limit]):
        entry_id = entry.get("entry_id", f"entry-{i}")
        project = entry.get("project", "unknown")
        vuln_type = entry.get("vuln_category_l1", "unknown")

        file_path = resolve_entry_repo_path(entry)
        if file_path is None:
            results.append({
                "entry_id": entry_id,
                "project": project,
                "vuln_type": vuln_type,
                "status": "skipped",
                "reason": "file_not_found",
            })
            skipped += 1
            continue

        resolved += 1

        if tool in ("semgrep", "all"):
            semgrep_result = run_semgrep_on_repo_file(file_path, entry)
            results.append({
                "entry_id": entry_id,
                "project": project,
                "vuln_type": vuln_type,
                "status": "scanned",
                "file": str(file_path),
                "semgrep_hits": semgrep_result["total_hits"],
                "semgrep_rules": semgrep_result["rules"],
                "semgrep_severities": semgrep_result["severities"],
                "semgrep_error": semgrep_result.get("error", ""),
            })
        else:  # hosls
            hosls_result = run_hosls_on_repo_file(file_path, entry, ai_provider=ai_provider)
            results.append({
                "entry_id": entry_id,
                "project": project,
                "vuln_type": vuln_type,
                "status": "scanned",
                "file": str(file_path),
                "hosls_findings": hosls_result["hosls_findings"],
                "hosls_confirmed": hosls_result["hosls_confirmed"],
                "hosls_error": hosls_result["hosls_error"],
            })

        if (i + 1) % 10 == 0:
            elapsed = time.time() - start
            print(f"  {tool}: {i+1}/{limit} ({elapsed:.0f}s, resolved={resolved}, skipped={skipped})")

    elapsed = time.time() - start
    scanned = [r for r in results if r["status"] == "scanned"]

    detection_key = "semgrep_hits" if tool == "semgrep" else "hosls_findings"
    hit_entries = sum(1 for r in scanned if r.get(detection_key, 0) > 0)

    return {
        "tool": tool,
        "mode": "repo",
        "total_entries": len(results),
        "resolved": resolved,
        "skipped": skipped,
        "entries_with_hits": hit_entries,
        "detection_rate": round(hit_entries / len(scanned) * 100, 1) if scanned else 0,
        "total_hits": sum(r.get(detection_key, 0) for r in scanned),
        "wall_time_s": round(elapsed, 1),
        "details": results,
    }


def print_repo_report(report: dict):
    """打印仓库级扫描报告"""
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
    """检查已下载的仓库状态"""
    available = {}
    for repo_dir in sorted(REPOS_DIR.iterdir()):
        if repo_dir.is_dir() and (repo_dir / ".git").exists():
            git_size = sum(f.stat().st_size for f in repo_dir.rglob("*") if f.is_file())
            available[repo_dir.name] = {
                "path": str(repo_dir),
                "size_mb": round(git_size / (1024 * 1024), 1),
            }
    return available


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="对比测试: Semgrep vs HOS-LS on VulnGym")
    ap.add_argument("--tool", choices=["semgrep", "hosls", "all"], default="all")
    ap.add_argument("--limit", type=int, default=20, help="测试条目数")
    ap.add_argument("--output", default="bench/artifacts/comparison-result.json")
    ap.add_argument("--mode", choices=["snippet", "repo"], default="snippet",
                    help="snippet: 代码片段级; repo: 仓库级文件扫描")
    ap.add_argument("--ai-provider", default="deepinfra",
                    help="HOS-LS AI provider (deepinfra, deepseek, aliyun; 默认 deepinfra)")
    args = ap.parse_args()

    if args.mode == "repo" and args.tool == "all":
        print("[INFO] 仓库模式不支持同时跑所有工具，请用 --tool semgrep 或 --tool hosls")
        return

    if args.mode == "repo":
        # ── 仓库级模式 ──
        available = check_available_repos()
        if not available:
            print("[ERROR] 无可用仓库，请先下载到 bench/datasets/repos/")
            print("        示例: git clone --depth 1 <url> bench/datasets/repos/<name>")
            return

        print(f"[INFO] 已下载 {len(available)} 个仓库:")
        for name, info in sorted(available.items()):
            print(f"  - {name}: {info['size_mb']} MB")

        entries = load_vulngym_entries(args.limit)
        if not entries:
            print("[ERROR] 无可用条目")
            return

        report = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "mode": "repo",
                  "config": {"tool": args.tool, "limit": args.limit,
                             "ai_provider": args.ai_provider},
                  "tools": {}}

        print(f"\n[仓库扫描] 工具={args.tool}, AI provider={args.ai_provider}, 限制={args.limit} 条")
        repo_report = run_repo_benchmark(entries, args.tool, args.limit, ai_provider=args.ai_provider)
        print_repo_report(repo_report)
        report["tools"][args.tool] = repo_report
    else:
        # ── 代码片段模式（原有逻辑） ──
        entries = load_vulngym_entries(args.limit)
        if not entries:
            print("[ERROR] 无可用条目")
            return

        report = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "config": {"ai_provider": args.ai_provider},
                  "tools": {}}

        if args.tool in ("semgrep", "all"):
            print(f"\n[Semgrep] 测试 {min(len(entries), 50)} 条...")
            semgrep_report = run_semgrep_benchmark(entries, min(50, args.limit))
            print_report(semgrep_report)
            report["tools"]["semgrep"] = semgrep_report

        if args.tool in ("hosls", "all"):
            print(f"\n[HOS-LS] 测试 {min(len(entries), args.limit)} 条... (provider={args.ai_provider})")
            hosls_report = run_hosls_benchmark(entries, args.limit, ai_provider=args.ai_provider)
            print_report(hosls_report)
            report["tools"]["hosls"] = hosls_report

    # 保存
    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = REPO_ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[INFO] 结果已保存: {out_path}")


if __name__ == "__main__":
    main()
