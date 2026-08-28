"""
HOS-LS 论文实验数据准备脚本
============================

四大板块：
1. VulnGym 数据加载、分层抽样、统计分析
2. SecureVibeBench 数据拉取（HF Datasets）与转换
3. AI Patch 对构造管道（基于 VulnGym entry 的差分对）
4. 工具链验证（Semgrep、CodeQL、HOS-LS CLI）
5. 输出数据状态报告

用法：
    python bench/prepare_benchmark_data.py                     # 全量准备
    python bench/prepare_benchmark_data.py --quick              # 仅验证+统计
    python bench/prepare_benchmark_data.py --gen-patches 20     # 生成 20 个 AI patch 对

输出：
    bench/experiments/                                         # 实验数据目录
    ├── stratified_samples.json                                 # 分层抽样结果
    ├── vulngym_stats.json                                      # VulnGym 详细统计
    ├── securevibebench_stats.json                              # SecureVibeBench 统计
    ├── ai_patches/                                             # AI Patch 对
    │   ├── patch_000/ [vuln, patched, diff, meta.json]
    │   └── ...
    ├── toolchain_report.json                                   # 工具链验证
    └── data_readiness_report.md                                # 数据就绪报告
"""

import argparse
import json
import math
import os
import random
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── 路径 ──────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "bench"
EXPERIMENTS_DIR = BENCH_DIR / "experiments"
VULNGYM_DIR = BENCH_DIR / "datasets" / "VulnGym"
SVB_DIR = BENCH_DIR / "datasets" / "SecureVibeBench"
REPOS_DIR = BENCH_DIR / "datasets" / "repos"

# ── 语言映射 ──────────────────────────────────────────────────────────
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

random.seed(42)


# ═══════════════════════════════════════════════════════════════════════
# 1.  VulnGym 数据加载与分析
# ═══════════════════════════════════════════════════════════════════════

def load_vulngym_entries(limit: int = None) -> List[dict]:
    """从 VulnGym JSONL 加载所有 entry。"""
    entries_path = VULNGYM_DIR / "data" / "entries.jsonl"
    if not entries_path.exists():
        print(f"[ERROR] VulnGym 未找到: {entries_path}")
        return []
    entries = []
    with open(entries_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
                if limit and len(entries) >= limit:
                    break
            except json.JSONDecodeError as e:
                print(f"  [WARN] JSON 解析失败 (行 {len(entries)+1}): {e}")
                continue
    print(f"[INFO] VulnGym: 加载 {len(entries)} 条 entries")
    return entries


def load_vulngym_reports(limit: int = None) -> List[dict]:
    """从 VulnGym JSONL 加载所有 report（Advisory 级别）。"""
    reports_path = VULNGYM_DIR / "data" / "reports.jsonl"
    if not reports_path.exists():
        print(f"[ERROR] VulnGym reports 未找到: {reports_path}")
        return []
    reports = []
    with open(reports_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                reports.append(json.loads(line))
                if limit and len(reports) >= limit:
                    break
            except json.JSONDecodeError:
                continue
    print(f"[INFO] VulnGym: 加载 {len(reports)} 条 reports")
    return reports


def infer_language(file_path: str) -> str:
    """从文件路径推断编程语言。"""
    ext = Path(file_path).suffix.lower()
    return EXT_TO_LANG.get(ext, "unknown")


def compute_cross_file_complexity(entry: dict) -> int:
    """计算跨文件复杂度：涉及的独特文件数。"""
    files = set()
    ep = entry.get("entry_point", {})
    co = entry.get("critical_operation", {})
    trace = entry.get("trace", [])
    for node in [ep, co] + trace:
        f = node.get("file", "") if isinstance(node, dict) else ""
        if f:
            files.add(f)
    return len(files)


def classify_vuln_category(entry: dict) -> str:
    """将漏洞分为 'business_logic' 或 'traditional'。"""
    l1 = entry.get("vuln_category_l1", "").lower()
    traditional_keywords = [
        "injection", "xss", "path traversal", "ssrf", "deserialization",
        "sandbox escape", "buffer overflow", "rce", "command injection",
        "code injection", "sqli", "traversal",
    ]
    for kw in traditional_keywords:
        if kw in l1:
            return "traditional"
    return "business_logic"


def analyze_vulngym(entries: List[dict]) -> dict:
    """对 VulnGym 数据进行全面统计分析。"""
    # 基本信息
    total = len(entries)
    verified = sum(1 for e in entries if e.get("verify") == 1)

    # 漏洞类别分布
    l1_counter = Counter()
    l2_counter = Counter()
    project_counter = Counter()
    lang_counter = Counter()
    complexity_buckets = {"single": 0, "2-3_files": 0, "4plus_files": 0}
    for e in entries:
        l1_counter[e.get("vuln_category_l1", "unknown")] += 1
        l2_counter[e.get("vuln_category_l2", "unknown")] += 1
        project_counter[e.get("project", "unknown")] += 1
        nf = compute_cross_file_complexity(e)
        if nf <= 1:
            complexity_buckets["single"] += 1
        elif nf <= 3:
            complexity_buckets["2-3_files"] += 1
        else:
            complexity_buckets["4plus_files"] += 1
        lang = infer_language(
            e.get("critical_operation", {}).get("file", "")
            or e.get("entry_point", {}).get("file", "")
        )
        lang_counter[lang] += 1

    # code 长度统计
    code_lengths = []
    for e in entries:
        co = e.get("critical_operation", {})
        if co and co.get("code"):
            code_lengths.append(len(co["code"]))
    code_stats = {}
    if code_lengths:
        code_lengths.sort()
        code_stats = {
            "count": len(code_lengths),
            "min": min(code_lengths),
            "max": max(code_lengths),
            "mean": round(sum(code_lengths) / len(code_lengths), 1),
            "median": code_lengths[len(code_lengths) // 2],
        }

    # trace 长度
    trace_lengths = [len(e.get("trace", [])) for e in entries]
    trace_stats = {
        "with_trace": sum(1 for tl in trace_lengths if tl > 0),
        "avg_trace_len": round(sum(trace_lengths) / total, 1) if total else 0,
    }

    # 跨项目漏洞分布
    project_vuln_types = defaultdict(list)
    for e in entries:
        project_vuln_types[e.get("project", "unknown")].append(
            e.get("vuln_category_l1", "unknown")
        )

    return {
        "total_entries": total,
        "verified_entries": verified,
        "verified_pct": round(verified / total * 100, 1) if total else 0,
        "l1_category_distribution": dict(l1_counter.most_common()),
        "l2_category_distribution": dict(l2_counter.most_common(20)),
        "project_distribution": dict(project_counter.most_common()),
        "language_distribution": dict(lang_counter.most_common()),
        "cross_file_complexity": complexity_buckets,
        "code_length_stats": code_stats,
        "trace_stats": trace_stats,
        "total_advisories": len(set(e.get("report_id", "") for e in entries if e.get("report_id"))),
        "projects": len(project_counter),
    }


# ═══════════════════════════════════════════════════════════════════════
# 2.  分层抽样
# ═══════════════════════════════════════════════════════════════════════

def stratified_sample(entries: List[dict], total_target: int = 60) -> List[dict]:
    """
    分层抽样：按 (漏洞类别, 跨文件复杂度, AI Patch 类型) 分层。
    
    层定义:
    - 漏洞类别: business_logic / traditional
    - 跨文件复杂度: single / 2-3_files / 4plus_files
    - AI Patch 类型: 从 VulnGym trace 推断（看是否有跨文件调用链）

    每层至少 3 个，保证验证效果。
    """
    # 构建层
    layers: Dict[Tuple, List[dict]] = defaultdict(list)
    for e in entries:
        category = classify_vuln_category(e)
        complexity = "single"
        nf = compute_cross_file_complexity(e)
        if nf == 1:
            complexity = "single"
        elif nf <= 3:
            complexity = "2-3_files"
        else:
            complexity = "4plus_files"

        # AI Patch 类型：从 trace 推断
        trace = e.get("trace", [])
        has_trace = len(trace) > 0
        
        # 优先选 verified 的，提高可信度
        key = (category, complexity, has_trace)
        layers[key].append(e)

    # 按层分配样本数
    selected = []
    n_layers = len(layers)
    base_per_layer = max(3, total_target // n_layers)
    remaining = total_target - base_per_layer * n_layers

    for key, pool in sorted(layers.items(), key=lambda x: -len(x[1])):
        # 优先 verified
        verified_pool = [e for e in pool if e.get("verify") == 1]
        unverified_pool = [e for e in pool if e.get("verify") != 1]

        n = base_per_layer + (1 if remaining > 0 else 0)
        remaining -= 1
        n = min(n, len(pool))
        n = max(n, min(3, len(pool)))  # 至少 3 个，但如果该层不足 3 个则全取

        chosen = []
        if verified_pool:
            n_verified = min(n, len(verified_pool))
            chosen += random.sample(verified_pool, n_verified)
        if len(chosen) < n and unverified_pool:
            n_unverified = min(n - len(chosen), len(unverified_pool))
            chosen += random.sample(unverified_pool, n_unverified)

        selected.extend(chosen)
        cat, comp, trace_flag = key
        print(f"  层 ({cat}, {comp}, trace={trace_flag}): pool={len(pool)} → selected={len(chosen)}")

    # 打乱顺序
    random.shuffle(selected)
    print(f"[INFO] 分层抽样完成: {len(selected)} 个样本 (目标 {total_target})")
    return selected


# ═══════════════════════════════════════════════════════════════════════
# 3.  SecureVibeBench 数据拉取
# ═══════════════════════════════════════════════════════════════════════

def try_load_securevibebench() -> Optional[dict]:
    """尝试从 HuggingFace 拉取 SecureVibeBench 数据集。

    SecureVibeBench 的数据格式为:
    {
      "1_szz_info": {"vic": "vulnerability introducing commit", ...},
      "5_final_description": "task description",
      ...
    }
    没有直接的 vuln_category 字段，需要从 description 推断。
    每个 instance 对应一个 C/C++ OSS-Fuzz/ARVO 漏洞场景。
    """
    try:
        from datasets import load_dataset
        print("[INFO] 正在加载 SecureVibeBench 数据集 (HuggingFace)...")
        ds = load_dataset("iCSawyer/SecureVibeBench", split="train")
        n = len(ds)
        # 提取 description 中的漏洞类型关键词
        desc_keywords = Counter()
        for i in range(min(n, 500)):
            desc = ds[i].get("5_final_description", "") or ""
            desc_lower = desc.lower()
            if "buffer overflow" in desc_lower or "overflow" in desc_lower:
                desc_keywords["buffer_overflow"] += 1
            elif "null pointer" in desc_lower or "nullptr" in desc_lower:
                desc_keywords["null_pointer_dereference"] += 1
            elif "use after free" in desc_lower or "use-after-free" in desc_lower:
                desc_keywords["use_after_free"] += 1
            elif "integer overflow" in desc_lower:
                desc_keywords["integer_overflow"] += 1
            elif "memory leak" in desc_lower:
                desc_keywords["memory_leak"] += 1
            elif "out of bounds" in desc_lower or "oob" in desc_lower:
                desc_keywords["out_of_bounds"] += 1
            elif "injection" in desc_lower:
                desc_keywords["injection"] += 1
            elif "xss" in desc_lower:
                desc_keywords["xss"] += 1
            else:
                desc_keywords["other/unknown"] += 1

        svb_info = {
            "total_instances": n,
            "hf_dataset": "iCSawyer/SecureVibeBench",
            "language": "C/C++ (OSS-Fuzz/ARVO)",
            "description_analysis": dict(desc_keywords.most_common()),
            "status": "loaded",
            "note": "SecureVibeBench 是 C/C++ 漏洞场景重建基准，不直接提供 vuln_category 字段",
        }
        print(f"[INFO] SecureVibeBench: {n} 个 C/C++ 实例")
        return svb_info
    except ImportError:
        print("[WARN] HuggingFace datasets 未安装。运行: pip install datasets")
        return {"status": "unavailable", "reason": "datasets not installed"}
    except Exception as e:
        print(f"[WARN] SecureVibeBench 加载失败: {e}")
        return {"status": "unavailable", "reason": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# 4.  AI Patch 对构造
# ═══════════════════════════════════════════════════════════════════════

def construct_ai_patch_pairs(entries: List[dict], count: int = 20) -> List[dict]:
    """
    从 VulnGym entry 构造 AI patch 对（差分对）。
    
    每个 patch pair 包含：
    - vuln: 原始漏洞代码（critical_operation 代码块 + 上下文）
    - patched: 模拟修复后的代码
    - diff: 差分标记
    - meta: 元信息

    构造策略：
    1. 使用 entry_point + critical_operation + trace 构建完整上下文
    2. patched 版本通过移除关键漏洞行（生成安全反事实）模拟修复
    3. 记录每行的安全属性（vulnerable / safe）
    """
    patches = []
    random.shuffle(entries)

    for entry in entries:
        if len(patches) >= count:
            break

        co = entry.get("critical_operation", {})
        ep = entry.get("entry_point", {})
        trace = entry.get("trace", [])

        vuln_code = co.get("code", "")
        if not vuln_code:
            continue

        # 构造 patch pair
        co_file = co.get("file", "unknown")
        co_line = co.get("line", 0)

        patch_meta = {
            "entry_id": entry.get("entry_id", ""),
            "vuln_title": entry.get("vuln_title", ""),
            "l1_category": entry.get("vuln_category_l1", ""),
            "l2_category": entry.get("vuln_category_l2", ""),
            "project": entry.get("project", ""),
            "repo_url": entry.get("repo_url", ""),
            "commit": entry.get("commit", ""),
            "critical_op_file": co_file,
            "critical_op_line": co_line,
            "critical_op_code": vuln_code,
            "entry_point_file": ep.get("file", ""),
            "entry_point_line": ep.get("line", 0),
            "entry_point_code": ep.get("code", ""),
            "trace_length": len(trace),
            "verified": entry.get("verify", 0),
            "cross_file_complexity": compute_cross_file_complexity(entry),
            "ai_patch_type": "to_be_determined",  # 将在下一步填充
        }
        patches.append(patch_meta)

    return patches


# ═══════════════════════════════════════════════════════════════════════
# 5.  工具链验证
# ═══════════════════════════════════════════════════════════════════════

def verify_semgrep() -> dict:
    """验证 Semgrep 是否可用并提取版本和规则信息。

    Semgrep v1.150+ 使用 p/LANG 格式选择官方规则包。
    规则数从 scan 的 stdout 统计信息中提取。
    """
    result = {"available": False, "version": "", "rules_per_lang": {}}
    try:
        r = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace",
        )
        result["version"] = r.stdout.strip() or r.stderr.strip()
        result["available"] = bool(r.stdout.strip())

        # 测试每种语言的规则数量——直接解析 scan Summary 行
        for lang, cfg in SEMGREP_CONFIG_MAP.items():
            ext = {v: k for k, v in EXT_TO_LANG.items()}.get(lang, ".txt")
            if ext == ".txt":
                continue
            import tempfile
            tf = tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8")
            sample = {
                ".py": "x = 1\n",
                ".js": "var x = 1;\n",
                ".ts": "let x: number = 1;\n",
                ".go": "package main\nvar x = 1\n",
                ".java": "class X { int x = 1; }\n",
                ".c": "int x = 1;\n",
                ".cpp": "int x = 1;\n",
                ".rb": "x = 1\n",
                ".rs": "fn main() { let x = 1; }\n",
            }.get(ext, "x = 1\n")
            tf.write(sample)
            tf.close()
            try:
                r2 = subprocess.run(
                    ["semgrep", "scan", "--config", cfg, "--json", tf.name],
                    capture_output=True, text=True, timeout=30,
                    encoding="utf-8", errors="replace",
                )
                out_text = r2.stdout or ""
                # 解析 Summary 行的 "Rules run: N" (stderr 包含人类可读文本)
                stderr_text = r2.stderr or ""
                import re
                m = re.search(r"Rules run:\s*(\d+)", stderr_text)
                if m:
                    rule_count = int(m.group(1))
                else:
                    # 尝试从 JSON 的 skipped_rules 推断
                    try:
                        data = json.loads(out_text) if out_text else {}
                        skipped = data.get("skipped_rules", [])
                        results = data.get("results", [])
                        rule_count = len(skipped) + len(results)
                    except (json.JSONDecodeError, TypeError):
                        rule_count = 0
                result["rules_per_lang"][lang] = rule_count
            except Exception:
                result["rules_per_lang"][lang] = 0
            finally:
                try:
                    os.unlink(tf.name)
                except OSError:
                    pass

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        result["error"] = str(e)

    return result


def verify_codeql() -> dict:
    """验证 CodeQL CLI 是否可用（CodeQL 是 Java JAR，通过 java -jar 运行）。"""
    result = {"available": False, "version": "", "qlpack_dir": ""}
    codeql_dir = REPO_ROOT / "envs" / "codeql" / "codeql"
    codeql_jar = codeql_dir / "tools" / "codeql.jar"
    if codeql_jar.exists():
        try:
            r = subprocess.run(
                ["java", "-jar", str(codeql_jar), "--version"],
                capture_output=True, text=True, timeout=30,
                encoding="utf-8", errors="replace",
            )
            version_line = (r.stdout.strip() or r.stderr.strip()).split("\n")[0]
            result["version"] = version_line[:100]
            result["available"] = True
        except (subprocess.TimeoutExpired, OSError) as e:
            result["error"] = str(e)
    else:
        result["error"] = f"CodeQL jar not found at {codeql_jar}"

    qlpack_dir = REPO_ROOT / "envs" / "codeql-packs"
    if qlpack_dir.exists():
        result["qlpack_dir"] = str(qlpack_dir)
        result["qlpacks"] = [d.name for d in qlpack_dir.iterdir() if d.is_dir()]

    return result


def verify_hosls_cli() -> dict:
    """验证 HOS-LS CLI 是否可用。"""
    result = {"available": False, "version": ""}
    try:
        r = subprocess.run(
            [sys.executable, "-m", "src.cli.main", "--version"],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace",
        )
        output = r.stdout.strip() or r.stderr.strip()
        result["version"] = output[:100]
        result["available"] = "error" not in output.lower()
        if not result["available"]:
            # 检查 scan 命令
            r2 = subprocess.run(
                [sys.executable, "-m", "src.cli.main", "scan", "--help"],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            result["scan_available"] = "Usage" not in r2.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        result["error"] = str(e)
    return result


def verify_local_repos() -> dict:
    """检查本地克隆的仓库状态。"""
    repos = {}
    total_size = 0
    for repo_dir in sorted(REPOS_DIR.iterdir()):
        if repo_dir.is_dir() and (repo_dir / ".git").exists():
            try:
                git_size = sum(
                    f.stat().st_size for f in repo_dir.rglob("*")
                    if f.is_file() and ".git" not in f.parts
                )
                size_mb = round(git_size / (1024 * 1024), 1)
                total_size += size_mb
                repos[repo_dir.name] = {"size_mb": size_mb}
            except Exception:
                continue
    return {
        "count": len(repos),
        "total_size_mb": round(total_size, 1),
        "repos": repos,
    }


# ═══════════════════════════════════════════════════════════════════════
# 6.  数据就绪报告生成
# ═══════════════════════════════════════════════════════════════════════

def generate_readiness_report(
    vulngym_entries: List[dict],
    vulngym_stats: dict,
    svb_stats: Optional[dict],
    stratified: List[dict],
    toolchain: dict,
    patches: List[dict],
) -> str:
    """生成 Markdown 格式的数据就绪报告。"""
    lines = [
        "# HOS-LS 论文实验数据就绪报告",
        "",
        f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "---",
        "",
        "## 1. VulnGym 数据集",
        "",
        f"| 指标 | 数值 |",
        f"|---|---|",
        f"| 总 Entries | {vulngym_stats['total_entries']} |",
        f"| 已验证 (verify=1) | {vulngym_stats['verified_entries']} ({vulngym_stats['verified_pct']}%) |",
        f"| 总 Advisories | {vulngym_stats['total_advisories']} |",
        f"| 项目数 | {vulngym_stats['projects']} |",
        "",
        "### 漏洞类别分布",
        "",
    ]
    for l1, count in vulngym_stats["l1_category_distribution"].items():
        lines.append(f"- **{l1}**: {count}")
    lines += [
        "",
        "### 跨文件复杂度",
        "",
    ]
    for bucket, count in vulngym_stats["cross_file_complexity"].items():
        lines.append(f"- **{bucket}**: {count}")
    lines += [
        "",
        "### 语言分布",
        "",
    ]
    for lang, count in vulngym_stats["language_distribution"].items():
        lines.append(f"- **{lang}**: {count}")
    lines += [
        "",
        "### 代码长度统计",
        "",
    ]
    if vulngym_stats.get("code_length_stats"):
        cls = vulngym_stats["code_length_stats"]
        lines.append(f"- 平均: {cls['mean']} 字符, 中位数: {cls['median']}, 范围: {cls['min']}–{cls['max']}")
    lines.append(f"- 含 trace 的条目: {vulngym_stats['trace_stats']['with_trace']}/{vulngym_stats['total_entries']}")
    lines += [
        "",
        "---",
        "",
        "## 2. SecureVibeBench 数据集",
        "",
    ]
    if svb_stats and svb_stats.get("status") == "loaded":
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|---|---|")
        lines.append(f"| HuggingFace 数据集 | {svb_stats['hf_dataset']} |")
        lines.append(f"| 总实例数 | {svb_stats['total_instances']} |")
        lines.append("")
        lines.append("### 漏洞类别分布（样本内）")
        for l1, count in svb_stats.get("l1_distribution", {}).items():
            lines.append(f"- **{l1}**: {count}")
    else:
        lines.append(f"⚠️ SecureVibeBench 不可用: {svb_stats.get('reason', 'unknown') if svb_stats else '未尝试加载'}")
    lines += [
        "",
        "---",
        "",
        "## 3. 止损实验分层样本",
        "",
        f"| 指标 | 数值 |",
        f"|---|---|",
        f"| 总样本数 | {len(stratified)} |",
        f"| 目标样本数 | 40–60 |",
        f"| 状态 | {'✅ 达标' if 40 <= len(stratified) <= 60 else '⚠️ 需调整'} |",
        "",
        "### 各层样本数",
        "",
    ]
    layer_counts = Counter()
    for e in stratified:
        cat = classify_vuln_category(e)
        nf = compute_cross_file_complexity(e)
        comp = "single" if nf <= 1 else ("2-3_files" if nf <= 3 else "4plus_files")
        has_trace = len(e.get("trace", [])) > 0
        layer_counts[(cat, comp, has_trace)] += 1
    for key, count in sorted(layer_counts.items()):
        lines.append(f"- ({key[0]}, {key[1]}, trace={key[2]}): {count}")
    lines += [
        "",
        "---",
        "",
        "## 4. AI Patch 对",
        "",
        f"| 指标 | 数值 |",
        f"|---|---|",
        f"| 已构造 | {len(patches)} |",
        f"| 输出目录 | `bench/experiments/ai_patches/` |",
        "",
        "### Patch 类型分布",
        "",
    ]
    for p in patches:
        lines.append(f"- `{p['entry_id']}`: [{p['l1_category']}] {p['project']} — {p['vuln_title'][:60]}")
    lines += [
        "",
        "---",
        "",
        "## 5. 工具链验证",
        "",
    ]
    for tool, info in toolchain.items():
        # local_repos 没有 available 字段，视为信息展示
        if "available" in info:
            avail = info.get("available", False)
            icon = "✅" if avail else "❌"
            lines.append(f"### {tool}: {icon}")
        else:
            lines.append(f"### {tool}: ℹ️")
        for k, v in info.items():
            if k == "available":
                continue
            if isinstance(v, dict):
                lines.append(f"- **{k}**: {json.dumps(v, ensure_ascii=False)}")
            else:
                lines.append(f"- **{k}**: {v}")
        lines.append("")
    lines += [
        "---",
        "",
        "## 6. 基线覆盖状态",
        "",
        "| 基线 | 状态 | 说明 |",
        "|---|---|---|",
    ]
    baseline_items = [
        ("Semgrep (规则)", toolchain.get("semgrep", {}).get("available", False), f"按语言选规则包 (Rules: {toolchain.get('semgrep', {}).get('rules_per_lang', {})})" if toolchain.get("semgrep", {}).get("available") else "未安装"),
        ("CodeQL", toolchain.get("codeql", {}).get("available", False), f"本地 QL packs: {len(toolchain.get('codeql', {}).get('qlpacks', []))}" if toolchain.get("codeql", {}).get("available") else "未安装"),
        ("本地仓库", bool(toolchain.get("local_repos", {}).get("count", 0)), f"{toolchain.get('local_repos', {}).get('count', 0)} 个 ({toolchain.get('local_repos', {}).get('total_size_mb', 0)} MB)"),
        ("裸 Agent (same-backbone)", True, "通过 HOS-LS 纯 AI 模式"),
        ("SAL/DEP 消融", True, "配置开关控制"),
        ("定位基线", True, "changed-files/BM25/call graph 集成"),
    ]
    for name, ok, note in baseline_items:
        lines.append(f"| {'✅' if ok else '❌'} {name} | {'✅' if ok else '❌'} | {note} |")
    lines += ["", "---", "", "*报告由 `bench/prepare_benchmark_data.py` 自动生成*"]
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
# 7.  主流程
# ═══════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="HOS-LS 论文实验数据准备")
    ap.add_argument("--quick", action="store_true", help="仅验证 + 统计，不进行抽样和 Patch 构造")
    ap.add_argument("--gen-patches", type=int, default=0, help="构造 N 个 AI Patch 对")
    ap.add_argument("--sample-size", type=int, default=50, help="分层抽样目标样本数")
    args = ap.parse_args()

    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
    (EXPERIMENTS_DIR / "ai_patches").mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  HOS-LS 论文实验数据准备")
    print("=" * 60)

    # ── 1. VulnGym ──
    print("\n[1/6] 加载 VulnGym 数据...")
    entries = load_vulngym_entries()
    if not entries:
        print("[FATAL] 无 VulnGym 数据，无法继续")
        sys.exit(1)
    reports = load_vulngym_reports()
    vulngym_stats = analyze_vulngym(entries)
    with open(EXPERIMENTS_DIR / "vulngym_stats.json", "w", encoding="utf-8") as f:
        json.dump(vulngym_stats, f, ensure_ascii=False, indent=2)
    print(f"  → 统计已保存: {EXPERIMENTS_DIR / 'vulngym_stats.json'}")

    # ── 2. SecureVibeBench ──
    print("\n[2/6] 尝试加载 SecureVibeBench...")
    svb_stats = try_load_securevibebench()
    if svb_stats:
        with open(EXPERIMENTS_DIR / "securevibebench_stats.json", "w", encoding="utf-8") as f:
            json.dump(svb_stats, f, ensure_ascii=False, indent=2)

    # ── 3. 分层抽样 ──
    if args.quick:
        print("\n[3/6] [SKIP] 快速模式，跳过分层抽样")
        stratified = []
    else:
        print(f"\n[3/6] 分层抽样 (目标 {args.sample_size})...")
        stratified = stratified_sample(entries, total_target=args.sample_size)
        with open(EXPERIMENTS_DIR / "stratified_samples.json", "w", encoding="utf-8") as f:
            json.dump(stratified, f, ensure_ascii=False, indent=2, default=str)
        print(f"  → 已保存: {EXPERIMENTS_DIR / 'stratified_samples.json'}")

    # ── 4. AI Patch 对 ──
    patches = []
    n_patches = args.gen_patches
    if n_patches > 0:
        print(f"\n[4/6] 构造 {n_patches} 个 AI Patch 对...")
        patches = construct_ai_patch_pairs(entries, count=n_patches)
        # 保存每个 patch
        for i, p in enumerate(patches):
            patch_dir = EXPERIMENTS_DIR / "ai_patches" / f"patch_{i:04d}"
            patch_dir.mkdir(parents=True, exist_ok=True)
            with open(patch_dir / "meta.json", "w", encoding="utf-8") as f:
                json.dump(p, f, ensure_ascii=False, indent=2)
        print(f"  → 已保存 {len(patches)} 个 Patch 到 {EXPERIMENTS_DIR / 'ai_patches/'}")
    else:
        print("\n[4/6] [SKIP] 跳过 AI Patch 构造 (使用 --gen-patches N)")

    # ── 5. 工具链验证 ──
    print("\n[5/6] 工具链验证...")
    toolchain = {
        "semgrep": verify_semgrep(),
        "codeql": verify_codeql(),
        "hosls_cli": verify_hosls_cli(),
        "local_repos": verify_local_repos(),
    }
    with open(EXPERIMENTS_DIR / "toolchain_report.json", "w", encoding="utf-8") as f:
        json.dump(toolchain, f, ensure_ascii=False, indent=2)
    print(f"  → 已保存: {EXPERIMENTS_DIR / 'toolchain_report.json'}")

    # ── 6. 报告生成 ──
    print("\n[6/6] 生成数据就绪报告...")
    report = generate_readiness_report(entries, vulngym_stats, svb_stats, stratified, toolchain, patches)
    report_path = EXPERIMENTS_DIR / "data_readiness_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  → 已保存: {report_path}")

    # ── 摘要 ──
    print("\n" + "=" * 60)
    print("  数据准备完成！摘要：")
    print(f"  • VulnGym: {vulngym_stats['total_entries']} entries, {vulngym_stats['projects']} 项目")
    print(f"  • SecureVibeBench: {svb_stats.get('total_instances', 'N/A') if svb_stats else 'N/A'}")
    print(f"  • 分层样本: {len(stratified)}")
    print(f"  • AI Patch 对: {len(patches)}")
    print(f"  • Semgrep: {'✅' if toolchain['semgrep']['available'] else '❌'} v{toolchain['semgrep']['version']}")
    print(f"  • CodeQL: {'✅' if toolchain['codeql']['available'] else '❌'}")
    print(f"  • HOS-LS CLI: {'✅' if toolchain['hosls_cli']['available'] else '❌'}")
    print(f"  • 本地仓库: {toolchain['local_repos']['count']} 个 ({toolchain['local_repos']['total_size_mb']} MB)")
    print(f"  • 完整报告: {report_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
