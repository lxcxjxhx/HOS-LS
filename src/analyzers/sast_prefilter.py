"""SAST 深度前置过滤 v2（OPT-SASTR2 · hard-first）— AI 之前先让硬检测出结果。

**架构（用户指定）**：
- 硬检测（CodeQL，仓库级深度分析底座）能确定的 → 直接产出硬 findings，**不消耗 AI token**；
- CodeQL 判不了的盲区样本（跨函数/语义类，如 RepoPairBench 的 06fdf927/08926a1a）→ 才进入 AI 深度分析。

**模式（config.sast_prefilter.mode）**：
- `hard-first`（默认，用户指定）：CodeQL 命中文件 → 硬 findings（无 AI）；CodeQL 未命中文件 → AI。
- `skip`（旧版，废弃参考）：零命中文件跳过 AI（反向，丢盲区检出，不推荐）。
- `evidence-only`：全部文件仍走 AI，SAST 证据注入 Agent-3。
- `off`：完全关闭。

**CodeQL 正确用法**（安装后自动探测）：
1. `codeql version` 探测 CLI。
2. `codeql database create <db> --language=<lang> --source-root=<src> --overwrite` 建库
   （Python 提取器无需编译，松散 .py 目录亦可建库）。
3. `codeql database analyze <db> --format=sarif-latest --output=<sarif> <query-suite>`
   其中 query-suite 解析顺序：环境变量 `CODEQL_QUERIES` > 内建包（CLI zip 捆绑的
   codeql/<lang>-queries 或 codeql-security-and-quality）> `--download` 自动拉取。
4. SARIF 解析 → hits（file/line/ruleId/CWE/level）。

内置 AST/CST 过滤（上一版）仅作可选证据注入（`backends` 含 builtin 时），不作门控。
全部本地确定性计算，0 LLM token。
"""
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SastPrefilter:
    """SAST 深度前置过滤执行器（v2 · hard-first）。"""

    def __init__(self, config: Optional[Any] = None):
        if isinstance(config, dict):
            self.enabled = config.get("enabled", True)
            self.mode = config.get("mode", "cascade")
            self.skip_ai_if_no_hits = config.get("skip_ai_if_no_hits", False)  # 兼容旧配置
            self.inject_evidence = config.get("inject_evidence", True)
            self.backends = config.get("backends", ["codeql", "semgrep", "bandit"])
            self.min_severity = config.get("min_severity", "warning")
            self.codeql_db_path = config.get("codeql_db_path", "")
            self.codeql_queries = config.get("codeql_queries", "")
            self.codeql_pack_dir = config.get("codeql_pack_dir", "")
            self.semgrep_rules_dir = config.get("semgrep_rules_dir", "")
        else:
            self.enabled = getattr(config, "enabled", True)
            self.mode = getattr(config, "mode", "cascade")
            self.skip_ai_if_no_hits = getattr(config, "skip_ai_if_no_hits", False)
            self.inject_evidence = getattr(config, "inject_evidence", True)
            self.backends = getattr(config, "backends", ["codeql", "semgrep", "bandit"])
            self.min_severity = getattr(config, "min_severity", "warning")
            self.codeql_db_path = getattr(config, "codeql_db_path", "")
            self.codeql_queries = getattr(config, "codeql_queries", "")
            self.codeql_pack_dir = getattr(config, "codeql_pack_dir", "")
            self.semgrep_rules_dir = getattr(config, "semgrep_rules_dir", "")
        # 旧 skip 模式兼容
        if self.mode == "skip" and self.skip_ai_if_no_hits:
            self.mode = "skip"

    # ---------- 探测 ----------

    @staticmethod
    def _envs_bin(name: str) -> Optional[str]:
        """在项目 envs 布局下定位工具二进制（codeql / semgrep / bandit）。"""
        cand = shutil.which(name)
        if cand:
            return cand
        here = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        probes = {
            "codeql": [os.path.join(here, "envs", "codeql", "codeql.exe")],
            "semgrep": [os.path.join(here, "envs", "sast-venv", "Scripts", "semgrep.exe")],
            "bandit": [os.path.join(here, "envs", "sast-venv", "Scripts", "bandit.exe")],
        }
        for p in probes.get(name, []):
            if os.path.exists(p):
                return p
        return None

    @staticmethod
    def codeql_available() -> bool:
        return SastPrefilter._envs_bin("codeql") is not None

    @staticmethod
    def _run(cmd: List[str], timeout: int = 3600) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")

    def _resolve_query_suite(self, codeql_bin: str) -> Optional[str]:
        """解析 CodeQL 查询套件：环境变量 > 内建包 > 默认套件。"""
        if self.codeql_queries and os.path.exists(self.codeql_queries):
            return self.codeql_queries
        env_q = os.environ.get("CODEQL_QUERIES", "")
        if env_q and os.path.exists(env_q):
            return env_q
        # 探测 CLI 捆绑的查询包（codeql/python-queries 等）
        cli_root = os.path.dirname(os.path.dirname(codeql_bin))
        candidates = [
            os.path.join(cli_root, "codeql", "python-queries"),
            os.path.join(cli_root, "python-queries"),
            os.path.join(cli_root, "codeql", "codeql-queries"),
            os.path.join(cli_root, "codeql-queries"),
        ]
        # 项目 envs 布局下的查询包（codeql_pack_dir 或 envs/codeql-packs）
        for base in (self.codeql_pack_dir, os.path.join(cli_root, "..", "codeql-packs")):
            if base and os.path.exists(base):
                qp = os.path.join(base, "codeql", "python-queries")
                if os.path.isdir(qp):
                    versions = sorted(os.listdir(qp), reverse=True)
                    if versions:
                        candidates.insert(0, os.path.join(qp, versions[0]))
                        # 硬层优先 security-only 套件（code-scanning）；
                        # security-and-quality 混入质量类查询会污染硬检出
                        for suite_name in ("python-code-scanning.qls",
                                           "python-security-and-quality.qls"):
                            suite = os.path.join(qp, versions[0], "codeql-suites", suite_name)
                            if os.path.exists(suite):
                                return suite
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    # ---------- CodeQL 硬分析（仓库级）----------

    def codeql_hard_analyze(self, source_root: str) -> Dict[str, Any]:
        """CodeQL 硬分析：建库 → 跑安全查询套件 → SARIF → hits。

        Returns:
            {"available": bool, "hits": [ {file,line,rule,cwe,severity,message} ], "note": str}
        """
        codeql_bin = self._envs_bin("codeql")
        if not codeql_bin:
            return {"available": False, "hits": [], "note": "codeql CLI 未安装（装好后自动启用）"}
        try:
            db_path = self.codeql_db_path or os.path.join(source_root, ".codeql-db")
            # 1) 建库（Python 提取器无需编译；受限沙箱下需完整权限——命名管道）
            if not os.path.exists(os.path.join(db_path, "codeql-database.yml")):
                r = self._run([codeql_bin, "database", "create", db_path,
                               "--language=python", f"--source-root={source_root}",
                               "--overwrite"])
                if r.returncode != 0:
                    return {"available": True, "hits": [], "note": "建库失败: " + r.stderr[-300:]}
            # 2) 查询套件（envs/codeql-packs 官方安全套件）
            suite = self._resolve_query_suite(codeql_bin)
            analyze_cmd = [codeql_bin, "database", "analyze", db_path,
                           "--format=sarif-latest",
                           f"--output={os.path.join(source_root, '.codeql-results.sarif')}"]
            if self.codeql_pack_dir and os.path.exists(self.codeql_pack_dir):
                analyze_cmd += ["--search-path", self.codeql_pack_dir]
            if suite:
                analyze_cmd.append(suite)
            else:
                analyze_cmd.append("--download")  # 自动拉取默认套件
            r = self._run(analyze_cmd)
            sarif_path = os.path.join(source_root, ".codeql-results.sarif")
            if r.returncode != 0 or not os.path.exists(sarif_path):
                return {"available": True, "hits": [], "note": "analyze 失败: " + r.stderr[-300:]}
            # 3) SARIF 解析
            hits = []
            sarif = json.load(open(sarif_path, encoding="utf-8"))
            for run in sarif.get("runs", []):
                rules_meta = {}
                for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                    try:
                        rules_meta[rule.get("id", "")] = rule
                    except Exception:
                        pass
                for res in run.get("results", []):
                    rid = str(res.get("ruleId", ""))
                    rule_meta = rules_meta.get(rid, {})
                    loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
                    region = loc.get("region") or {}
                    uri = str(loc.get("artifactLocation", {}).get("uri", ""))
                    sev = str(res.get("level") or rule_meta.get("defaultConfiguration", {}).get("level", "warning"))
                    # 提取 CWE（SARIF tags/properties 常见 CWE-1234 形）
                    cwe = ""
                    tags = rule_meta.get("properties", {}).get("tags", []) or []
                    for t in tags:
                        if str(t).startswith("CWE-") or str(t).startswith("external/cwe/cwe-"):
                            cwe = str(t).replace("external/cwe/cwe-", "CWE-").upper()
                            break
                    if not cwe:
                        import re as _re
                        m = _re.search(r"CWE[-_](\d+)", json.dumps(rule_meta, ensure_ascii=False))
                        if m:
                            cwe = "CWE-" + m.group(1)
                    hits.append({
                        "file": uri.replace("file://", "").replace("\\\\", "/"),
                        "line": int(region.get("startLine", 0) or 0),
                        "rule": rid,
                        "cwe": cwe,
                        "severity": sev,
                        "message": str((res.get("message") or {}).get("text", ""))[:300],
                        "backend": "codeql",
                    })
            return {"available": True, "hits": hits, "note": f"codeql 命中 {len(hits)} 条"}
        except Exception as e:
            return {"available": True, "hits": [], "note": "codeql 异常: " + str(e)[:200]}

    def codeql_hits_for(self, source_root: str, files: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """跑一次 CodeQL 分析，按文件归并 hits（仅返回指定 files 的）。"""
        res = self.codeql_hard_analyze(source_root)
        if not res.get("available"):
            return {}
        by_file: Dict[str, List[Dict[str, Any]]] = {}
        norm = {str(Path(f)).replace("\\", "/") for f in files}
        for h in res.get("hits", []):
            hf = h["file"]
            key = None
            if hf in norm:
                key = hf
            else:
                for f in files:
                    if hf.endswith("/" + str(Path(f)).replace("\\", "/")) or hf == str(Path(f)).replace("\\", "/"):
                        key = str(Path(f))
                        break
            if key:
                by_file.setdefault(key, []).append(h)
        return by_file

    def cascade(self, source_root: str, files: List[str]) -> Dict[str, Any]:
        """[OPT-SASTR2] 三级 cascade：semgrep/bandit 快扫(S1) → CodeQL 深扫(S2) → AI 盲区(S3)。

        Returns:
            {
              "s1_by_file": {path: [hits]},       # semgrep 优先，bandit 兜底
              "s2_by_file": {path: [hits]},       # codeql 确认（高精度）
              "hard_files": [path...],            # codeql 确认 -> 硬检出，不需 AI
              "ai_files": [path...],              # 其余 -> AI（候选验证 + 盲区）
              "note": str
            }
        """
        # S1: 快扫（semgrep 优先，功能探测；bandit 兜底——纯 Python 沙箱可用）
        s1_by_file: Dict[str, List[Dict[str, Any]]] = {}
        semgrep_bin = None
        if "semgrep" in self.backends and self.semgrep_available():
            semgrep_bin = self._envs_bin("semgrep")
        if semgrep_bin:
            try:
                rules_dir = self.semgrep_rules_dir
                if not rules_dir and "semgrep-rules" not in str(source_root):
                    for cand in (os.path.join(os.path.dirname(os.path.dirname(source_root)),
                                              "envs", "semgrep-rules", "python"),
                                 os.path.join(source_root, "envs", "semgrep-rules", "python")):
                        if os.path.exists(cand):
                            rules_dir = cand
                            break
                cmd = [semgrep_bin, "scan", "--json", "-q"]
                if rules_dir and os.path.exists(rules_dir):
                    cmd += ["--config", rules_dir]
                cmd += [source_root]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                                   encoding="utf-8", errors="replace")
                data = json.loads(r.stdout or "{}")
                for res in data.get("results", []):
                    path = str(res.get("path", "")).replace("\\", "/")
                    s1_by_file.setdefault(path, []).append({
                        "file": path,
                        "line": int((res.get("start") or {}).get("line", 0) or 0),
                        "rule": (res.get("check_id") or "semgrep").split(".")[-1],
                        "cwe": "",
                        "severity": str((res.get("extra") or {}).get("severity", "warning")),
                        "snippet": str((res.get("extra") or {}).get("lines", ""))[:200],
                        "backend": "semgrep",
                    })
            except Exception as e:
                logger.debug(f"[SAST] semgrep 层失败，降级 bandit: {e}")
        if not semgrep_bin or not s1_by_file:
            try:
                bandit_bin = self._envs_bin("bandit")
                if bandit_bin is None:
                    bandit_bin = os.path.join(os.path.dirname(os.path.dirname(source_root)),
                                              "envs", "sast-venv", "Scripts", "bandit.exe")
                r = subprocess.run([bandit_bin, "-r", source_root, "-f", "json"],
                                   capture_output=True, text=True, timeout=600,
                                   encoding="utf-8", errors="replace")
                data = json.loads(r.stdout or "{}")
                sev_map = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
                for res in data.get("results", []):
                    path = str(res.get("filename", "")).replace("\\", "/")
                    s1_by_file.setdefault(path, []).append({
                        "file": path,
                        "line": int(res.get("line_number", 0) or 0),
                        "rule": str(res.get("test_id", "B000")),
                        "cwe": "",
                        "severity": sev_map.get(str(res.get("issue_severity", "MEDIUM")), "warning"),
                        "snippet": str(res.get("code", ""))[:200],
                        "backend": "bandit",
                    })
            except Exception as e:
                logger.debug(f"[SAST] bandit 层失败: {e}")
        # S2: CodeQL 深扫（确认集，高精度）
        s2_by_file = self.codeql_hits_for(source_root, files)
        hard_files = [f for f in files if s2_by_file.get(f)]
        ai_files = [f for f in files if not s2_by_file.get(f)]
        return {
            "s1_by_file": s1_by_file,
            "s2_by_file": s2_by_file,
            "hard_files": hard_files,
            "ai_files": ai_files,
            "note": f"S1 命中文件 {len({k for k in s1_by_file})}, S2 codeql 确认 {len(hard_files)}, AI 盲区 {len(ai_files)}",
        }

    # ---------- 单文件证据（可选：semgrep/builtin 注入）----------

    @staticmethod
    def semgrep_available() -> bool:
        sem = SastPrefilter._envs_bin("semgrep")
        if sem is None:
            return False
        try:
            r = subprocess.run([sem, "--version"], capture_output=True, text=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    def prefilter_file(self, file_path: str) -> Dict[str, Any]:
        """单文件证据（仅 inject_evidence 用；门控由 CodeQL 硬分析决定）。"""
        hits: List[Dict[str, Any]] = []
        if not os.path.exists(file_path):
            return {"hits": hits, "evidence": ""}
        if "semgrep" in self.backends and self.semgrep_available():
            try:
                r = subprocess.run(["semgrep", "scan", "--json", "-q", str(file_path)],
                                   capture_output=True, text=True, timeout=120)
                data = json.loads(r.stdout or "{}")
                for res in data.get("results", []):
                    hits.append({
                        "file": res.get("path", file_path),
                        "line": int((res.get("start") or {}).get("line", 0) or 0),
                        "rule": (res.get("check_id") or "semgrep").split(".")[-1],
                        "cwe": "",
                        "severity": (res.get("extra") or {}).get("severity", "medium"),
                        "snippet": str((res.get("extra") or {}).get("lines", ""))[:300],
                        "backend": "semgrep",
                    })
            except Exception as e:
                logger.debug(f"[SAST] semgrep 跳过 {file_path}: {e}")
        evidence = ""
        if self.inject_evidence and hits:
            evidence = json.dumps({"sast_evidence": hits[:20]}, ensure_ascii=False, indent=1)
        return {"hits": hits, "evidence": evidence}

    def prefilter_batch(self, files: List[str]) -> Dict[str, Dict[str, Any]]:
        out = {}
        for fp in files:
            out[str(fp)] = self.prefilter_file(str(fp))
        return out
