"""SAST 深度前置过滤（OPT-SASTR）：AI 之前先把候选收窄，0 LLM token。

后端优先级（环境可用性自动探测）：
1. **CodeQL**（仓库级深度分析底座）：`codeql` CLI + 代码数据库存在时启用，
   运行 security 查询套件，SARIF 解析出候选命中（file:line:CWE）。
2. **Semgrep**（函数/文件级）：功能探测，可用时对单文件跑安全规则。
3. **内置规则引擎**（CodeVulnScanner，本地始终可用）：危险模式 + 上下文分析。

产出：
- hits: [{file, line, rule, cwe, severity, snippet, backend}]
- evidence: 紧凑 JSON 字符串，注入 Agent-3 供 AI 有据验证（同 M4 AST 证据风格）

设计意图：软门控（skip_ai_if_no_hits=False）时零命中文件仍走 AI 早停路径（保留
盲区检出）；硬门控（=True）时零命中文件完全跳过 AI（最大 token 节省，召回=过滤层召回）。
"""
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 供 Agent-3 证据注入的固定标识
EVIDENCE_MARKER = "SAST_PREFILTER_EVIDENCE"


class SastPrefilter:
    """SAST 深度前置过滤执行器。"""

    def __init__(self, config: Optional[Any] = None):
        if isinstance(config, dict):
            self.enabled = config.get("enabled", True)
            self.skip_ai_if_no_hits = config.get("skip_ai_if_no_hits", False)
            self.inject_evidence = config.get("inject_evidence", True)
            self.backends = config.get("backends", ["codeql", "semgrep", "builtin"])
            self.min_severity = config.get("min_severity", "medium")
            self.codeql_db_path = config.get("codeql_db_path", "")
        else:
            self.enabled = getattr(config, "enabled", True)
            self.skip_ai_if_no_hits = getattr(config, "skip_ai_if_no_hits", False)
            self.inject_evidence = getattr(config, "inject_evidence", True)
            self.backends = getattr(config, "backends", ["codeql", "semgrep", "builtin"])
            self.min_severity = getattr(config, "min_severity", "medium")
            self.codeql_db_path = getattr(config, "codeql_db_path", "")

    # ---------- 探测 ----------

    @staticmethod
    def codeql_available() -> bool:
        return shutil.which("codeql") is not None

    @staticmethod
    def semgrep_available() -> bool:
        # semgrep 在本机 OCaml X509 证书存储异常，功能探测必须实测子进程
        if shutil.which("semgrep") is None:
            return False
        try:
            r = subprocess.run(
                ["semgrep", "--version"], capture_output=True, text=True, timeout=10
            )
            return r.returncode == 0
        except Exception:
            return False

    # ---------- 单文件过滤（内置规则 + 可选 semgrep）----------

    def prefilter_file(self, file_path: str) -> Dict[str, Any]:
        hits: List[Dict[str, Any]] = []
        if not os.path.exists(file_path):
            return {"hits": hits, "evidence": ""}
        # 1) 内置规则引擎（与静态规则层同源：ASTAnalyzer + CSTAnalyzer）
        if "builtin" in self.backends:
            try:
                from src.analyzers.ast_analyzer import ASTAnalyzer
                from src.analyzers.base import AnalysisContext
                from src.analyzers.cst_analyzer import CSTAnalyzer

                ext = os.path.splitext(file_path)[1].lower()
                lang = (
                    "python"
                    if ext in (".py", ".pyw")
                    else "javascript"
                    if ext in (".js", ".jsx", ".ts", ".tsx")
                    else "java"
                    if ext == ".java"
                    else "python"
                )
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                ctx = AnalysisContext(
                    file_path=Path(file_path), file_content=content, language=lang
                )
                analyzers: list = []
                try:
                    ast_a = ASTAnalyzer()
                    ast_a.initialize()
                    analyzers.append(ast_a)
                except Exception as e:
                    logger.debug(f"[SAST] AST 分析器初始化失败: {e}")
                try:
                    analyzers.append(CSTAnalyzer())
                except Exception as e:
                    logger.debug(f"[SAST] CST 分析器初始化失败: {e}")
                for analyzer in analyzers:
                    try:
                        res = analyzer.analyze(ctx)
                        for issue in res.issues or []:
                            hits.append(
                                {
                                    "file": file_path,
                                    "line": int(getattr(issue, "line", 0) or 0),
                                    "rule": str(getattr(issue, "rule_id", "UNKNOWN")),
                                    "cwe": str(getattr(issue, "cwe_id", "") or ""),
                                    "severity": str(getattr(issue, "severity", "medium")).lower(),
                                    "snippet": str(
                                        getattr(issue, "code_snippet", "")
                                        or getattr(issue, "message", "")
                                    )[:300],
                                    "backend": "builtin",
                                }
                            )
                    except Exception as e:
                        logger.debug(f"[SAST] 分析器 {type(analyzer).__name__} 失败: {e}")
            except Exception as e:
                logger.debug(f"[SAST] 内置规则过滤失败 {file_path}: {e}")
        # 2) Semgrep（功能探测，失败静默跳过）
        if "semgrep" in self.backends and self.semgrep_available():
            try:
                r = subprocess.run(
                    ["semgrep", "scan", "--json", "-q", str(file_path)],
                    capture_output=True, text=True, timeout=120,
                )
                data = json.loads(r.stdout or "{}")
                for res in data.get("results", []):
                    hits.append(
                        {
                            "file": res.get("path", file_path),
                            "line": int((res.get("start") or {}).get("line", 0) or 0),
                            "rule": (res.get("check_id") or "semgrep").split(".")[-1],
                            "cwe": "",
                            "severity": (res.get("extra") or {}).get("severity", "medium"),
                            "snippet": str((res.get("extra") or {}).get("lines", ""))[:300],
                            "backend": "semgrep",
                        }
                    )
            except Exception as e:
                logger.debug(f"[SAST] semgrep 过滤跳过 {file_path}: {e}")
        # 去重（同 line+rule）
        seen = set()
        dedup = []
        for h in hits:
            key = (h["line"], h["rule"])
            if key in seen:
                continue
            seen.add(key)
            dedup.append(h)
        evidence = ""
        if self.inject_evidence and dedup:
            evidence = json.dumps(
                {"sast_evidence": dedup[:20]}, ensure_ascii=False, indent=1
            )
        return {"hits": dedup, "evidence": evidence}

    # ---------- 仓库级 CodeQL（深度分析底座）----------

    def prefilter_repo_codeql(self, repo_root: str) -> Dict[str, Any]:
        if not self.codeql_available():
            return {"available": False, "hits": [], "note": "codeql CLI 未安装"}
        db_path = self.codeql_db_path or os.path.join(repo_root, ".codeql-db")
        try:
            if not os.path.exists(os.path.join(db_path, "codeql-database.yml")):
                r = subprocess.run(
                    ["codeql", "database", "create", db_path, "--language", "python",
                     "--source-root", repo_root, "--overwrite"],
                    capture_output=True, text=True, timeout=1800,
                )
                if r.returncode != 0:
                    return {"available": True, "hits": [], "note": r.stderr[-300:]}
            out_sarif = os.path.join(repo_root, ".codeql-results.sarif")
            r = subprocess.run(
                ["codeql", "database", "analyze", db_path,
                 "--format", "sarif-latest", "--output", out_sarif],
                capture_output=True, text=True, timeout=1800,
            )
            if r.returncode != 0 or not os.path.exists(out_sarif):
                return {"available": True, "hits": [], "note": r.stderr[-300:]}
            hits = []
            sarif = json.load(open(out_sarif, encoding="utf-8"))
            for run in sarif.get("runs", []):
                for res in run.get("results", []):
                    loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
                    region = loc.get("region") or {}
                    hits.append(
                        {
                            "file": str(loc.get("artifactLocation", {}).get("uri", "")),
                            "line": int(region.get("startLine", 0) or 0),
                            "rule": str(res.get("ruleId", "")),
                            "cwe": "",
                            "severity": (res.get("level") or "warning"),
                            "snippet": "",
                            "backend": "codeql",
                        }
                    )
            return {"available": True, "hits": hits, "note": f"codeql 命中 {len(hits)}"}
        except Exception as e:
            return {"available": True, "hits": [], "note": str(e)[:200]}

    def prefilter_batch(self, files: List[str]) -> Dict[str, Dict[str, Any]]:
        out = {}
        for fp in files:
            out[str(fp)] = self.prefilter_file(str(fp))
        return out
