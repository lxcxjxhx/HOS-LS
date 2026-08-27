"""SAST 前置过滤处理器

从 scanner.py 提取（原 scanner.py 2228-2360 行）。
负责在 AI 分析前运行 SAST 工具（CodeQL/semgrep/bandit）进行前置过滤，
将 SAST 可识别的漏洞标记为 hard-finding（0 AI token），
仅将 SAST 不明确或不可识别的项目特有盲区送入 AI 深度分析。
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

from src.core.engine import Finding, Location, Severity
from src.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


def run_sast_prefilter(
    config: Any,
    pending_files: List[Tuple[int, Any]],
    pure_ai_analyzer: Optional[Any] = None,
) -> Tuple[List[Tuple[int, Any]], List[Dict[str, Any]], set, Dict[str, set], Dict[str, str]]:
    """执行 SAST 前置过滤。

    对 pending_files 运行 SAST 分析（CodeQL/semgrep/bandit）：
    - SAST 可确信的 → 标记为 hard_sast_findings（不走 AI）
    - SAST 命中的行号 → 收集到 sast_candidate_lines（给 AI 作线索）
    - SAST 不命中的 → 保留为 AI 盲区

    Args:
        config: 扫描配置
        pending_files: [(index, FileInfo), ...] 待处理文件列表
        pure_ai_analyzer: PureAIAnalyzer 实例（可选）

    Returns:
        (pending_files, hard_sast_findings, sast_filtered_paths,
         sast_candidate_lines, sast_pipeline_evidence)
    """
    sast_filtered_paths: set = set()
    sast_pipeline_evidence: Dict[str, str] = {}
    hard_sast_findings: list = []
    sast_candidate_lines: Dict[str, set] = {}

    sast_cfg = getattr(config, "sast_prefilter", None)
    if not config.pure_ai or not sast_cfg or not sast_cfg.enabled:
        return pending_files, hard_sast_findings, sast_filtered_paths, sast_candidate_lines, sast_pipeline_evidence

    try:
        from src.analyzers.sast_prefilter import SastPrefilter

        sast = SastPrefilter(sast_cfg)
        mode = getattr(sast, "mode", "cascade")
        paths = [str(fi.path) for _, fi in pending_files]

        if mode in ("cascade", "hard-first"):
            src_root = os.path.commonpath(paths) if paths else "."
            if mode == "cascade":
                c = sast.cascade(src_root, paths)
            else:
                s2 = sast.codeql_hits_for(src_root, paths)
                c = {
                    "s1_by_file": {},
                    "s2_by_file": s2,
                    "hard_files": list(s2.keys()),
                    "ai_files": [p for p in paths if p not in s2],
                    "note": "hard-first",
                }

            if c.get("hard_files"):
                # [OPT-C1] 相关性筛选：硬候选过确定性污点门（M4 InputTracer）
                hard_keep, demoted = [], []
                try:
                    from src.analyzers.input_tracer import InputTracer

                    tracer = InputTracer(src_root)
                except Exception:
                    tracer = None

                for hpath in c["hard_files"]:
                    hhits = c["s2_by_file"].get(hpath, [])
                    if tracer is not None and hhits:
                        taint_ok = False
                        for h in hhits:
                            try:
                                r_ = tracer.trace_controllability(
                                    hpath, int(h.get("line", 0) or 0), ""
                                )
                                if getattr(r_, "is_exploitable", False):
                                    taint_ok = True
                                    break
                            except Exception:
                                pass
                        if not taint_ok:
                            demoted.append(hpath)
                            continue
                    hard_keep.append(hpath)

                for hpath in demoted:
                    sast_filtered_paths.discard(hpath)
                if demoted:
                    console.print(
                        f"[yellow][SAST] {len(demoted)} 个 codeql 候选未过污点门，降级回 AI 验证[/yellow]"
                    )

                for hpath in hard_keep:
                    for h in c["s2_by_file"].get(hpath, []):
                        sev = (
                            Severity.HIGH
                            if str(h.get("severity", "")).lower() in ("error", "high", "critical")
                            else Severity.MEDIUM
                        )
                        hard_sast_findings.append(
                            Finding(
                                rule_id=str(h.get("rule", "codeql")),
                                rule_name=f"CodeQL {h.get('rule', '')}",
                                description=str(h.get("message", ""))[:300],
                                severity=sev,
                                location=Location(
                                    file=hpath, line=int(h.get("line", 0) or 1), column=0
                                ),
                                confidence=0.9,
                                message=str(h.get("message", ""))[:200],
                                code_snippet="",
                                fix_suggestion="",
                                references=[],
                                metadata={"source": "codeql", "cwe": h.get("cwe", "")},
                            )
                        )
                    sast_filtered_paths.add(hpath)

                console.print(
                    f"[bold green][SAST] CodeQL 硬检出 {len(hard_keep)} 个文件（0 AI token）[/bold green]"
                )

            # 剩余文件进 AI（候选验证 + 盲区）
            pending_files = [
                (i, fi) for i, fi in pending_files if str(fi.path) not in sast_filtered_paths
            ]
            # [OPT-DEDUP] 收集 SAST 候选位置（S1 semgrep/bandit + S2 codeql）
            for _sfile, _hits in (c.get("s1_by_file") or {}).items():
                sast_candidate_lines.setdefault(_sfile, set()).update(
                    int(h.get("line", 0) or 0) for h in _hits
                )
            for _sfile, _hits in (c.get("s2_by_file") or {}).items():
                sast_candidate_lines.setdefault(_sfile, set()).update(
                    int(h.get("line", 0) or 0) for h in _hits
                )
        else:
            # skip / evidence-only：单文件证据 + 旧门控
            pre = sast.prefilter_batch(paths)
            sast_pipeline_evidence = {
                str(fi.path): pre.get(str(fi.path), {}).get("evidence", "")
                for _, fi in pending_files
            }
            if mode == "skip":
                keep = []
                for i, fi in pending_files:
                    if pre.get(str(fi.path), {}).get("hits"):
                        keep.append((i, fi))
                    else:
                        sast_filtered_paths.add(str(fi.path))
                if sast_filtered_paths:
                    console.print(
                        f"[yellow][SAST] 前置过滤跳过 {len(sast_filtered_paths)} 个零命中文件（省 AI token）[/yellow]"
                    )
                pending_files = keep

    except Exception as e:
        logger.debug(f"[SAST] 前置过滤失败，降级为全部 AI 分析: {e}")

    return (
        pending_files,
        hard_sast_findings,
        sast_filtered_paths,
        sast_candidate_lines,
        sast_pipeline_evidence,
    )
