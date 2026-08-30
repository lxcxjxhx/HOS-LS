"""Agent 3：漏洞验证

从 MultiAgentPipeline 提取，保留 LLM 调用（不可确定性替代）。

优化：
  1. patch_detector 注入 - 将确定性修复模式检测结果作为先验证据传入 prompt
  2. 自一致性投票 - 3 次采样多数裁决，消除单次采样的随机 Lucky Hit
"""

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.ai.prompt_engine import PromptEngine
from src.ai.pure_ai.patch_detector import analyze as patch_detect, format_for_prompt
from src.ai.pure_ai.pipeline_constants import SIGNAL_QUEUE_TIMEOUT
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ── 自一致性投票配置 ──────────────────────────────────────────────────────────
# 运行次数与温度梯度
_CONSISTENCY_RUNS = 3
_CONSISTENCY_TEMPS = [0.0, 0.1, 0.2]

# 单次运行触发一致性的最小风险信号数（信号太少时无需多次采样）
_MIN_RISKS_FOR_VOTING = 1

# 需要多数同意的决策（少于此运行数一致时降级为 REFINED）
_MAJORITY_THRESHOLD = 2  # ≥2/3 即多数


def _majority_vote_result(
    all_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """对多次 Agent-3 运行结果按信号 ID 进行多数裁决。

    策略：
    - 对每个 signal_id，收集各次运行的 verification_decision
    - CONFIRMED ≥ majority → CONFIRMED
    - REJECTED  ≥ majority → REJECTED
    - 其他 → 保留置信度最高的原始结果，decision 改为 REFINED
    """
    if not all_results:
        return {"vulnerabilities": [], "signal_tracking": {}}
    if len(all_results) == 1:
        return all_results[0]

    # 聚合：signal_id → list of vuln dicts
    signal_votes: Dict[str, List[Dict[str, Any]]] = {}
    for run_result in all_results:
        for vuln in run_result.get("vulnerabilities", []):
            sid = vuln.get("signal_id", "")
            if not sid:
                continue
            signal_votes.setdefault(sid, []).append(vuln)

    merged_vulns: List[Dict[str, Any]] = []

    for signal_id, vuln_list in signal_votes.items():
        decisions = [v.get("verification_decision", "REFINED") for v in vuln_list]
        decision_counts = Counter(decisions)
        top_decision, top_count = decision_counts.most_common(1)[0]

        # 选出置信度最高的那份作为基础
        best = max(vuln_list, key=lambda v: float(v.get("confidence", 0) or 0))
        merged = dict(best)

        if top_count >= _MAJORITY_THRESHOLD:
            # 多数一致，采用多数决策
            merged["verification_decision"] = top_decision
            merged["signal_state"] = top_decision
            if top_decision == "CONFIRMED":
                merged["verification_reason"] = (
                    f"[自一致性投票 {top_count}/{len(all_results)}次 CONFIRMED] "
                    + merged.get("verification_reason", "")
                )
            elif top_decision == "REJECTED":
                merged["verification_reason"] = (
                    f"[自一致性投票 {top_count}/{len(all_results)}次 REJECTED] "
                    + merged.get("verification_reason", "")
                )
        else:
            # 无多数，降级为 REFINED
            merged["verification_decision"] = "REFINED"
            merged["signal_state"] = "REFINED"
            merged["verification_reason"] = (
                f"[自一致性投票无多数，降级为待复核] 各次决策: {dict(decision_counts)} - "
                + merged.get("verification_reason", "")
            )

        merged_vulns.append(merged)

    # 重新计算 signal_tracking
    confirmed = sum(1 for v in merged_vulns if v.get("verification_decision") == "CONFIRMED")
    rejected = sum(1 for v in merged_vulns if v.get("verification_decision") == "REJECTED")
    refined = sum(1 for v in merged_vulns if v.get("verification_decision") == "REFINED")

    return {
        "vulnerabilities": merged_vulns,
        "signal_tracking": {
            "signals_confirmed": confirmed,
            "signals_rejected": rejected,
            "signals_refined": refined,
            "signals_new": 0,
            "consistency_runs": len(all_results),
        },
    }


async def run_agent_3(
    self,
    file_path: str,
    risk_enumeration: Any,
    file_content: str,
    detected_language: str = "Unknown",
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 3：漏洞验证（含 patch_detector 注入 + 自一致性投票）

    Args:
        file_path: 文件路径
        risk_enumeration: 风险枚举结果
        file_content: 文件内容
        detected_language: 检测到的语言
        context: 上下文信息（包含映射关系）

    Returns:
        (漏洞验证结果, token使用信息)
    """
    logger.debug(f" 运行Agent 3 (漏洞验证) on: {file_path}")
    self.debug_logs.append(f"[DEBUG] 运行Agent 3 (漏洞验证) on: {file_path}")

    if not isinstance(risk_enumeration, dict):
        logger.warning(
            f"[Agent-3] risk_enumeration 不是字典类型: {type(risk_enumeration).__name__}, 使用空风险列表"
        )
        self.debug_logs.append(
            f"[WARN] [Agent-3] risk_enumeration 不是字典类型: {type(risk_enumeration).__name__}"
        )
        risk_enumeration = {
            "risks": [],
            "signal_tracking": {
                "signals_new": 0,
                "signals_confirmed": 0,
                "signals_rejected": 0,
                "signals_refined": 0,
            },
        }

    risks = risk_enumeration.get("risks", [])

    logger.debug(f" [Agent-3] 从 risk_enumeration 获取到 {len(risks)} 个风险")
    if len(risks) == 0:
        logger.debug(" [Agent-3] risk_enumeration 返回空风险列表，检查原始数据...")

    self._init_signal_queue()
    for risk in risks:
        if not isinstance(risk, dict):
            logger.warning(
                f"[Agent-3] risk 不是字典类型: {type(risk).__name__}, 跳过, 值: {str(risk)[:100]}"
            )
            self.debug_logs.append(f"[WARN] [Agent-3] risk 不是字典类型: {type(risk).__name__}, 跳过")
            continue
        signal_id = risk.get("signal_id", "")
        if signal_id:
            self._add_to_signal_queue(signal_id, risk)
            logger.debug(
                f"[Agent-3] 添加信号到队列: {signal_id} - {risk.get('title', risk.get('risk_type', 'UNKNOWN'))}"
            )
    if len(self._signal_queue) == 0 and hasattr(self, "evidence_chain_tracker"):
        tracked_signals = self.evidence_chain_tracker.get_all_signals()
        file_path_str = str(file_path)
        file_path_name = str(Path(file_path).name)
        current_file_signals = [
            s
            for s in tracked_signals.values()
            if isinstance(s, dict)
            and (
                s.get("location", "").startswith(file_path_name)
                or file_path_str in s.get("location", "")
            )
        ]
        if current_file_signals:
            logger.debug(f"  信号队列为空，从tracker中恢复 {len(current_file_signals)} 个信号")
            for sig in current_file_signals:
                sig_id = sig.get("signal_id", "")
                if sig_id:
                    self._add_to_signal_queue(sig_id, sig)

    logger.debug(f" 信号队列初始化完成，共 {len(self._signal_queue)} 个信号待处理")

    risk_list = self._format_risk_list_concise(risks)
    known_file_paths = self._file_registry.get_known_file_paths()
    line_counts = dict(self._file_registry._line_counts)
    file_path_str = str(file_path)
    if file_path_str not in known_file_paths:
        known_file_paths.append(file_path_str)
        line_counts[file_path_str] = file_content.count("\n") + 1 if file_content else 1
    known_files_summary = "\n".join(
        [f"- {path} ({line_counts[path]} lines)" for path in known_file_paths]
    )

    context_mappings_summary = ""
    if context:
        context_mappings_summary = self._format_context_mappings_for_agent(context)

    queue_info = f"共 {len(self._signal_queue)} 个信号进入验证队列"
    logger.debug(f" {queue_info}")

    # AST/污点确定性预验证证据（M4）：机器可查事实，供 Agent-3 验证时引用
    ast_evidence = ""
    if getattr(self, "ast_evidence_enabled", False):
        ast_evidence = self._build_ast_evidence(
            risks, file_path, file_content, detected_language
        )

    # [OPT-SASTR] SAST 前置过滤证据注入（与 M4 同通道，AI 有据验证）
    if getattr(self, "sast_evidence", None):
        sast_evidence = self.sast_evidence.get(str(file_path), "") or ""
        if sast_evidence:
            ast_evidence = (
                ast_evidence + "\n" + sast_evidence if ast_evidence else sast_evidence
            )

    # CWE 专项检测指引
    cwe_guidance = ""
    if risks and (getattr(self, "cwe_guidance_enabled", False) or len(risks) > 0):
        cwe_guidance = self._build_cwe_guidance(file_content, file_path, detected_language)

    # ── 确定性修复模式检测（patch_detector，0 token） ───────────────────────
    patch_result = patch_detect(file_path, file_content)
    fix_patterns_summary = format_for_prompt(patch_result) if patch_result.is_likely_patched() else ""
    if fix_patterns_summary:
        logger.debug(
            f"[patch_detector] {Path(file_path).name} 检测到 {len(patch_result.fix_patterns)} 个修复模式: "
            + ", ".join(fp.pattern_name for fp in patch_result.fix_patterns[:5])
        )
        self.debug_logs.append(
            f"[patch_detector] 检测到修复模式: {patch_result.summary()}"
        )

    def _build_prompt() -> str:
        return self.prompt_engine.render_agent_prompt(
            "vulnerability_verification",
            file_path=file_path,
            risk_list=risk_list,
            file_content=file_content,
            detected_language=detected_language,
            known_files_summary=known_files_summary,
            known_file_paths=known_file_paths,
            line_counts=line_counts,
            context_mappings=context_mappings_summary,
            queue_info=queue_info,
            ast_evidence=ast_evidence,
            cwe_guidance=cwe_guidance,
            fix_patterns_summary=fix_patterns_summary,
        )

    # ── 自一致性投票（仅当有足够信号时启用） ────────────────────────────────
    use_voting = (
        len(risks) >= _MIN_RISKS_FOR_VOTING
        and getattr(self, "consistency_voting_enabled", True)
    )

    total_token_usage: Dict[str, int] = {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }

    if use_voting:
        logger.debug(f"[Agent-3] 启用自一致性投票 ({_CONSISTENCY_RUNS} 次采样)")
        prompt = _build_prompt()
        all_run_results: List[Dict[str, Any]] = []

        for run_idx, temp in enumerate(_CONSISTENCY_TEMPS):
            agent_start_time = time.time()
            response, run_token_usage = await self._generate_with_retry(
                prompt, f"Agent 3 (run {run_idx+1}/{_CONSISTENCY_RUNS})", temperature=temp
            )
            for k in total_token_usage:
                total_token_usage[k] += run_token_usage.get(k, 0)

            run_result = self._parse_json_response(response, schema_name="vulnerability")
            run_result = self._safety_net_agent_3(run_result, file_content)
            all_run_results.append(run_result)

            agent_elapsed = time.time() - agent_start_time
            logger.debug(
                f"[Agent-3] run {run_idx+1} 完成: "
                f"CONFIRMED={sum(1 for v in run_result.get('vulnerabilities',[]) if v.get('verification_decision')=='CONFIRMED')} "
                f"REJECTED={sum(1 for v in run_result.get('vulnerabilities',[]) if v.get('verification_decision')=='REJECTED')} "
                f"elapsed={agent_elapsed:.1f}s"
            )

        result = _majority_vote_result(all_run_results)
        logger.debug(
            f"[Agent-3] 投票结果: "
            f"CONFIRMED={result['signal_tracking'].get('signals_confirmed',0)} "
            f"REJECTED={result['signal_tracking'].get('signals_rejected',0)} "
            f"REFINED={result['signal_tracking'].get('signals_refined',0)}"
        )

    else:
        # 单次运行（原始逻辑）
        prompt = _build_prompt()
        agent_start_time = time.time()
        response, total_token_usage = await self._generate_with_retry(
            prompt, "Agent 3", temperature=self.temperature
        )
        agent_elapsed = time.time() - agent_start_time

        timedout_signals = self._check_signal_queue_timeout()
        if timedout_signals:
            logger.debug(f" 信号验证超时 ({SIGNAL_QUEUE_TIMEOUT}秒)，超时信号: {timedout_signals}")

        result = self._parse_json_response(response, schema_name="vulnerability")
        result = self._safety_net_agent_3(result, file_content)

    verified_signals = []
    if isinstance(result.get("vulnerabilities"), list):
        verified_signals = [
            v.get("signal_id", "")
            for v in result.get("vulnerabilities", [])
            if isinstance(v, dict) and v.get("signal_id")
        ]
    for sig_id in verified_signals:
        self._mark_signal_processed(sig_id)

    unverified_from_queue = self._get_pending_signals()
    if unverified_from_queue:
        logger.warning(
            f" 风险枚举({len(self._signal_queue)})与验证({len(verified_signals)})信号数不一致，{len(unverified_from_queue)}个信号未被验证: {unverified_from_queue}"
        )
        for sig_id in unverified_from_queue:
            queue_item = next(
                (item for item in self._signal_queue if item["signal_id"] == sig_id), None
            )
            if queue_item:
                risk_data = queue_item.get("risk_data", {})
                refined_signal = {
                    "title": risk_data.get("title", "UNVERIFIED_RISK"),
                    "severity": risk_data.get("severity", "MEDIUM"),
                    "location": risk_data.get("location", ""),
                    "evidence": risk_data.get("evidence", []),
                    "cwe_id": risk_data.get("cwe_id", ""),
                    "cvss_score": risk_data.get("cvss_score", ""),
                    "signal_id": sig_id,
                    "signal_state": "REFINED",
                    "verification_decision": "REFINED",
                    "verification_reason": f"Signal {sig_id} was not processed by Agent-3 verification - marked as pending review (timeout or coverage gap)",
                }
                if "vulnerabilities" not in result:
                    result["vulnerabilities"] = []
                result["vulnerabilities"].append(refined_signal)
                logger.debug(f" 添加未验证信号 {sig_id} 到待复核列表")

    logger.debug(f" Agent 3 完成，令牌使用: {total_token_usage['total_tokens']}")
    self.debug_logs.append(
        f"[DEBUG] Agent 3 完成，令牌使用: {total_token_usage['total_tokens']}"
    )
    return result, total_token_usage



async def _legacy_run_agent_3(
    self,
    file_path: str,
    risk_enumeration: Any,
    file_content: str,
    detected_language: str = "Unknown",
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """旧版 Agent 3 实现（保留兼容，不由主流水线调用）。

    Args:
        file_path: 文件路径
        risk_enumeration: 风险枚举结果
        file_content: 文件内容
        detected_language: 检测到的语言
        context: 上下文信息（包含映射关系）

    Returns:
        (漏洞验证结果, token使用信息)
    """
    logger.debug(f" 运行Agent 3 (漏洞验证) on: {file_path}")
    self.debug_logs.append(f"[DEBUG] 运行Agent 3 (漏洞验证) on: {file_path}")

    if not isinstance(risk_enumeration, dict):
        logger.warning(
            f"[Agent-3] risk_enumeration 不是字典类型: {type(risk_enumeration).__name__}, 使用空风险列表"
        )
        self.debug_logs.append(
            f"[WARN] [Agent-3] risk_enumeration 不是字典类型: {type(risk_enumeration).__name__}"
        )
        risk_enumeration = {
            "risks": [],
            "signal_tracking": {
                "signals_new": 0,
                "signals_confirmed": 0,
                "signals_rejected": 0,
                "signals_refined": 0,
            },
        }

    risks = risk_enumeration.get("risks", [])

    logger.debug(f" [Agent-3] 从 risk_enumeration 获取到 {len(risks)} 个风险")
    if len(risks) == 0:
        logger.debug(" [Agent-3] risk_enumeration 返回空风险列表，检查原始数据...")

    self._init_signal_queue()
    for risk in risks:
        if not isinstance(risk, dict):
            logger.warning(
                f"[Agent-3] risk 不是字典类型: {type(risk).__name__}, 跳过, 值: {str(risk)[:100]}"
            )
            self.debug_logs.append(f"[WARN] [Agent-3] risk 不是字典类型: {type(risk).__name__}, 跳过")
            continue
        signal_id = risk.get("signal_id", "")
        if signal_id:
            self._add_to_signal_queue(signal_id, risk)
            logger.debug(
                f"[Agent-3] 添加信号到队列: {signal_id} - {risk.get('title', risk.get('risk_type', 'UNKNOWN'))}"
            )
    if len(self._signal_queue) == 0 and hasattr(self, "evidence_chain_tracker"):
        tracked_signals = self.evidence_chain_tracker.get_all_signals()
        file_path_str = str(file_path)
        file_path_name = str(Path(file_path).name)
        current_file_signals = [
            s
            for s in tracked_signals.values()
            if isinstance(s, dict)
            and (
                s.get("location", "").startswith(file_path_name)
                or file_path_str in s.get("location", "")
            )
        ]
        if current_file_signals:
            logger.debug(f"  信号队列为空，从tracker中恢复 {len(current_file_signals)} 个信号")
            for sig in current_file_signals:
                sig_id = sig.get("signal_id", "")
                if sig_id:
                    self._add_to_signal_queue(sig_id, sig)

    logger.debug(f" 信号队列初始化完成，共 {len(self._signal_queue)} 个信号待处理")

    risk_list = self._format_risk_list_concise(risks)
    known_file_paths = self._file_registry.get_known_file_paths()
    line_counts = dict(self._file_registry._line_counts)
    file_path_str = str(file_path)
    if file_path_str not in known_file_paths:
        known_file_paths.append(file_path_str)
        line_counts[file_path_str] = file_content.count("\n") + 1 if file_content else 1
    known_files_summary = "\n".join(
        [f"- {path} ({line_counts[path]} lines)" for path in known_file_paths]
    )

    context_mappings_summary = ""
    if context:
        context_mappings_summary = self._format_context_mappings_for_agent(context)

    queue_info = f"共 {len(self._signal_queue)} 个信号进入验证队列"
    logger.debug(f" {queue_info}")

    # AST/污点确定性预验证证据（M4）：机器可查事实，供 Agent-3 验证时引用
    ast_evidence = ""
    if getattr(self, "ast_evidence_enabled", False):
        ast_evidence = self._build_ast_evidence(
            risks, file_path, file_content, detected_language
        )

    # [OPT-SASTR] SAST 前置过滤证据注入（与 M4 同通道，AI 有据验证）
    if getattr(self, "sast_evidence", None):
        sast_evidence = self.sast_evidence.get(str(file_path), "") or ""
        if sast_evidence:
            ast_evidence = (
                ast_evidence + "\n" + sast_evidence if ast_evidence else sast_evidence
            )

    # CWE 专项检测指引
    cwe_guidance = ""
    if risks and (getattr(self, "cwe_guidance_enabled", False) or len(risks) > 0):
        cwe_guidance = self._build_cwe_guidance(file_content, file_path, detected_language)

    prompt = self.prompt_engine.render_agent_prompt(
        "vulnerability_verification",
        file_path=file_path,
        risk_list=risk_list,
        file_content=file_content,
        detected_language=detected_language,
        known_files_summary=known_files_summary,
        known_file_paths=known_file_paths,
        line_counts=line_counts,
        context_mappings=context_mappings_summary,
        queue_info=queue_info,
        ast_evidence=ast_evidence,
        cwe_guidance=cwe_guidance,
    )

    agent_start_time = time.time()
    response, token_usage = await self._generate_with_retry(
        prompt, "Agent 3", temperature=self.temperature
    )
    agent_elapsed = time.time() - agent_start_time

    timedout_signals = self._check_signal_queue_timeout()
    if timedout_signals:
        logger.debug(f" 信号验证超时 ({SIGNAL_QUEUE_TIMEOUT}秒)，超时信号: {timedout_signals}")

    result = self._parse_json_response(response, schema_name="vulnerability")

    result = self._safety_net_agent_3(result, file_content)

    verified_signals = []
    if isinstance(result.get("vulnerabilities"), list):
        verified_signals = [
            v.get("signal_id", "")
            for v in result.get("vulnerabilities", [])
            if isinstance(v, dict) and v.get("signal_id")
        ]
    for sig_id in verified_signals:
        self._mark_signal_processed(sig_id)

    unverified_from_queue = self._get_pending_signals()
    if unverified_from_queue:
        logger.warning(
            f" 风险枚举({len(self._signal_queue)})与验证({len(verified_signals)})信号数不一致，{len(unverified_from_queue)}个信号未被验证: {unverified_from_queue}"
        )
        for sig_id in unverified_from_queue:
            queue_item = next(
                (item for item in self._signal_queue if item["signal_id"] == sig_id), None
            )
            if queue_item:
                risk_data = queue_item.get("risk_data", {})
                refined_signal = {
                    "title": risk_data.get("title", "UNVERIFIED_RISK"),
                    "severity": risk_data.get("severity", "MEDIUM"),
                    "location": risk_data.get("location", ""),
                    "evidence": risk_data.get("evidence", []),
                    "cwe_id": risk_data.get("cwe_id", ""),
                    "cvss_score": risk_data.get("cvss_score", ""),
                    "signal_id": sig_id,
                    "signal_state": "REFINED",
                    "verification_decision": "REFINED",
                    "verification_reason": f"Signal {sig_id} was not processed by Agent-3 verification - marked as pending review (timeout or coverage gap)",
                }
                if "vulnerabilities" not in result:
                    result["vulnerabilities"] = []
                result["vulnerabilities"].append(refined_signal)
                logger.debug(f" 添加未验证信号 {sig_id} 到待复核列表")

    logger.debug(f" Agent 3 完成，令牌使用: {token_usage['total_tokens']}, 耗时: {agent_elapsed:.2f}s")
    self.debug_logs.append(
        f"[DEBUG] Agent 3 完成，令牌使用: {token_usage['total_tokens']}, 耗时: {agent_elapsed:.2f}s"
    )
    return result, token_usage
