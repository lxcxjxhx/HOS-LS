"""Agent 3：漏洞验证

从 MultiAgentPipeline 提取，保留 LLM 调用（不可确定性替代）。
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.ai.prompt_engine import PromptEngine
from src.ai.pure_ai.pipeline_constants import SIGNAL_QUEUE_TIMEOUT
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def run_agent_3(
    self,
    file_path: str,
    risk_enumeration: Any,
    file_content: str,
    detected_language: str = "Unknown",
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 3：漏洞验证

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
