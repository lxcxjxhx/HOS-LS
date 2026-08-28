"""信号追踪模块

从 MultiAgentPipeline 提取的信号追踪和验证方法集合。
"""

from typing import Any, Dict, List, Optional, Tuple

from src.ai.pure_ai.evidence_chain import EvidenceChain
from src.ai.pure_ai.pipeline_constants import (
    CONFIDENCE_THRESHOLDS,
    HIGH_SEVERITY_RISK_TYPES,
    REJECTED_PLACEHOLDERS,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


def _track_risk_signals(self, risk_enumeration: Any) -> None:
    """追踪风险信号"""
    if not isinstance(risk_enumeration, dict):
        logger.error(
            f"Agent-2 数据结构错误 - risk_enumeration 不是字典类型: {type(risk_enumeration).__name__}, 值: {str(risk_enumeration)[:100]}"
        )
        return

    # [FIX-B2] 检查 JSON 解析是否失败
    if risk_enumeration.get("_parse_failed"):
        logger.warning("Agent-2 JSON 解析失败，使用兜底数据，信号追踪可能不完整")

    risks = risk_enumeration.get("risks", [])
    if not isinstance(risks, list):
        logger.error(
            f"Agent-2 数据结构错误 - risks 不是列表类型: {type(risks).__name__}, 值: {str(risks)[:100]}"
        )
        risks = []
    current_file_path = getattr(self, "_current_file_path", "unknown")
    file_hash = str(abs(hash(current_file_path)))[:8]
    signal_counter = 0

    for risk in risks:
        if not isinstance(risk, dict):
            logger.error(
                f"Agent-3 数据结构错误修复已应用 - risk 不是字典类型: {type(risk).__name__}, 值: {str(risk)[:100]}"
            )
            continue
        original_signal_id = risk.get("signal_id", "")
        if original_signal_id:
            signal_id = original_signal_id  # [FIX-B5] 保持原始 ID 一致性
        else:
            signal_counter += 1
            signal_id = f"{file_hash}-{signal_counter:03d}"  # 仅在无原始 ID 时生成
            evidence = risk.get("evidence", [])
            risk_title = (
                risk.get("title", "")
                or risk.get("vulnerability", "")
                or risk.get("risk_type", "")
            )
            risk_description = risk.get("description", "") or risk.get("reason", "")

            if self.reject_on_signal_creation and self._should_reject_signal(risk_title):
                logger.debug(
                    f"拒绝占位符信号: {risk_title} (signal_id: {signal_id}, original: {original_signal_id})"
                )
                continue

            generic_titles = ["risk相关安全风险", "UNKNOWN", "unknown", ""]
            if risk_title in generic_titles or not risk_title:
                desc = risk_description
                if desc:
                    vuln_keywords = [
                        "SQL injection",
                        "SQL注入",
                        "XSS",
                        "CSRF",
                        "injection",
                        "注入",
                        "authentication",
                        "认证",
                        "authorization",
                        "授权",
                        "sensitive info",
                        "敏感信息",
                        "password",
                        "密码",
                        "token",
                        "令牌",
                        "session",
                        "会话",
                        "cookie",
                        "Cookie",
                        "privilege",
                        "越权",
                        "bypass",
                        "绕过",
                        "traversal",
                        "遍历",
                        "serialization",
                        "序列化",
                        "deserialization",
                        "反序列化",
                        "command execution",
                        "命令执行",
                        "path traversal",
                        "路径穿越",
                        "file inclusion",
                        "文件包含",
                        "upload",
                        "上传",
                        "JWT",
                        "OAuth",
                        "Spring Security",
                        "CORS",
                        "API",
                        "REST",
                        "GraphQL",
                        "WebSocket",
                        " Actuator",
                        "端点",
                        "泄露",
                        "exposure",
                    ]
                    for keyword in vuln_keywords:
                        if keyword.lower() in desc.lower():
                            risk_title = keyword
                            logger.debug(f" Extracted vuln type from description: '{keyword}'")
                            break
                if not risk_title or risk_title in generic_titles:
                    risk_title = (
                        risk.get("vulnerability", "") or risk.get("risk_type", "") or risk_title
                    )

            self.evidence_chain_tracker.add_signal(
                signal_id=signal_id,
                signal_type="risk",
                title=risk_title,
                description=risk_description,
                agent="Agent-2",
                state=risk.get("signal_state", SignalState.NEW.value),
                evidence=evidence,
            )
            self._current_file_signals.add(signal_id)
            logger.debug(
                f"Added risk signal: {signal_id} (original: {original_signal_id}) with title: {risk_title or 'UNKNOWN'}"
            )

def _track_verification_signals(self, vulnerability_verification: Any) -> None:
    """追踪验证信号"""
    if not isinstance(vulnerability_verification, dict):
        logger.error(
            f"Agent-3 数据结构错误 - vulnerability_verification 不是字典类型: {type(vulnerability_verification).__name__}, 值: {str(vulnerability_verification)[:100]}"
        )
        return
    vulnerabilities = vulnerability_verification.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        logger.error(
            f"Agent-3 数据结构错误 - vulnerabilities 不是列表类型: {type(vulnerabilities).__name__}, 值: {str(vulnerabilities)[:100]}"
        )
        vulnerabilities = []
    current_file_signals: set = getattr(self, "_current_file_signals", set())
    all_signal_ids = current_file_signals
    processed_signal_ids = set()

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            logger.error(
                f"Agent-3 数据结构错误修复已应用 - vuln 不是字典类型: {type(vuln).__name__}, 值: {str(vuln)[:100]}"
            )
            continue
        signal_id = vuln.get("signal_id", "") or vuln.get("id", "")
        if signal_id:
            processed_signal_ids.add(signal_id)
            evidence = vuln.get("evidence", [])
            new_state = vuln.get("signal_state", SignalState.NEW.value)
            verification_decision = vuln.get("verification_decision", "")

            if verification_decision == "CONFIRMED":
                new_state = "CONFIRMED"
            elif verification_decision == "REJECTED":
                new_state = "REJECTED"
            elif verification_decision == "REFINED":
                new_state = "REFINED"

            verification_reason = vuln.get("verification_reason", "")
            old_signal = self.evidence_chain_tracker.get_signal(signal_id)
            if old_signal:
                old_confidence = self._get_avg_confidence(old_signal.get("evidence_chain", []))
                new_confidence = self._get_avg_confidence(evidence)
                confidence_change = (
                    new_confidence - old_confidence
                    if old_confidence and new_confidence
                    else 0.0
                )

                self.evidence_chain_tracker.update_signal_state(
                    signal_id=signal_id,
                    agent="Agent-3",
                    new_state=new_state,
                    evidence=evidence,
                    confidence_change=confidence_change,
                    reason=f"verification_decision={verification_decision}, reason={verification_reason}",
                )
                logger.debug(f" Updated verification signal: {signal_id} -> {new_state}")
            else:
                logger.warning(
                    f"Verification signal {signal_id} not found in tracker (Agent-2 original signals), may be a new signal from Agent-3"
                )
                logger.debug(f" Adding new signal from Agent-3: {signal_id}")
                vuln_title = (
                    vuln.get("vulnerability", "")
                    or vuln.get("title", "")
                    or vuln.get("risk_type", signal_id)
                )
                vuln_description = vuln.get("description", "") or vuln.get(
                    "verification_reason", ""
                )

                if self.reject_on_signal_creation and self._should_reject_signal(
                    vuln_title or ""
                ):
                    logger.debug(f" 拒绝占位符验证信号: {vuln_title} (signal_id: {signal_id})")
                    continue

                self.evidence_chain_tracker.add_signal(
                    signal_id=signal_id,
                    signal_type="verification",
                    title=vuln_title or "",
                    description=vuln_description,
                    agent="Agent-3",
                    state=new_state,
                    evidence=evidence,
                )
                self._current_file_signals.add(signal_id)

    unverified_signals = all_signal_ids - processed_signal_ids
    if unverified_signals:
        coverage_ratio = (
            len(processed_signal_ids) / len(all_signal_ids) if all_signal_ids else 0
        )
        logger.debug(f" Signals from Agent-2 not verified by Agent-3: {unverified_signals}")
        logger.warning(
            f"Agent-3 verification coverage: {len(processed_signal_ids)}/{len(all_signal_ids)} ({coverage_ratio * 100:.1f}%)"
        )
        if coverage_ratio < 0.5:
            logger.warning(
                f" Agent-3 验证覆盖率低于50%阈值 ({coverage_ratio * 100:.1f}%)，尝试从风险列表匹配..."
            )
            matched_count = self._match_unverified_signals(
                unverified_signals, vulnerability_verification
            )
            adjusted_coverage = (
                (len(processed_signal_ids) + matched_count) / len(all_signal_ids)
                if all_signal_ids
                else 0
            )
            logger.debug(
                f"匹配后调整覆盖率: {len(processed_signal_ids) + matched_count}/{len(all_signal_ids)} ({adjusted_coverage * 100:.1f}%)"
            )
            if adjusted_coverage >= 0.5:
                logger.debug(f" 匹配成功，覆盖率已提升至 {adjusted_coverage * 100:.1f}%")
                coverage_ratio = adjusted_coverage

        if coverage_ratio < 0.5:
            logger.debug("  将相关风险标记为需要人工复核")
            for signal_id in unverified_signals:
                signal = self.evidence_chain_tracker.get_signal(signal_id)
                if signal:
                    signal["requires_human_review"] = True

def _match_unverified_signals(
    self, unverified_signals: set, vulnerability_verification: Dict[str, Any]
) -> int:
    """尝试通过位置或类型匹配未验证的信号

    Args:
        unverified_signals: 未验证的信号ID集合
        vulnerability_verification: Agent-3的验证结果

    Returns:
        匹配成功的数量
    """
    matched = 0
    vulnerabilities = vulnerability_verification.get("vulnerabilities", [])

    for signal_id in unverified_signals:
        signal = self.evidence_chain_tracker.get_signal(signal_id)
        if not signal:
            continue

        risk_type = signal.get("risk_type", "")
        location = ""
        for key in ["location", "evidence"]:
            if key in signal:
                val = signal[key]
                if isinstance(val, str):
                    location = val
                    break
                elif isinstance(val, list) and val:
                    first_evidence = val[0] if isinstance(val[0], dict) else {}
                    location = first_evidence.get("location", "")

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            vuln_location = vuln.get("location", "")
            vuln_type = vuln.get("vulnerability", vuln.get("type", ""))
            if location and vuln_location and location == vuln_location:
                evidence = vuln.get("evidence", [])
                self.evidence_chain_tracker.update_signal_state(
                    signal_id=signal_id,
                    agent="Agent-3",
                    new_state=vuln.get("signal_state", SignalState.REFINED.value),
                    evidence=evidence,
                    reason=f"Matched by location: verification_decision={vuln.get('verification_decision', 'REFINED')}",
                )
                matched += 1
                break
            elif risk_type and vuln_type and risk_type.lower() in vuln_type.lower():
                evidence = vuln.get("evidence", [])
                self.evidence_chain_tracker.update_signal_state(
                    signal_id=signal_id,
                    agent="Agent-3",
                    new_state=vuln.get("signal_state", SignalState.REFINED.value),
                    evidence=evidence,
                    reason=f"Matched by type: verification_decision={vuln.get('verification_decision', 'REFINED')}",
                )
                matched += 1
                break

    return matched

def _track_attack_chain_signals(self, attack_chain_analysis: Any) -> None:
    """追踪攻击链信号"""
    if not isinstance(attack_chain_analysis, dict):
        logger.warning(
            f"_track_attack_chain_signals received non-dict type: {type(attack_chain_analysis).__name__}, expected dict"
        )
        chains: list = []
    else:
        chains = attack_chain_analysis.get("attack_chains", [])
    for chain in chains:
        signal_id = chain.get("signal_id", "")
        if signal_id:
            evidence = chain.get("evidence", [])
            self.evidence_chain_tracker.add_signal(
                signal_id=signal_id,
                signal_type="attack_chain",
                agent="Agent-4",
                state=chain.get("signal_state", SignalState.NEW.value),
                evidence=evidence,
            )
            logger.debug(f" Added attack chain signal: {signal_id}")

def _track_adversarial_signals(self, adversarial_validation: Any) -> None:
    """追踪对抗验证信号"""
    if not isinstance(adversarial_validation, dict):
        logger.warning(
            f"_track_adversarial_signals received non-dict type: {type(adversarial_validation).__name__}, expected dict"
        )
        analysis = []
    else:
        analysis = adversarial_validation.get("adversarial_analysis", [])
    for item in analysis:
        challenged_id = item.get("challenged_signal_id", "")
        if challenged_id:
            evidence = item.get("evidence", [])
            verdict = item.get("verdict", "UNCERTAIN")
            reason = item.get("reason", "")
            state_mapping = {
                "ACCEPT": SignalState.CONFIRMED.value,
                "REFUTE": SignalState.REJECTED.value,
                "ESCALATE": SignalState.UNCERTAIN.value,
                "UNCERTAIN": SignalState.UNCERTAIN.value,
            }
            new_state = state_mapping.get(verdict, SignalState.UNCERTAIN.value)
            old_signal = self.evidence_chain_tracker.get_signal(challenged_id)
            old_confidence = (
                self._get_avg_confidence(old_signal.get("evidence_chain", []))
                if old_signal
                else None
            )
            new_confidence = self._get_avg_confidence(evidence)
            confidence_change = (
                new_confidence - old_confidence if old_confidence and new_confidence else None
            )

            self.evidence_chain_tracker.update_signal_state(
                signal_id=challenged_id,
                agent="Agent-5",
                new_state=new_state,
                evidence=evidence,
                confidence_change=confidence_change,
                reason=f"verdict={verdict}, detail={reason}",
            )
            logger.debug(f" Updated adversarial signal: {challenged_id} -> {new_state}")

def _check_semantic_consistency(
    self, check_name: str, upstream: Dict[str, Any], downstream: Dict[str, Any]
) -> None:
    """检查语义一致性

    Args:
        check_name: 检查名称
        upstream: 上游输出
        downstream: 下游输出
    """
    logger.debug(f" Running semantic consistency check: {check_name}")

    if check_name == "agent_2_to_3":
        upstream_signals = set(r.get("signal_id", "") for r in upstream.get("risks", []))
        downstream_signals = set(
            v.get("signal_id", "") for v in downstream.get("vulnerabilities", [])
        )

        missing_signals = upstream_signals - downstream_signals
        if missing_signals:
            logger.warning(
                f"Semantic gap detected: signals in Agent-2 but not in Agent-3: {missing_signals}"
            )
            logger.debug(
                f"Agent-2 produced {len(upstream_signals)} signals, Agent-3 consumed {len(downstream_signals)} signals"
            )
            self._fill_missing_signals_via_refinement(missing_signals, downstream, "risk")
            downstream_signals = set(
                v.get("signal_id", "") for v in downstream.get("vulnerabilities", [])
            )
            remaining_gaps = upstream_signals - downstream_signals
            if remaining_gaps:
                logger.debug(f" After refinement, still missing signals: {remaining_gaps}")

    elif check_name == "agent_4_to_5":
        upstream_signals = set(
            c.get("signal_id", "") for c in upstream.get("attack_chains", [])
        )
        downstream_signals = set(
            a.get("challenged_signal_id", "")
            for a in downstream.get("adversarial_analysis", [])
        )

        missing_signals = upstream_signals - downstream_signals
        if missing_signals:
            logger.warning(
                f"Semantic gap detected: signals in Agent-4 but not in Agent-5: {missing_signals}"
            )
            logger.debug(
                f"Agent-4 produced {len(upstream_signals)} signals, Agent-5 consumed {len(downstream_signals)} signals"
            )
            self._fill_missing_signals_via_refinement(
                missing_signals, downstream, "attack_chain"
            )

def _fill_missing_signals_via_refinement(
    self, missing_signals: set, downstream: Dict[str, Any], signal_type: str
) -> None:
    """处理未在下游被消费的信号

    将未验证的信号添加到下游输出中，标记为REFINED状态，等待进一步验证。

    Args:
        missing_signals: 缺失的信号ID集合
        downstream: 下游输出（将被修改）
        signal_type: 信号类型 ('risk' 或 'attack_chain')
    """
    logger.warning(
        f"Semantic gap: signals {missing_signals} were not consumed by downstream agent"
    )
    if signal_type == "risk" and missing_signals:
        vulnerabilities = downstream.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []
            downstream["vulnerabilities"] = vulnerabilities

        for sig_id in missing_signals:
            refined_signal = {
                "title": "WEAK_SECURITY_SIGNAL",
                "severity": "MEDIUM",
                "location": "",
                "evidence": [],
                "cwe_id": "",
                "cvss_score": "",
                "signal_id": sig_id,
                "signal_state": "REFINED",
                "verification_decision": "REFINED",
                "verification_reason": f"Signal {sig_id} was not consumed by vulnerability verification agent - requires manual review",
            }
            vulnerabilities.append(refined_signal)
            logger.debug(f" 添加已细化信号用于未消耗的 {sig_id}")

        signal_tracking = downstream.get("signal_tracking", {})
        if isinstance(signal_tracking, dict):
            signal_tracking["signals_refined"] = signal_tracking.get(
                "signals_refined", 0
            ) + len(missing_signals)
            downstream["signal_tracking"] = signal_tracking

    elif signal_type == "attack_chain" and missing_signals:
        adversarial_analysis = downstream.get("adversarial_analysis", [])
        if not isinstance(adversarial_analysis, list):
            adversarial_analysis = []
            downstream["adversarial_analysis"] = adversarial_analysis

        for sig_id in missing_signals:
            refined_signal = {
                "attack_chain_name": sig_id,
                "verdict": "UNCERTAIN",
                "confidence": 0.3,
                "reason": f"Signal {sig_id} was not properly challenged - requires manual review",
                "counter_arguments": [],
                "evidence": [],
                "requires_human_review": True,
                "challenged_signal_id": sig_id,
            }
            adversarial_analysis.append(refined_signal)
            logger.debug(f" 添加待定判定用于未消耗的 {sig_id}")

def _get_signal_summary(self) -> Dict[str, Any]:
    """获取信号摘要"""
    signals = self.evidence_chain_tracker.get_all_signals()
    summary: Dict[str, Any] = {
        "total_signals": len(signals),
        "by_state": {},
        "by_type": {},
        "signal_states": {},
    }
    for signal_id, signal_data in signals.items():
        state = signal_data.get("current_state", "UNKNOWN")
        signal_type = signal_data.get("signal_type", "unknown")
        summary["by_state"][state] = summary["by_state"].get(state, 0) + 1
        summary["by_type"][signal_type] = summary["by_type"].get(signal_type, 0) + 1
        summary["signal_states"][signal_id] = {
            "state": state,
            "type": signal_type,
            "title": signal_data.get("title", ""),
            "description": signal_data.get("description", ""),
            "history": signal_data.get("state_history", []),
        }

    logger.debug(f" Signal summary: {summary}")
    return summary

def _verify_location_exists(self, location: str, context: Dict[str, Any]) -> tuple[bool, str]:
    """验证 location 是否在上下文中存在

    Args:
        location: 位置字符串（格式：文件路径:行号）
        context: 上下文信息

    Returns:
        (是否有效, 错误信息)
    """
    if not location:
        return False, "Empty location"

    parts = location.rsplit(":", 1)
    if len(parts) != 2:
        return False, f"Invalid location format: {location}"

    file_path, line_str = parts

    try:
        if "-" in line_str:
            line_num = int(line_str.split("-")[0])
        else:
            line_num = int(line_str)
    except ValueError:
        return False, f"Invalid line number: {line_str}"

    current_file = context.get("current_file", "")
    current_file_normalized = Path(current_file).resolve()
    file_path_normalized = Path(file_path).resolve()
    if file_path_normalized != current_file_normalized:
        return False, f"File path mismatch: expected {current_file}, got {file_path}"

    file_content = context.get("file_content", "")
    if not file_content:
        return False, "No file content in context"

    line_count = file_content.count("\n") + 1
    if line_num < 1 or line_num > line_count:
        return False, f"Line number {line_num} out of range (1-{line_count})"

    return True, ""

def _check_agent3_agent6_consistency(
    self, final_findings: List[Dict[str, Any]], vulnerability_verification: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """检查 Agent-6 与 Agent-3 的一致性

    如果 Agent-6 REJECTED 但 Agent-3 CONFIRMED 的信号，自动进入人工复核队列

    Args:
        final_findings: Agent-6 的最终发现
        vulnerability_verification: Agent-3 的验证结果

    Returns:
        添加了人工复核标记的最终发现
    """
    inconsistencies = []

    agent3_confirmed = {}
    for vuln in vulnerability_verification.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        signal_id = vuln.get("signal_id", "")
        decision = vuln.get("verification_decision", "")
        if decision == "CONFIRMED" and signal_id:
            agent3_confirmed[signal_id] = vuln

    if not agent3_confirmed:
        return final_findings

    agent6_rejected_signals = set()
    agent6_confirmed_signals = set()
    for finding in final_findings:
        linked_signals = finding.get("linked_signals", [])
        status = finding.get("status", "")
        signal_state = finding.get("signal_state", "")

        for sig in linked_signals:
            if status == "REJECTED" or signal_state == "REJECTED":
                agent6_rejected_signals.add(sig)
            elif status == "CONFIRMED" or signal_state == "CONFIRMED":
                agent6_confirmed_signals.add(sig)

    conflict_signals = set(agent3_confirmed.keys()) - agent6_confirmed_signals

    if not conflict_signals:
        return final_findings

    for sig in conflict_signals:
        if sig in agent6_rejected_signals:
            inconsistencies.append(sig)
            logger.warning(
                f"Agent-6 与 Agent-3 不一致: 信号 {sig} 被 Agent-6 REJECTED 但被 Agent-3 CONFIRMED"
            )
    if inconsistencies:
        logger.debug(f" 发现 {len(inconsistencies)} 个 Agent-6 与 Agent-3 不一致的信号，标记为需要人工复核")
        for finding in final_findings:
            linked_signals = finding.get("linked_signals", [])
            for sig in inconsistencies:
                if sig in linked_signals:
                    finding["requires_human_review"] = True
                    finding[
                        "consistency_warning"
                    ] = f"Agent-6 与 Agent-3 不一致: 信号 {sig} 被 Agent-6 拒绝但被 Agent-3 确认"
                    logger.debug(f" 标记发现 {finding.get('vulnerability', 'unknown')} 需要人工复核")

    agent6_final_findings = final_findings
    for sig in inconsistencies:
        if sig not in [f.get("signal_id") for f in agent6_final_findings]:
            agent3_data = agent3_confirmed[sig]
            human_review_finding = {
                "vulnerability": agent3_data.get("vulnerability", "人工复核风险"),
                "location": agent3_data.get("location", ""),
                "severity": agent3_data.get("severity", "MEDIUM"),
                "status": "WEAK",
                "confidence": "MEDIUM",
                "cvss_score": agent3_data.get("cvss_score", "5.0"),
                "description": f'[人工复核] Agent-6 拒绝但 Agent-3 确认的风险: {agent3_data.get("vulnerability", "")}',
                "recommendation": "需要人工复核确认",
                "evidence": agent3_data.get("evidence", []),
                "evidence_chain_summary": f"Agent-3 CONFIRMED but Agent-6 REJECTED - signal: {sig}",
                "requires_human_review": True,
                "signal_state": "UNCERTAIN",
                "linked_signals": [sig],
                "consistency_warning": f"Agent-6 与 Agent-3 不一致: 信号 {sig} 被 Agent-6 拒绝但被 Agent-3 确认",
            }
            agent6_final_findings.append(human_review_finding)
            logger.debug(
                f"添加人工复核发现: signal={sig}, vulnerability={agent3_data.get('vulnerability', '')}"
            )
    return agent6_final_findings

def _validate_final_findings(
    self,
    final_decision: Dict[str, Any],
    context: Dict[str, Any],
    vulnerability_verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """验证并过滤最终发现中的无效 location

    Args:
        final_decision: Agent-6 的输出
        context: 上下文信息
        vulnerability_verification: Agent-3 的验证结果（用于一致性检查）

    Returns:
        验证后的结果
    """
    from src.ai.pure_ai.line_number_mapper import LineNumberValidator

    findings = final_decision.get("final_findings", [])

    if vulnerability_verification:
        findings = self._check_agent3_agent6_consistency(findings, vulnerability_verification)

    if not findings:
        return final_decision

    validator = LineNumberValidator(self.line_number_mapper)
    validator._snapshots = self.line_number_mapper._snapshots

    valid_findings = []
    rejected_count = 0
    line_validation_summary = {
        "total": 0,
        "exact": 0,
        "fuzzy": 0,
        "not_found": 0,
        "corrected": 0,
        "unverified": 0,
    }

    for finding in findings:
        location = finding.get("location", "")
        is_valid, error = self._verify_location_exists(location, context)

        if is_valid:
            code_snippet = finding.get("code_snippet", "")
            validation_result = validator.verify_and_correct(location, code_snippet)

            finding["ai_reported_line"] = validation_result["ai_reported_line"]
            finding["verified_line"] = validation_result["verified_line"]
            finding["line_match_status"] = validation_result["line_match_status"]
            finding["code_snippet"] = validation_result["code_snippet"]

            line_validation_summary["total"] += 1
            if validation_result["line_match_status"] == "EXACT":
                line_validation_summary["exact"] += 1
            elif validation_result["line_match_status"] == "FUZZY":
                line_validation_summary["fuzzy"] += 1
            elif validation_result["line_match_status"] == "NOT_FOUND":
                line_validation_summary["not_found"] += 1
            elif validation_result["line_match_status"] == "UNVERIFIED":
                line_validation_summary["unverified"] += 1

            if validation_result["deviation"] > 0:
                line_validation_summary["corrected"] += 1
                logger.debug(
                    f"Line corrected: {location} -> {validation_result['verified_line']} (deviation: {validation_result['deviation']})"
                )
            if validation_result.get("is_valid", True):
                valid_findings.append(finding)
            else:
                logger.warning(
                    f"Filtered finding without valid code snippet: {finding.get('rule_name', 'unknown')} at {location}"
                )
                logger.warning(
                    f"Reason: {validation_result.get('warning_message', 'code_snippet is empty or invalid')}"
                )
                rejected_count += 1
        else:
            logger.warning(
                f"Filtered invalid finding: {finding.get('rule_name', 'unknown')} at {location} - {error}"
            )
            rejected_count += 1

    summary = final_decision.get("summary", {})
    summary["invalid_vulnerabilities"] = (
        summary.get("invalid_vulnerabilities", 0) + rejected_count
    )
    summary["total_vulnerabilities"] = len(valid_findings)
    summary["valid_vulnerabilities"] = len(valid_findings)
    summary["line_validation"] = line_validation_summary

    return {"final_findings": valid_findings, "summary": summary}

def _deterministic_promote(
    self,
    final_decision: Dict[str, Any],
    vulnerability_verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """[OPT-P1/P3] 确定性升级：验证优先于 LLM 保守裁决。

    规则（全部基于机器可查事实，不引入新的 LLM 判断）：
    1. 高危/严重（HIGH/CRITICAL）finding，Agent-3 验证决策为 CONFIRMED，
       但 Agent-6 因"攻击链/数据流未走完"压为 WEAK/REFINED/UNCERTAIN →
       升级为 CONFIRMED，并记录 deterministic_basis（验证优先于拒绝，与
       论文 C2 声称「CONFIRMED 优先于 REJECTED」一致）。
    2. 高危 finding 且 Agent-3 验证决策为 REFINED → 保持 REFINED 但标记
       requires_human_review=True（不静默丢弃，回收 Sifting-the-Noise 类
       "被吞真漏洞"）。
    仅在 deterministic_promote_enabled=True 时生效（可消融）。
    """
    if not getattr(self, "deterministic_promote_enabled", False):
        return final_decision
    try:
        findings = final_decision.get("final_findings") or []
        if not findings or not isinstance(vulnerability_verification, dict):
            return final_decision
        vulns = vulnerability_verification.get("vulnerabilities") or []
        # signal_id -> Agent-3 验证决策
        verify_map = {}
        for v in vulns:
            if not isinstance(v, dict):
                continue
            sid = v.get("signal_id") or ""
            if sid:
                verify_map[sid] = (
                    v.get("verification_decision") or v.get("signal_state") or "UNKNOWN"
                )
        promoted = 0
        marked_review = 0
        for f in findings:
            if not isinstance(f, dict):
                continue
            severity = str(f.get("severity", "")).upper()
            if severity not in ("HIGH", "CRITICAL"):
                continue
            status = str(f.get("status", "")).upper()
            if status in ("CONFIRMED", "REJECTED", "INVALID"):
                continue
            # 收集该 finding 关联的 Agent-3 决策
            linked = f.get("linked_signals") or []
            if isinstance(linked, str):
                linked = [linked]
            decisions = [
                verify_map.get(str(s), "UNKNOWN")
                for s in (linked or [])
                if str(s) in verify_map
            ]
            if not decisions:
                decisions = [
                    verify_map.get(str(f.get("signal_id", "")), "UNKNOWN")
                ]
            if any(d == "CONFIRMED" for d in decisions):
                f["status"] = "CONFIRMED"
                f["signal_state"] = "CONFIRMED"
                f["promoted_by"] = "deterministic-evidence"
                f["deterministic_basis"] = (
                    "Agent-3 CONFIRMED + HIGH/CRITICAL：验证优先于 Agent-6 保守裁决"
                )
                f["requires_human_review"] = False
                promoted += 1
            elif any(d == "REFINED" for d in decisions):
                f["requires_human_review"] = True
                f["review_note"] = "高危信号 Agent-3 已细化但验证链未完整，保留人工复核"
                marked_review += 1
        if promoted or marked_review:
            logger.info(
                f"[OPT-P1/P3] 确定性升级: {promoted} 条 WEAK→CONFIRMED, {marked_review} 条标记人工复核"
            )
            self.debug_logs.append(
                f"[OPT-P1/P3] 确定性升级: {promoted} 条 WEAK→CONFIRMED, {marked_review} 条标记人工复核"
            )
            summary = final_decision.get("summary", {})
            summary["deterministic_promoted"] = promoted
            summary["deterministic_marked_review"] = marked_review
            final_decision["summary"] = summary
    except Exception as e:
        logger.debug(f"[OPT-P1/P3] 确定性升级失败: {e}")
    return final_decision

def _validate_result_consistency(self, result: Dict[str, Any]) -> Dict[str, Any]:
    """验证结果一致性

    检查风险枚举与验证阶段的信号数量是否一致
    如果不一致，发出警告并计算一致性评分

    Args:
        result: 分析结果

    Returns:
        添加了一致性信息的result
    """
    risk_enum = result.get("risk_enumeration", {})
    vuln_verif = result.get("vulnerability_verification", {})

    risk_signals = risk_enum.get("risks", [])
    vuln_signals = vuln_verif.get("vulnerabilities", [])

    risk_count = len(risk_signals)
    vuln_count = len(vuln_signals)

    tracker_signals = (
        self.evidence_chain_tracker.get_all_signals()
        if hasattr(self, "evidence_chain_tracker")
        else {}
    )
    tracker_count = len(tracker_signals)
    tracker_verified = sum(
        1
        for s in tracker_signals.values()
        if s.get("current_state") in ["CONFIRMED", "REJECTED", "REFINED"]
    )
    tracker_new = sum(1 for s in tracker_signals.values() if s.get("current_state") == "NEW")

    if vuln_count == 0 and tracker_count > 0:
        vuln_count = tracker_verified
        logger.debug(
            f"Using tracker signal count for verification: {vuln_count} (total: {tracker_count}, verified: {tracker_verified}, new: {tracker_new})"
        )
    consistency_score = 1.0
    if risk_count > 0:
        consistency_score = min(vuln_count / risk_count, 1.0) if vuln_count > 0 else 0.0

    stability_warning = None
    if risk_count != vuln_count and risk_count > 0:
        if vuln_count < risk_count:
            stability_warning = f"[稳定性警告] 风险枚举({risk_count})与验证({vuln_count})信号数不一致，{risk_count - vuln_count}个信号未被验证"
            logger.debug(f" {stability_warning}")
            self.debug_logs.append(stability_warning)
        else:
            stability_warning = f"[稳定性警告] 验证阶段发现了额外的{vuln_count - risk_count}个信号"
            logger.debug(f" {stability_warning}")
            self.debug_logs.append(stability_warning)

    result["consistency_score"] = consistency_score
    result["stability_warning"] = stability_warning
    result["signal_count"] = {
        "risk_enumeration": risk_count,
        "vulnerability_verification": vuln_count,
        "tracker_total": tracker_count,
        "tracker_verified": tracker_verified,
        "tracker_new": tracker_new,
        "difference": abs(risk_count - vuln_count),
    }

    return result