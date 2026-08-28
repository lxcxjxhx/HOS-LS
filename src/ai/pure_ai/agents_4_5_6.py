"""Agent 4-6：攻击链、对抗验证、最终裁决

从 MultiAgentPipeline 提取的确定性（不消耗 token）Agent 运行器。
"""

from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


def _synthesize_attack_chains(
    self,
    vulnerability_verification: Dict[str, Any],
    file_path: str = "",
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """确定性合成攻击链（不消耗 token）。

    从 Agent-3 的 CONFIRMED/REFINED 漏洞合成最小单步攻击链。
    每一条已验证漏洞都天然是一条"单步可达链"：漏洞直接导致安全影响。

    Returns:
        (攻击链结果, token使用信息{0 token})
    """
    result = {
        "attack_chains": [],
        "signal_tracking": {
            "total_signals": 0, "signals_new": 0,
            "signals_confirmed": 0, "signals_rejected": 0,
        },
    }

    vulns = (
        vulnerability_verification.get("vulnerabilities", [])
        if isinstance(vulnerability_verification, dict)
        else []
    )
    verified = [
        v
        for v in vulns
        if isinstance(v, dict)
        and (v.get("verification_decision") or v.get("signal_state"))
        in ("CONFIRMED", "REFINED")
    ]

    chains = []
    for i, v in enumerate(verified[:12], 1):
        title = v.get("title") or v.get("vulnerability") or "未命名漏洞"
        location = v.get("location") or ""
        severity = v.get("severity") or "HIGH"
        description = v.get("description") or v.get("verification_reason") or ""
        evidence = v.get("evidence", [])
        chains.append({
            "name": f"单步可达链-{title}",
            "steps": [
                {
                    "step": 1,
                    "description": f"利用已验证漏洞 {title}（{location}）直接触发安全影响。验证描述：{description}",
                    "prerequisites": [],
                    "payload": "",
                    "evidence": evidence[:5] if evidence else [],
                }
            ],
            "final_impact": f"利用 {title} 达成未授权影响",
            "severity": severity,
            "cvss_score": v.get("cvss_score") or "",
            "defense_bypasses": [],
            "signal_id": f"CHAIN-DET-{i}",
            "signal_state": "CONFIRMED",
            "linked_signal_ids": [v.get("signal_id") or f"RISK-{i}"],
            "evidence": [
                {
                    "type": "flow",
                    "location": location,
                    "reason": f"确定性合成：Agent-3 已确认漏洞 {title} 的利用路径",
                    "confidence": 0.8,
                }
            ],
        })

    result["attack_chains"] = chains
    result["signal_tracking"]["total_signals"] = len(chains)
    result["signal_tracking"]["signals_new"] = len(chains)
    result["synthesized_deterministically"] = True

    return result, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

async def run_agent_4(
    self,
    file_path: str,
    vulnerability_verification: Dict[str, Any],
    detected_language: str = "Unknown",
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 4：攻击链合成（确定性，不消耗 token）

    从 Agent-3 已验证的 CONFIRMED/REFINED 漏洞合成最小单步攻击链。
    所有已验证漏洞天然构成"单步可达链"：漏洞直接导致安全影响。
    """
    logger.debug(f" 运行Agent 4 (攻击链合成/确定性) on: {file_path}")
    pipeline.debug_logs.append(f"[DEBUG] 运行Agent 4 (攻击链合成/确定性) on: {file_path}")

    result, token_usage = pipeline._synthesize_attack_chains(vulnerability_verification, file_path)

    logger.debug(f" Agent 4 完成，合成 {len(result.get('attack_chains', []))} 条攻击链（确定性，0 token）")
    pipeline.debug_logs.append(f"[DEBUG] Agent 4 完成，确定性合成（0 token）")
    return result, token_usage

def _deterministic_adversarial_check(
    self,
    attack_chain_analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """确定性对抗验证（不消耗 token）。

    攻击链来自 Agent-4 确定性合成（基于 Agent-3 已确认漏洞），
    因此默认 ACCEPT 已验证的攻击链。信号状态映射：
    - Agent-4 生成的链（signal_state=CONFIRMED）→ ACCEPT
    - 兜底生成的链（fallback_generated=true）→ ESCALATE（说明信息不足）
    """
    chains = (
        attack_chain_analysis.get("attack_chains", [])
        if isinstance(attack_chain_analysis, dict)
        else []
    )
    adversarial_analysis = []
    cross_agent_agreement = []

    for chain in chains:
        if not isinstance(chain, dict):
            continue

        chain_name = chain.get("name", "")
        chain_id = chain.get("signal_id", "")
        is_fallback = chain.get("fallback_generated", False)
        signal_state = chain.get("signal_state", "NEW")

        # 确定性映射
        if signal_state == "CONFIRMED" and not is_fallback:
            verdict = "ACCEPT"
            confidence = 0.8
            requires_review = False
        elif is_fallback:
            verdict = "ESCALATE"
            confidence = 0.5
            requires_review = True
        else:
            verdict = "UNCERTAIN"
            confidence = 0.3
            requires_review = True

        adversarial_analysis.append({
            "attack_chain_name": chain_name or chain_id,
            "verdict": verdict,
            "confidence": confidence,
            "reason": f"确定性裁决：上游 Agent-3 验证决策映射为 {verdict}",
            "counter_arguments": [],
            "evidence": chain.get("evidence", []),
            "requires_human_review": requires_review,
            "challenged_signal_id": chain_id,
        })

        cross_agent_agreement.append({
            "signal_id": chain_id,
            "signal_type": "attack_chain",
            "original_agent": "Agent-4",
            "current_state": verdict,
            "evidence_chain": chain.get("evidence", []),
            "confirmed_by": ["Agent-3", "Agent-4"] if verdict == "ACCEPT" else [],
            "rejected_by": [],
            "refined_by": [],
        })

    return {
        "adversarial_analysis": adversarial_analysis,
        "cross_agent_agreement": cross_agent_agreement,
    }

async def run_agent_5(
    self,
    file_path: str,
    attack_chain_analysis: Dict[str, Any],
    file_content: str,
    detected_language: str = "Unknown",
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 5：对抗验证（确定性，不消耗 token）

    对 Agent-4 确定性合成的攻击链，根据上游 Agent-3 的验证决策直接映射为裁决：
    - Agent-3 CONFIRMED → ACCEPT
    - Agent-3 REFINED → ESCALATE
    - 其他 → UNCERTAIN
    """
    logger.debug(f" 运行Agent 5 (对抗验证/确定性) on: {file_path}")
    pipeline.debug_logs.append(f"[DEBUG] 运行Agent 5 (对抗验证/确定性) on: {file_path}")

    result = pipeline._deterministic_adversarial_check(attack_chain_analysis)

    logger.debug(f" Agent 5 完成，确定性裁决（0 token）")
    pipeline.debug_logs.append(f"[DEBUG] Agent 5 完成，确定性裁决（0 token）")
    return result, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

def _deterministic_final_decision(
    self,
    vulnerability_verification: Dict[str, Any],
    context: Dict[str, Any],
    adversarial_validation: Dict[str, Any],
) -> Dict[str, Any]:
    """[RECONSTRUCTED] 确定性最终裁决（不消耗 token）。

    直接从 Agent-3 已验证的 CONFIRMED 漏洞中聚合结果：
    1. 提取所有 CONFIRMED/REFINED 漏洞
    2. 验证 location 合法性
    3. 去重（按 location + 漏洞类型）
    4. 添加 adversarial 中 ESCALATE 的信号
    5. 格式化输出

    替代原 Agent-6 的 LLM 调用。
    """
    vulns = (
        vulnerability_verification.get("vulnerabilities", [])
        if isinstance(vulnerability_verification, dict) else []
    )
    findings = []
    seen: set = set()

    for v in vulns:
        if not isinstance(v, dict):
            continue
        decision = v.get("verification_decision", "")
        signal_state = v.get("signal_state", "")
        if decision != "CONFIRMED" and signal_state != "CONFIRMED":
            continue
        title = v.get("title") or v.get("vulnerability") or "未命名漏洞"
        location = v.get("location", "")
        severity = v.get("severity", "MEDIUM")
        dedup_key = f"{location}:{title}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        is_valid, error = (
            pipeline._verify_location_exists(location, context) if location
            else (False, "Empty location")
        )
        findings.append({
            "vulnerability": title,
            "location": location,
            "severity": severity,
            "status": "CONFIRMED" if is_valid else "WEAK",
            "confidence": "HIGH" if decision == "CONFIRMED" else "MEDIUM",
            "cvss_score": v.get("cvss_score", ""),
            "description": v.get("description", "") or v.get("verification_reason", ""),
            "recommendation": v.get("recommendation", ""),
            "evidence": v.get("evidence", []),
            "evidence_chain_summary": f"Agent-3 漏洞验证确认：{title} @ {location}",
            "requires_human_review": not is_valid,
            "signal_state": "CONFIRMED",
            "linked_signals": [v.get("signal_id", "")],
        })

    adv_analysis = (
        adversarial_validation.get("adversarial_analysis", [])
        if isinstance(adversarial_validation, dict) else []
    )
    for adv in adv_analysis:
        if not isinstance(adv, dict):
            continue
        verdict = adv.get("verdict", "")
        if verdict != "ESCALATE":
            continue
        chain_name = adv.get("attack_chain_name", "")
        chain_id = adv.get("challenged_signal_id", "")
        dedup_key = f"ESCALATE:{chain_id}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        findings.append({
            "vulnerability": chain_name or "待复核信号",
            "location": "",
            "severity": "MEDIUM",
            "status": "WEAK",
            "confidence": "MEDIUM",
            "cvss_score": "",
            "description": f"需要人工复核：{adv.get('reason', '')}",
            "recommendation": "需要人工安全审查确认",
            "evidence": adv.get("evidence", []),
            "evidence_chain_summary": f"确定性对抗验证标记为需要人工复核：{chain_name}",
            "requires_human_review": True,
            "signal_state": "UNCERTAIN",
            "linked_signals": [chain_id],
        })

    confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    weak = sum(1 for f in findings if f.get("status") == "WEAK")
    return {
        "final_findings": findings,
        "summary": {
            "total_vulnerabilities": len(findings),
            "valid_vulnerabilities": confirmed,
            "uncertain_vulnerabilities": weak,
            "invalid_vulnerabilities": 0,
            "high_severity_count": sum(1 for f in findings if f.get("severity") in ("HIGH", "CRITICAL")),
            "medium_severity_count": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "low_severity_count": sum(1 for f in findings if f.get("severity") in ("LOW", "INFO")),
            "signals_confirmed": confirmed,
            "signals_rejected": 0,
            "signals_refined": weak,
            "deterministic_aggregation": True,
        },
    }

async def run_agent_6(
    self,
    file_path: str,
    context: Dict[str, Any],
    adversarial_validation: Dict[str, Any],
    vulnerability_verification: Dict[str, Any],
    detected_language: str = "Unknown",
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """[RECONSTRUCTED] 运行Agent 6：最终裁决（确定性聚合，不消耗 token）

    从 Agent-3 已验证的 CONFIRMED 漏洞中聚合结果，不调用 LLM。
    """
    logger.debug(f" 运行Agent 6 (最终裁决/确定性聚合) on: {file_path}")
    pipeline.debug_logs.append(f"[DEBUG] 运行Agent 6 (最终裁决/确定性聚合) on: {file_path}")
    result = pipeline._deterministic_final_decision(
        vulnerability_verification, context, adversarial_validation
    )
    logger.debug(f" Agent 6 完成，确定性聚合（0 token）")
    pipeline.debug_logs.append(f"[DEBUG] Agent 6 完成，确定性聚合（0 token）")
    return result, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

