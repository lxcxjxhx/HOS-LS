"""Agent 6：最终裁决（确定性聚合，不消耗 token）

从 Agent-3 已验证的 CONFIRMED 漏洞中聚合结果：去重 + 位置验证 + 格式化输出。
"""

from typing import Any, Dict, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


async def run_agent_6(
    self,
    file_path: str,
    context: Dict[str, Any],
    adversarial_validation: Dict[str, Any],
    vulnerability_verification: Dict[str, Any],
    detected_language: str = "Unknown",
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 6：最终裁决（确定性聚合，不消耗 token）

    从 Agent-3 已验证的 CONFIRMED 漏洞中聚合结果，不调用 LLM。
    """
    logger.debug(f" 运行Agent 6 (最终裁决/确定性聚合) on: {file_path}")
    self.debug_logs.append(f"[DEBUG] 运行Agent 6 (最终裁决/确定性聚合) on: {file_path}")
    result = _deterministic_final_decision(
        self, vulnerability_verification, context, adversarial_validation
    )
    logger.debug(f" Agent 6 完成，确定性聚合（0 token）")
    self.debug_logs.append(f"[DEBUG] Agent 6 完成，确定性聚合（0 token）")
    return result, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def _deterministic_final_decision(
    self,
    vulnerability_verification: Dict[str, Any],
    context: Dict[str, Any],
    adversarial_validation: Dict[str, Any],
) -> Dict[str, Any]:
    """确定性最终裁决（不消耗 token）。

    直接从 Agent-3 已验证的 CONFIRMED 漏洞中聚合结果：
    1. 提取所有 CONFIRMED 漏洞
    2. 验证 location 合法性
    3. 去重（按 location + 漏洞类型）
    4. 添加 adversarial 中 ESCALATE 的信号
    5. 格式化输出
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
            self._verify_location_exists(location, context) if location
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
