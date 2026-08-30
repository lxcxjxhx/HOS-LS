"""Agent 6：最终裁决（确定性聚合，不消耗 token）。

在输出前对 Agent 3 结果去重、校验位置，并将仅与漏洞位置邻近的确定性
修复证据作为人工复核依据，避免文件中无关的安全代码抑制真实发现。
"""

from typing import Any, Dict, Optional, Tuple

from src.ai.pure_ai.patch_detector import PatchDetectionResult, analyze as patch_detect
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
    """聚合 Agent 3 的验证结果，不额外调用 LLM。"""
    logger.debug("运行 Agent 6（最终裁决/确定性聚合）: %s", file_path)
    self.debug_logs.append(f"[DEBUG] 运行 Agent 6（最终裁决）: {file_path}")

    file_content = context.get("file_content", "") if isinstance(context, dict) else ""
    patch_result = patch_detect(file_path, file_content)
    result = _deterministic_final_decision(
        self,
        vulnerability_verification,
        context,
        adversarial_validation,
        patch_result,
    )
    return result, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def _deterministic_final_decision(
    self,
    vulnerability_verification: Dict[str, Any],
    context: Dict[str, Any],
    adversarial_validation: Dict[str, Any],
    patch_result: Optional[PatchDetectionResult] = None,
) -> Dict[str, Any]:
    """生成最终结果，并保留不确定发现供人工复核。

    只有相同 CWE 的修复模式出现在漏洞 location 附近时，才把已确认发现降为
    WEAK；修复模式不是证明整个文件不存在该类漏洞的依据。
    """
    vulns = (
        vulnerability_verification.get("vulnerabilities", [])
        if isinstance(vulnerability_verification, dict)
        else []
    )
    findings = []
    seen: set = set()

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        decision = vuln.get("verification_decision", "")
        signal_state = vuln.get("signal_state", "")
        confirmed = decision == "CONFIRMED" or signal_state == "CONFIRMED"
        cross_file_refined = (
            decision == "REFINED"
            and "跨文件" in str(vuln.get("verification_reason", ""))
        )
        if not (confirmed or cross_file_refined):
            continue

        title = vuln.get("title") or vuln.get("vulnerability") or "未命名漏洞"
        location = vuln.get("location", "")
        dedup_key = f"{location}:{title}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        cwe_id = vuln.get("cwe_id", "")
        locally_fixed = bool(
            confirmed
            and patch_result is not None
            and patch_result.has_fix_near_location(cwe_id, location)
        )
        location_valid, _ = (
            self._verify_location_exists(location, context)
            if location
            else (False, "Empty location")
        )
        if locally_fixed:
            status, confidence = "WEAK", "LOW"
            fix_note = "[fix gate] 同 CWE 修复模式位于报告位置附近，需人工复核。"
        elif cross_file_refined:
            status, confidence = "WEAK", "MEDIUM"
            fix_note = "[跨文件路径待验证] "
        elif location_valid:
            status, confidence, fix_note = "CONFIRMED", "HIGH", ""
        else:
            status, confidence, fix_note = "WEAK", "MEDIUM", ""

        description = vuln.get("description", "") or vuln.get("verification_reason", "")
        findings.append({
            "vulnerability": title,
            "location": location,
            "severity": vuln.get("severity", "MEDIUM"),
            "status": status,
            "confidence": confidence,
            "cvss_score": vuln.get("cvss_score", ""),
            "description": fix_note + description,
            "recommendation": vuln.get("recommendation", ""),
            "evidence": vuln.get("evidence", []),
            "evidence_chain_summary": f"Agent-3 验证结果：{title} @ {location}",
            "requires_human_review": status != "CONFIRMED",
            "signal_state": status,
            "linked_signals": [vuln.get("signal_id", "")],
        })

    for adversarial in (
        adversarial_validation.get("adversarial_analysis", [])
        if isinstance(adversarial_validation, dict)
        else []
    ):
        if not isinstance(adversarial, dict) or adversarial.get("verdict") != "ESCALATE":
            continue
        signal_id = adversarial.get("challenged_signal_id", "")
        dedup_key = f"ESCALATE:{signal_id}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        title = adversarial.get("attack_chain_name") or "待复核信号"
        findings.append({
            "vulnerability": title,
            "location": "",
            "severity": "MEDIUM",
            "status": "WEAK",
            "confidence": "MEDIUM",
            "cvss_score": "",
            "description": f"需要人工复核：{adversarial.get('reason', '')}",
            "recommendation": "需要人工安全审查确认",
            "evidence": adversarial.get("evidence", []),
            "evidence_chain_summary": f"对抗验证要求复核：{title}",
            "requires_human_review": True,
            "signal_state": "UNCERTAIN",
            "linked_signals": [signal_id],
        })

    confirmed = sum(f["status"] == "CONFIRMED" for f in findings)
    weak = sum(f["status"] != "CONFIRMED" for f in findings)
    return {
        "final_findings": findings,
        "summary": {
            "total_vulnerabilities": len(findings),
            "valid_vulnerabilities": confirmed,
            "uncertain_vulnerabilities": weak,
            "invalid_vulnerabilities": 0,
            "high_severity_count": sum(
                f["severity"] in ("HIGH", "CRITICAL") for f in findings
            ),
            "medium_severity_count": sum(f["severity"] == "MEDIUM" for f in findings),
            "low_severity_count": sum(f["severity"] in ("LOW", "INFO") for f in findings),
            "signals_confirmed": confirmed,
            "signals_rejected": 0,
            "signals_refined": weak,
            "deterministic_aggregation": True,
        },
    }
