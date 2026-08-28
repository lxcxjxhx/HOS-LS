"""Agent 4：攻击链合成（确定性，不消耗 token）

从 Agent-3 的 CONFIRMED/REFINED 漏洞确定性合成最小单步攻击链。
"""

from typing import Any, Dict, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


async def run_agent_4(
    self,
    file_path: str,
    vulnerability_verification: Dict[str, Any],
    detected_language: str = "Unknown",
    context: Any = None,
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """运行Agent 4：攻击链合成（确定性，不消耗 token）

    从 Agent-3 已验证的 CONFIRMED/REFINED 漏洞合成最小单步攻击链。
    """
    logger.debug(f" 运行Agent 4 (攻击链合成/确定性) on: {file_path}")
    self.debug_logs.append(f"[DEBUG] 运行Agent 4 (攻击链合成/确定性) on: {file_path}")

    result, token_usage = _synthesize_attack_chains(self, vulnerability_verification)

    logger.debug(f" Agent 4 完成，合成 {len(result.get('attack_chains', []))} 条攻击链（确定性，0 token）")
    self.debug_logs.append(f"[DEBUG] Agent 4 完成，确定性合成（0 token）")
    return result, token_usage


def _synthesize_attack_chains(
    self,
    vulnerability_verification: Dict[str, Any],
    file_path: str = "",
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """确定性合成攻击链（不消耗 token）。

    从 Agent-3 的 CONFIRMED/REFINED 漏洞合成最小单步攻击链。
    每一条已验证漏洞都天然是一条"单步可达链"：漏洞直接导致安全影响。
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
