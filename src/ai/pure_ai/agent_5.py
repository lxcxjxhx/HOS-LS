"""Agent 5：对抗验证（确定性，不消耗 token）

对 Agent-4 确定性合成的攻击链，根据上游 Agent-3 的验证决策直接映射裁决。
"""

from typing import Any, Dict, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


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
    self.debug_logs.append(f"[DEBUG] 运行Agent 5 (对抗验证/确定性) on: {file_path}")

    result = _deterministic_adversarial_check(self, attack_chain_analysis)

    logger.debug(f" Agent 5 完成，确定性裁决（0 token）")
    self.debug_logs.append(f"[DEBUG] Agent 5 完成，确定性裁决（0 token）")
    return result, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def _deterministic_adversarial_check(
    self,
    attack_chain_analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """确定性对抗验证（不消耗 token）。

    攻击链来自 Agent-4 确定性合成（基于 Agent-3 已确认漏洞）。
    确定性映射规则：
    - signal_state=CONFIRMED → ACCEPT（已验证漏洞的利用路径默认可行）
    - fallback_generated=True → ESCALATE（兜底生成，信息不足）
    - 其他 → UNCERTAIN
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

        if signal_state == "CONFIRMED" and not is_fallback:
            verdict, confidence, requires_review = "ACCEPT", 0.8, False
        elif is_fallback:
            verdict, confidence, requires_review = "ESCALATE", 0.5, True
        else:
            verdict, confidence, requires_review = "UNCERTAIN", 0.3, True

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
