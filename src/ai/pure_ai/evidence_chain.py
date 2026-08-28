"""证据链追踪器

追踪和管理多Agent流水线中的信号和证据链。
"""

from typing import Any, Dict, List, Optional, Tuple

from src.ai.pure_ai.schema import SignalState
from src.utils.logger import get_logger

logger = get_logger(__name__)

class EvidenceChain:
    """证据链追踪器"""

    SIGNAL_COOLDOWN_SECONDS = 5
    MAX_STATE_CHANGES = 15
    TERMINAL_STATES = ["CONFIRMED", "REJECTED"]

    def __init__(self):
        self.signals: Dict[str, Dict[str, Any]] = {}
        self.evidence_chain: Dict[str, List[Dict[str, Any]]] = {}
        self._signal_cooldown: Dict[str, float] = {}
        self._signal_versions: Dict[str, int] = {}
        self._created_signal_ids: set = set()
        self._signal_locations: Dict[str, Tuple[str, str]] = {}

    def _is_duplicate_signal(
        self, signal_id: str, location: str, description: str
    ) -> Tuple[bool, str]:
        """检查是否存在重复信号

        Args:
            signal_id: 信号ID
            location: 信号位置
            description: 信号描述

        Returns:
            (是否重复, 重复信号ID)
        """
        location_lower = location.lower() if location else ""
        desc_lower = description.lower() if description else ""

        for existing_id, (existing_location, existing_desc) in self._signal_locations.items():
            if existing_id == signal_id:
                continue

            existing_location_lower = existing_location.lower() if existing_location else ""
            existing_desc_lower = existing_desc.lower() if existing_desc else ""

            location_match = (
                location_lower
                and existing_location_lower
                and location_lower == existing_location_lower
            )
            desc_similar = (
                desc_lower
                and existing_desc_lower
                and (
                    desc_lower in existing_desc_lower
                    or existing_desc_lower in desc_lower
                    or (
                        len(desc_lower) > 10
                        and len(existing_desc_lower) > 10
                        and (
                            desc_lower[:20] == existing_desc_lower[:20]
                            if len(desc_lower) >= 20 and len(existing_desc_lower) >= 20
                            else False
                        )
                    )
                )
            )

            if location_match and desc_similar:
                return True, existing_id

            if location_match and not description and not existing_desc:
                return True, existing_id

        return False, ""

    def _check_cooldown(self, signal_id: str) -> Tuple[bool, float]:
        """检查信号是否处于冷却期

        Args:
            signal_id: 信号ID

        Returns:
            (是否在冷却中, 剩余冷却时间)
        """
        if signal_id not in self._signal_cooldown:
            return False, 0.0

        elapsed = time.time() - self._signal_cooldown[signal_id]
        if elapsed < self.SIGNAL_COOLDOWN_SECONDS:
            return True, self.SIGNAL_COOLDOWN_SECONDS - elapsed

        return False, 0.0

    def _update_cooldown(self, signal_id: str) -> None:
        """更新信号冷却时间

        Args:
            signal_id: 信号ID
        """
        self._signal_cooldown[signal_id] = time.time()

    def add_signal(
        self,
        signal_id: str,
        signal_type: str,
        agent: str,
        state: str,
        evidence: List[Dict[str, Any]],
        title: str = "",
        description: str = "",
        location: str = "",
    ):
        """添加信号

        Args:
            signal_id: 信号ID
            signal_type: 信号类型
            agent: 来源Agent
            state: 信号状态
            evidence: 证据列表
            title: 风险标题（可选）
            description: 风险描述（可选）
            location: 信号位置（可选）
        """
        in_cooldown, remaining = self._check_cooldown(signal_id)
        if in_cooldown:
            logger.warning(
                f"Signal {signal_id} in cooldown ({remaining:.1f}s remaining), ignoring add request from {agent}"
            )
            return

        if signal_id in self._created_signal_ids:
            current = self.signals.get(signal_id, {})
            current_state = current.get("current_state", "")
            if current_state in self.TERMINAL_STATES:
                logger.debug(
                    f"Signal {signal_id} already created with terminal state {current_state}, ignoring duplicate creation request from {agent}"
                )
                return
            existing_history_len = len(current.get("state_history", []))
            if existing_history_len >= self.MAX_STATE_CHANGES and current_state != "REFINED":
                logger.debug(
                    f"Signal {signal_id} reached max state changes ({self.MAX_STATE_CHANGES}), ignoring creation request from {agent}"
                )
                return

        location_for_dedup = location
        if not location_for_dedup and evidence:
            for e in evidence:
                if isinstance(e, dict) and e.get("location"):
                    location_for_dedup = e.get("location", "")
                    break

        is_dup, dup_id = self._is_duplicate_signal(signal_id, location_for_dedup, description)
        if is_dup:
            dup_signal = self.signals.get(dup_id, {})
            dup_state = dup_signal.get("current_state", "")
            if dup_state in ["REFINED", "CONFIRMED"]:
                logger.debug(
                    f"Duplicate signal detected: {signal_id} matches {dup_id} (state: {dup_state}), ignoring new signal creation"
                )
                return

        if signal_id not in self.signals:
            self.signals[signal_id] = {
                "signal_id": signal_id,
                "signal_type": signal_type,
                "title": title,
                "description": description,
                "original_agent": agent,
                "current_state": state,
                "state_history": [(agent, state)],
                "location": location_for_dedup,
            }
            self._created_signal_ids.add(signal_id)
            self._signal_versions[signal_id] = 1
            self._signal_cooldown[signal_id] = time.time()
            if location_for_dedup:
                self._signal_locations[signal_id] = (location_for_dedup, description)
            self.evidence_chain[signal_id] = list(evidence) if evidence else []
            logger.debug(f" Created new signal {signal_id} with state {state} by {agent}")

            unverified_placeholder_titles = [
                "UNVERIFIED_RISK",
                "UNVERIFIED",
                "GENERIC",
                "PLACEHOLDER",
                "risk相关安全风险",
                "UNKNOWN",
                "unknown",
                "",
            ]
            if title in unverified_placeholder_titles or "UNVERIFIED" in (title or "").upper():
                has_concrete_evidence = False
                if evidence:
                    for e in evidence:
                        if isinstance(e, dict) and e.get("code_snippet"):
                            has_concrete_evidence = True
                            break
                if not has_concrete_evidence:
                    logger.debug(
                        f" 信号 {signal_id} 标题为占位符且无具体证据，标记为待拒绝: title={title}"
                    )
                    self.signals[signal_id]["current_state"] = SignalState.REJECTED.value
                    self.signals[signal_id]["state_history"].append(
                        (agent, SignalState.REJECTED.value + " (UNVERIFIED_RISK placeholder)")
                    )
                    self.signals[signal_id]["unverified_placeholder"] = True
        else:
            existing_title = self.signals[signal_id].get("title", "")
            generic_titles = ["risk相关安全风险", "UNKNOWN", "unknown", ""]
            if existing_title in generic_titles or not existing_title:
                if title and title not in generic_titles:
                    self.signals[signal_id]["title"] = title
                    logger.debug(
                        f"Updated signal {signal_id} title from '{existing_title}' to '{title}'"
                    )
            if not self.signals[signal_id].get("description"):
                self.signals[signal_id]["description"] = description

            current_state = self.signals[signal_id].get("current_state")

            if current_state != state:
                history = self.signals[signal_id].get("state_history", [])

                if len(history) >= self.MAX_STATE_CHANGES and state != "REFINED":
                    logger.warning(
                        f"Signal {signal_id} state change limit ({self.MAX_STATE_CHANGES}) reached, ignoring transition from {current_state} to {state}"
                    )
                    self.signals[signal_id]["state_history"].append(
                        (agent, state + " (BLOCKED: limit reached)")
                    )
                elif state in self.TERMINAL_STATES and current_state not in self.TERMINAL_STATES:
                    if not self.validate_state_transition(signal_id, current_state or "", state):
                        logger.warning(
                            f"Signal {signal_id} invalid transition: {current_state} -> {state} blocked by state machine validation"
                        )
                        self.signals[signal_id]["state_history"].append(
                            (agent, state + " (BLOCKED: invalid transition)")
                        )
                    else:
                        self.signals[signal_id]["current_state"] = state
                        self.signals[signal_id]["state_history"].append((agent, state))
                        self._update_cooldown(signal_id)
                        logger.debug(
                            f"Signal {signal_id} state changed: {current_state} -> {state} (change #{len(history) + 1}, terminal state)"
                        )
                else:
                    in_cooldown_transition, remaining_transition = self._check_cooldown(signal_id)
                    if in_cooldown_transition:
                        logger.warning(
                            f"Signal {signal_id} in cooldown ({remaining_transition:.1f}s), ignoring transition from {current_state} to {state}"
                        )
                    elif not self.validate_state_transition(signal_id, current_state or "", state):
                        logger.warning(
                            f"Signal {signal_id} invalid transition: {current_state} -> {state} blocked by state machine validation"
                        )
                        self.signals[signal_id]["state_history"].append(
                            (agent, state + " (BLOCKED: invalid transition)")
                        )
                    else:
                        self.signals[signal_id]["current_state"] = state
                        self.signals[signal_id]["state_history"].append((agent, state))
                        self._update_cooldown(signal_id)
                        logger.debug(
                            f"Signal {signal_id} state changed: {current_state} -> {state} (change #{len(history) + 1})"
                        )
        if evidence:
            self.evidence_chain[signal_id].extend(evidence)

    def update_signal_state(
        self,
        signal_id: str,
        agent: str,
        new_state: str,
        evidence: List[Dict[str, Any]],
        confidence_change: Optional[float] = None,
        reason: Optional[str] = None,
    ) -> None:
        """更新信号状态

        Args:
            signal_id: 信号ID
            agent: 更新Agent
            new_state: 新状态
            evidence: 新证据
            confidence_change: 置信度变化（可选）
            reason: 状态转换原因（可选）
        """
        in_cooldown, remaining = self._check_cooldown(signal_id)
        if in_cooldown:
            logger.warning(
                f"Signal {signal_id} update blocked - in cooldown ({remaining:.1f}s remaining), requested by {agent}"
            )
            return

        if signal_id in self.signals:
            old_state = self.signals[signal_id]["current_state"]
            # old_agent = self.signals[signal_id].get("original_agent", "")

            state_change_count = len(self.signals[signal_id]["state_history"])
            if state_change_count >= self.MAX_STATE_CHANGES and new_state != "REFINED":
                logger.warning(
                    f"Signal {signal_id} state change limit ({self.MAX_STATE_CHANGES}) reached, ignoring transition from {old_state} to {new_state}"
                )
                self.signals[signal_id]["state_history"].append(
                    (agent, new_state + " (BLOCKED: limit reached)")
                )
                return

            if (
                old_state in self.TERMINAL_STATES
                and new_state in self.TERMINAL_STATES
                and old_state != new_state
            ):
                logger.warning(
                    f"Attempt to change terminal state {old_state} -> {new_state} for {signal_id} blocked"
                )
                self.signals[signal_id]["state_history"].append(
                    (agent, new_state + " (BLOCKED: terminal state protected)")
                )
                return

            if not self.validate_state_transition(signal_id, old_state, new_state):
                logger.warning(
                    f"Signal {signal_id} invalid transition: {old_state} -> {new_state} blocked by state machine validation"
                )
                self.signals[signal_id]["state_history"].append(
                    (agent, new_state + " (BLOCKED: invalid transition)")
                )
                return

            self.signals[signal_id]["current_state"] = new_state
            self.signals[signal_id]["state_history"].append((agent, new_state))
            self.evidence_chain[signal_id].extend(evidence)
            self._update_cooldown(signal_id)

            log_parts = [f"[DEBUG] Signal {signal_id} state: {old_state} -> {new_state} by {agent}"]
            if confidence_change is not None:
                log_parts.append(f"(confidence: {confidence_change:+.2f})")
            if reason:
                log_parts.append(f"reason: {reason}")
            logger.debug(" ".join(log_parts))

    def get_signal(self, signal_id: str) -> Optional[Dict[str, Any]]:
        """获取信号"""
        return self.signals.get(signal_id)

    def get_evidence_chain(self, signal_id: str) -> List[Dict[str, Any]]:
        """获取信号证据链"""
        return self.evidence_chain.get(signal_id, [])

    def get_all_signals(self) -> Dict[str, Dict[str, Any]]:
        """获取所有信号"""
        return self.signals

    def validate_state_transition(self, signal_id: str, from_state: str, to_state: str) -> bool:
        """验证状态转换是否合法

        Args:
            signal_id: 信号ID
            from_state: 原始状态
            to_state: 目标状态

        Returns:
            是否合法
        """
        valid_transitions = {
            SignalState.NEW.value: [
                SignalState.CONFIRMED.value,
                SignalState.REJECTED.value,
                SignalState.REFINED.value,
                SignalState.UNCERTAIN.value,
            ],
            SignalState.CONFIRMED.value: [SignalState.REJECTED.value, SignalState.UNCERTAIN.value],
            SignalState.REFINED.value: [
                SignalState.CONFIRMED.value,
                SignalState.REJECTED.value,
                SignalState.UNCERTAIN.value,
            ],
            SignalState.UNCERTAIN.value: [SignalState.CONFIRMED.value, SignalState.REJECTED.value],
            SignalState.REJECTED.value: [],
        }

        allowed = valid_transitions.get(from_state, [])
        return to_state in allowed

