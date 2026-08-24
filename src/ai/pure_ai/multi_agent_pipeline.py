import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

from src.ai.models import AIRequest
from src.ai.prompt_engine import PromptEngine, get_prompt_engine
from src.ai.pure_ai.context_builder import ContextBuilder
from src.ai.pure_ai.line_number_mapper import LineNumberMapper
from src.ai.pure_ai.schema_validator import SchemaValidator

try:
    from src.ai.token_tracker import get_token_tracker
except ImportError:

    def get_token_tracker(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        return None


from src.ai.pure_ai.schema import SignalState
from src.utils.logger import get_logger

logger = get_logger(__name__)

console = Console()


class SemanticConsistencyError(Exception):
    """语义一致性异常"""


HIGH_SEVERITY_RISK_TYPES = [
    "CSRF",
    "csrf",
    "Cross-Site Request Forgery",
    "authentication",
    "Authentication",
    "认证",
    "authorization",
    "Authorization",
    "授权",
    "Privilege",
    "privilege",
    "越权",
    "token",
    "Token",
    "session",
    "Session",
    "令牌",
    "会话",
    "JWT",
    "OAuth",
    "OIDC",
    "SAML",
    "credential",
    "Credential",
    "凭证",
    "密码",
    "password",
    "Password",
    "IDOR",
    "idor",
    "访问控制",
    "access control",
    "SQL injection",
    "SQL注入",
    "sql injection",
    "SQL Injection",
    "XSS",
    "xss",
    "Cross-Site Scripting",
    "跨站脚本",
    "RCE",
    "rce",
    "Remote Code Execution",
    "命令执行",
    "SSRF",
    "ssrf",
    "Server-Side Request Forgery",
    "deserialize",
    "Deserialize",
    "反序列化",
    "serialization",
    "Serialization",
    "path traversal",
    "Path Traversal",
    "路径穿越",
    "directory traversal",
    "file inclusion",
    "File Inclusion",
    "文件包含",
    "LFI",
    "RFI",
    "XXE",
    "xxe",
    "XML External Entity",
    "SSTI",
    "ssti",
    "Server-Side Template Injection",
    "Race Condition",
    "race condition",
    "竞态条件",
    "Heap Inspection",
    "heap inspection",
    "Type Confusion",
    "type confusion",
]

CONFIDENCE_THRESHOLDS = {"high_severity": 0.3, "default": 0.5}

SIGNAL_QUEUE_TIMEOUT = 30

REJECTED_PLACEHOLDERS = [
    "UNVERIFIED_RISK",
    "UNVERIFIED",
    "GENERIC",
    "PLACEHOLDER",
    "UNKNOWN",
    "unknown",
    "未知风险",
    "风险相关安全风险",
    "UNVERIFIED_RISK相关安全风险",
    "风险",
    "安全风险",
    "相关安全风险",
    "漏洞",
    "待验证",
]

TOKEN_BUDGET_PER_FILE = 100000
TOKEN_WARNING_THRESHOLD = 0.8
TOKEN_CRITICAL_THRESHOLD = 0.95


class KnownFileRegistry:
    """已知文件注册表 - 防止幻觉引用

    维护一个已知文件的注册表，确保所有引用的 location
    都在已知的文件范围内，防止 AI 生成不存在的文件引用。
    """

    def __init__(self):
        self._files: Dict[str, str] = {}
        self._line_counts: Dict[str, int] = {}

    def register(self, file_path: str, content: str) -> None:
        """注册文件到注册表

        Args:
            file_path: 文件路径
            content: 文件内容
        """
        self._files[file_path] = content
        self._line_counts[file_path] = content.count("\n") + 1 if content else 1

    def clear(self) -> None:
        """清空注册表"""
        self._files.clear()
        self._line_counts.clear()

    def validate_location(self, location: str) -> Tuple[bool, str]:
        """验证 location 是否有效

        Args:
            location: 位置字符串（格式：文件路径:行号）

        Returns:
            (是否有效, 错误信息)
        """
        if not location:
            return False, "Empty location"

        parts = location.rsplit(":", 1)
        if len(parts) != 2:
            return False, f"Invalid location format: {location}"

        path, line_str = parts

        if path not in self._files:
            available = ", ".join(list(self._files.keys())[:3])
            return False, f"Unknown file: {path}. Available: {available}"

        try:
            line_num = int(line_str)
        except ValueError:
            return False, f"Invalid line number: {line_str}"

        max_line = self._line_counts[path]
        if line_num < 1 or line_num > max_line:
            return False, f"Line {line_num} out of range (1-{max_line})"

        return True, ""

    def get_file_content(self, file_path: str) -> Optional[str]:
        """获取文件内容"""
        return self._files.get(file_path)

    def get_known_file_paths(self) -> List[str]:
        """获取所有已知文件路径"""
        return list(self._files.keys())

    def get_file_summary(self) -> str:
        """获取文件摘要列表"""
        return "\n".join(
            [f"- {path} ({self._line_counts[path]} lines)" for path in self._files.keys()]
        )


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


class MultiAgentPipeline:
    """多Agent流水线系统

    协调6个专业Agent完成代码安全分析
    """

    def _is_high_severity_risk(
        self, title: str, description: str = "", risk_type: str = ""
    ) -> bool:
        """判断是否为高危风险类型

        Args:
            title: 风险标题
            description: 风险描述
            risk_type: 风险类型

        Returns:
            是否为高危风险
        """
        combined_text = f"{title} {description} {risk_type}".lower()
        for high_severity_type in HIGH_SEVERITY_RISK_TYPES:
            if high_severity_type.lower() in combined_text:
                return True
        return False

    def _get_confidence_threshold(
        self, title: str, description: str = "", risk_type: str = ""
    ) -> float:
        """获取置信度阈值

        Args:
            title: 风险标题
            description: 风险描述
            risk_type: 风险类型

        Returns:
            置信度阈值
        """
        if self._is_high_severity_risk(title, description, risk_type):
            return CONFIDENCE_THRESHOLDS["high_severity"]
        return CONFIDENCE_THRESHOLDS["default"]

    def _should_reject_signal(self, title: str) -> bool:
        """检查信号标题是否为应被拒绝的占位符

        Args:
            title: 信号标题

        Returns:
            是否应拒绝该信号
        """
        if not title:
            return True
        title_upper = title.upper()
        title_lower = title.lower()
        return (
            any(ph in title_upper for ph in ["UNVERIFIED", "GENERIC", "PLACEHOLDER", "UNKNOWN"])
            or title in REJECTED_PLACEHOLDERS
            or title_lower in ["风险", "漏洞", "安全风险", "待验证"]
            or len(title) < 5
        )

    def _should_early_exit(
        self,
        risk_enumeration: Any,
        code_understanding: Dict[str, Any],
        file_path: str,
        file_content: str,
    ) -> bool:
        """判断是否早停（跳过 Agent-3~6，节省 token/时间）。

        条件（全部满足才早停，避免漏报）：
        1. Agent-2 返回零风险信号
        2. Agent-1 未发现 security_hotspots
        3. 静态规则门（CodeVulnScanner）零命中
        4. 信号跟踪器中无未决信号
        """
        try:
            if isinstance(risk_enumeration, dict) and risk_enumeration.get("risks"):
                return False
            hotspots = code_understanding.get("security_hotspots") or []
            if hotspots:
                return False

            # 静态规则门
            try:
                from src.analyzers.code_vuln_scanner import CodeVulnScanner

                scanner = CodeVulnScanner()
                findings = scanner.scan_file(str(file_path))
                if findings:
                    return False
            except Exception:
                # 静态扫描异常时不早停（保守）
                return False

            # 未决信号检查
            if hasattr(self, "evidence_chain_tracker") and self.evidence_chain_tracker:
                pending = [
                    s
                    for s in self.evidence_chain_tracker.get_all_signals().values()
                    if isinstance(s, dict)
                    and s.get("current_state") not in ("CONFIRMED", "REJECTED")
                ]
                if pending:
                    return False
            return True
        except Exception:
            return False

    def _init_signal_queue(self) -> None:
        """初始化信号队列"""
        self._signal_queue: List[Dict[str, Any]] = []
        self._signal_queue_processed: set = set()
        self._signal_queue_timedout: set = set()

    def _add_to_signal_queue(self, signal_id: str, risk_data: Dict[str, Any]) -> None:
        """添加信号到队列

        Args:
            signal_id: 信号ID
            risk_data: 风险数据
        """
        if not hasattr(self, "_signal_queue"):
            self._init_signal_queue()
        if signal_id not in self._signal_queue_processed and signal_id not in [
            s["signal_id"] for s in self._signal_queue
        ]:
            self._signal_queue.append(
                {
                    "signal_id": signal_id,
                    "risk_data": risk_data,
                    "enqueued_at": time.time(),
                    "status": "pending",
                }
            )

    def _mark_signal_processed(self, signal_id: str) -> None:
        """标记信号已处理

        Args:
            signal_id: 信号ID
        """
        if hasattr(self, "_signal_queue"):
            self._signal_queue_processed.add(signal_id)
            for item in self._signal_queue:
                if item["signal_id"] == signal_id:
                    item["status"] = "processed"
                    item["processed_at"] = time.time()

    def _mark_signal_timeout(self, signal_id: str) -> None:
        """标记信号超时

        Args:
            signal_id: 信号ID
        """
        if hasattr(self, "_signal_queue"):
            self._signal_queue_timedout.add(signal_id)
            for item in self._signal_queue:
                if item["signal_id"] == signal_id:
                    item["status"] = "timeout"
                    item["timedout_at"] = time.time()

    def _check_signal_queue_timeout(self) -> List[str]:
        """检查信号队列中的超时信号

        Returns:
            超时信号ID列表
        """
        if not hasattr(self, "_signal_queue"):
            return []
        current_time = time.time()
        timedout_signals = []
        for item in self._signal_queue:
            if (
                item["status"] == "pending"
                and (current_time - item["enqueued_at"]) > SIGNAL_QUEUE_TIMEOUT
            ):
                timedout_signals.append(item["signal_id"])
                self._mark_signal_timeout(item["signal_id"])
        return timedout_signals

    def _get_pending_signals(self) -> List[str]:
        """获取待处理的信号ID列表

        Returns:
            待处理信号ID列表
        """
        if not hasattr(self, "_signal_queue"):
            return []
        return [item["signal_id"] for item in self._signal_queue if item["status"] == "pending"]

    def __init__(self, client, config: Optional[Any] = None):
        """初始化多Agent流水线

        Args:
            client: AI客户端
            config: 配置参数
        """
        self.client = client
        self.config = config
        self.context_builder = ContextBuilder(config)
        self.prompt_engine = get_prompt_engine()
        self.token_tracker = get_token_tracker()
        self.checkpoint_callback: Optional[Any] = None
        self._processed_files: List[str] = []
        self._current_step: Optional[str] = None
        self._agent_timings: Dict[str, float] = {}
        self.evidence_chain_tracker = EvidenceChain()
        self.schema_validator = SchemaValidator()
        self._file_registry = KnownFileRegistry()
        self.line_number_mapper = LineNumberMapper()
        self.debug_logs: List[str] = []
        self._file_analysis_cache: Dict[str, Dict[str, Any]] = {}
        self._token_budget_warned: bool = False
        self.reject_on_signal_creation: bool = True
        if hasattr(config, "get") and config is not None:
            self.max_retries = config.get("max_retries", 3)
            self.model = config.get("model", "mimo-v2.5-pro")
            self.temperature = config.get("temperature", 0.1)
            self.reject_on_signal_creation = config.get("reject_on_signal_creation", True)
            self.json_mode = config.get("json_mode", "auto")
            self.request_timeout = config.get("request_timeout", 180)
            self.ast_evidence_enabled = config.get("ast_evidence_enabled", False)
            self.cwe_guidance_enabled = config.get("cwe_guidance_enabled", False)
            self.deterministic_promote_enabled = config.get("deterministic_promote_enabled", False)
        else:
            self.max_retries = getattr(config, "max_retries", 3)
            self.model = (
                getattr(config, "ai", {}).get("model", "mimo-v2.5-pro")
                if hasattr(config, "ai")
                else "mimo-v2.5-pro"
            )
            self.temperature = (
                getattr(config, "ai", {}).get("temperature", 0.1) if hasattr(config, "ai") else 0.1
            )
            self.reject_on_signal_creation = getattr(config, "reject_on_signal_creation", True)
            self.json_mode = (
                getattr(config, "ai", {}).get("json_mode", "auto") if hasattr(config, "ai") else "auto"
            )
            self.request_timeout = (
                getattr(config, "ai", {}).get("request_timeout", 180)
                if hasattr(config, "ai")
                else 180
            )
            self.ast_evidence_enabled = (
                getattr(config, "ai", {}).get("ast_evidence_enabled", False)
                if hasattr(config, "ai")
                else False
            )
            self.cwe_guidance_enabled = (
                getattr(config, "ai", {}).get("cwe_guidance_enabled", False)
                if hasattr(config, "ai")
                else False
            )
            self.deterministic_promote_enabled = (
                getattr(config, "ai", {}).get("deterministic_promote_enabled", False)
                if hasattr(config, "ai")
                else False
            )
        # [OPT-SASTR] SAST 前置过滤证据（由 scanner 在批量分析前注入）
        self.sast_evidence: Dict[str, str] = {}
        # [OPT-TRIAGE] per-agent 模型映射（大小模型协同；主实验留空保持同模型口径）
        self.agent_model_overrides: Dict[str, str] = {}
        try:
            tiered = config.get("tiered_architecture") if isinstance(config, dict) else (
                getattr(config, "ai", {}).get("tiered_architecture") if hasattr(config, "ai") else None
            )
            if tiered and isinstance(tiered, dict):
                self.agent_model_overrides = tiered.get("agent_overrides", {}) or {}
        except Exception:
            pass
        # [OPT-COMPACT] 代码压缩门（默认关）
        self.compaction_enabled = (
            config.get("compaction_enabled", False) if isinstance(config, dict)
            else getattr(getattr(config, "ai", None), "compaction_enabled", False)
        )

        logger.debug(
            f" Pipeline 使用模型: {self.model}, Temperature: {self.temperature}, reject_on_signal_creation: {self.reject_on_signal_creation}"
        )

    def _detect_language(self, file_path: str, file_content: str) -> str:
        """检测代码语言/框架

        Args:
            file_path: 文件路径
            file_content: 文件内容

        Returns:
            检测到的语言/框架描述
        """
        file_path = str(file_path)
        if file_path.endswith(".java"):
            return "Java"
        elif file_path.endswith(".py"):
            return "Python"
        elif file_path.endswith(".js"):
            return "JavaScript"
        elif file_path.endswith(".go"):
            return "Go"
        elif file_path.endswith(".php"):
            return "PHP"
        elif file_path.endswith(".cs"):
            return "C#"
        elif file_path.endswith(".rb"):
            return "Ruby"
        elif file_path.endswith(".ts"):
            return "TypeScript"

        # 配置文件格式
        elif file_path.endswith((".yml", ".yaml")):
            return "YAML"
        elif file_path.endswith(".properties"):
            return "Properties"
        elif file_path.endswith(".xml"):
            return "XML"
        elif file_path.endswith(".json"):
            return "JSON"
        elif file_path.endswith(".toml"):
            return "TOML"
        elif file_path.endswith((".ini", ".con", ".cfg")):
            return "Config"

        # Web文件格式
        elif file_path.endswith((".html", ".htm")):
            return "HTML"
        elif file_path.endswith(".vue"):
            return "Vue"
        elif file_path.endswith(".jsx"):
            return "JSX"
        elif file_path.endswith(".tsx"):
            return "TSX"
        elif file_path.endswith((".css", ".scss", ".sass", ".less")):
            return "CSS"

        # 脚本文件格式
        elif file_path.endswith(".sql"):
            return "SQL"
        elif file_path.endswith((".sh", ".bash")):
            return "Shell"
        elif file_path.endswith(".ps1"):
            return "PowerShell"
        elif file_path.endswith((".bat", ".cmd")):
            return "Batch"

        # 其他文件格式
        elif file_path.endswith(".md"):
            return "Markdown"
        elif file_path.endswith(".txt"):
            return "Text"
        elif file_path.endswith(".gradle"):
            return "Gradle"
        elif file_path.endswith(".kts"):
            return "Kotlin"
        elif file_path.endswith("Dockerfile"):
            return "Dockerfile"
        elif file_path.endswith(".dockerfile"):
            return "Dockerfile"
        elif file_path.endswith(".csv"):
            return "CSV"
        elif file_path.endswith(".proto"):
            return "Protobuf"

        # 检查文件内容中的框架特征
        if "import org.springframework" in file_content or "package com." in file_content:
            return "Java"
        if "from django" in file_content or "import django" in file_content:
            return "Python"
        if "from flask" in file_content or "import flask" in file_content:
            return "Python"
        if "const express" in file_content or "require(express)" in file_content:
            return "JavaScript"
        if "import React" in file_content or "from react" in file_content:
            return "JavaScript"

        return "Unknown"

    def _register_known_files(self, context: Dict[str, Any]) -> None:
        """注册已知文件到注册表

        Args:
            context: 上下文信息
        """
        self._file_registry.clear()
        self._file_registry.register(context["current_file"], context["file_content"])
        for rf in context.get("related_files", []):
            self._file_registry.register(rf["path"], rf["content"])
        logger.debug(f" Registered {len(self._file_registry.get_known_file_paths())} known files")

    def set_checkpoint_callback(self, callback) -> None:
        """设置检查点回调函数

        Args:
            callback: 回调函数，签名: callback(checkpoint_data)
        """
        self.checkpoint_callback = callback

    def get_state(self) -> Dict[str, Any]:
        """获取流水线状态用于序列化

        Returns:
            包含当前状态的字典
        """
        return {
            "agent_timings": self._agent_timings if hasattr(self, "_agent_timings") else {},
            "current_step": self._current_step if hasattr(self, "_current_step") else None,
            "processed_files": self._processed_files if hasattr(self, "_processed_files") else [],
            "timestamp": time.time(),
        }

    def set_state(self, state: Dict[str, Any]) -> None:
        """从序列化状态恢复

        Args:
            state: 包含之前状态的字典
        """
        if "agent_timings" in state:
            self._agent_timings = state["agent_timings"]
        if "current_step" in state:
            self._current_step = state["current_step"]
        if "processed_files" in state:
            self._processed_files = state["processed_files"]

    def _trigger_checkpoint_callback(self, step: str, data: Dict[str, Any]) -> None:
        """触发检查点回调

        Args:
            step: 当前步骤名称
            data: 步骤数据
        """
        if self.checkpoint_callback:
            try:
                self.checkpoint_callback(
                    {
                        "step": step,
                        "data": data,
                        "state": self.get_state(),
                        "timestamp": time.time(),
                    }
                )
            except Exception as e:
                logger.warning(f"检查点回调失败: {e}")

    async def run_pipeline(self, file_path: str) -> Dict[str, Any]:
        """运行完整的多Agent流水线

        Args:
            file_path: 文件路径

        Returns:
            分析结果
        """
        from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

        try:
            logger.debug(f" 开始运行多Agent流水线: {file_path}")
            total_start_time = time.time()
            self._agent_timings = {}
            self._current_step = "started"
            self._current_file_path = file_path
            self.evidence_chain_tracker = EvidenceChain()
            self._current_file_signals: set = set()
            total_token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            self._token_budget_warned = False

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
                refresh_per_second=1,
            ) as progress:
                main_task = progress.add_task(f"[cyan]分析: {Path(file_path).name}[/cyan]", total=7)

                start_time = time.time()
                context = self.context_builder.build_context(file_path)
                self._register_known_files(context)
                self.line_number_mapper.record_file_snapshot(file_path, context["file_content"])
                elapsed = time.time() - start_time
                self._agent_timings["context_build"] = elapsed
                self._current_step = "context_build"
                self._trigger_checkpoint_callback("context_build", {"elapsed": elapsed})
                progress.advance(main_task)

                detected_language = self._detect_language(file_path, context["file_content"])
                logger.debug(f" 检测到语言: {detected_language}")

                cached = self._get_cached_result(file_path, context["file_content"])
                use_cache = cached is not None
                context_analysis: Optional[Dict[str, Any]] = None
                code_understanding: Optional[Dict[str, Any]] = None

                start_time = time.time()
                if use_cache and cached is not None:
                    logger.debug(f" 使用缓存结果跳过 Agent-0/1: {Path(file_path).name}")
                    context_analysis = cached.get("context_analysis", {})
                    code_understanding = cached.get("code_understanding", {})
                    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                else:
                    context_analysis, token_usage = await self._run_agent_0(
                        file_path, context, detected_language
                    )
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                elapsed = time.time() - start_time
                self._agent_timings["agent_0"] = elapsed
                self._current_step = "agent_0"
                self._trigger_checkpoint_callback(
                    "agent_0", {"elapsed": elapsed, "token_usage": token_usage}
                )
                progress.advance(main_task)

                start_time = time.time()
                if not use_cache:
                    code_understanding, token_usage = await self._run_agent_1(
                        file_path, context, context_analysis, detected_language
                    )
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                elapsed = time.time() - start_time
                self._agent_timings["agent_1"] = elapsed
                self._current_step = "agent_1"
                self._trigger_checkpoint_callback(
                    "agent_1", {"elapsed": elapsed, "token_usage": token_usage}
                )
                progress.advance(main_task)

                start_time = time.time()
                risk_enumeration, token_usage = await self._run_agent_2(
                    file_path, code_understanding or {}, detected_language
                )
                elapsed = time.time() - start_time
                self._agent_timings["agent_2"] = elapsed
                self._current_step = "agent_2"
                self._trigger_checkpoint_callback(
                    "agent_2", {"elapsed": elapsed, "token_usage": token_usage}
                )
                total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                total_token_usage["total_tokens"] += token_usage["total_tokens"]
                self._track_risk_signals(risk_enumeration)
                progress.advance(main_task)

                start_time = time.time()
                vulnerability_verification, token_usage = await self._run_agent_3(
                    file_path, risk_enumeration, context["file_content"], detected_language, context
                )
                elapsed = time.time() - start_time
                self._agent_timings["agent_3"] = elapsed
                self._current_step = "agent_3"
                self._trigger_checkpoint_callback(
                    "agent_3", {"elapsed": elapsed, "token_usage": token_usage}
                )
                total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                total_token_usage["total_tokens"] += token_usage["total_tokens"]
                self._track_verification_signals(vulnerability_verification)
                self._check_semantic_consistency(
                    "agent_2_to_3", risk_enumeration, vulnerability_verification
                )
                progress.advance(main_task)

                self._check_token_budget_and_warn(total_token_usage, "Agent-3")
                skip_agent_4_5 = (
                    total_token_usage["total_tokens"]
                    >= TOKEN_BUDGET_PER_FILE * TOKEN_CRITICAL_THRESHOLD
                )

                start_time = time.time()
                if skip_agent_4_5:
                    logger.warning(
                        f"[TOKEN-SKIP] 跳过 Agent-4 (Token: {total_token_usage['total_tokens']:,}/{TOKEN_BUDGET_PER_FILE:,})"
                    )
                    console.print(
                        f"[yellow][TOKEN-SKIP] 跳过 Agent-4 (Token: {total_token_usage['total_tokens']:,}/{TOKEN_BUDGET_PER_FILE:,})[/yellow]"
                    )
                    attack_chain_analysis = {
                        "attack_chains": [],
                        "note": "skipped due to token budget",
                    }
                    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                else:
                    attack_chain_analysis, token_usage = await self._run_agent_4(
                        file_path, vulnerability_verification, detected_language, context
                    )
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                    self._track_attack_chain_signals(attack_chain_analysis)
                elapsed = time.time() - start_time
                self._agent_timings["agent_4"] = elapsed
                self._current_step = "agent_4"
                progress.advance(main_task)

                start_time = time.time()
                if skip_agent_4_5:
                    logger.warning(
                        f"[TOKEN-SKIP] 跳过 Agent-5 (Token: {total_token_usage['total_tokens']:,}/{TOKEN_BUDGET_PER_FILE:,})"
                    )
                    console.print(
                        f"[yellow][TOKEN-SKIP] 跳过 Agent-5 (Token: {total_token_usage['total_tokens']:,}/{TOKEN_BUDGET_PER_FILE:,})[/yellow]"
                    )
                    adversarial_validation = {
                        "adversarial_analysis": [],
                        "note": "skipped due to token budget",
                    }
                    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                else:
                    adversarial_validation, token_usage = await self._run_agent_5(
                        file_path, attack_chain_analysis, context["file_content"], detected_language
                    )
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                    self._track_adversarial_signals(adversarial_validation)
                    self._check_semantic_consistency(
                        "agent_4_to_5", attack_chain_analysis, adversarial_validation
                    )
                elapsed = time.time() - start_time
                self._agent_timings["agent_5"] = elapsed
                self._current_step = "agent_5"
                progress.advance(main_task)

                start_time = time.time()
                final_decision, token_usage = await self._run_agent_6(
                    file_path,
                    context,
                    adversarial_validation,
                    vulnerability_verification,
                    detected_language,
                )
                validated_final_decision = self._validate_final_findings(
                    final_decision, context, vulnerability_verification
                )
                validated_final_decision = self._deterministic_promote(
                    validated_final_decision, vulnerability_verification
                )
                elapsed = time.time() - start_time
                self._agent_timings["agent_6"] = elapsed
                self._current_step = "agent_6"
                self._trigger_checkpoint_callback(
                    "agent_6", {"elapsed": elapsed, "token_usage": token_usage}
                )
                total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                total_token_usage["total_tokens"] += token_usage["total_tokens"]
                progress.advance(main_task)

            total_elapsed = time.time() - total_start_time
            self._current_step = "completed"
            self._trigger_checkpoint_callback(
                "pipeline_completed",
                {
                    "total_elapsed": total_elapsed,
                    "total_token_usage": total_token_usage,
                    "agent_timings": self._agent_timings,
                    "signal_summary": self._get_signal_summary(),
                },
            )
            if file_path not in self._processed_files:
                self._processed_files.append(file_path)
            logger.info(
                f"[bold cyan][PURE-AI][/bold cyan] [bold green]OK {Path(file_path).name} 分析完成[/bold green] ({total_elapsed:.2f}s)"
            )
            if total_token_usage["total_tokens"] > 0:
                # avg_tokens_per_agent = total_token_usage["total_tokens"] / 6 if 6 > 0 else 0
                logger.debug(
                    f"   Token: {total_token_usage['total_tokens']:,} (提示词: {total_token_usage['prompt_tokens']:,}, 补全: {total_token_usage['completion_tokens']:,})"
                )
            self._cache_analysis_result(
                file_path,
                context.get("file_content", ""),
                context_analysis or {},
                code_understanding or {},
            )

            return {
                "file_path": file_path,
                "context_analysis": context_analysis,
                "code_understanding": code_understanding,
                "risk_enumeration": risk_enumeration,
                "vulnerability_verification": vulnerability_verification,
                "attack_chain_analysis": attack_chain_analysis,
                "adversarial_validation": adversarial_validation,
                "final_decision": validated_final_decision,
                "evidence_chain": self._get_signal_summary(),
                "debug_logs": self.debug_logs,
            }
        except Exception as e:
            self._current_step = "error"
            self._trigger_checkpoint_callback("pipeline_error", {"error": str(e)})
            logger.error(f"{Path(file_path).name} 分析失败: {e}")
            console.print(f"[red]分析失败: {Path(file_path).name}[/red]")
            import traceback

            traceback.print_exc()
            return {"file_path": file_path, "error": str(e)}

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

    def _get_avg_confidence(self, evidence_list: List[Dict[str, Any]]) -> Optional[float]:
        """计算证据列表的平均置信度

        Args:
            evidence_list: 证据列表

        Returns:
            平均置信度或None
        """
        if not evidence_list:
            return None
        confidences = [
            e.get("confidence", 0)
            for e in evidence_list
            if isinstance(e, dict) and "confidence" in e
        ]
        if not confidences:
            return None
        return float(sum(confidences) / len(confidences))

    def _check_token_budget_and_warn(
        self, total_token_usage: Dict[str, int], agent_name: str = ""
    ) -> bool:
        """检查 Token 预算并发出警告

        Args:
            total_token_usage: 当前累计 token 使用
            agent_name: 当前运行的 agent 名称

        Returns:
            是否应该继续运行（True=继续，False=跳过后续 Agent-4/5）
        """
        total = total_token_usage.get("total_tokens", 0)
        budget = TOKEN_BUDGET_PER_FILE
        warning_threshold = budget * TOKEN_WARNING_THRESHOLD
        critical_threshold = budget * TOKEN_CRITICAL_THRESHOLD

        if total >= critical_threshold and not self._token_budget_warned:
            logger.warning(
                f"[TOKEN-WARNING] Token消耗达到 {total:,}/{budget:,} ({(total / budget) * 100:.1f}%)，即将跳过 Agent-4/5"
            )
            console.print(
                f"[bold yellow][TOKEN-WARNING] Token消耗达到 {total:,}/{budget:,} ({(total / budget) * 100:.1f}%)，即将跳过 Agent-4/5[/bold yellow]"
            )
            self._token_budget_warned = True
            return False

        if total >= warning_threshold and not self._token_budget_warned:
            logger.warning(
                f"[TOKEN-WARNING] Token消耗较高: {total:,}/{budget:,} ({(total / budget) * 100:.1f}%) - Agent: {agent_name}"
            )
            console.print(
                f"[yellow][TOKEN-WARNING] Token消耗较高: {total:,}/{budget:,} ({(total / budget) * 100:.1f}%) - Agent: {agent_name}[/yellow]"
            )
            self._token_budget_warned = True

        if total >= critical_threshold:
            logger.warning(
                f"[TOKEN-SKIP] 跳过 Agent-4/5，Token预算已超出 {total:,}/{budget:,}"
            )
            console.print(
                f"[yellow][TOKEN-SKIP] 跳过 Agent-4/5，Token预算已超出 {total:,}/{budget:,}[/yellow]"
            )
            return False

        return True

    def _should_skip_agent(self, total_token_usage: Dict[str, int], agent_name: str) -> bool:
        """判断是否应该跳过指定的 Agent

        Args:
            total_token_usage: 当前累计 token 使用
            agent_name: Agent 名称

        Returns:
            是否应该跳过
        """
        if agent_name in ["agent_4", "agent_5"]:
            total = total_token_usage.get("total_tokens", 0)
            if total >= TOKEN_BUDGET_PER_FILE * TOKEN_CRITICAL_THRESHOLD:
                logger.warning(f" 跳过 {agent_name} (Token: {total:,}/{TOKEN_BUDGET_PER_FILE:,})")
                return True
        return False

    def _get_file_content_hash(self, file_path: str, file_content: Optional[str] = None) -> str:
        """获取文件内容哈希

        Args:
            file_path: 文件路径
            file_content: 文件内容（可选）

        Returns:
            文件内容哈希值
        """
        import hashlib

        if file_content is None:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read()
            except Exception:
                return str(abs(hash(file_path)))[:16]
        return hashlib.md5(file_content.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def _cache_analysis_result(
        self,
        file_path: str,
        file_content: str,
        context_analysis: Dict[str, Any],
        code_understanding: Dict[str, Any],
    ) -> None:
        """缓存分析结果

        Args:
            file_path: 文件路径
            file_content: 文件内容
            context_analysis: 上下文分析结果
            code_understanding: 代码理解结果
        """
        content_hash = self._get_file_content_hash(file_path, file_content)
        cache_key = f"{file_path}:{content_hash}"
        self._file_analysis_cache[cache_key] = {
            "context_analysis": context_analysis,
            "code_understanding": code_understanding,
            "content_hash": content_hash,
            "cached_at": time.time(),
        }
        logger.debug(f" 缓存已更新: {Path(file_path).name} (hash: {content_hash})")

    def _get_cached_result(
        self, file_path: str, file_content: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """获取缓存的分析结果

        Args:
            file_path: 文件路径
            file_content: 文件内容（可选）

        Returns:
            缓存的结果或None
        """
        content_hash = self._get_file_content_hash(file_path, file_content)
        cache_key = f"{file_path}:{content_hash}"
        cached = self._file_analysis_cache.get(cache_key)
        if cached:
            logger.debug(f" 命中缓存: {Path(file_path).name} (hash: {content_hash})")
        return cached

    def _slim_json_for_prompt(self, obj: Any, max_len: int = 12000) -> str:
        """[OPT-TOKEN] 序列化对象并截断到 max_len 字符（保留头部，标注截断）。

        用于 Agent-4/5 输出传入下游 Agent 时压缩 prompt token；
        截断只影响 prompt 展示，不影响完整结果落盘。
        """
        try:
            s = json.dumps(obj, ensure_ascii=False)
        except Exception:
            s = str(obj)[: max_len // 2]
        if len(s) > max_len:
            return s[:max_len] + f"\n...[已截断 {len(s) - max_len} 字符，完整数据见上游 Agent 结果]"
        return s

    async def _run_agent_0(
        self, file_path: str, context: Dict[str, Any], detected_language: str = "Unknown"
    ) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 0：上下文构建

        Args:
            file_path: 文件路径
            context: 上下文信息
            detected_language: 检测到的语言

        Returns:
            (上下文分析结果, token使用信息)
        """
        logger.debug(f" 运行Agent 0 (上下文构建) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 0 (上下文构建) on: {file_path}")
        # [OPT-COMPACT] 代码压缩：函数骨架摘要（签名+文档首行）注入 function_calls 通道
        skeleton_summary = ""
        if getattr(self, "compaction_enabled", False):
            try:
                structure = context.get("file_structure") or {}
                funcs = structure.get("functions") or []
                lines = []
                for f in funcs[:30]:
                    args = ",".join(str(a) for a in (f.get("args") or [])[:6])
                    doc = str(f.get("docstring") or "").strip().splitlines()
                    doc1 = doc[0][:60] if doc else ""
                    lines.append(f"{f.get('name')}({args})  # L{f.get('line')} {doc1}")
                if lines:
                    skeleton_summary = "\n".join(["# [函数骨架摘要]"] + lines)
            except Exception as e:
                logger.debug(f"[OPT-COMPACT] 骨架构建失败: {e}")
        function_calls_text = PromptEngine.format_function_calls(
            context.get("function_calls", [])
        )
        if skeleton_summary:
            function_calls_text = skeleton_summary + "\n" + function_calls_text
        prompt = self.prompt_engine.render_agent_prompt(
            "context_builder",
            file_path=file_path,
            file_content=context["file_content"],
            related_files=PromptEngine.format_related_files(context.get("related_files", [])),
            imports=PromptEngine.format_imports(context.get("imports", [])),
            function_calls=function_calls_text,
            detected_language=detected_language,
        )

        response, token_usage = await self._generate_with_retry(
            prompt, "Agent 0", temperature=self.temperature
        )
        result = self._parse_json_response(response, schema_name="context_analysis")
        logger.debug(f" Agent 0 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 0 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage

    async def _run_agent_1(
        self,
        file_path: str,
        context: Dict[str, Any],
        context_analysis: Dict[str, Any],
        detected_language: str = "Unknown",
    ) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 1：代码理解

        Args:
            file_path: 文件路径
            context: 上下文信息
            context_analysis: 上下文分析结果
            detected_language: 检测到的语言

        Returns:
            (代码理解结果, token使用信息)
        """
        logger.debug(f" 运行Agent 1 (代码理解) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 1 (代码理解) on: {file_path}")
        context_info = json.dumps(context_analysis, ensure_ascii=False)
        prompt = self.prompt_engine.render_agent_prompt(
            "code_understanding",
            file_path=file_path,
            file_content=context["file_content"],
            context_info=context_info,
            detected_language=detected_language,
        )

        response, token_usage = await self._generate_with_retry(
            prompt, "Agent 1", temperature=self.temperature
        )
        result = self._parse_json_response(response, schema_name="code_understanding")
        logger.debug(f" Agent 1 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 1 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage

    def _slim_structured_data(self, code_understanding: Dict[str, Any]) -> str:
        """将 Agent-1 的结构化输出精简为关键字段（减少 Agent-2 的输入 token）。

        保留：file_function、key_functions、input_sources、
        security_hotspots、file_relationships；丢弃冗余字段，evidence 截断。
        """
        if not isinstance(code_understanding, dict):
            return json.dumps(code_understanding, ensure_ascii=False)

        def _keep_fields(items: Any, fields: List[str], max_items: int = 8) -> Any:
            if not isinstance(items, list):
                return items
            out = []
            for item in items[:max_items]:
                if isinstance(item, dict):
                    out.append({k: v for k, v in item.items() if k in fields})
                else:
                    out.append(item)
            return out

        slim: Dict[str, Any] = {
            "file_function": code_understanding.get("file_function", ""),
            "key_functions": _keep_fields(
                code_understanding.get("key_functions", []),
                ["name", "purpose", "security_impact"],
            ),
            "input_sources": (code_understanding.get("input_sources") or [])[:6],
            "security_hotspots": _keep_fields(
                code_understanding.get("security_hotspots", []),
                ["location", "type", "confidence"],
            ),
            "file_relationships": _keep_fields(
                code_understanding.get("file_relationships", []),
                ["file", "relationship"],
            ),
        }
        return json.dumps(slim, ensure_ascii=False)

    async def _run_agent_2(
        self, file_path: str, code_understanding: Dict[str, Any], detected_language: str = "Unknown"
    ) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 2：风险枚举

        Args:
            file_path: 文件路径
            code_understanding: 代码理解结果
            detected_language: 检测到的语言

        Returns:
            (风险枚举结果, token使用信息)
        """
        logger.debug(f" 运行Agent 2 (风险枚举) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 2 (风险枚举) on: {file_path}")
        structured_data = self._slim_structured_data(code_understanding)
        known_file_paths = self._file_registry.get_known_file_paths()
        prompt = self.prompt_engine.render_agent_prompt(
            "risk_enumeration",
            file_path=file_path,
            structured_data=structured_data,
            detected_language=detected_language,
            known_file_paths=known_file_paths,
        )

        response, token_usage = await self._generate_with_retry(
            prompt, "Agent 2", temperature=self.temperature
        )
        result = self._parse_json_response(response, schema_name="risk_enumeration")
        logger.debug(f" Agent 2 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 2 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage

    def _format_context_mappings_for_agent(self, context: Dict[str, Any]) -> str:
        """格式化上下文映射信息以供 Agent 使用

        Args:
            context: 上下文信息字典

        Returns:
            格式化后的映射信息字符串
        """
        lines = []

        lines.append("=== 代码上下文映射信息 ===")

        spring_mappings = context.get("spring_mappings", [])
        if spring_mappings:
            lines.append(f"\n[Spring MVC 映射] ({len(spring_mappings)} 个):")
            for m in spring_mappings[:10]:
                lines.append(f"  - {m.get('mapping_type', 'Mapping')} {m.get('path', 'unknown')}")

        lambda_mappings = context.get("lambda_mappings", [])
        if lambda_mappings:
            lines.append(f"\n[Lambda 路由映射] ({len(lambda_mappings)} 个):")
            for m in lambda_mappings[:10]:
                lines.append(f"  - {m.get('path', 'unknown')} ({m.get('route_type', 'unknown')})")

        bean_references = context.get("bean_references", [])
        if bean_references:
            lines.append(f"\n[Bean 依赖注入] ({len(bean_references)} 个):")
            for b in bean_references[:10]:
                lines.append(
                    f"  - {b.get('field_type', 'unknown')} {b.get('field_name', 'unknown')} ({b.get('injection_type', 'unknown')})"
                )

        class_hierarchy = context.get("class_hierarchy", {})
        extends = class_hierarchy.get("extends", [])
        if extends:
            lines.append(f"\n[类继承关系] ({len(extends)} 个):")
            for e in extends[:5]:
                lines.append(
                    f"  - {e.get('class', 'unknown')} extends {e.get('parent', 'unknown')}"
                )

        implements = class_hierarchy.get("implements", [])
        if implements:
            lines.append(f"\n[类实现关系] ({len(implements)} 个):")
            for i in implements[:5]:
                lines.append(
                    f"  - {i.get('class', 'unknown')} implements {', '.join(i.get('interfaces', []))}"
                )

        lines.append("\n=== 映射信息结束 ===")

        return "\n".join(lines)

    def _build_cwe_guidance(self, file_content: str, file_path: str, detected_language: str) -> str:
        """CWE 专项检测指引（M7）：按代码启发式检测 CWE 类型，注入对应验证要点。

        配置门 cwe_guidance_enabled 默认关闭；每模板约 1K token，最多 2 个。
        """
        if not file_content:
            return ""
        try:
            from src.ai.pure_ai.cwe_prompt_selector import get_cwe_prompt_selector

            selector = get_cwe_prompt_selector()
            templates = selector.get_cwe_templates_for_code(
                file_content,
                max_templates=2,
                file_path=file_path,
                file_content=file_content,
                detected_language=detected_language,
            )
            if not templates:
                return ""
            parts = ["[CWE 专项验证要点（来自 CWE 知识库模板）]"]
            for t in templates:
                content = (t.get("template_content") or "")[:1600]
                parts.append(f"## {t.get('cwe_id')} ({t.get('cwe_name', '')})")
                parts.append(content)
            parts.append("[END CWE GUIDANCE]")
            return "\n".join(parts)
        except Exception as e:
            logger.debug(f"[M7] CWE 指引构建失败: {e}")
            return ""

    def _build_ast_evidence(
        self,
        risks: List[Dict[str, Any]],
        file_path: str,
        file_content: str,
        detected_language: str = "Unknown",
    ) -> str:
        """AST/污点确定性预验证（M4）：对每个候选风险生成机器可查证据块。

        使用 InputTracer 判断输入可控性/可利用性，输出紧凑 JSON 证据，
        供 Agent-3 在验证时引用（减少纯 LLM 猜测，提升精度）。
        全部为本地确定性计算，不消耗 token；异常时返回空。
        """
        if not risks:
            return ""
        try:
            from src.analyzers.input_tracer import InputTracer

            project_root = str(Path(file_path).parent)
            tracer = InputTracer(project_root)
            evidence_items = []
            for risk in risks[:10]:  # 最多 10 条，避免 prompt 膨胀
                if not isinstance(risk, dict):
                    continue
                signal_id = risk.get("signal_id", "")
                location = risk.get("location", "")
                line_number = 0
                if location:
                    try:
                        line_number = int(str(location).rsplit(":", 1)[-1])
                    except ValueError:
                        line_number = 0
                snippet = ""
                if line_number > 0 and file_content:
                    lines = file_content.split("\n")
                    if 1 <= line_number <= len(lines):
                        start = max(0, line_number - 2)
                        snippet = "\n".join(lines[start:line_number + 2])
                try:
                    result = tracer.trace_controllability(
                        str(file_path), line_number, snippet or ""
                    )
                    item = {
                        "signal_id": signal_id,
                        "location": location,
                        "is_direct_user_input": result.is_direct_user_input,
                        "is_indirect": result.is_indirect,
                        "is_internal": result.is_internal,
                        "is_exploitable": result.is_exploitable,
                        "controllability_level": result.controllability_level.value,
                        "confidence": round(float(result.confidence), 2),
                        "attack_prerequisites": (result.attack_prerequisites or [])[:3],
                        "summary": (result.summary or "")[:120],
                    }
                except Exception as e:
                    item = {
                        "signal_id": signal_id,
                        "location": location,
                        "error": str(e)[:80],
                    }
                evidence_items.append(item)
            if not evidence_items:
                return ""
            return json.dumps({"ast_evidence": evidence_items}, ensure_ascii=False, indent=1)
        except Exception as e:
            logger.debug(f"[M4] AST 证据构建失败: {e}")
            return ""

    async def _run_agent_3(
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

        # CWE 专项检测指引（M7·[OPT-CWE2] 两阶段：Agent-2 检出风险后才定向注入，≤2 模板）
        # 不再依赖全局开关：有风险信号即注入（成本 ~1K token/文件，只发生在候选文件上）
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

    def _format_risk_list_concise(self, risks: List[Dict[str, Any]]) -> str:
        """格式化风险列表为简洁形式以减少token使用"""
        if not risks:
            return "无风险信号"
        lines = []
        for i, risk in enumerate(risks):
            signal_id = risk.get("signal_id", f"RISK-{i + 1}")
            title = risk.get("title", risk.get("risk_type", "未知风险"))
            location = risk.get("location", "未知位置")
            confidence = risk.get("confidence", "")
            severity = risk.get("severity", "")
            extra_info = f"[{severity}]" if severity else ""
            if confidence:
                extra_info = f"{extra_info} 置信度:{confidence}" if extra_info else f"置信度:{confidence}"
            lines.append(f"- {signal_id}: {title} @ {location} {extra_info}")
        return "\n".join(lines)

    def _safety_net_agent_3(self, result: Any, file_content: str) -> Dict[str, Any]:
        """Agent-3 安全网：检测并修正伪 REJECTED

        当 file_content 存在但 Agent-3 仍因"无法验证 code_snippet"而拒绝时，
        系统自动将 REJECTED 降级为 REFINED。

        同时检测伪拒绝理由，如"仅为import语句"、"注释"、"空行"等，
        这些情况下代码位置有效但判断错误，需要进入人工复核。

        ISSUE-008修复：
        - 高危类型即使Agent-3拒绝也保留（CSRF、认证、授权、令牌安全等）
        - 高危类型最低置信度阈值0.3，其他类型0.5
        """
        if not isinstance(result, dict):
            logger.debug(f" [Agent-3] _safety_net_agent_3 收到非字典输入: {type(result).__name__}, 返回安全默认值")
            self.debug_logs.append(
                f"[WARN] [Agent-3] _safety_net_agent_3 收到非字典输入: {type(result).__name__}"
            )
            return {
                "vulnerabilities": [],
                "signal_tracking": {
                    "signals_new": 0,
                    "signals_confirmed": 0,
                    "signals_rejected": 0,
                    "signals_refined": 0,
                },
            }

        vulnerabilities = result.get("vulnerabilities", [])
        modified = False

        FAKE_REJECTION_PATTERNS = [
            "无法验证",
            "未提供",
            "code_snippet",
            "仅为import语句",
            "仅为import",
            "import语句",
            "注释结束符号",
            "注释行",
            "为注释",
            "空行",
            "无可执行代码",
            "字段声明",
            "方法声明",
            "类声明",
            "Lombok",
            "@SneakyThrows",
            "注解",
            "Javadoc",
            "javadoc",
            "文档注释",
        ]

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                logger.warning(
                    f"[Agent-3] vuln 不是字典类型: {type(vuln).__name__}, 跳过, 值: {str(vuln)[:100]}"
                )
                self.debug_logs.append(f"[WARN] [Agent-3] vuln 不是字典类型: {type(vuln).__name__}, 跳过")
                continue
            vuln_signal_id = vuln.get("signal_id", "")
            vuln_title = vuln.get("title", "")
            vuln_description = vuln.get("description", "")
            vuln_risk_type = vuln.get("risk_type", "")
            confidence = vuln.get("confidence", 0.5)
            original_verification_decision = vuln.get("verification_decision", "")

            is_high_severity = self._is_high_severity_risk(
                vuln_title, vuln_description, vuln_risk_type
            )
            confidence_threshold = self._get_confidence_threshold(
                vuln_title, vuln_description, vuln_risk_type
            )

            if is_high_severity:
                logger.debug(
                    f"高危风险检测: {vuln_signal_id} - {vuln_title} (置信度: {confidence}, 阈值: {confidence_threshold})"
                )
            if original_verification_decision == "REJECTED":
                reason = vuln.get("verification_reason", "")

                should_upgrade = False
                upgrade_reason = ""

                is_fake_rejection = False
                fake_pattern_matched = ""

                if "无法验证" in reason or "未提供" in reason or "code_snippet" in reason.lower():
                    if file_content:
                        should_upgrade = True
                        is_fake_rejection = True
                        upgrade_reason = "系统降级：file_content存在，code_snippet验证失败，降级为待复核"

                if not should_upgrade:
                    for pattern in FAKE_REJECTION_PATTERNS:
                        if pattern in reason:
                            should_upgrade = True
                            is_fake_rejection = True
                            fake_pattern_matched = pattern
                            upgrade_reason = f'系统降级：检测到伪拒绝理由"{pattern}"，代码位置可能有效，降级为待复核'
                            break

                if is_fake_rejection:
                    vuln["verification_decision"] = "REFINED"
                    vuln["verification_reason"] = reason + f" [{upgrade_reason}]"
                    modified = True
                    logger.debug(
                        f"[HALLU-2修复] 检测到伪拒绝理由: {vuln_signal_id} - 模式:{fake_pattern_matched}, 原理由:{reason}"
                    )
                    self.debug_logs.append(
                        f"[DEBUG] [HALLU-2修复] 伪拒绝降级: {vuln_signal_id}，原拒绝理由: {reason}"
                    )
                    continue

                if is_high_severity and confidence >= confidence_threshold:
                    should_upgrade = False
                    upgrade_reason = ""
                    old_decision = vuln.get("verification_decision")
                    vuln["verification_decision"] = "CONFIRMED"
                    vuln[
                        "verification_reason"
                    ] = f"[ISSUE-008修复] 高危风险保留确认：{vuln_title} (置信度:{confidence} >= 阈值:{confidence_threshold})，原拒绝理由: {reason}"
                    modified = True
                    logger.warning(f" [ISSUE-008修复] 高危风险被错误拒绝已恢复: {vuln_signal_id} - {vuln_title}")
                    logger.warning(
                        f" 高危风险保留确认: {vuln_title} (置信度:{confidence} >= 阈值:{confidence_threshold})"
                    )
                    self.debug_logs.append(
                        f"[WARN] [ISSUE-008修复] 高危风险保留确认: {vuln_signal_id} - {vuln_title}，原拒绝理由: {reason}"
                    )
                    continue

                if is_high_severity and confidence < confidence_threshold:
                    should_upgrade = False
                    vuln["verification_decision"] = "UNCERTAIN"
                    vuln[
                        "verification_reason"
                    ] = f"[ISSUE-008修复] 高危风险降级待复核：{vuln_title} (置信度:{confidence} < 阈值:{confidence_threshold})，原拒绝理由: {reason}"
                    modified = True
                    logger.warning(
                        f"[ISSUE-008修复] 高危风险降级待复核: {vuln_signal_id} - {vuln_title} (置信度:{confidence} < 阈值:{confidence_threshold})"
                    )
                    self.debug_logs.append(
                        f"[WARN] [ISSUE-008修复] 高危风险降级待复核: {vuln_signal_id} - {vuln_title}，原拒绝理由: {reason}"
                    )
                    continue

                if should_upgrade and file_content:
                    old_decision = vuln.get("verification_decision")
                    vuln["verification_decision"] = "REFINED"
                    vuln["verification_reason"] = reason + f" [{upgrade_reason}]"
                    modified = True
                    old_decision_display = (
                        "已拒绝"
                        if old_decision == "REJECTED"
                        else ("已确认" if old_decision == "CONFIRMED" else old_decision)
                    )
                    logger.debug(
                        f"安全网修正: {vuln.get('signal_id', 'unknown')} 从 {old_decision_display} -> 已细化"
                    )
                    self.debug_logs.append(
                        f"[DEBUG] 安全网修正: {vuln.get('signal_id', 'unknown')} 从 {old_decision_display} -> 已细化，原始原因: {reason}"
                    )

        if modified:
            signal_tracking = result.get("signal_tracking", {})
            signal_tracking["signals_refined"] = signal_tracking.get("signals_refined", 0) + 1
            signal_tracking["signals_rejected"] = max(
                0, signal_tracking.get("signals_rejected", 0) - 1
            )
            result["signal_tracking"] = signal_tracking
        return result

    async def _run_agent_4(
        self,
        file_path: str,
        vulnerability_verification: Dict[str, Any],
        detected_language: str = "Unknown",
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 4：攻击链分析

        Args:
            file_path: 文件路径
            vulnerability_verification: 漏洞验证结果
            detected_language: 检测到的语言
            context: 上下文信息（包含映射关系）

        Returns:
            (攻击链分析结果, token使用信息)
        """
        logger.debug(f" 运行Agent 4 (攻击链分析) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 4 (攻击链分析) on: {file_path}")
        verification_results = json.dumps(vulnerability_verification, ensure_ascii=False)

        context_mappings_summary = ""
        if context:
            context_mappings_summary = self._format_context_mappings_for_agent(context)

        prompt = self.prompt_engine.render_agent_prompt(
            "attack_chain",
            file_path=file_path,
            verification_results=verification_results,
            detected_language=detected_language,
            context_mappings=context_mappings_summary,
        )

        response, token_usage = await self._generate_with_retry(
            prompt, "Agent 4", temperature=self.temperature
        )
        result = self._parse_json_response(response, schema_name="attack_chain")
        # [OPT-P2] Agent-4 确定性兜底：LLM 未生成攻击链时，从 Agent-3 已验证漏洞
        # 合成最小单步攻击链，保证 Agent-5/6 输入不为空（历史根因：空链→裁决保守拒绝）
        result = self._fallback_attack_chains(result, vulnerability_verification)
        logger.debug(f" Agent 4 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 4 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage

    def _fallback_attack_chains(
        self,
        result: Dict[str, Any],
        vulnerability_verification: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """[OPT-P2] 攻击链确定性兜底（不消耗 token）。

        当 Agent-4 输出为空链或解析失败时，从 Agent-3 的 CONFIRMED/REFINED 漏洞
        合成最小单步攻击链（signal 直接到影响），并附 note 标记为确定性兜底生成。
        """
        try:
            if not isinstance(result, dict):
                result = {}
            chains = result.get("attack_chains") or []
            if chains:
                return result
            vulns = []
            if isinstance(vulnerability_verification, dict):
                vulns = vulnerability_verification.get("vulnerabilities") or []
            verified = [
                v
                for v in vulns
                if isinstance(v, dict)
                and (v.get("verification_decision") or v.get("signal_state"))
                in ("CONFIRMED", "REFINED")
            ]
            if not verified:
                return result
            fallback_chains = []
            for i, v in enumerate(verified[:6], 1):
                title = v.get("title") or v.get("vulnerability") or "未命名漏洞"
                location = v.get("location") or ""
                severity = v.get("severity") or "HIGH"
                fallback_chains.append(
                    {
                        "name": f"单步可达链-{title}",
                        "steps": [
                            {
                                "step": 1,
                                "description": f"利用已确认漏洞 {title}（{location}）直接触发安全影响",
                                "prerequisites": [],
                                "payload": "",
                                "evidence": [],
                            }
                        ],
                        "final_impact": f"利用 {title} 达成未授权影响",
                        "severity": severity,
                        "cvss_score": v.get("cvss_score") or "",
                        "defense_bypasses": [],
                        "signal_id": f"CHAIN-FB-{i}",
                        "signal_state": "NEW",
                        "linked_signal_ids": [v.get("signal_id") or f"RISK-{i}"],
                        "evidence": [
                            {
                                "type": "flow",
                                "location": location,
                                "reason": "Agent-4 未生成完整攻击链，由确定性兜底从已验证漏洞合成",
                                "confidence": 0.6,
                            }
                        ],
                        "fallback_generated": True,
                    }
                )
            result["attack_chains"] = fallback_chains
            result["fallback_generated"] = True
            logger.debug(
                f"[OPT-P2] Agent-4 兜底合成 {len(fallback_chains)} 条单步攻击链（原输出为空）"
            )
            self.debug_logs.append(
                f"[OPT-P2] Agent-4 兜底合成 {len(fallback_chains)} 条单步攻击链（原输出为空）"
            )
        except Exception as e:
            logger.debug(f"[OPT-P2] 攻击链兜底失败: {e}")
        return result

    async def _run_agent_5(
        self,
        file_path: str,
        attack_chain_analysis: Dict[str, Any],
        file_content: str,
        detected_language: str = "Unknown",
    ) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 5：对抗验证

        Args:
            file_path: 文件路径
            attack_chain_analysis: 攻击链分析结果
            file_content: 文件内容
            detected_language: 检测到的语言

        Returns:
            (对抗验证结果, token使用信息)
        """
        logger.debug(f" 运行Agent 5 (对抗验证) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 5 (对抗验证) on: {file_path}")
        # [OPT-TOKEN] 压缩攻击链输入：只保留必要字段，控制 Agent-5 prompt token
        attack_chain_json = self._slim_json_for_prompt(attack_chain_analysis, max_len=12000)
        prompt = self.prompt_engine.render_agent_prompt(
            "adversarial_validation",
            file_path=file_path,
            attack_chain_analysis=attack_chain_json,
            file_content=file_content,
            detected_language=detected_language,
        )

        response, token_usage = await self._generate_with_retry(
            prompt, "Agent 5", temperature=self.temperature
        )
        result = self._parse_json_response(response, schema_name="adversarial")
        logger.debug(f" Agent 5 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 5 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage

    async def _run_agent_6(
        self,
        file_path: str,
        context: Dict[str, Any],
        adversarial_validation: Dict[str, Any],
        vulnerability_verification: Dict[str, Any],
        detected_language: str = "Unknown",
    ) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """运行Agent 6：最终裁决

        Args:
            file_path: 文件路径
            context: 上下文信息
            adversarial_validation: 对抗验证结果
            vulnerability_verification: 漏洞验证结果
            detected_language: 检测到的语言

        Returns:
            (最终裁决结果, token使用信息)
        """
        logger.debug(f" 运行Agent 6 (最终裁决) on: {file_path}")
        self.debug_logs.append(f"[DEBUG] 运行Agent 6 (最终裁决) on: {file_path}")
        # [OPT-TOKEN] 压缩上游输入：对抗验证 + 漏洞验证结果只保留骨架，控制 Agent-6 prompt token
        adversarial_results = self._slim_json_for_prompt(adversarial_validation, max_len=12000)
        verification_results = self._slim_json_for_prompt(vulnerability_verification, max_len=16000)
        known_files_summary = self._file_registry.get_file_summary()
        known_file_paths = self._file_registry.get_known_file_paths()
        line_counts = self._file_registry._line_counts
        prompt = self.prompt_engine.render_agent_prompt(
            "final_decision",
            file_path=file_path,
            file_content=context.get("file_content", ""),
            adversarial_results=adversarial_results,
            verification_results=verification_results,
            detected_language=detected_language,
            known_files_summary=known_files_summary,
            known_file_paths=known_file_paths,
            line_counts=line_counts,
        )

        response, token_usage = await self._generate_with_retry(
            prompt, "Agent 6", temperature=self.temperature
        )
        result = self._parse_json_response(response, schema_name="final_decision")
        logger.debug(f" Agent 6 完成，令牌使用: {token_usage['total_tokens']}")
        self.debug_logs.append(f"[DEBUG] Agent 6 完成，令牌使用: {token_usage['total_tokens']}")
        return result, token_usage

    async def _generate_with_retry(
        self, prompt: str, agent_name: str = "unknown", temperature: float = 0.0
    ) -> Tuple[str, Dict[str, int]]:
        """带重试的生成

        Args:
            prompt: 提示词
            agent_name: Agent名称
            temperature: 温度值

        Returns:
            (生成的响应, token使用信息)

        Raises:
            APIError: 当API错误应该立即截断时（如402、超时、连接错误）
        """
        from src.ai.providers.deepseek import APIError as DeepSeekAPIError

        for i in range(self.max_retries):
            try:
                # [OPT-CACHE] 版本化固定前缀：DeepSeek 上下文缓存按精确前缀匹配，
                # 契约变更才升版本号（SYSTEM_PREFIX_V1 → V2 …），日常扫描零改动保命中。
                json_guard_prompt = (
                    "只输出JSON，否则视为失败\n\n"
                    "[SYSTEM-CONTRACT-V1] 输出契约：仅输出符合 schema 的 JSON 对象；"
                    "禁止 markdown 代码块、解释性文字、多余字段；必须可被 json.loads 解析。\n\n"
                    + prompt
                )

                # 结构化输出（不裁剪 max_tokens；输出 token 一律不限制）
                response_format = None
                json_mode = getattr(self, "json_mode", "auto")
                if json_mode in ("auto", "on"):
                    response_format = {"type": "json_object"}

                # 创建AIRequest对象
                request = AIRequest(
                    prompt=json_guard_prompt,
                    model=self.agent_model_overrides.get(agent_name, self.model),
                    temperature=temperature,
                    max_tokens=8192,
                    response_format=response_format,
                    timeout=getattr(self, "request_timeout", 180),
                )

                # 调用客户端生成
                response = await self.client.generate(request)

                # 提取token使用信息
                token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                response_content = ""
                if hasattr(response, "usage") and response.usage:
                    token_usage["prompt_tokens"] = response.usage.get("prompt_tokens", 0)
                    token_usage["completion_tokens"] = response.usage.get("completion_tokens", 0)
                    token_usage["total_tokens"] = response.usage.get("total_tokens", 0)

                if hasattr(response, "content"):
                    response_content = response.content
                else:
                    response_content = str(response)

                # 跟踪token使用（包含prompt和response内容）
                if self.token_tracker:
                    self.token_tracker.track_usage(
                        provider=self.client.__class__.__name__,
                        model=self.model,
                        prompt_tokens=(
                            token_usage.get("prompt_tokens", 0)
                            if isinstance(token_usage, dict)
                            else 0
                        ),
                        completion_tokens=(
                            token_usage.get("completion_tokens", 0)
                            if isinstance(token_usage, dict)
                            else 0
                        ),
                        total_tokens=(
                            token_usage.get("total_tokens", 0)
                            if isinstance(token_usage, dict)
                            else 0
                        ),
                        duration=0.0,
                        success=True,
                        prompt=json_guard_prompt,
                        response=response_content,
                        agent_name=agent_name,
                        file_path=getattr(self, "_current_file_path", "unknown"),
                    )

                # 返回响应内容和token使用信息
                return response_content, token_usage

            except DeepSeekAPIError as e:
                logger.error(f"API错误 (Agent: {agent_name}): {e.message}")
                console.print(f"[red]API错误 (Agent: {agent_name})[/red]")
                if e.should_truncate:
                    logger.error("检测到需立即截断的错误，不进行重试")
                    raise
                logger.warning(
                    f"生成失败 (Agent: {agent_name}, 尝试 {i + 1}/{self.max_retries}): {e.message}"
                )
                if i == self.max_retries - 1:
                    raise
                await asyncio.sleep(2)
            except Exception as e:
                logger.warning(
                    f"生成失败 (Agent: {agent_name}, 尝试 {i + 1}/{self.max_retries}): {e}"
                )
                if i == self.max_retries - 1:
                    raise
                await asyncio.sleep(2)

        # Fallback return if max_retries is 0 or loop completes without returning
        return "", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def _parse_json_response(
        self, response: str, schema_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """解析JSON响应

        注意: 基础 JSON 提取逻辑已抽取到 json_utils.extract_json_from_text()，
        本方法保留了 schema 合规性修复（_ensure_schema_compliance）等特殊处理，
        后续可考虑将无 schema 场景替换为 json_utils.safe_json_parse()。

        Args:
            response: 响应字符串
            schema_name: Schema名称，用于验证

        Returns:
            解析后的JSON对象
        """

        def _ensure_schema_compliance(result: Dict[str, Any], schema_name: str) -> Dict[str, Any]:
            """确保返回结果符合schema要求

            Args:
                result: 解析后的数据
                schema_name: Schema名称

            Returns:
                符合schema要求的数据
            """
            if schema_name == "vulnerability":
                if "vulnerabilities" not in result or not isinstance(
                    result.get("vulnerabilities"), list
                ):
                    logger.debug(" [Schema Fix] _parse_json_response 确保 vulnerabilities 字段存在")
                    result["vulnerabilities"] = []
                if "signal_tracking" not in result or not isinstance(
                    result.get("signal_tracking"), dict
                ):
                    logger.debug(" [Schema Fix] _parse_json_response 确保 signal_tracking 字段存在")
                    result["signal_tracking"] = {
                        "signals_new": 0,
                        "signals_confirmed": 0,
                        "signals_rejected": 0,
                        "signals_refined": 0,
                    }
            elif schema_name == "risk_enumeration":
                if "risks" not in result or not isinstance(result.get("risks"), list):
                    logger.debug(" [Schema Fix] _parse_json_response 确保 risks 字段存在")
                    result["risks"] = []
                if "signal_tracking" not in result or not isinstance(
                    result.get("signal_tracking"), dict
                ):
                    logger.debug(" [Schema Fix] _parse_json_response 确保 signal_tracking 字段存在")
                    result["signal_tracking"] = {
                        "signals_new": 0,
                        "signals_confirmed": 0,
                        "signals_rejected": 0,
                        "signals_refined": 0,
                    }
            elif schema_name == "adversarial":
                if "adversarial_analysis" not in result or not isinstance(
                    result.get("adversarial_analysis"), list
                ):
                    logger.debug(" [Schema Fix] _parse_json_response 确保 adversarial_analysis 字段存在")
                    result["adversarial_analysis"] = []
                if "cross_agent_agreement" not in result or not isinstance(
                    result.get("cross_agent_agreement"), list
                ):
                    logger.debug(" [Schema Fix] _parse_json_response 确保 cross_agent_agreement 字段存在")
                    result["cross_agent_agreement"] = []
            elif schema_name == "attack_chain":
                if "attack_chains" not in result or not isinstance(
                    result.get("attack_chains"), list
                ):
                    logger.debug(" [Schema Fix] _parse_json_response 确保 attack_chains 字段存在")
                    result["attack_chains"] = []
                if "signal_tracking" not in result or not isinstance(
                    result.get("signal_tracking"), dict
                ):
                    logger.debug(" [Schema Fix] _parse_json_response 确保 signal_tracking 字段存在")
                    result["signal_tracking"] = {
                        "signals_new": 0,
                        "signals_confirmed": 0,
                        "signals_rejected": 0,
                    }
            return result

        try:
            cleaned_response = response.strip()

            try:
                data = json.loads(cleaned_response)
                if schema_name:
                    validator = SchemaValidator()
                    validated_data, is_valid = validator.validate_with_fallback(data, schema_name)
                    result = _ensure_schema_compliance(validated_data, schema_name)
                    if not is_valid:
                        logger.warning(
                            "[PURE-AI] validate_with_fallback 返回 is_valid=False，schema 修复后返回"
                        )
                    return result
                if isinstance(data, dict):
                    return data
                logger.debug(f" [PURE-AI] json.loads 返回非字典类型: {type(data).__name__}")
                return {"raw_response": response, "_parse_failed": True}  # [FIX-B3]
            except json.JSONDecodeError:
                pass

            # 容错修复：response 可能在 JSON 之后附加了文本，或 JSON 被截断
            # 尝试从最后一个 } 或 ] 截断后重新解析
            for end_char in ("}", "]"):
                idx = cleaned_response.rfind(end_char)
                if idx > 0:
                    try:
                        candidate = cleaned_response[: idx + 1]
                        data = json.loads(candidate)
                        if isinstance(data, dict):
                            logger.warning(
                                f"[PURE-AI] JSON 尾部截断修复成功 (schema={schema_name}, len={len(candidate)})"
                            )
                            if schema_name:
                                validator = SchemaValidator()
                                validated_data, is_valid = validator.validate_with_fallback(
                                    data, schema_name
                                )
                                return _ensure_schema_compliance(validated_data, schema_name)
                            return data
                    except json.JSONDecodeError:
                        continue

            json_match = re.search(r"```json\s*([\s\S]*?)```", cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    data = json.loads(json_str)
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data, is_valid = validator.validate_with_fallback(
                            data, schema_name
                        )
                        result = _ensure_schema_compliance(validated_data, schema_name)
                        if not is_valid:
                            logger.warning(
                                "[PURE-AI] validate_with_fallback(json_code_block) 返回 is_valid=False，schema 修复后返回"
                            )
                        return result
                    if isinstance(data, dict):
                        return data
                    logger.warning(
                        f"[PURE-AI] json.loads(json_code_block) 返回非字典类型: {type(data).__name__}"
                    )
                    return {"raw_response": response, "_parse_failed": True}  # [FIX-B3]
                except json.JSONDecodeError:
                    pass

            json_match = re.search(r"```\s*([\s\S]*?)```", cleaned_response)
            if json_match:
                json_str = json_match.group(1).strip()
                try:
                    data = json.loads(json_str)
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data, is_valid = validator.validate_with_fallback(
                            data, schema_name
                        )
                        result = _ensure_schema_compliance(validated_data, schema_name)
                        if not is_valid:
                            logger.warning(
                                "[PURE-AI] validate_with_fallback(code_block) 返回 is_valid=False，schema 修复后返回"
                            )
                        return result
                    if isinstance(data, dict):
                        return data
                    logger.debug(f" [PURE-AI] json.loads(code_block) 返回非字典类型: {type(data).__name__}")
                    return {"raw_response": response, "_parse_failed": True}  # [FIX-B3]
                except json.JSONDecodeError:
                    pass

            json_match = re.search(r"\{[\s\S]*\}", cleaned_response)
            if json_match:
                json_str = json_match.group(0)
                try:
                    data = json.loads(json_str)
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data, is_valid = validator.validate_with_fallback(
                            data, schema_name
                        )
                        result = _ensure_schema_compliance(validated_data, schema_name)
                        if not is_valid:
                            logger.warning(
                                "[PURE-AI] validate_with_fallback(curly_brace) 返回 is_valid=False，schema 修复后返回"
                            )
                        return result
                    if isinstance(data, dict):
                        return data
                    logger.warning(
                        f"[PURE-AI] json.loads(curly_brace) 返回非字典类型: {type(data).__name__}"
                    )
                    return {"raw_response": response, "_parse_failed": True}  # [FIX-B3]
                except json.JSONDecodeError:
                    pass

            first_brace = cleaned_response.find("{")
            last_brace = cleaned_response.rfind("}")
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                json_str = cleaned_response[first_brace : last_brace + 1]
                json_str = re.sub(r"(?<!\\)\'", '"', json_str)
                json_str = re.sub(r"(\w+)\s*:", '"\1":', json_str)
                try:
                    data = json.loads(json_str)
                    if schema_name:
                        validator = SchemaValidator()
                        validated_data, is_valid = validator.validate_with_fallback(
                            data, schema_name
                        )
                        result = _ensure_schema_compliance(validated_data, schema_name)
                        if not is_valid:
                            logger.warning(
                                "[PURE-AI] validate_with_fallback(last_brace) 返回 is_valid=False，schema 修复后返回"
                            )
                        return result
                    if isinstance(data, dict):
                        return data
                    logger.debug(f" [PURE-AI] json.loads(last_brace) 返回非字典类型: {type(data).__name__}")
                    return {"raw_response": response, "_parse_failed": True}  # [FIX-B3]
                except json.JSONDecodeError:
                    pass

            if schema_name:
                validator = SchemaValidator()
                validated_data, is_valid = validator.validate_with_fallback(
                    {"raw": response}, schema_name
                )
                result = _ensure_schema_compliance(validated_data, schema_name)
                result["_parse_failed"] = True  # [FIX-B3] 标记解析失败
                logger.warning(" [PURE-AI] JSON 解析失败，使用 fallback 并修复 schema")
                return result

            return {"raw_response": response, "_parse_failed": True}  # [FIX-B3]
        except Exception as e:
            logger.warning(f"JSON解析失败: {e}")
            logger.debug(f"原始响应: {response[:500]}...")
            return {"raw_response": response, "error": str(e), "_parse_failed": True}  # [FIX-B3]

    async def run_parallel_agents(
        self, file_path: str, agents: List[str], context: Dict[str, Any], detected_language: str
    ) -> Dict[str, Any]:
        """并行运行多个独立的 Agent

        适用于 Agent 3-5，它们可以并行执行以提高效率。

        Args:
            file_path: 文件路径
            agents: Agent 名称列表，如 ['agent_3', 'agent_4', 'agent_5']
            context: 上下文信息
            detected_language: 检测到的语言

        Returns:
            各 Agent 结果的字典
        """
        logger.debug(f" 并行运行 Agents: {agents}")
        # start_time = time.time()

        tasks = []
        agent_names = []

        if "agent_3" in agents:
            tasks.append(
                self._run_agent_3(
                    file_path,
                    context.get("risk_enumeration", {}),
                    context.get("file_content", ""),
                    detected_language,
                    context,
                )
            )
            agent_names.append("agent_3")

        if "agent_4" in agents:
            tasks.append(
                self._run_agent_4(
                    file_path,
                    context.get("vulnerability_verification", {}),
                    detected_language,
                    context,
                )
            )
            agent_names.append("agent_4")

        if "agent_5" in agents:
            tasks.append(
                self._run_agent_5(
                    file_path,
                    context.get("attack_chain_analysis", {}),
                    context.get("file_content", ""),
                    detected_language,
                )
            )
            agent_names.append("agent_5")

        if not tasks:
            return {}

        results = await asyncio.gather(*tasks, return_exceptions=True)

        result_dict: Dict[str, Any] = {}
        for i, result in enumerate(results):
            agent_name = agent_names[i]
            if isinstance(result, Exception):
                logger.warning(f"Agent {agent_name} failed: {result}")
                result_dict[agent_name] = {}
            else:
                token_usage = result[1] if isinstance(result, tuple) else {}
                agent_result = result[0] if isinstance(result, tuple) else result
                if not isinstance(agent_result, dict):
                    logger.warning(
                        f"Agent {agent_name} returned non-dict result type: {type(agent_result).__name__}, treating as empty result"
                    )
                    agent_result = {}
                result_dict[agent_name] = {"result": agent_result, "token_usage": token_usage}

        return result_dict

    async def run_pipeline_optimized(
        self, file_path: str, enable_parallel: bool = True
    ) -> Dict[str, Any]:
        """优化版流水线运行

        Stage 1-2: 顺序执行（上下文构建 -> 代码理解）
        Stage 3-5: 可选并行执行（漏洞验证 -> 攻击链 -> 对抗验证）
        Stage 6: 顺序执行（最终裁决）

        Args:
            file_path: 文件路径
            enable_parallel: 是否启用并行执行

        Returns:
            分析结果
        """
        from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

        try:
            logger.debug(f" 开始运行优化版多Agent流水线: {file_path}")
            total_start_time = time.time()
            self._agent_timings = {}
            self._current_step = "started"
            self._current_file_path = file_path
            if not hasattr(self, "evidence_chain_tracker") or self.evidence_chain_tracker is None:
                self.evidence_chain_tracker = EvidenceChain()
            self._current_file_signals = set()
            total_token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            self._token_budget_warned = False

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
                refresh_per_second=1,
            ) as progress:
                total_steps = 5 if enable_parallel else 8
                main_task = progress.add_task(
                    f"[cyan]分析: {Path(file_path).name}[/cyan]", total=total_steps
                )

                start_time = time.time()
                context = self.context_builder.build_context(file_path)
                self._register_known_files(context)
                self.line_number_mapper.record_file_snapshot(file_path, context["file_content"])
                elapsed = time.time() - start_time
                self._agent_timings["context_build"] = elapsed
                progress.advance(main_task)

                detected_language = self._detect_language(file_path, context["file_content"])
                logger.debug(f" 检测到语言: {detected_language}")

                cached = self._get_cached_result(file_path, context["file_content"])
                use_cache = cached is not None
                context_analysis: Optional[Dict[str, Any]] = None
                code_understanding: Optional[Dict[str, Any]] = None

                start_time = time.time()
                if use_cache and cached is not None:
                    logger.debug(f" 使用缓存结果跳过 Agent-0/1: {Path(file_path).name}")
                    context_analysis = cached.get("context_analysis", {})
                    code_understanding = cached.get("code_understanding", {})
                    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                else:
                    context_analysis, token_usage = await self._run_agent_0(
                        file_path, context, detected_language
                    )
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                elapsed = time.time() - start_time
                self._agent_timings["agent_0"] = elapsed
                progress.advance(main_task)

                start_time = time.time()
                if not use_cache:
                    code_understanding, token_usage = await self._run_agent_1(
                        file_path, context, context_analysis, detected_language
                    )
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                elapsed = time.time() - start_time
                self._agent_timings["agent_1"] = elapsed
                progress.advance(main_task)

                risk_enumeration = None
                vulnerability_verification = None
                attack_chain_analysis = None
                adversarial_validation = None

                if enable_parallel:
                    start_time = time.time()

                    risk_enum_result, _ = await self._run_agent_2(
                        file_path, code_understanding or {}, detected_language
                    )
                    risk_enumeration = risk_enum_result
                    self._track_risk_signals(risk_enumeration)

                    # 早停：Agent-2 零风险 + Agent-1 无安全热点 + 静态规则门零命中
                    # → 跳过 Agent-3~6（省 token/时间），直接返回空结果
                    if self._should_early_exit(
                        risk_enumeration,
                        code_understanding or {},
                        file_path,
                        context.get("file_content", ""),
                    ):
                        logger.info(
                            f"[EARLY-EXIT] {Path(file_path).name} 无风险信号且静态门零命中，跳过 Agent-3~6"
                        )
                        self.debug_logs.append(
                            f"[EARLY-EXIT] {Path(file_path).name} 无风险信号，跳过 Agent-3~6"
                        )
                        vulnerability_verification = {"vulnerabilities": [], "signal_tracking": {}}
                        attack_chain_analysis = {"attack_chains": []}
                        adversarial_validation = {"adversarial_analysis": []}
                        self._agent_timings["agent_3"] = 0.0
                        self._agent_timings["agent_4"] = 0.0
                        self._agent_timings["agent_5"] = 0.0
                        self._agent_timings["early_exit"] = True

                        start_time = time.time()
                        final_decision, token_usage = await self._run_agent_6(
                            file_path,
                            context,
                            adversarial_validation,
                            vulnerability_verification,
                            detected_language,
                        )
                        validated_final_decision = self._validate_final_findings(
                            final_decision, context, vulnerability_verification
                        )
                        validated_final_decision = self._deterministic_promote(
                            validated_final_decision, vulnerability_verification
                        )
                        elapsed = time.time() - start_time
                        self._agent_timings["agent_6"] = elapsed
                        total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                        total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                        total_token_usage["total_tokens"] += token_usage["total_tokens"]
                        progress.advance(main_task)
                        progress.advance(main_task)
                        progress.advance(main_task)
                        progress.advance(main_task)

                        total_elapsed = time.time() - total_start_time
                        self._current_step = "completed"
                        if file_path not in self._processed_files:
                            self._processed_files.append(file_path)
                        if not use_cache:
                            self._cache_analysis_result(
                                file_path,
                                context.get("file_content", ""),
                                context_analysis or {},
                                code_understanding or {},
                            )
                        logger.info(
                            f"[bold cyan][PURE-AI][/bold cyan] [bold green]OK {Path(file_path).name} 分析完成（早停）[/bold green] ({total_elapsed:.2f}s)"
                        )
                        return {
                            "file_path": file_path,
                            "context_analysis": context_analysis,
                            "code_understanding": code_understanding,
                            "risk_enumeration": risk_enumeration or {},
                            "vulnerability_verification": vulnerability_verification,
                            "attack_chain_analysis": attack_chain_analysis,
                            "adversarial_validation": adversarial_validation,
                            "final_decision": validated_final_decision,
                            "evidence_chain": self._get_signal_summary(),
                            "debug_logs": self.debug_logs,
                            "parallel_mode": enable_parallel,
                            "early_exit": True,
                            "file_snapshot": {
                                "path": file_path,
                                "recorded": True,
                                "has_content": file_path in self.line_number_mapper._snapshots,
                            },
                        }

                    self._check_token_budget_and_warn(total_token_usage, "Agent-2")
                    skip_agent_4_5 = (
                        total_token_usage["total_tokens"]
                        >= TOKEN_BUDGET_PER_FILE * TOKEN_CRITICAL_THRESHOLD
                    )

                    # [FIX-B4] 顺序执行 Agent-3 → Agent-4 → Agent-5
                    # Agent-4 依赖 Agent-3 结果，Agent-5 依赖 Agent-4 结果，
                    # 不能并行执行。保留并行模式框架以备未来无依赖任务使用。

                    if skip_agent_4_5:
                        logger.warning(
                            f"[TOKEN-SKIP] 跳过 Agent-4/5 (并行模式，Token: {total_token_usage['total_tokens']:,}/{TOKEN_BUDGET_PER_FILE:,})"
                        )
                        console.print(
                            f"[yellow][TOKEN-SKIP] 跳过 Agent-4/5 (并行模式，Token: {total_token_usage['total_tokens']:,}/{TOKEN_BUDGET_PER_FILE:,})[/yellow]"
                        )

                    # Agent-3: 漏洞验证 (先执行，因为 Agent-4 依赖其结果)
                    start_t = time.time()
                    try:
                        vuln_verify_result, token_usage = await self._run_agent_3(
                            file_path, risk_enumeration or {}, context["file_content"],
                            detected_language, context
                        )
                        total_token_usage["prompt_tokens"] += token_usage.get("prompt_tokens", 0)
                        total_token_usage["completion_tokens"] += token_usage.get("completion_tokens", 0)
                        total_token_usage["total_tokens"] += token_usage.get("total_tokens", 0)
                        if isinstance(vuln_verify_result, dict):
                            vulnerability_verification = vuln_verify_result
                            self._track_verification_signals(vulnerability_verification)
                        else:
                            logger.warning(
                                f"Agent-3 returned non-dict result type: {type(vuln_verify_result).__name__}, treating as empty"
                            )
                            vulnerability_verification = {"vulnerabilities": []}
                    except Exception as e:
                        logger.error(f"Agent-3 执行失败: {e}")
                        vulnerability_verification = {"vulnerabilities": []}
                    self._agent_timings["agent_3"] = time.time() - start_t

                    # Agent-4: 攻击链分析 (依赖 Agent-3 结果)
                    if not skip_agent_4_5:
                        start_t = time.time()
                        try:
                            attack_result, token_usage = await self._run_agent_4(
                                file_path,
                                vulnerability_verification or {},
                                detected_language,
                                context,
                            )
                            total_token_usage["prompt_tokens"] += token_usage.get("prompt_tokens", 0)
                            total_token_usage["completion_tokens"] += token_usage.get("completion_tokens", 0)
                            total_token_usage["total_tokens"] += token_usage.get("total_tokens", 0)
                            if isinstance(attack_result, dict):
                                attack_chain_analysis = attack_result
                                self._track_attack_chain_signals(attack_chain_analysis)
                            else:
                                logger.warning(
                                    f"Agent-4 returned non-dict result type: {type(attack_result).__name__}, treating as empty"
                                )
                                attack_chain_analysis = {"attack_chains": []}
                        except Exception as e:
                            logger.error(f"Agent-4 执行失败: {e}")
                            attack_chain_analysis = {"attack_chains": []}
                        self._agent_timings["agent_4"] = time.time() - start_t

                        # Agent-5: 对抗验证 (依赖 Agent-4 结果)
                        start_t = time.time()
                        try:
                            adversarial_result, token_usage = await self._run_agent_5(
                                file_path,
                                attack_chain_analysis or {},
                                context["file_content"],
                                detected_language,
                            )
                            total_token_usage["prompt_tokens"] += token_usage.get("prompt_tokens", 0)
                            total_token_usage["completion_tokens"] += token_usage.get("completion_tokens", 0)
                            total_token_usage["total_tokens"] += token_usage.get("total_tokens", 0)
                            if isinstance(adversarial_result, dict):
                                adversarial_validation = adversarial_result
                                self._track_adversarial_signals(adversarial_validation)
                            else:
                                logger.warning(
                                    f"Agent-5 returned non-dict result type: {type(adversarial_result).__name__}, treating as empty"
                                )
                                adversarial_validation = {"adversarial_analysis": []}
                        except Exception as e:
                            logger.error(f"Agent-5 执行失败: {e}")
                            adversarial_validation = {"adversarial_analysis": []}
                        self._agent_timings["agent_5"] = time.time() - start_t

                    elapsed = time.time() - start_time
                    self._agent_timings["parallel_stage"] = elapsed
                    logger.debug(f" 顺序 Stage 3-5 耗时: {elapsed:.2f}s (已修复数据依赖)")
                else:
                    start_time = time.time()
                    risk_enumeration, token_usage = await self._run_agent_2(
                        file_path, code_understanding or {}, detected_language
                    )
                    elapsed = time.time() - start_time
                    self._agent_timings["agent_2"] = elapsed
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                    progress.advance(main_task)

                    vulnerability_verification, token_usage = await self._run_agent_3(
                        file_path,
                        risk_enumeration,
                        context["file_content"],
                        detected_language,
                        context,
                    )
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                    progress.advance(main_task)

                    self._check_token_budget_and_warn(total_token_usage, "Agent-3")
                    skip_agent_4_5 = (
                        total_token_usage["total_tokens"]
                        >= TOKEN_BUDGET_PER_FILE * TOKEN_CRITICAL_THRESHOLD
                    )

                    attack_chain_analysis, token_usage = await self._run_agent_4(
                        file_path, vulnerability_verification, detected_language, context
                    )
                    total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                    total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                    total_token_usage["total_tokens"] += token_usage["total_tokens"]
                    progress.advance(main_task)

                    if skip_agent_4_5:
                        logger.warning(
                            f"[TOKEN-SKIP] 跳过 Agent-5 (非并行模式，Token: {total_token_usage['total_tokens']:,}/{TOKEN_BUDGET_PER_FILE:,})"
                        )
                        console.print(
                            f"[yellow][TOKEN-SKIP] 跳过 Agent-5 (非并行模式，Token: {total_token_usage['total_tokens']:,}/{TOKEN_BUDGET_PER_FILE:,})[/yellow]"
                        )
                        adversarial_validation = {
                            "adversarial_analysis": [],
                            "note": "skipped due to token budget",
                        }
                        token_usage = {
                            "prompt_tokens": 0,
                            "completion_tokens": 0,
                            "total_tokens": 0,
                        }
                    else:
                        adversarial_validation, token_usage = await self._run_agent_5(
                            file_path,
                            attack_chain_analysis,
                            context["file_content"],
                            detected_language,
                        )
                        total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                        total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                        total_token_usage["total_tokens"] += token_usage["total_tokens"]
                    progress.advance(main_task)

                start_time = time.time()
                final_decision, token_usage = await self._run_agent_6(
                    file_path,
                    context,
                    adversarial_validation or {},
                    vulnerability_verification or {},
                    detected_language,
                )
                validated_final_decision = self._validate_final_findings(
                    final_decision, context, vulnerability_verification or {}
                )
                validated_final_decision = self._deterministic_promote(
                    validated_final_decision, vulnerability_verification or {}
                )
                elapsed = time.time() - start_time
                self._agent_timings["agent_6"] = elapsed
                total_token_usage["prompt_tokens"] += token_usage["prompt_tokens"]
                total_token_usage["completion_tokens"] += token_usage["completion_tokens"]
                total_token_usage["total_tokens"] += token_usage["total_tokens"]
                progress.advance(main_task)

            total_elapsed = time.time() - total_start_time
            self._current_step = "completed"

            if file_path not in self._processed_files:
                self._processed_files.append(file_path)

            logger.info(
                f"[bold cyan][PURE-AI][/bold cyan] [bold green]OK {Path(file_path).name} 优化流水线分析完成[/bold green] ({total_elapsed:.2f}s)"
            )
            if total_token_usage["total_tokens"] > 0:
                logger.debug(
                    f"   Token: {total_token_usage['total_tokens']:,} (提示词: {total_token_usage['prompt_tokens']:,}, 补全: {total_token_usage['completion_tokens']:,})"
                )
            if not use_cache:
                self._cache_analysis_result(
                    file_path,
                    context.get("file_content", ""),
                    context_analysis or {},
                    code_understanding or {},
                )

            consistency_result = self._validate_result_consistency(
                {
                    "risk_enumeration": risk_enumeration or {},
                    "vulnerability_verification": vulnerability_verification or {},
                }
            )
            consistency_info = {
                "consistency_score": consistency_result.get("consistency_score", 1.0),
                "stability_warning": consistency_result.get("stability_warning"),
                "signal_count": consistency_result.get("signal_count", {}),
            }

            return {
                "file_path": file_path,
                "context_analysis": context_analysis,
                "code_understanding": code_understanding,
                "risk_enumeration": risk_enumeration or {},
                "vulnerability_verification": vulnerability_verification or {},
                "attack_chain_analysis": attack_chain_analysis or {},
                "adversarial_validation": adversarial_validation or {},
                "final_decision": validated_final_decision,
                "evidence_chain": self._get_signal_summary(),
                "debug_logs": self.debug_logs,
                "parallel_mode": enable_parallel,
                "consistency": consistency_info,
                "file_snapshot": {
                    "path": file_path,
                    "recorded": True,
                    "has_content": file_path in self.line_number_mapper._snapshots,
                },
            }

        except Exception as e:
            self._current_step = "error"
            logger.error(f"优化流水线分析失败: {e}")
            console.print("[red]优化流水线分析失败[/red]")
            import traceback

            traceback.print_exc()
            return {"file_path": file_path, "error": str(e)}

    def get_agent_dependencies(self) -> Dict[str, List[str]]:
        """获取 Agent 依赖关系

        Returns:
            Agent 名称到其依赖的 Agent 列表的映射
        """
        return {
            "agent_0": [],
            "agent_1": ["agent_0"],
            "agent_2": ["agent_1"],
            "agent_3": ["agent_2"],
            "agent_4": ["agent_3"],
            "agent_5": ["agent_4"],
            "agent_6": ["agent_3", "agent_4", "agent_5"],
        }

    def get_parallelizable_agents(self) -> List[Tuple[str, Any]]:
        """获取可并行的 Agent 对

        Returns:
            (Agent 组名, Agent 列表) 列表
        """
        return [
            ("stage_1", "agent_0"),
            ("stage_2", "agent_1"),
            ("stage_3_parallel", ["agent_3", "agent_4", "agent_5"]),
            ("stage_4", "agent_6"),
        ]
