"""文件优先级引擎模块

计算文件的扫描优先级，基于业务关键度、代码复杂度、安全敏感度和变更频率等多维度评分。
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .file_discovery import FileInfo, FileType, Language


class PriorityStrategy(Enum):
    """优先级策略"""

    BALANCED = "balanced"
    SECURITY_FIRST = "security_first"
    COMPLEXITY_FIRST = "complexity_first"
    BUSINESS_FIRST = "business_first"
    CHANGE_FREQUENCY_FIRST = "change_frequency_first"


class PriorityLevel(Enum):
    """优先级等级"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FilePriority:
    """文件优先级信息"""

    file_info: FileInfo
    total_score: float
    business_score: float
    complexity_score: float
    security_score: float
    change_frequency_score: float
    priority_level: PriorityLevel
    rank: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "file_path": str(self.file_info.path),
            "total_score": self.total_score,
            "business_score": self.business_score,
            "complexity_score": self.complexity_score,
            "security_score": self.security_score,
            "change_frequency_score": self.change_frequency_score,
            "priority_level": self.priority_level.value,
            "rank": self.rank,
        }


@dataclass
class PriorityConfig:
    """优先级配置"""

    business_weight: float = 0.25
    complexity_weight: float = 0.25
    security_weight: float = 0.30
    change_frequency_weight: float = 0.20

    critical_threshold: float = 0.8
    high_threshold: float = 0.6
    medium_threshold: float = 0.4
    low_threshold: float = 0.2

    security_sensitive_patterns: List[str] = field(
        default_factory=lambda: [
            "auth",
            "login",
            "password",
            "credential",
            "token",
            "session",
            "api_key",
            "secret",
            "crypto",
            "encrypt",
            "decrypt",
            "hash",
            "salt",
            "permission",
            "privilege",
            "admin",
            "root",
            "sudo",
            "user",
            "account",
            "profile",
            "payment",
            "transaction",
            "order",
            "checkout",
            "cart",
            "invoice",
            "billing",
            "subscription",
            "license",
            "validation",
            "sanitize",
            "escape",
            "filter",
            "input",
            "output",
            "request",
            "response",
            "header",
            "cookie",
            "upload",
            "download",
            "file",
            "path",
            "url",
            "redirect",
            "forward",
            "proxy",
            "socket",
            "network",
            "database",
            "query",
            "sql",
            "nosql",
            "cache",
            "queue",
            "message",
            "event",
            "handler",
            "controller",
            "route",
            "endpoint",
            "api",
            "rest",
            "graphql",
            "rpc",
            "grpc",
            "soap",
            "wsdl",
            "xmlrpc",
            "callback",
            "webhook",
            "hook",
            "middleware",
            "interceptor",
            "filter",
            "guard",
            "shield",
            "barrier",
            "gate",
            "wall",
            "firewall",
            "waf",
            "ids",
            "ips",
            "siem",
            "log",
            "audit",
            "monitor",
            "alert",
            "notify",
            "report",
            "analytics",
            "tracking",
            "telemetry",
            "metric",
            "health",
            "status",
            "ping",
            "heartbeat",
        ]
    )

    business_critical_patterns: List[str] = field(
        default_factory=lambda: [
            "main",
            "app",
            "server",
            "client",
            "core",
            "engine",
            "manager",
            "service",
            "controller",
            "handler",
            "processor",
            "executor",
            "scheduler",
            "worker",
            "runner",
            "driver",
            "factory",
            "builder",
            "provider",
            "repository",
            "model",
            "entity",
            "schema",
            "mapper",
            "adapter",
            "connector",
            "client",
            "gateway",
            "proxy",
            "router",
            "dispatcher",
            "loader",
            "parser",
            "serializer",
            "validator",
            "converter",
            "transformer",
            "aggregator",
            "collector",
            "analyzer",
            "scanner",
            "checker",
            "detector",
            "finder",
            "searcher",
            "matcher",
            "filter",
            "sorter",
            "grouper",
            "partitioner",
            "splitter",
            "merger",
            "joiner",
            "composer",
            "assembler",
            "renderer",
            "generator",
            "producer",
            "consumer",
            "publisher",
            "subscriber",
            "listener",
            "observer",
            "watcher",
            "monitor",
            "supervisor",
            "coordinator",
            "orchestrator",
            "director",
            "leader",
            "master",
            "slave",
            "primary",
            "secondary",
            "backup",
            "failover",
            "recovery",
            "restore",
            "backup",
            "archive",
            "export",
            "import",
            "migration",
            "upgrade",
            "downgrade",
            "install",
            "uninstall",
            "setup",
            "teardown",
            "init",
            "destroy",
            "start",
            "stop",
            "restart",
            "reload",
            "refresh",
            "reset",
            "clear",
            "purge",
            "clean",
            "optimize",
            "compress",
            "decompress",
            "encode",
            "decode",
            "encrypt",
            "decrypt",
            "sign",
            "verify",
            "authenticate",
            "authorize",
            "login",
            "logout",
            "register",
            "deregister",
            "subscribe",
            "unsubscribe",
            "connect",
            "disconnect",
            "bind",
            "unbind",
            "attach",
            "detach",
            "mount",
            "unmount",
            "lock",
            "unlock",
            "acquire",
            "release",
            "allocate",
            "deallocate",
            "reserve",
            "commit",
            "rollback",
            "abort",
            "cancel",
            "undo",
            "redo",
            "revert",
            "apply",
            "reject",
            "approve",
            "confirm",
            "validate",
            "invalidate",
            "expire",
            "renew",
            "refresh",
            "update",
            "delete",
            "create",
            "read",
            "write",
            "append",
            "prepend",
            "insert",
            "modify",
            "replace",
            "swap",
            "exchange",
            "transfer",
            "move",
            "copy",
            "clone",
            "duplicate",
            "replicate",
            "sync",
            "async",
            "parallel",
            "serial",
            "batch",
            "stream",
            "flow",
            "pipeline",
            "chain",
            "sequence",
            "series",
            "loop",
            "iterate",
            "recurse",
            "traverse",
            "navigate",
            "explore",
            "discover",
            "detect",
            "identify",
            "recognize",
            "classify",
            "categorize",
            "tag",
            "label",
            "mark",
            "flag",
            "highlight",
            "annotate",
            "comment",
            "document",
            "describe",
            "explain",
            "illustrate",
            "demonstrate",
            "show",
            "hide",
            "display",
            "render",
            "paint",
            "draw",
            "plot",
            "chart",
            "graph",
            "visualize",
            "present",
            "format",
            "style",
            "design",
            "layout",
            "structure",
            "organize",
            "arrange",
            "order",
            "sort",
            "rank",
            "prioritize",
            "weight",
            "score",
            "rate",
            "grade",
            "assess",
            "evaluate",
            "measure",
            "quantify",
            "calculate",
            "compute",
            "estimate",
            "predict",
            "forecast",
            "project",
            "simulate",
            "model",
            "emulate",
            "imitate",
            "mock",
            "stub",
            "fake",
            "dummy",
            "test",
            "spec",
            "benchmark",
            "profile",
            "debug",
            "trace",
            "log",
            "audit",
            "inspect",
            "examine",
            "analyze",
            "review",
            "check",
            "verify",
            "validate",
            "ensure",
            "guarantee",
            "assert",
            "expect",
            "require",
            "demand",
            "enforce",
            "impose",
            "restrict",
            "limit",
            "constrain",
            "bound",
            "cap",
            "throttle",
            "rate_limit",
            "quota",
            "budget",
            "allocation",
            "reservation",
            "booking",
            "appointment",
            "schedule",
            "calendar",
            "timeline",
            "deadline",
            "due",
            "overdue",
            "pending",
            "queued",
            "processing",
            "running",
            "completed",
            "failed",
            "error",
            "warning",
            "info",
            "debug",
            "trace",
            "critical",
            "emergency",
            "alert",
            "urgent",
            "important",
            "normal",
            "low",
            "background",
            "foreground",
            "interactive",
            "batch",
            "scheduled",
            "manual",
            "automatic",
            "autonomous",
            "self",
            "auto",
            "smart",
            "intelligent",
            "adaptive",
            "dynamic",
            "static",
            "constant",
            "variable",
            "mutable",
            "immutable",
            "readonly",
            "writeonly",
            "readwrite",
            "volatile",
            "transient",
            "persistent",
            "temporary",
            "permanent",
            "ephemeral",
            "durable",
            "reliable",
            "unreliable",
            "available",
            "unavailable",
            "accessible",
            "inaccessible",
            "visible",
            "invisible",
            "public",
            "private",
            "protected",
            "internal",
            "external",
            "local",
            "global",
            "scope",
            "context",
            "environment",
            "setting",
            "preference",
            "option",
            "parameter",
            "argument",
            "variable",
            "constant",
            "literal",
            "expression",
            "statement",
            "block",
            "function",
            "method",
            "procedure",
            "routine",
            "subroutine",
            "program",
            "script",
            "module",
            "package",
            "library",
            "framework",
            "platform",
            "system",
            "application",
            "service",
            "daemon",
            "process",
            "thread",
            "task",
            "job",
            "work",
            "operation",
            "action",
            "command",
            "instruction",
            "directive",
            "rule",
            "policy",
            "strategy",
            "tactic",
            "plan",
            "design",
            "architecture",
            "pattern",
            "template",
            "blueprint",
            "schema",
            "model",
            "view",
            "controller",
            "presenter",
            "viewmodel",
            "adapter",
            "bridge",
            "facade",
            "proxy",
            "decorator",
            "composite",
            "flyweight",
            "observer",
            "mediator",
            "command",
            "chain",
            "iterator",
            "memento",
            "state",
            "strategy",
            "template",
            "visitor",
            "singleton",
            "factory",
            "builder",
            "prototype",
            "object_pool",
            "lazy",
            "eager",
            "async",
            "sync",
            "blocking",
            "nonblocking",
            "concurrent",
            "parallel",
            "distributed",
            "clustered",
            "replicated",
            "sharded",
            "partitioned",
            "segmented",
            "fragmented",
            "chunked",
            "batched",
            "streamed",
            "piped",
            "channeled",
            "queued",
            "buffered",
            "cached",
            "memoized",
            "indexed",
            "hashed",
            "sorted",
            "ordered",
            "grouped",
            "aggregated",
            "summarized",
            "compressed",
            "encoded",
            "encrypted",
            "signed",
            "certified",
            "verified",
            "validated",
            "authenticated",
            "authorized",
            "permitted",
            "allowed",
            "granted",
            "denied",
            "rejected",
            "blocked",
            "filtered",
            "screened",
            "sanitized",
            "cleaned",
            "purified",
            "refined",
            "polished",
            "optimized",
            "improved",
            "enhanced",
            "upgraded",
            "updated",
            "patched",
            "fixed",
            "repaired",
            "restored",
            "recovered",
            "reconstructed",
            "rebuilt",
            "refactored",
            "rewritten",
            "redesigned",
            "reimplemented",
            "replaced",
            "substituted",
            "swapped",
            "exchanged",
            "converted",
            "transformed",
            "translated",
            "interpreted",
            "compiled",
            "built",
            "packaged",
            "deployed",
            "released",
            "published",
            "distributed",
            "delivered",
            "installed",
            "configured",
            "initialized",
            "started",
            "launched",
            "executed",
            "run",
            "processed",
            "handled",
            "served",
            "responded",
            "replied",
            "acknowledged",
            "confirmed",
            "accepted",
            "approved",
            "authorized",
            "permitted",
            "enabled",
            "activated",
            "triggered",
            "fired",
            "invoked",
            "called",
            "requested",
            "demanded",
            "required",
            "needed",
            "wanted",
            "desired",
            "expected",
            "anticipated",
            "predicted",
            "forecasted",
            "projected",
            "estimated",
            "calculated",
            "computed",
            "determined",
            "decided",
            "chosen",
            "selected",
            "picked",
            "elected",
            "nominated",
            "appointed",
            "assigned",
            "allocated",
            "distributed",
            "shared",
            "divided",
            "split",
            "separated",
            "isolated",
            "quarantined",
            "sandboxed",
            "containerized",
            "virtualized",
            "abstracted",
            "encapsulated",
            "wrapped",
            "packaged",
            "bundled",
            "grouped",
            "clustered",
            "categorized",
            "classified",
            "labeled",
            "tagged",
            "marked",
            "flagged",
            "highlighted",
            "emphasized",
            "stressed",
            "prioritized",
            "ranked",
            "ordered",
            "sorted",
            "arranged",
            "organized",
            "structured",
            "formatted",
            "styled",
            "designed",
            "rendered",
            "displayed",
            "shown",
            "presented",
            "exposed",
            "published",
            "released",
            "distributed",
            "shared",
            "communicated",
            "transmitted",
            "sent",
            "delivered",
            "received",
            "accepted",
            "processed",
            "handled",
            "consumed",
            "used",
            "utilized",
            "exploited",
            "leveraged",
            "capitalized",
            "benefited",
            "profited",
            "gained",
            "won",
            "achieved",
            "accomplished",
            "completed",
            "finished",
            "done",
            "ended",
            "terminated",
            "stopped",
            "halted",
            "paused",
            "suspended",
            "deferred",
            "postponed",
            "delayed",
            "waited",
            "slept",
            "idle",
            "inactive",
            "dormant",
            "hibernating",
            "frozen",
            "locked",
            "blocked",
            "disabled",
            "deactivated",
            "inactive",
            "offline",
            "disconnected",
            "unavailable",
            "missing",
            "lost",
            "deleted",
            "removed",
            "cleared",
            "purged",
            "destroyed",
            "killed",
            "terminated",
            "aborted",
            "cancelled",
            "revoked",
            "retracted",
            "withdrawn",
            "rejected",
            "denied",
            "refused",
            "declined",
            "dismissed",
            "ignored",
            "skipped",
            "omitted",
            "excluded",
            "filtered",
            "screened",
            "blocked",
            "prohibited",
            "forbidden",
            "banned",
            "restricted",
            "limited",
            "constrained",
            "bound",
            "tied",
            "chained",
            "linked",
            "connected",
            "associated",
            "related",
            "referenced",
            "pointed",
            "directed",
            "targeted",
            "aimed",
            "focused",
            "centered",
            "oriented",
            "aligned",
            "synchronized",
            "coordinated",
            "orchestrated",
            "managed",
            "controlled",
            "governed",
            "regulated",
            "supervised",
            "monitored",
            "observed",
            "watched",
            "tracked",
            "traced",
            "logged",
            "recorded",
            "documented",
            "reported",
            "notified",
            "alerted",
            "warned",
            "informed",
            "updated",
            "notified",
            "messaged",
            "emailed",
            "sent",
            "delivered",
            "received",
            "read",
            "seen",
            "viewed",
            "opened",
            "clicked",
            "tapped",
            "pressed",
            "touched",
            "swiped",
            "scrolled",
            "zoomed",
            "panned",
            "rotated",
            "scaled",
            "resized",
            "moved",
            "dragged",
            "dropped",
            "placed",
            "positioned",
            "located",
            "found",
            "discovered",
            "detected",
            "identified",
            "recognized",
            "authenticated",
            "verified",
            "validated",
            "confirmed",
            "approved",
            "accepted",
            "authorized",
            "permitted",
            "allowed",
            "enabled",
            "activated",
            "started",
            "initiated",
            "launched",
            "executed",
            "run",
            "processed",
            "handled",
            "served",
            "completed",
            "finished",
            "done",
        ]
    )


class FilePriorityEngine:
    """文件优先级引擎

    计算文件的扫描优先级，支持多种评分维度和策略。
    """

    def __init__(self, config: Optional[PriorityConfig] = None):
        """初始化文件优先级引擎

        Args:
            config: 优先级配置
        """
        self.config = config or PriorityConfig()
        self._score_cache: Dict[str, FilePriority] = {}

    def calculate_priority(
        self,
        file_info: FileInfo,
        strategy: PriorityStrategy = PriorityStrategy.BALANCED,
    ) -> FilePriority:
        """计算文件优先级

        Args:
            file_info: 文件信息
            strategy: 优先级策略

        Returns:
            文件优先级信息
        """
        cache_key = f"{file_info.path}_{strategy.value}"
        if cache_key in self._score_cache:
            return self._score_cache[cache_key]

        business_score = self.get_business_criticality_score(file_info)
        complexity_score = self.get_complexity_score(file_info)
        security_score = self.get_security_sensitivity_score(file_info)
        change_frequency_score = self.get_change_frequency_score(file_info)

        weights = self._get_weights(strategy)

        total_score = (
            business_score * weights["business"]
            + complexity_score * weights["complexity"]
            + security_score * weights["security"]
            + change_frequency_score * weights["change_frequency"]
        )

        priority_level = self._determine_priority_level(total_score)

        priority = FilePriority(
            file_info=file_info,
            total_score=total_score,
            business_score=business_score,
            complexity_score=complexity_score,
            security_score=security_score,
            change_frequency_score=change_frequency_score,
            priority_level=priority_level,
        )

        self._score_cache[cache_key] = priority
        return priority

    def rank_files(
        self,
        files: List[FileInfo],
        strategy: PriorityStrategy = PriorityStrategy.BALANCED,
    ) -> List[FilePriority]:
        """对文件进行优先级排序

        Args:
            files: 文件列表
            strategy: 优先级策略

        Returns:
            排序后的文件优先级列表
        """
        priorities = [
            self.calculate_priority(file_info, strategy) for file_info in files
        ]

        sorted_priorities = sorted(
            priorities, key=lambda p: p.total_score, reverse=True
        )

        for rank, priority in enumerate(sorted_priorities, 1):
            priority.rank = rank

        return sorted_priorities

    def get_business_criticality_score(self, file_info: FileInfo) -> float:
        """获取业务关键度评分

        Args:
            file_info: 文件信息

        Returns:
            业务关键度评分 (0.0 - 1.0)
        """
        score = 0.0
        path_str = str(file_info.path).lower()
        file_stem = file_info.path.stem.lower()

        for pattern in self.config.business_critical_patterns:
            if pattern in path_str or pattern in file_stem:
                score += 0.1

        if file_info.file_type == FileType.SOURCE:
            score += 0.2
        elif file_info.file_type == FileType.CONFIG:
            score += 0.15
        elif file_info.file_type == FileType.TEST:
            score -= 0.1

        if "entry" in path_str or "main" in path_str or "app" in path_str:
            score += 0.15

        if "core" in path_str or "engine" in path_str or "service" in path_str:
            score += 0.1

        return min(max(score, 0.0), 1.0)

    def get_complexity_score(self, file_info: FileInfo) -> float:
        """获取复杂度评分

        Args:
            file_info: 文件信息

        Returns:
            复杂度评分 (0.0 - 1.0)
        """
        score = 0.0

        if file_info.line_count > 0:
            if file_info.line_count > 1000:
                score += 0.4
            elif file_info.line_count > 500:
                score += 0.3
            elif file_info.line_count > 200:
                score += 0.2
            elif file_info.line_count > 100:
                score += 0.1

        if file_info.size > 0:
            if file_info.size > 100 * 1024:
                score += 0.3
            elif file_info.size > 50 * 1024:
                score += 0.2
            elif file_info.size > 20 * 1024:
                score += 0.1

        if file_info.language in [Language.CPP, Language.JAVA, Language.TYPESCRIPT]:
            score += 0.1
        elif file_info.language == Language.PYTHON:
            score += 0.05

        return min(max(score, 0.0), 1.0)

    def get_security_sensitivity_score(self, file_info: FileInfo) -> float:
        """获取安全敏感度评分

        Args:
            file_info: 文件信息

        Returns:
            安全敏感度评分 (0.0 - 1.0)
        """
        score = 0.0
        path_str = str(file_info.path).lower()
        file_stem = file_info.path.stem.lower()

        for pattern in self.config.security_sensitive_patterns:
            if pattern in path_str or pattern in file_stem:
                score += 0.08

        security_keywords = [
            "password",
            "secret",
            "key",
            "token",
            "credential",
            "auth",
            "login",
            "session",
            "cookie",
            "header",
            "input",
            "request",
            "query",
            "sql",
            "execute",
            "eval",
            "system",
            "subprocess",
            "shell",
            "command",
            "inject",
            "xss",
            "csrf",
            "srf",
            "rce",
            "lfi",
            "rfi",
            "ssrf",
            "xxe",
            "sqli",
            "bypass",
            "vulnerability",
            "exploit",
            "attack",
            "hack",
            "malicious",
            "threat",
            "risk",
            "dangerous",
            "unsafe",
            "insecure",
            "sensitive",
            "confidential",
            "private",
            "protected",
            "restricted",
            "classified",
            "critical",
            "important",
            "valuable",
        ]

        for keyword in security_keywords:
            if keyword in path_str or keyword in file_stem:
                score += 0.05

        if file_info.file_type == FileType.CONFIG:
            score += 0.15

        if file_info.language == Language.PYTHON:
            if any(
                kw in path_str
                for kw in ["views.py", "controllers.py", "handlers.py", "api.py"]
            ):
                score += 0.2

        if file_info.language in [Language.JAVASCRIPT, Language.TYPESCRIPT]:
            if any(
                kw in path_str
                for kw in ["route", "controller", "handler", "middleware", "api"]
            ):
                score += 0.15

        return min(max(score, 0.0), 1.0)

    def get_change_frequency_score(self, file_info: FileInfo) -> float:
        """获取变更频率评分

        Args:
            file_info: 文件信息

        Returns:
            变更频率评分 (0.0 - 1.0)
        """
        score = 0.0

        if file_info.metadata.get("commit_count", 0) > 0:
            commit_count = file_info.metadata["commit_count"]
            if commit_count > 50:
                score += 0.4
            elif commit_count > 20:
                score += 0.3
            elif commit_count > 10:
                score += 0.2
            elif commit_count > 5:
                score += 0.1

        if file_info.metadata.get("recently_modified", False):
            score += 0.2

        if file_info.metadata.get("hotspot", False):
            score += 0.2

        if file_info.metadata.get("bug_fix_count", 0) > 0:
            bug_fix_count = file_info.metadata["bug_fix_count"]
            if bug_fix_count > 10:
                score += 0.3
            elif bug_fix_count > 5:
                score += 0.2
            elif bug_fix_count > 2:
                score += 0.1

        return min(max(score, 0.0), 1.0)

    def get_top_priority_files(
        self,
        files: List[FileInfo],
        top_n: int = 10,
        strategy: PriorityStrategy = PriorityStrategy.BALANCED,
    ) -> List[FilePriority]:
        """获取优先级最高的文件

        Args:
            files: 文件列表
            top_n: 返回数量
            strategy: 优先级策略

        Returns:
            优先级最高的文件列表
        """
        ranked = self.rank_files(files, strategy)
        return ranked[:top_n]

    def filter_by_priority_level(
        self,
        files: List[FileInfo],
        min_level: PriorityLevel,
        strategy: PriorityStrategy = PriorityStrategy.BALANCED,
    ) -> List[FilePriority]:
        """按优先级等级过滤文件

        Args:
            files: 文件列表
            min_level: 最低优先级等级
            strategy: 优先级策略

        Returns:
            过滤后的文件优先级列表
        """
        level_order = {
            PriorityLevel.CRITICAL: 5,
            PriorityLevel.HIGH: 4,
            PriorityLevel.MEDIUM: 3,
            PriorityLevel.LOW: 2,
            PriorityLevel.INFO: 1,
        }

        min_order = level_order[min_level]

        priorities = [
            self.calculate_priority(file_info, strategy) for file_info in files
        ]

        return [p for p in priorities if level_order[p.priority_level] >= min_order]

    def _get_weights(self, strategy: PriorityStrategy) -> Dict[str, float]:
        """获取策略权重

        Args:
            strategy: 优先级策略

        Returns:
            权重字典
        """
        if strategy == PriorityStrategy.BALANCED:
            return {
                "business": self.config.business_weight,
                "complexity": self.config.complexity_weight,
                "security": self.config.security_weight,
                "change_frequency": self.config.change_frequency_weight,
            }
        elif strategy == PriorityStrategy.SECURITY_FIRST:
            return {
                "business": 0.15,
                "complexity": 0.15,
                "security": 0.50,
                "change_frequency": 0.20,
            }
        elif strategy == PriorityStrategy.COMPLEXITY_FIRST:
            return {
                "business": 0.20,
                "complexity": 0.40,
                "security": 0.20,
                "change_frequency": 0.20,
            }
        elif strategy == PriorityStrategy.BUSINESS_FIRST:
            return {
                "business": 0.40,
                "complexity": 0.20,
                "security": 0.20,
                "change_frequency": 0.20,
            }
        elif strategy == PriorityStrategy.CHANGE_FREQUENCY_FIRST:
            return {
                "business": 0.20,
                "complexity": 0.20,
                "security": 0.20,
                "change_frequency": 0.40,
            }
        else:
            return {
                "business": self.config.business_weight,
                "complexity": self.config.complexity_weight,
                "security": self.config.security_weight,
                "change_frequency": self.config.change_frequency_weight,
            }

    def _determine_priority_level(self, score: float) -> PriorityLevel:
        """确定优先级等级

        Args:
            score: 总评分

        Returns:
            优先级等级
        """
        if score >= self.config.critical_threshold:
            return PriorityLevel.CRITICAL
        elif score >= self.config.high_threshold:
            return PriorityLevel.HIGH
        elif score >= self.config.medium_threshold:
            return PriorityLevel.MEDIUM
        elif score >= self.config.low_threshold:
            return PriorityLevel.LOW
        else:
            return PriorityLevel.INFO

    def clear_cache(self) -> None:
        """清除缓存"""
        self._score_cache.clear()

    def get_statistics(
        self, priorities: List[FilePriority]
    ) -> Dict[str, Any]:
        """获取统计信息

        Args:
            priorities: 文件优先级列表

        Returns:
            统计信息字典
        """
        if not priorities:
            return {
                "total_files": 0,
                "avg_score": 0.0,
                "by_level": {},
                "top_files": [],
            }

        by_level: Dict[str, int] = {}
        for priority in priorities:
            level = priority.priority_level.value
            by_level[level] = by_level.get(level, 0) + 1

        avg_score = sum(p.total_score for p in priorities) / len(priorities)

        top_files = sorted(priorities, key=lambda p: p.total_score, reverse=True)[:5]

        return {
            "total_files": len(priorities),
            "avg_score": avg_score,
            "by_level": by_level,
            "top_files": [p.to_dict() for p in top_files],
        }
