"""扫描引擎模块

提供核心的扫描流程管理和执行功能。
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Set, Union

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.core.config import Config


class ScanStatus(Enum):
    """扫描状态"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(Enum):
    """漏洞严重级别"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        return not self < other


class ScanMode(Enum):
    AUTO = "auto"
    PURE_AI = "pure-ai"
    FAST = "fast"
    DEEP = "deep"
    STEALTH = "stealth"
    VULN_LAB = "vuln-lab"


class ModeRouter:
    """模式路由器

    根据 --mode 参数选择对应的分析引擎
    """

    def __init__(self, config):
        self.config = config
        self.checkpoint_manager = None
        self.incremental_index = None
        self.context_memory = None

    def set_checkpoint_manager(self, manager):
        self.checkpoint_manager = manager

    def set_incremental_index(self, manager):
        self.incremental_index = manager

    def set_context_memory(self, manager):
        self.context_memory = manager

    def get_mode(self) -> ScanMode:
        """获取当前模式"""
        mode_str = getattr(self.config, 'scan_mode', 'auto')
        try:
            return ScanMode(mode_str.lower())
        except ValueError:
            return ScanMode.AUTO

    def should_use_pure_ai(self) -> bool:
        """判断是否使用纯AI模式"""
        return self.get_mode() in [ScanMode.PURE_AI, ScanMode.DEEP]

    def should_incremental_scan(self) -> bool:
        """判断是否使用增量扫描"""
        return self.config.scan.incremental and not getattr(self.config, 'full_scan', False)


@dataclass
class Location:
    """漏洞位置"""

    file: str
    line: int = 0
    column: int = 0
    end_line: int = 0
    end_column: int = 0

    def __str__(self) -> str:
        if self.line > 0:
            if self.column > 0:
                return f"{self.file}:{self.line}:{self.column}"
            return f"{self.file}:{self.line}"
        return self.file


@dataclass
class Finding:
    """安全发现"""

    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    location: Location
    confidence: float = 1.0
    message: str = ""
    code_snippet: str = ""
    fix_suggestion: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "location": {
                "file": self.location.file,
                "line": self.location.line,
                "column": self.location.column,
                "end_line": self.location.end_line,
                "end_column": self.location.end_column,
            },
            "confidence": self.confidence,
            "message": self.message,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "references": self.references,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    """扫描结果"""

    target: str
    status: ScanStatus
    findings: List[Finding] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    debug_logs: List[str] = field(default_factory=list)
    token_records: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.start_time is None:
            self.start_time = datetime.now()

    @property
    def duration(self) -> float:
        """扫描持续时间（秒）"""
        if self.start_time is None:
            return 0.0
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    @property
    def findings_by_severity(self) -> Dict[Severity, List[Finding]]:
        """按严重级别分组的发现"""
        result: Dict[Severity, List[Finding]] = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
            Severity.INFO: [],
        }
        for finding in self.findings:
            result[finding.severity].append(finding)
        return result

    def add_finding(self, finding: Finding) -> None:
        """添加发现"""
        self.findings.append(finding)

    def deduplicate_findings(self) -> int:
        """去重发现，基于规则名称、位置和严重级别

        Returns:
            被去重的发现数量
        """
        seen = {}
        unique_findings = []
        removed_count = 0

        for finding in self.findings:
            key = (
                finding.rule_id,
                str(finding.location),
                finding.severity.value
            )
            if key not in seen:
                seen[key] = finding
                unique_findings.append(finding)
            else:
                existing = seen[key]
                if finding.confidence > existing.confidence:
                    unique_findings.remove(existing)
                    unique_findings.append(finding)
                    seen[key] = finding
                removed_count += 1

        self.findings = unique_findings
        if removed_count > 0:
            print(f"[DEBUG] Deduplicated {removed_count} findings, {len(self.findings)} unique findings remain")
        return removed_count

    def complete(self) -> None:
        """标记扫描完成"""
        self.status = ScanStatus.COMPLETED
        self.end_time = datetime.now()

    def fail(self, message: str) -> None:
        """标记扫描失败"""
        self.status = ScanStatus.FAILED
        self.error_message = message
        self.end_time = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "target": self.target,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "error_message": self.error_message,
            "metadata": self.metadata,
            "debug_logs": self.debug_logs,
            "token_records": self.token_records,
            "summary": {
                "total": len(self.findings),
                "critical": len(self.findings_by_severity[Severity.CRITICAL]),
                "high": len(self.findings_by_severity[Severity.HIGH]),
                "medium": len(self.findings_by_severity[Severity.MEDIUM]),
                "low": len(self.findings_by_severity[Severity.LOW]),
                "info": len(self.findings_by_severity[Severity.INFO]),
            },
        }


class ScannerPlugin(Protocol):
    """扫描器插件协议"""

    name: str
    version: str

    async def scan(self, target: Union[str, Path], config: Config) -> ScanResult:
        """执行扫描

        Args:
            target: 扫描目标
            config: 扫描配置

        Returns:
            扫描结果
        """
        ...

    def supports(self, target: Union[str, Path]) -> bool:
        """检查是否支持目标

        Args:
            target: 扫描目标

        Returns:
            是否支持
        """
        ...


class BaseScanner(ABC):
    """扫描器基类"""

    name: str = "base"
    version: str = "1.0.0"

    def __init__(self, config: Config) -> None:
        self.config = config
        self.console = Console()

    @abstractmethod
    async def scan(self, target: Union[str, Path]) -> ScanResult:
        """执行扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
        """
        pass

    @abstractmethod
    def supports(self, target: Union[str, Path]) -> bool:
        """检查是否支持目标

        Args:
            target: 扫描目标

        Returns:
            是否支持
        """
        pass

    def create_result(self, target: Union[str, Path]) -> ScanResult:
        """创建扫描结果对象

        Args:
            target: 扫描目标

        Returns:
            扫描结果对象
        """
        return ScanResult(
            target=str(target),
            status=ScanStatus.PENDING,
        )


class ScanEngine:
    """扫描引擎

    管理扫描流程和插件。
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.scanners: List[BaseScanner] = []
        self.console = Console()
        self._plugins: Dict[str, ScannerPlugin] = {}
        self._mode_router = ModeRouter(config)

    def get_mode_router(self) -> ModeRouter:
        """获取模式路由器

        Returns:
            模式路由器实例
        """
        return self._mode_router

    def register_scanner(self, scanner: BaseScanner) -> None:
        """注册扫描器

        Args:
            scanner: 扫描器实例
        """
        self.scanners.append(scanner)

    def unregister_scanner(self, scanner: BaseScanner) -> None:
        """注销扫描器

        Args:
            scanner: 扫描器实例
        """
        if scanner in self.scanners:
            self.scanners.remove(scanner)

    def register_plugin(self, name: str, plugin: ScannerPlugin) -> None:
        """注册插件

        Args:
            name: 插件名称
            plugin: 插件实例
        """
        self._plugins[name] = plugin

    async def scan(self, target: Union[str, Path]) -> ScanResult:
        """执行扫描

        Args:
            target: 扫描目标

        Returns:
            扫描结果
        """
        target_path = Path(target)

        # 创建结果对象
        result = ScanResult(
            target=str(target_path),
            status=ScanStatus.RUNNING,
        )

        try:
            # 查找支持的扫描器
            supported_scanners = [s for s in self.scanners if s.supports(target_path)]

            if not supported_scanners:
                result.fail(f"没有支持目标 '{target}' 的扫描器")
                return result

            # 执行扫描
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
                disable=self.config.quiet,
            ) as progress:
                task = progress.add_task(f"扫描 {target}...", total=None)

                for scanner in supported_scanners:
                    progress.update(task, description=f"使用 {scanner.name} 扫描...")
                    scan_result = await scanner.scan(target_path)
                    result.findings.extend(scan_result.findings)

                progress.update(task, description="扫描完成")

            result.complete()

        except Exception as e:
            result.fail(str(e))

        return result

    async def scan_batch(
        self, targets: List[Union[str, Path]], max_concurrent: Optional[int] = None
    ) -> List[ScanResult]:
        """批量扫描

        Args:
            targets: 扫描目标列表
            max_concurrent: 最大并发数，如果为 None 则使用配置中的值

        Returns:
            扫描结果列表
        """
        # 使用配置中的最大工作线程数或默认值
        concurrent_limit = max_concurrent or self.config.scan.max_workers
        semaphore = asyncio.Semaphore(concurrent_limit)

        async def scan_with_limit(target: Union[str, Path]) -> ScanResult:
            async with semaphore:
                try:
                    return await self.scan(target)
                except Exception as e:
                    # 创建失败结果
                    result = ScanResult(
                        target=str(target),
                        status=ScanStatus.FAILED,
                        error_message=str(e)
                    )
                    result.end_time = datetime.now()
                    return result

        tasks = [scan_with_limit(target) for target in targets]
        return await asyncio.gather(*tasks, return_exceptions=False)

    def get_supported_scanners(self, target: Union[str, Path]) -> List[BaseScanner]:
        """获取支持目标的扫描器

        Args:
            target: 扫描目标

        Returns:
            支持的扫描器列表
        """
        return [s for s in self.scanners if s.supports(target)]
