"""日志分析器模块

解析 CLI stdout/stderr，提取警告/错误/异常信息。
"""

import re
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class LogLevel(Enum):
    """日志级别"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ErrorType(Enum):
    """错误类型"""
    CLI_ERROR = "cli_error"
    IMPORT_ERROR = "import_error"
    CONFIG_ERROR = "config_error"
    ANALYSIS_ERROR = "analysis_error"
    REPORT_ERROR = "report_error"
    NETWORK_ERROR = "network_error"
    AI_ERROR = "ai_error"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class LogEntry:
    """日志条目"""
    level: LogLevel
    timestamp: Optional[datetime]
    message: str
    source: str = ""
    line_number: int = 0
    raw_line: str = ""


@dataclass
class ErrorEntry:
    """错误条目"""
    error_type: ErrorType
    message: str
    source_file: Optional[str] = None
    line_number: int = 0
    stack_trace: Optional[str] = None
    context: str = ""
    severity: str = "error"
    fix_suggestion: Optional[str] = None


@dataclass
class LogAnalysisResult:
    """日志分析结果"""
    entries: List[LogEntry] = field(default_factory=list)
    errors: List[ErrorEntry] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info_messages: List[str] = field(default_factory=list)
    token_usage: int = 0
    scan_progress: List[str] = field(default_factory=list)
    silent_failures: List[str] = field(default_factory=list)
    is_success: bool = True
    exit_code: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)


class LogAnalyzer:
    """日志分析器"""

    ERROR_PATTERNS = [
        (r"ImportError:\s*(.+)", ErrorType.IMPORT_ERROR),
        (r"ModuleNotFoundError:\s*(.+)", ErrorType.IMPORT_ERROR),
        (r"Import\s+Error:\s*(.+)", ErrorType.IMPORT_ERROR),
        (r"ConfigurationError:\s*(.+)", ErrorType.CONFIG_ERROR),
        (r"ConfigError:\s*(.+)", ErrorType.CONFIG_ERROR),
        (r"analysis error", ErrorType.ANALYSIS_ERROR),
        (r"scan error", ErrorType.ANALYSIS_ERROR),
        (r"report.*error", ErrorType.REPORT_ERROR),
        (r"failed.*report", ErrorType.REPORT_ERROR),
        (r"ConnectionError", ErrorType.NETWORK_ERROR),
        (r"Timeout", ErrorType.NETWORK_ERROR),
        (r"AI.*error", ErrorType.AI_ERROR),
        (r"openai.*error", ErrorType.AI_ERROR),
        (r"anthropic.*error", ErrorType.AI_ERROR),
        (r"claude.*error", ErrorType.AI_ERROR),
    ]

    WARNING_PATTERNS = [
        r"Warning:",
        r"warning:",
        r"WARNING",
        r"\[WARN\]",
        r"\[yellow\]",
        r"⚠",
        r"Failed to",
        r"fallback",
        r"timeout",
        r"retry",
    ]

    INFO_PATTERNS = [
        r"Scanning file:",
        r"Analyzing",
        r"Found",
        r"Starting",
        r"Completed",
        r"Success",
        r"✓",
        r"✔",
    ]

    TOKEN_PATTERNS = [
        r"token.*?[:\s]+(\d+)",
        r"usage[:\s]+(\d+)",
        r"tokens?[:\s]+(\d+)",
        r"Token usage:\s*(\d+)",
    ]

    def __init__(self):
        self.entries: List[LogEntry] = []
        self.errors: List[ErrorEntry] = []
        self.warnings: List[str] = []
        self.info_messages: List[str] = []
        self.scan_progress: List[str] = []

    def analyze_output(
        self,
        stdout: str,
        stderr: str = "",
        exit_code: int = 0
    ) -> LogAnalysisResult:
        """
        分析命令输出

        Args:
            stdout: 标准输出
            stderr: 标准错误
            exit_code: 退出码

        Returns:
            日志分析结果
        """
        self.entries = []
        self.errors = []
        self.warnings = []
        self.info_messages = []
        self.scan_progress = []
        self.token_usage = 0

        self._parse_stdout(stdout)
        if stderr:
            self._parse_stderr(stderr)

        self.token_usage = self._extract_token_usage(stdout + stderr)

        is_success = exit_code == 0 and len(self.errors) == 0

        silent_failures = self._detect_silent_failures(stdout, stderr, is_success)

        self._generate_summary()

        return LogAnalysisResult(
            entries=self.entries,
            errors=self.errors,
            warnings=self.warnings,
            info_messages=self.info_messages,
            token_usage=self.token_usage,
            scan_progress=self.scan_progress,
            silent_failures=silent_failures,
            is_success=is_success,
            exit_code=exit_code,
            summary=self._get_summary_dict()
        )

    def _parse_stdout(self, stdout: str) -> None:
        """解析标准输出"""
        if not stdout:
            return

        for line in stdout.split("\n"):
            if not line.strip():
                continue

            stripped = line.strip()

            if self._is_error_line(stripped):
                error = self._parse_error_line(stripped)
                if error:
                    self.errors.append(error)
                self.entries.append(LogEntry(
                    level=LogLevel.ERROR,
                    timestamp=None,
                    message=stripped,
                    raw_line=line
                ))
            elif self._is_warning_line(stripped):
                self.warnings.append(stripped)
                self.entries.append(LogEntry(
                    level=LogLevel.WARNING,
                    timestamp=None,
                    message=stripped,
                    raw_line=line
                ))
            elif self._is_info_line(stripped):
                self.info_messages.append(stripped)
                self.entries.append(LogEntry(
                    level=LogLevel.INFO,
                    timestamp=None,
                    message=stripped,
                    raw_line=line
                ))

                progress_match = re.search(r"(Scanning file:|Analyzing|Found|Starting|Completed)[^\n]*", stripped)
                if progress_match:
                    self.scan_progress.append(progress_match.group(0))

    def _parse_stderr(self, stderr: str) -> None:
        """解析标准错误"""
        if not stderr:
            return

        for line in stderr.split("\n"):
            if not line.strip():
                continue

            stripped = line.strip()

            error = self._parse_error_line(stripped)
            if error:
                self.errors.append(error)

            if "Traceback" not in stripped and not self._is_error_line(stripped):
                if self._is_warning_line(stripped):
                    self.warnings.append(stripped)

            self.entries.append(LogEntry(
                level=LogLevel.ERROR if self._is_error_line(stripped) else LogLevel.UNKNOWN,
                timestamp=None,
                message=stripped,
                raw_line=line
            ))

        stack_trace = ""
        in_traceback = False
        for line in stderr.split("\n"):
            if "Traceback" in line:
                in_traceback = True
                stack_trace = line + "\n"
            elif in_traceback:
                stack_trace += line + "\n"
                if line.strip() and not line.startswith("  "):
                    if self.errors:
                        self.errors[-1].stack_trace = stack_trace
                    in_traceback = False
                    stack_trace = ""

    def _is_error_line(self, line: str) -> bool:
        """判断是否为错误行"""
        error_indicators = [
            "Error:",
            "ERROR",
            "Exception:",
            "EXCEPTION",
            "[ERROR]",
            "[red]",
            "Failed:",
            "FAIL",
            "Traceback",
            "raise ",
        ]
        return any(indicator in line for indicator in error_indicators)

    def _is_warning_line(self, line: str) -> bool:
        """判断是否为警告行"""
        return any(re.search(p, line) for p in self.WARNING_PATTERNS)

    def _is_info_line(self, line: str) -> bool:
        """判断是否为信息行"""
        return any(re.search(p, line) for p in self.INFO_PATTERNS)

    def _parse_error_line(self, line: str) -> Optional[ErrorEntry]:
        """解析错误行"""
        for pattern, error_type in self.ERROR_PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return ErrorEntry(
                    error_type=error_type,
                    message=line,
                    severity="error"
                )

        if self._is_error_line(line):
            return ErrorEntry(
                error_type=ErrorType.UNKNOWN_ERROR,
                message=line,
                severity="error"
            )

        return None

    def _extract_token_usage(self, text: str) -> int:
        """提取 token 使用量"""
        for pattern in self.TOKEN_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    pass
        return 0

    def _detect_silent_failures(
        self,
        stdout: str,
        stderr: str,
        is_success: bool
    ) -> List[str]:
        """检测静默失败"""
        silent_failures: List[str] = []

        if is_success:
            success_indicators = ["Scan Result", "Scan completed", "扫描完成", "✅"]
            if not any(indicator in stdout for indicator in success_indicators):
                silent_failures.append("未检测到扫描完成标志，但退出码为0")

        has_findings = "Found" in stdout or "发现" in stdout
        has_progress = len(self.scan_progress) > 0

        if not has_progress and not has_findings:
            silent_failures.append("未检测到扫描进度信息")

        return silent_failures

    def _generate_summary(self) -> None:
        """生成摘要"""
        error_types: Dict[str, int] = {}
        for error in self.errors:
            error_type_str = error.error_type.value
            error_types[error_type_str] = error_types.get(error_type_str, 0) + 1

        self._summary = {
            "total_errors": len(self.errors),
            "total_warnings": len(self.warnings),
            "error_types": error_types,
            "has_silent_failures": len(self.scan_progress) == 0 and len(self.errors) == 0,
            "scan_progress_count": len(self.scan_progress)
        }

    def _get_summary_dict(self) -> Dict[str, Any]:
        """获取摘要字典"""
        return getattr(self, "_summary", {})

    def get_problems_by_category(self) -> Dict[str, List[ErrorEntry]]:
        """按类别获取问题"""
        problems: Dict[str, List[ErrorEntry]] = {
            "execution_error": [],
            "analysis_error": [],
            "report_error": [],
            "ai_error": [],
            "unknown_error": []
        }

        for error in self.errors:
            category = error.error_type.value
            if category in problems:
                problems[category].append(error)
            else:
                problems["unknown_error"].append(error)

        return problems

    def suggest_fixes(self) -> List[Tuple[str, str]]:
        """
        建议修复方案

        Returns:
            List of (problem, suggested_fix)
        """
        suggestions: List[Tuple[str, str]] = []

        for error in self.errors:
            if error.error_type == ErrorType.IMPORT_ERROR:
                suggestions.append((
                    error.message,
                    "检查 Python 依赖是否正确安装，确保所有 import 的模块都已安装"
                ))
            elif error.error_type == ErrorType.CONFIG_ERROR:
                suggestions.append((
                    error.message,
                    "检查配置文件格式和参数是否正确"
                ))
            elif error.error_type == ErrorType.AI_ERROR:
                suggestions.append((
                    error.message,
                    "检查 AI API 密钥配置和网络连接"
                ))
            elif error.error_type == ErrorType.REPORT_ERROR:
                suggestions.append((
                    error.message,
                    "检查报告生成器模板和数据格式"
                ))
            elif error.error_type == ErrorType.ANALYSIS_ERROR:
                suggestions.append((
                    error.message,
                    "检查分析器代码和输入数据"
                ))

        return suggestions


def analyze_log_file(log_path: Path) -> LogAnalysisResult:
    """分析日志文件"""
    analyzer = LogAnalyzer()

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            content = f.read()

        stderr = ""
        stdout = content

        if "=== STDERR ===" in content:
            parts = content.split("=== STDERR ===")
            stdout = parts[0]
            stderr = parts[1] if len(parts) > 1 else ""

        exit_code_match = re.search(r"Exit code:\s*(\d+)", content)
        exit_code = int(exit_code_match.group(1)) if exit_code_match else 0

        return analyzer.analyze_output(stdout, stderr, exit_code)

    except Exception as e:
        result = LogAnalysisResult()
        result.is_success = False
        result.errors.append(ErrorEntry(
            error_type=ErrorType.UNKNOWN_ERROR,
            message=f"日志文件分析失败: {str(e)}"
        ))
        return result
