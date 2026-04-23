"""迭代优化器模块

管理扫描迭代循环的生命周期，实现收敛判断逻辑。
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class IterationStatus(Enum):
    """迭代状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CONVERGED = "converged"


class ProblemSeverity(Enum):
    """问题严重级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProblemCategory(Enum):
    """问题分类"""
    EXECUTION_ERROR = "execution_error"
    ANALYSIS_ERROR = "analysis_error"
    REPORT_ERROR = "report_error"
    QUALITY_ISSUE = "quality_issue"


@dataclass
class Problem:
    """问题描述"""
    category: ProblemCategory
    severity: ProblemSeverity
    description: str
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    suggested_fix: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IterationResult:
    """单次迭代结果"""
    iteration: int
    status: IterationStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    exit_code: int = 0
    report_path: Optional[str] = None
    findings_count: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    problems: List[Problem] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    token_usage: int = 0
    execution_time: float = 0.0
    fixes_applied: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """迭代持续时间（秒）"""
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

    def is_success(self) -> bool:
        """判断迭代是否成功"""
        return self.status == IterationStatus.COMPLETED and self.exit_code == 0

    def has_critical_issues(self) -> bool:
        """是否有严重问题"""
        return any(p.severity == ProblemSeverity.CRITICAL for p in self.problems)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "iteration": self.iteration,
            "status": self.status.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "exit_code": self.exit_code,
            "report_path": self.report_path,
            "findings_count": self.findings_count,
            "severity_counts": self.severity_counts,
            "problems": [
                {
                    "category": p.category.value,
                    "severity": p.severity.value,
                    "description": p.description,
                    "source_file": p.source_file,
                    "line_number": p.line_number,
                    "error_message": p.error_message,
                    "suggested_fix": p.suggested_fix
                }
                for p in self.problems
            ],
            "errors": self.errors,
            "warnings": self.warnings,
            "token_usage": self.token_usage,
            "fixes_applied": self.fixes_applied,
            "metadata": self.metadata
        }


@dataclass
class ConvergenceCriteria:
    """收敛标准"""
    max_iterations: int = 20
    stable_iterations: int = 3
    max_token_usage: int = 100000
    target_critical: int = 0
    target_high: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConvergenceCriteria":
        """从字典创建"""
        return cls(
            max_iterations=data.get("max_iterations", 20),
            stable_iterations=data.get("stable_iterations", 3),
            max_token_usage=data.get("max_token_usage", 100000),
            target_critical=data.get("target_critical", 0),
            target_high=data.get("target_high", 0)
        )


class ConvergenceChecker:
    """收敛检查器"""

    def __init__(self, criteria: ConvergenceCriteria):
        self.criteria = criteria
        self.stable_count = 0
        self.last_findings_count: Optional[int] = None
        self.last_severity_counts: Optional[Dict[str, int]] = None

    def check(self, result: IterationResult) -> tuple[bool, str]:
        """
        检查是否收敛

        Returns:
            (is_converged, reason)
        """
        if result.iteration >= self.criteria.max_iterations:
            return True, f"达到最大迭代次数 ({self.criteria.max_iterations})"

        if self.criteria.max_token_usage > 0 and result.token_usage >= self.criteria.max_token_usage:
            return True, f"Token 消耗达到限制 ({result.token_usage})"

        critical = result.severity_counts.get("critical", 0)
        high = result.severity_counts.get("high", 0)
        if critical <= self.criteria.target_critical and high <= self.criteria.target_high:
            return True, f"问题数量已达到目标 (Critical: {critical}, High: {high})"

        if self.last_findings_count is not None:
            if result.findings_count == self.last_findings_count:
                severity_same = True
                if self.last_severity_counts and result.severity_counts:
                    severity_same = self.last_severity_counts == result.severity_counts

                if severity_same and len(result.problems) == 0:
                    self.stable_count += 1
                    if self.stable_count >= self.criteria.stable_iterations:
                        return True, f"连续 {self.stable_count} 次迭代无变化"
                else:
                    self.stable_count = 0
            else:
                self.stable_count = 0

        self.last_findings_count = result.findings_count
        self.last_severity_counts = result.severity_counts.copy()

        return False, "未收敛"


class IterationHistory:
    """迭代历史记录"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = output_dir / "iteration_history.json"
        self.iterations: List[IterationResult] = []

    def add(self, result: IterationResult) -> None:
        """添加迭代结果"""
        self.iterations.append(result)
        self._save()

    def get_last(self, n: int = 1) -> List[IterationResult]:
        """获取最近n次迭代结果"""
        return self.iterations[-n:]

    def get_summary(self) -> Dict[str, Any]:
        """获取迭代历史摘要"""
        if not self.iterations:
            return {}

        total_findings = sum(r.findings_count for r in self.iterations)
        total_errors = sum(len(r.errors) for r in self.iterations)
        total_problems = sum(len(r.problems) for r in self.iterations)
        total_fixes = sum(len(r.fixes_applied) for r in self.iterations)

        return {
            "total_iterations": len(self.iterations),
            "total_findings": total_findings,
            "total_errors": total_errors,
            "total_problems": total_problems,
            "total_fixes": total_fixes,
            "average_findings": total_findings / len(self.iterations),
            "average_duration": sum(r.duration for r in self.iterations) / len(self.iterations),
            "final_status": self.iterations[-1].status.value,
            "final_findings_count": self.iterations[-1].findings_count
        }

    def _save(self) -> None:
        """保存历史记录"""
        data = {
            "iterations": [r.to_dict() for r in self.iterations],
            "summary": self.get_summary()
        }
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


class IterativeOptimizer:
    """迭代优化器主类"""

    def __init__(
        self,
        output_dir: Path,
        criteria: Optional[ConvergenceCriteria] = None
    ):
        self.output_dir = output_dir
        self.criteria = criteria or ConvergenceCriteria()
        self.convergence_checker = ConvergenceChecker(self.criteria)
        self.history = IterationHistory(output_dir)
        self.current_iteration: Optional[IterationResult] = None

        self.logs_dir = output_dir / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def create_iteration(self, iteration: int) -> IterationResult:
        """创建新的迭代"""
        self.current_iteration = IterationResult(
            iteration=iteration,
            status=IterationStatus.RUNNING,
            start_time=datetime.now()
        )
        return self.current_iteration

    def complete_iteration(self) -> None:
        """完成当前迭代"""
        if self.current_iteration:
            self.current_iteration.end_time = datetime.now()
            self.current_iteration.status = IterationStatus.COMPLETED
            self.current_iteration.execution_time = self.current_iteration.duration
            self.history.add(self.current_iteration)

    def fail_iteration(self, error: str) -> None:
        """标记迭代失败"""
        if self.current_iteration:
            self.current_iteration.status = IterationStatus.FAILED
            self.current_iteration.end_time = datetime.now()
            self.current_iteration.errors.append(error)
            self.current_iteration.execution_time = self.current_iteration.duration
            self.history.add(self.current_iteration)

    def add_problem(self, problem: Problem) -> None:
        """添加问题"""
        if self.current_iteration:
            self.current_iteration.problems.append(problem)

    def add_fix(self, fix_description: str) -> None:
        """添加已应用的修复"""
        if self.current_iteration:
            self.current_iteration.fixes_applied.append(fix_description)

    def check_convergence(self) -> tuple[bool, str]:
        """检查收敛状态"""
        if self.current_iteration:
            return self.convergence_checker.check(self.current_iteration)
        return False, "无迭代结果"

    def get_iteration_log_path(self, iteration: int) -> Path:
        """获取迭代日志路径"""
        return self.logs_dir / f"iteration_{iteration}_full.log"

    def should_stop(self) -> bool:
        """判断是否应该停止"""
        if not self.current_iteration:
            return False

        is_converged, reason = self.check_convergence()
        if is_converged:
            print(f"[收敛检测] {reason}")
            self.current_iteration.status = IterationStatus.CONVERGED
            return True

        if self.current_iteration.iteration >= self.criteria.max_iterations:
            return True

        return False

    def get_progress_report(self) -> str:
        """获取进度报告"""
        if not self.current_iteration:
            return "无进行中的迭代"

        result = self.current_iteration
        lines = [
            f"=== 迭代进度报告 (第 {result.iteration} 次) ===",
            f"状态: {result.status.value}",
            f"执行时间: {result.duration:.2f}s",
            f"发现问题: {result.findings_count}",
            f"  - Critical: {result.severity_counts.get('critical', 0)}",
            f"  - High: {result.severity_counts.get('high', 0)}",
            f"  - Medium: {result.severity_counts.get('medium', 0)}",
            f"  - Low: {result.severity_counts.get('low', 0)}",
            f"错误数: {len(result.errors)}",
            f"警告数: {len(result.warnings)}",
            f"已应用修复: {len(result.fixes_applied)}",
        ]

        if result.problems:
            lines.append("\n当前问题:")
            for i, p in enumerate(result.problems, 1):
                lines.append(f"  {i}. [{p.severity.value}] {p.description}")

        return "\n".join(lines)
