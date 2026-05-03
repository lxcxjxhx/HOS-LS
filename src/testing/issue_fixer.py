"""问题修复器模块

根据问题类型选择修复策略，自动修改源代码。
"""

import os
import re
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class FixCategory(Enum):
    """修复类别"""
    CLI_FIX = "cli_fix"
    CONFIG_FIX = "config_fix"
    IMPORT_FIX = "import_fix"
    ANALYSIS_FIX = "analysis_fix"
    REPORT_FIX = "report_fix"
    QUALITY_FIX = "quality_fix"
    PROMPT_FIX = "prompt_fix"


@dataclass
class FixResult:
    """修复结果"""
    success: bool
    category: FixCategory
    description: str
    file_path: Optional[str] = None
    original_code: Optional[str] = None
    fixed_code: Optional[str] = None
    line_number: int = 0
    error_message: Optional[str] = None
    backup_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    suggested_fix: Optional[str] = None


@dataclass
class FixPlan:
    """修复计划"""
    category: FixCategory
    priority: int
    description: str
    target_file: Optional[str] = None
    target_line: int = 0
    suggested_fix: str = ""
    reason: str = ""


class BaseFixer(ABC):
    """修复器基类"""

    def __init__(self, backup_dir: Optional[Path] = None):
        self.backup_dir = backup_dir or Path("backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def can_fix(self, problem: Any) -> bool:
        """判断是否可以修复"""
        pass

    @abstractmethod
    def fix(self, problem: Any) -> FixResult:
        """执行修复"""
        pass

    def _create_backup(self, file_path: Path) -> Optional[Path]:
        """创建备份"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{file_path.stem}_{timestamp}{file_path.suffix}"
            backup_path = self.backup_dir / backup_name
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception:
            return None

    def _read_file(self, file_path: Path) -> Optional[str]:
        """读取文件内容"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return None

    def _write_file(self, file_path: Path, content: str) -> bool:
        """写入文件内容"""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except Exception:
            return False


class ImportFixer(BaseFixer):
    """导入问题修复器"""

    def can_fix(self, problem: Any) -> bool:
        """判断是否可以修复"""
        if hasattr(problem, "error_type"):
            return "import" in str(problem.error_type).lower()
        if hasattr(problem, "message"):
            return "import" in str(problem.message).lower() or "module" in str(problem.message).lower()
        return False

    def fix(self, problem: Any) -> FixResult:
        """执行修复"""
        message = getattr(problem, "message", "") or getattr(problem, "error_message", "")

        module_match = re.search(r"ModuleNotFoundError:\s*No module named\s*'([^']+)'", message)
        if module_match:
            module_name = module_match.group(1)
            return FixResult(
                success=True,
                category=FixCategory.IMPORT_FIX,
                description=f"缺少模块 '{module_name}'，建议执行: pip install {module_name}",
                error_message=message,
                metadata={"module": module_name}
            )

        return FixResult(
            success=False,
            category=FixCategory.IMPORT_FIX,
            description="无法自动修复导入问题",
            error_message=message
        )


class ConfigFixer(BaseFixer):
    """配置问题修复器"""

    def can_fix(self, problem: Any) -> bool:
        """判断是否可以修复"""
        if hasattr(problem, "error_type"):
            return "config" in str(problem.error_type).lower()
        if hasattr(problem, "category"):
            return "config" in str(problem.category).lower()
        return False

    def fix(self, problem: Any) -> FixResult:
        """执行修复"""
        message = getattr(problem, "message", "") or getattr(problem, "error_message", "")

        missing_key_match = re.search(r"Missing config key[:\s]*['\"]?([^'\"\n]+)['\"]?", message)
        if missing_key_match:
            key = missing_key_match.group(1)
            return FixResult(
                success=True,
                category=FixCategory.CONFIG_FIX,
                description=f"缺少配置键 '{key}'",
                suggested_fix=f"在配置文件中添加 {key} 的值"
            )

        return FixResult(
            success=False,
            category=FixCategory.CONFIG_FIX,
            description="无法自动修复配置问题",
            error_message=message
        )


class AnalysisFixer(BaseFixer):
    """分析问题修复器"""

    def can_fix(self, problem: Any) -> bool:
        """判断是否可以修复"""
        if hasattr(problem, "error_type"):
            return "analysis" in str(problem.error_type).lower()
        if hasattr(problem, "category"):
            return "analysis" in str(problem.category).lower()
        return False

    def fix(self, problem: Any) -> FixResult:
        """执行修复"""
        message = getattr(problem, "message", "") or getattr(problem, "error_message", "")

        null_match = re.search(r"'NoneType'.*?object has no attribute\s*'([^']+)'", message)
        if null_match:
            attr = null_match.group(1)
            return FixResult(
                success=True,
                category=FixCategory.ANALYSIS_FIX,
                description=f"对象缺少属性 '{attr}'",
                suggested_fix=f"在访问属性前添加空值检查"
            )

        index_match = re.search(r"index\s*(\d+)\s*out of range", message)
        if index_match:
            index = index_match.group(1)
            return FixResult(
                success=True,
                category=FixCategory.ANALYSIS_FIX,
                description=f"索引越界: {index}",
                suggested_fix="检查数组/列表长度后再访问"
            )

        return FixResult(
            success=False,
            category=FixCategory.ANALYSIS_FIX,
            description="无法自动修复分析问题",
            error_message=message
        )


class ReportFixer(BaseFixer):
    """报告问题修复器"""

    def can_fix(self, problem: Any) -> bool:
        """判断是否可以修复"""
        if hasattr(problem, "error_type"):
            return "report" in str(problem.error_type).lower()
        if hasattr(problem, "category"):
            return "report" in str(problem.category).lower()
        return False

    def fix(self, problem: Any) -> FixResult:
        """执行修复"""
        message = getattr(problem, "message", "") or getattr(problem, "error_message", "")

        template_match = re.search(r"template.*?not found", message, re.IGNORECASE)
        if template_match:
            return FixResult(
                success=True,
                category=FixCategory.REPORT_FIX,
                description="报告模板未找到",
                suggested_fix="检查模板路径配置是否正确"
            )

        return FixResult(
            success=False,
            category=FixCategory.REPORT_FIX,
            description="无法自动修复报告问题",
            error_message=message
        )


class QualityFixer(BaseFixer):
    """质量问题修复器"""

    def can_fix(self, problem: Any) -> bool:
        """判断是否可以修复"""
        if hasattr(problem, "severity"):
            return problem.severity in ["low", "medium"]
        if hasattr(problem, "category"):
            return "quality" in str(problem.category).lower()
        return False

    def fix(self, problem: Any) -> FixResult:
        """执行修复"""
        message = getattr(problem, "message", "") or getattr(problem, "description", "")

        confidence_match = re.search(r"confidence[:\s]*(low|high)", message, re.IGNORECASE)
        if confidence_match:
            level = confidence_match.group(1)
            return FixResult(
                success=True,
                category=FixCategory.QUALITY_FIX,
                description=f"发现置信度 {level}",
                suggested_fix="调整 AI 分析参数以提高准确率"
            )

        return FixResult(
            success=False,
            category=FixCategory.QUALITY_FIX,
            description="无法自动修复质量问题",
            error_message=message
        )


class PromptFixer(BaseFixer):
    """Prompt 问题修复器"""

    def can_fix(self, problem: Any) -> bool:
        """判断是否可以修复"""
        if hasattr(problem, "message"):
            msg = str(problem.message).lower()
            return "prompt" in msg or "ai" in msg or "analysis" in msg
        return False

    def fix(self, problem: Any) -> FixResult:
        """执行修复"""
        message = getattr(problem, "message", "") or ""

        if "ai" in message.lower() or "analysis" in message.lower():
            return FixResult(
                success=True,
                category=FixCategory.PROMPT_FIX,
                description="AI 分析相关问题",
                suggested_fix="检查 AI 配置和 prompt 模板"
            )

        return FixResult(
            success=False,
            category=FixCategory.PROMPT_FIX,
            description="无法自动修复 prompt 问题",
            error_message=message
        )


class IssueFixer:
    """问题修复器主类"""

    def __init__(self, backup_dir: Optional[Path] = None):
        self.backup_dir = backup_dir or Path("backups")
        self.fixers: List[BaseFixer] = [
            ImportFixer(self.backup_dir),
            ConfigFixer(self.backup_dir),
            AnalysisFixer(self.backup_dir),
            ReportFixer(self.backup_dir),
            QualityFixer(self.backup_dir),
            PromptFixer(self.backup_dir),
        ]

    def fix(self, problem: Any) -> FixResult:
        """修复问题"""
        for fixer in self.fixers:
            if fixer.can_fix(problem):
                return fixer.fix(problem)

        return FixResult(
            success=False,
            category=FixCategory.QUALITY_FIX,
            description="无可用修复方案"
        )

    def fix_file_content(
        self,
        file_path: Path,
        line_number: int,
        old_content: str,
        new_content: str
    ) -> FixResult:
        """修复文件内容"""
        backup_path = self._create_backup(file_path)
        original = self._read_file(file_path)

        if original is None:
            return FixResult(
                success=False,
                category=FixCategory.QUALITY_FIX,
                description=f"无法读取文件: {file_path}",
                error_message="文件读取失败"
            )

        lines = original.split("\n")
        if 0 < line_number <= len(lines):
            lines[line_number - 1] = new_content
            new_file_content = "\n".join(lines)

            if self._write_file(file_path, new_file_content):
                return FixResult(
                    success=True,
                    category=FixCategory.QUALITY_FIX,
                    description=f"已修复第 {line_number} 行",
                    file_path=str(file_path),
                    original_code=old_content,
                    fixed_code=new_content,
                    line_number=line_number,
                    backup_path=str(backup_path) if backup_path else None
                )
            else:
                return FixResult(
                    success=False,
                    category=FixCategory.QUALITY_FIX,
                    description=f"无法写入文件: {file_path}",
                    error_message="文件写入失败"
                )
        else:
            return FixResult(
                success=False,
                category=FixCategory.QUALITY_FIX,
                description=f"行号无效: {line_number}",
                error_message="行号超出范围"
            )

    def fix_pattern_in_file(
        self,
        file_path: Path,
        pattern: str,
        replacement: str
    ) -> FixResult:
        """替换文件中的模式"""
        backup_path = self._create_backup(file_path)
        original = self._read_file(file_path)

        if original is None:
            return FixResult(
                success=False,
                category=FixCategory.QUALITY_FIX,
                description=f"无法读取文件: {file_path}",
                error_message="文件读取失败"
            )

        if pattern in original:
            new_content = original.replace(pattern, replacement)

            if self._write_file(file_path, new_content):
                return FixResult(
                    success=True,
                    category=FixCategory.QUALITY_FIX,
                    description=f"已替换模式",
                    file_path=str(file_path),
                    original_code=pattern,
                    fixed_code=replacement,
                    backup_path=str(backup_path) if backup_path else None
                )
            else:
                return FixResult(
                    success=False,
                    category=FixCategory.QUALITY_FIX,
                    description=f"无法写入文件: {file_path}",
                    error_message="文件写入失败"
                )
        else:
            return FixResult(
                success=False,
                category=FixCategory.QUALITY_FIX,
                description=f"未找到匹配模式",
                error_message=f"模式 '{pattern}' 未找到"
            )

    def _create_backup(self, file_path: Path) -> Optional[Path]:
        """创建备份"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{file_path.stem}_{timestamp}{file_path.suffix}"
            backup_path = self.backup_dir / backup_name
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception:
            return None

    def _read_file(self, file_path: Path) -> Optional[str]:
        """读取文件内容"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return None

    def _write_file(self, file_path: Path, content: str) -> bool:
        """写入文件内容"""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except Exception:
            return False


def generate_fix_plan(
    problems: List[Any],
    fixer: IssueFixer
) -> List[FixPlan]:
    """
    生成修复计划

    Args:
        problems: 问题列表
        fixer: 修复器

    Returns:
        修复计划列表
    """
    plans: List[FixPlan] = []

    for i, problem in enumerate(problems):
        fix_result = fixer.fix(problem)

        category_map = {
            "import_fix": FixCategory.IMPORT_FIX,
            "config_fix": FixCategory.CONFIG_FIX,
            "analysis_fix": FixCategory.ANALYSIS_FIX,
            "report_fix": FixCategory.REPORT_FIX,
            "quality_fix": FixCategory.QUALITY_FIX,
            "prompt_fix": FixCategory.PROMPT_FIX,
        }

        category = category_map.get(fix_result.category.value, FixCategory.QUALITY_FIX)

        priority = 0
        if hasattr(problem, "severity"):
            severity_map = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4
            }
            priority = severity_map.get(str(problem.severity).lower(), 4)

        plan = FixPlan(
            category=category,
            priority=priority,
            description=fix_result.description,
            target_file=getattr(problem, "source_file", None),
            target_line=getattr(problem, "line_number", 0),
            suggested_fix=fix_result.suggested_fix or "",
            reason=fix_result.error_message or ""
        )
        plans.append(plan)

    plans.sort(key=lambda x: x.priority)

    return plans
