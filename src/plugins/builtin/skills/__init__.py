"""技能插件模块

导出所有技能插件类。
"""

from .code_analysis_skill import CodeAnalysisSkill
from .report_generation_skill import ReportGenerationSkill

__all__ = [
    'CodeAnalysisSkill',
    'ReportGenerationSkill',
]
