"""
HOS-LS 动态验证模块

提供可选的漏洞复核验证功能，支持：
- 动态加载验证器
- AI 生成 POC 验证
- 方法存储管理
- 配置系统
"""

from .interfaces import Validator, ValidationResult, VulnContext
from .dynamic_loader import DynamicLoader
from .method_storage import MethodStorage, MethodDefinition
from .poc_generator import AIPOCGenerator
from .config_loader import ConfigLoader
from .result_reviewer import ResultReviewer

__all__ = [
    'Validator',
    'ValidationResult',
    'VulnContext',
    'DynamicLoader',
    'MethodStorage',
    'MethodDefinition',
    'AIPOCGenerator',
    'ConfigLoader',
    'ResultReviewer',
]
