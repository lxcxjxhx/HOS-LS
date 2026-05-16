"""
分析模块 - 提供代码分析能力

包含：
1. ModuleAnalyzer - 模块依赖分析
2. BeanScanner - Spring Bean扫描
3. SpELParser - SpEL表达式解析
4. FrameworkPatterns - 框架安全模式识别
"""

from .module_analyzer import ModuleAnalyzer, ModuleInfo
from .bean_scanner import BeanScanner, BeanDefinition
from .spel_parser import SpELParser, SpELReference, SpELVerificationResult

__all__ = [
    'ModuleAnalyzer',
    'ModuleInfo',
    'BeanScanner',
    'BeanDefinition',
    'SpELParser',
    'SpELReference',
    'SpELVerificationResult',
]