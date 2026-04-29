"""注入类安全规则

包含 SQL 注入、命令注入、XSS 等检测规则。
"""

from src.rules.builtin.injection.sql_injection import SQLInjectionRule
from src.rules.builtin.injection.command_injection import CommandInjectionRule
from src.rules.builtin.injection.xss import XSSRule

__all__ = ["SQLInjectionRule", "CommandInjectionRule", "XSSRule"]
