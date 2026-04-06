"""HOS-LS: AI生成代码安全扫描工具

HOS-LS (HOS - Language Security) 是一款专注于 AI 生成代码安全扫描的工业级工具。
它结合了静态分析、AI 语义分析和攻击模拟等多种技术，为开发者提供全面的代码安全保障。

Version: 0.3.0.3
"""

__version__ = "0.3.0.3"
__author__ = "HOS Team"
__license__ = "MIT"

from src.core.config import Config
from src.core.scanner import SecurityScanner

__all__ = ["Config", "SecurityScanner", "__version__"]
