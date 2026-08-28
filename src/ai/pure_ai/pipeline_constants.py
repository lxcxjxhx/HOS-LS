"""多Agent流水线常量配置

定义流水线使用的常量、阈值和默认配置。
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

from src.ai.models import AIRequest
from src.ai.prompt_engine import PromptEngine, get_prompt_engine
from src.ai.pure_ai.context_builder import ContextBuilder
from src.ai.pure_ai.line_number_mapper import LineNumberMapper
from src.ai.pure_ai.schema_validator import SchemaValidator

try:
    from src.ai.token_tracker import get_token_tracker
except ImportError:

    def get_token_tracker(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        return None


from src.ai.pure_ai.schema import SignalState
from src.utils.logger import get_logger

logger = get_logger(__name__)

console = Console()


class SemanticConsistencyError(Exception):
    """语义一致性异常"""


HIGH_SEVERITY_RISK_TYPES = [
    "CSRF",
    "csrf",
    "Cross-Site Request Forgery",
    "authentication",
    "Authentication",
    "认证",
    "authorization",
    "Authorization",
    "授权",
    "Privilege",
    "privilege",
    "越权",
    "token",
    "Token",
    "session",
    "Session",
    "令牌",
    "会话",
    "JWT",
    "OAuth",
    "OIDC",
    "SAML",
    "credential",
    "Credential",
    "凭证",
    "密码",
    "password",
    "Password",
    "IDOR",
    "idor",
    "访问控制",
    "access control",
    "SQL injection",
    "SQL注入",
    "sql injection",
    "SQL Injection",
    "XSS",
    "xss",
    "Cross-Site Scripting",
    "跨站脚本",
    "RCE",
    "rce",
    "Remote Code Execution",
    "命令执行",
    "SSRF",
    "ssrf",
    "Server-Side Request Forgery",
    "deserialize",
    "Deserialize",
    "反序列化",
    "serialization",
    "Serialization",
    "path traversal",
    "Path Traversal",
    "路径穿越",
    "directory traversal",
    "file inclusion",
    "File Inclusion",
    "文件包含",
    "LFI",
    "RFI",
    "XXE",
    "xxe",
    "XML External Entity",
    "SSTI",
    "ssti",
    "Server-Side Template Injection",
    "Race Condition",
    "race condition",
    "竞态条件",
    "Heap Inspection",
    "heap inspection",
    "Type Confusion",
    "type confusion",
]

CONFIDENCE_THRESHOLDS = {"high_severity": 0.3, "default": 0.5}

SIGNAL_QUEUE_TIMEOUT = 30

REJECTED_PLACEHOLDERS = [
    "UNVERIFIED_RISK",
    "UNVERIFIED",
    "GENERIC",
    "PLACEHOLDER",
    "UNKNOWN",
    "unknown",
    "未知风险",
    "风险相关安全风险",
    "UNVERIFIED_RISK相关安全风险",
    "风险",
    "安全风险",
    "相关安全风险",
    "漏洞",
    "待验证",
]

TOKEN_BUDGET_PER_FILE = 100000
TOKEN_WARNING_THRESHOLD = 0.8
TOKEN_CRITICAL_THRESHOLD = 0.95