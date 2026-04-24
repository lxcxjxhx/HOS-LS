"""认证类安全规则

包含硬编码凭证、弱密码等检测规则。
"""

from src.rules.builtin.authentication.hardcoded_credentials import HardcodedCredentialsRule

__all__ = ["HardcodedCredentialsRule"]
