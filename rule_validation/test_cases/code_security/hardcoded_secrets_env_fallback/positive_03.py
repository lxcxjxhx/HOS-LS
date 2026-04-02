# Test Case ID: HSEF-P03
# Rule: code_security.hardcoded_secrets_env_fallback
# Test Type: positive
# Description: getenv fallback 默认值
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from os import getenv

# getenv 带有默认值
secret_key = getenv("SECRET_KEY", "default_secret_key_123")
