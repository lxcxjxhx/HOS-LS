# Test Case ID: HSEF-P01
# Rule: code_security.hardcoded_secrets_env_fallback
# Test Type: positive
# Description: 环境变量 fallback 硬编码默认值
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import os

# 环境变量 fallback 中有硬编码默认值
api_key = os.environ.get("API_KEY", "sk-1234567890abcdef")
