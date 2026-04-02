# Test Case ID: HSEF-B01
# Rule: code_security.hardcoded_secrets_env_fallback
# Test Type: boundary
# Description: 短默认值（边界情况）
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

import os

# 短的默认值（可能漏检）
api_key = os.environ.get("API_KEY", "pwd")
