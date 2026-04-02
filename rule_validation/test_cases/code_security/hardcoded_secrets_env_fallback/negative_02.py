# Test Case ID: HSEF-N02
# Rule: code_security.hardcoded_secrets_env_fallback
# Test Type: negative
# Description: fallback 为 None
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import os

# fallback 为 None（安全）
api_key = os.environ.get("API_KEY", None)
