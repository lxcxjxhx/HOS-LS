# Test Case ID: HSEF-N01
# Rule: code_security.hardcoded_secrets_env_fallback
# Test Type: negative
# Description: 无 fallback 的环境变量
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import os

# 正确使用环境变量，无默认值
api_key = os.environ.get("API_KEY")
db_password = os.getenv("DB_PASSWORD")
