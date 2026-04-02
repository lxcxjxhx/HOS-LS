# Test Case ID: IR2-N01
# Rule: code_security.insecure_randomness
# Test Type: negative
# Description: 使用安全的随机数生成
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import secrets

# 使用 secrets 生成安全令牌（推荐）
token = secrets.token_hex(32)
