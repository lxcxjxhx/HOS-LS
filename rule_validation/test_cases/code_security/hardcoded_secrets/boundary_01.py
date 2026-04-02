# Test Case ID: HS-B01
# Rule: code_security.hardcoded_secrets
# Test Type: boundary
# Description: 短密钥（边界情况）
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

# 短密钥，可能因为长度不足而漏检
api_key = "sk-123"
password = "pwd"
