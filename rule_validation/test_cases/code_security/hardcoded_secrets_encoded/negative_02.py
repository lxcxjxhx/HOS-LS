# Test Case ID: HSE-N02
# Rule: code_security.hardcoded_secrets_encoded
# Test Type: negative
# Description: 短的 Base64 字符串
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

# 短的 Base64 字符串（不太可能是密钥）
short_b64 = "YWJj"  # "abc"
