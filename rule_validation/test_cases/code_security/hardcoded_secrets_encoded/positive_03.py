# Test Case ID: HSE-P03
# Rule: code_security.hardcoded_secrets_encoded
# Test Type: positive
# Description: 长 Base64 字符串（可能是密钥）
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

# 长的 Base64 编码字符串
secret_data = "VGhpcyBpcyBhIHNlY3JldCBrZXkgdGhhdCBzaG91bGQgbm90IGJlIGhhcmRjb2RlZA=="
