# Test Case ID: HSE-B01
# Rule: code_security.hardcoded_secrets_encoded
# Test Type: boundary
# Description: 包含特殊字符的 Base64 字符串
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

# 包含特殊字符的 Base64 字符串
weird_b64 = "c2stMTIz!@#$%^&*()"  # 格式异常
