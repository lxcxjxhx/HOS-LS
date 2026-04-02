# Test Case ID: HSP-N02
# Rule: code_security.hardcoded_secrets_private_key
# Test Type: negative
# Description: 测试用的假私钥
# Expected Detection: false
# Expected Severity: N/A
# Code Type: test

# 测试用的假私钥
test_key = """-----BEGIN PRIVATE KEY-----
TEST_KEY_DO_NOT_USE_IN_PRODUCTION
-----END PRIVATE KEY-----"""
