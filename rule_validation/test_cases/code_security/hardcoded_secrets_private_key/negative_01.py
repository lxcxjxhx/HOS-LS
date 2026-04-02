# Test Case ID: HSP-N01
# Rule: code_security.hardcoded_secrets_private_key
# Test Type: negative
# Description: 文档中的示例私钥（占位符）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: example

# 文档示例（占位符）
example_key = """-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----"""
