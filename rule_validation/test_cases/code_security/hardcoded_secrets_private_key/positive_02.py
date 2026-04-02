# Test Case ID: HSP-P02
# Rule: code_security.hardcoded_secrets_private_key
# Test Type: positive
# Description: EC 私钥硬编码
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# EC 私钥
ec_private_key = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBkg5mYjHl3yJ4b3V8z5L8wK
-----END EC PRIVATE KEY-----"""
