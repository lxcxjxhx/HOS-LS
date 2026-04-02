# Test Case ID: HSP-B01
# Rule: code_security.hardcoded_secrets_private_key
# Test Type: boundary
# Description: 不完整的私钥格式
# Expected Detection: true
# Expected Severity: MEDIUM
# Code Type: vulnerable

# 不完整的私钥格式（边界情况）
partial_key = """-----BEGIN PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z1VS5JJcds3xfn
"""
