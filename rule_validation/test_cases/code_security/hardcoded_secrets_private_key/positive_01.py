# Test Case ID: HSP-P01
# Rule: code_security.hardcoded_secrets_private_key
# Test Type: positive
# Description: RSA 私钥硬编码
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

# RSA 私钥
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z1VS5JJcds3xfn/ygWyF8PbnGy0AHB7MxUK
-----END RSA PRIVATE KEY-----"""
